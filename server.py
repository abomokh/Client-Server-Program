import os
import socket
import select
import sys

# configs
HOST				= ""	# All computer's network interfaces
DEFAULT_PORT		= 1337	# Port to listen on (non-privileged ports are > 1023)
BACK_LOG			= 5		# maximum number of pending, not-yet-accepted connections
SELECT_TIMEOUT		= 3
BUFF_SIZE			= 40
END_OF_MESSAGE		= '\x00'

# data structures
soc_to_msg			= {}	# dict of message buffers
soc_to_status		= {}	# track authenticated clients
registered_users	= {}	# users recognized by the server
rlist				= []	# list of sockets to read from (the listening socket and client socket)

# saved responses
NEW_SOC					= "new client, not authenticated yet"
NEW_SOC_USER			= "new client, username receved"
AUTHED_SOC				= "client authenticated"
WELCOME_MSG				= f"Welcome! Please log in."
FAIL_LOGIN				= "Failed to login."
PARENTHESES_BALANCED	= "the parentheses are balanced: yes"
PARENTHESES_IMBALANCED	= "the parentheses are balanced: no"
AWAITING_PASSWORD		= "User inserted. Awaiting Password"

# custom errors
BAD_REQUEST			= "command type is invalid or disallowed for this client"

# command types
ERROR_RQST			= 0
AUTH_RQST			= 1
USER_AUTH_RQST		= 2
QUIT_RQST			= 3
COMMAND_RQST		= 4

# modes
DEBUG				= False		# debug mode
LOG_PATH			= None		# None for stdout


def debug(log_msg):
	if DEBUG:
		if LOG_PATH == None:
			print(f"DEBUG > {log_msg}")
		else:
			with open(LOG_PATH, "w") as log_file:
				log_file.write(f"DEBUG > {log_msg}")

def main(path, port = DEFAULT_PORT):
	load_users(path, registered_users)

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listenSoc:
		listenSoc.bind((HOST, port))
		debug(f"{listenSoc.getsockname()}")
		listenSoc.listen(BACK_LOG)
		debug("socket is listening...")
		rlist.append(listenSoc)
		while(True):

			debug("calling select()")
			debug(f"len(rlist): {len(rlist)}")
			readable, _, _ = select.select(rlist, [], [], SELECT_TIMEOUT)
			
			for soc in readable:

				# handle the listening socket
				if soc is listenSoc:
					clientSoc, clientAddr = listenSoc.accept()
					
					# new client connected
					soc_to_msg[clientSoc] = b""
					soc_to_status[clientSoc] = NEW_SOC
					send_message_to_client(clientSoc, WELCOME_MSG)
					debug(f"new client connected: {clientSoc}")
					rlist.append(clientSoc)
					continue
					

				# handle other sockets
				soc_to_msg[soc] += soc.recv(BUFF_SIZE)
				debug(soc_to_msg[soc])
				if soc_to_msg[soc].decode() == "":
					# client disconnected. close connection
					rlist.remove(soc)
					soc_to_msg.pop(soc)
					soc_to_status.pop(soc)

				elif soc_to_msg[soc].decode()[-len(END_OF_MESSAGE)] == END_OF_MESSAGE:
					# end of message. handle it and clear the buffer
					general_request_handler(soc, soc_to_msg[soc])
					soc_to_msg[soc] = b""


def general_request_handler(clientSoc: socket, message: bytes):
	debug("inside general_request_handler")
	try:
		# assert the message structure
		request_type, request_parts = check_message_validity_v2(message)
		debug(f"request is {request_type}, {request_parts}")
		if request_type == ERROR_RQST:
			response = BAD_REQUEST
			send_message_to_client(clientSoc, response)
			close_connection_with_client(clientSoc)
			raise ValueError(BAD_REQUEST)
		
		# asset if the message type is of allowed

		# handle the message
		if soc_to_status[clientSoc] == NEW_SOC:

			if request_type != USER_AUTH_RQST:
				# disallowed action from un-authed client. close connection.
				response = BAD_REQUEST
				send_message_to_client(clientSoc, response)
				close_connection_with_client(clientSoc)
				debug(BAD_REQUEST)
				return
			
			else:
				soc_to_status[clientSoc] = NEW_SOC_USER
				send_message_to_client(clientSoc, AWAITING_PASSWORD)
				return
		
		elif soc_to_status[clientSoc] == NEW_SOC_USER:

			if request_type != AUTH_RQST:
				# disallowed action from un-authed client. close connection.
				response = BAD_REQUEST
				send_message_to_client(clientSoc, response)
				close_connection_with_client(clientSoc)
				debug(BAD_REQUEST)
				return
			
			else:
				username, password = request_parts
				response = auth(clientSoc, username, password)
				send_message_to_client(clientSoc, response)
		
		else:
			if request_type == QUIT_RQST:
				close_connection_with_client(clientSoc)
				return
			
			elif request_type == COMMAND_RQST:
				command, *params = request_parts
				response = route(command, params)
				send_message_to_client(clientSoc, response)
			
			else: #not really 
				response = BAD_REQUEST
				send_message_to_client(clientSoc, response)
				close_connection_with_client(clientSoc)


			
	except Exception as e:
		debug(f"ERROR in general_request_handler: {e}")
		return

def close_connection_with_client(clientSoc: socket):
	rlist.remove(clientSoc)
	soc_to_msg.pop(clientSoc)
	soc_to_status.pop(clientSoc)
	return

def send_message_to_client(socket: socket, response: str):
	socket.send((response + END_OF_MESSAGE).encode())

def auth(soc, username, password) -> str:
	debug(f"inside auth: inputs are ({username}, {password})")

	if username in registered_users and registered_users[username] == password:
		debug("logged in successfully. updating the status and sending 'Hi' message")
		soc_to_status[soc] = AUTHED_SOC
		return f"Hi {username}, good to see you."
	else:
		debug("falied to login. sending login-failed message")
		soc_to_status[soc] = NEW_SOC
		return FAIL_LOGIN

def check_message_validity_v2(msg: bytes):
	debug(f"inside check_message_validity_v2 > msg is {msg}")
	"""
	Validates a protocol message and returns:
		1. type: 'AUTH', 'COMMAND', 'QUIT', 'ERROR'
		2. values: list of strings (elements extracted from the message)
	"""
	try:
		text = msg.decode()
	except Exception:
		debug("failed to decode")
		return ERROR_RQST, []
	
	if not text.endswith(END_OF_MESSAGE):
		debug("no END_OF_MESSAGE found")
		return ERROR_RQST, []

	content = text[:-len(END_OF_MESSAGE)].rstrip()

	# Strip any accidental whitespace before terminator
	content = content.rstrip()

	# ---- Check for QUIT message ----
	if content == "quit":
		return QUIT_RQST, ["quit"]

	# ---- Check for AUTH message ----
	if content.startswith("User: ") and "\nPassword: " in content:
		parts = content.split("\nPassword: ", 1)
		if len(parts) == 2:
			user_part = parts[0][6:]
			pass_part = parts[1]

			if user_part != "" and pass_part != "":
				return AUTH_RQST, [user_part, pass_part]

		debug("falied to analyze the request as AUTH-request")
		return ERROR_RQST, []

	# ---- Check for COMMAND or USER_AUTH_RQST message ----
	if ": " in content:
		command_part, rest = content.split(":", 1)
		command = command_part.strip()

		if command == "":
			debug("command request with no command-name")
			return ERROR_RQST, []

		rest = rest.strip()
		params = rest.split(" ") if rest else []

		req_cmd = {"lcm", "parentheses", "caesar"}
		
		if command == "lcm":
			if len(params) == 2 and params[0].isnumeric() and params[1].isnumeric():
				return COMMAND_RQST, [command] + params
		
		elif command == "parentheses":
			if len(params) == 1 and set(params[0]) == {'(', ')'}:
				return COMMAND_RQST, [command] + params
		
		elif command == "caesar":
			if len(params) == 2 and check_caesar_validity(params[0]) and params[1].isnumeric():
				return COMMAND_RQST, [command] + params

		
		elif command == "User":
			return USER_AUTH_RQST, [command] + params
		else: 
			debug(f"falied to analyze the request as COMMAND-request or USER-AUTH-request.\n\tcommand={command}\n\tparams={params}")
			return ERROR_RQST, []

	# ---- nothing mached ----
	debug("falied to analyze the request")
	return ERROR_RQST, []


def route(command: str, params: list[str]) -> str:
	if (command == "parentheses"):
		is_parentheses = parentheses_check(params[0])
		return PARENTHESES_BALANCED if is_parentheses else PARENTHESES_IMBALANCED
	
	elif (command == "lcm"):
		lcm = compute_lcm(int(params[0]), int(params[1]))
		return "the lcm is: " + str(lcm)
	
	else: #(command == "caesar"):
		is_caesar_valid = check_caesar_validity(params[:-1])

		if not is_caesar_valid:
			return "error: invalid input"
		
		caesar = compute_caesar(params[:-1], int(params[-1])) 
		return "the ciphertext is: " + caesar



def compute_lcm(x: int, y: int) -> int:
	# handle zero case
	if x == 0 or y == 0:
		return 0
		
	# helper function: Euclidean algorithm for gcd
	def gcd(a, b):
		while b != 0:
			a, b = b, a % b
		return a
		
	g = gcd(x, y)
	return abs(x * y) // g

def parentheses_check(s: str) -> bool:
	count = 0
	for ch in s:
		if ch == '(':
			count += 1
		elif ch == ')':
			count -= 1
			if count < 0:
				return False
	return count == 0

def check_caesar_validity(text: list[str]) -> bool:
	full_text = " ".join(text)

	for ch in full_text:
		# allow only letters or spaces
		if ch == " ":
			continue

		# if it's a letter but not English → invalid
		if not ("A" <= ch <= "Z" or "a" <= ch <= "z"):
			return False

	return True


def compute_caesar(text: list[str], shift: int) -> str:

	# Join the list of words into a single string
	full_text = " ".join(text)

	# Convert everything to lowercase
	full_text = full_text.lower()

	# Normalize shift
	shift = shift % 26

	result = []

	for ch in full_text:
		if ch == " ":
			# keep spaces as they are
			result.append(" ")
		else:
			# rotate only lowercase letters
			shifted = chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))
			result.append(shifted)

	return "".join(result)

def load_users(path: str, registered_users):
	with open(path) as f:
		for user in f:
			username, password = user.split("\t")
			registered_users[username] = password.replace('\n', "")

# +------------------------------------------------------------------------------------------+
# |                                    Running The Server                                    |
# +------------------------------------------------------------------------------------------+

if __name__ == "__main__":
	# Check number of arguments
	if len(sys.argv) < 2 or len(sys.argv) > 3:
		print(f"Usage: {sys.argv[0]} users_file [port]")
		sys.exit(1)

	users_file = sys.argv[1]

	# Validate file path
	if not os.path.isfile(users_file):
		print(f"Error: '{users_file}' is not a valid file path.")
		sys.exit(1)

	# Validate optional port
	port = None
	if len(sys.argv) == 3:
		try:
			port = int(sys.argv[2])
			if not (1 <= port <= 65535):
				raise ValueError()
		except ValueError:
			print(f"Error: Port must be an integer between 1 and 65535.")
			sys.exit(1)
	
	if port:
		main(users_file, port)
	else:
		main(users_file)

