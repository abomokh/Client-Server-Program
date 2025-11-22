import socket
import select

# configs
HOST				= ""	# All computer's network interfaces
PORT				= 1337	# Port to listen on (non-privileged ports are > 1023)
BACK_LOG			= 5		# maximum number of pending, not-yet-accepted connections
SELECT_TIMEOUT		= 3
BUFF_SIZE			= 4
END_OF_MESSAGE		= '\x00'

# data structures
soc_to_msg			= {}	# dict of message buffers
soc_to_status		= {}	# track authenticated clients
registered_users	= {}	# users recognized by the server

# saved responses
AUTHED_SOC			= "client authenticated"
NEW_SOC				= "new client, not authenticated yet"
WELCOME_MSG			= f"Welcome! Please log in."
FAIL_LOGIN			= "Failed to login."

# custom errors
BAD_REQUEST			= "command type is invalid or disallowed for this client"

# command types
ERROR_RQST			= 0
AUTH_RQST			= 1
QUIT_RQST			= 2
COMMAND_RQST		= 3

# modes
DEBUG				= True		# debug mode
LOG_PATH			= None		# None for stdout


def debug(log_msg):
	if DEBUG:
		if LOG_PATH == None:
			print(f"DEBUG > {log_msg}")
		else:
			with open(LOG_PATH, "w") as log_file:
				log_file.write(f"DEBUG > {log_msg}")

def main(path):
	load_users(path, registered_users)

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listenSoc:
		listenSoc.bind((HOST, PORT))
		listenSoc.listen(BACK_LOG)
		debug("socket is listening...")
		rlist = [listenSoc]
		while(True):

			debug("calling select()")
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

				elif soc_to_msg[soc].decode()[-1] == END_OF_MESSAGE:
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
			raise ValueError(BAD_REQUEST)
		
		# asset if the message type is of allowed

		# handle the message
		if soc_to_status[clientSoc] == NEW_SOC:
			if request_type != AUTH_RQST:
				# disallowed action from un-authed client. close connection.
				close_connection_with_client(clientSoc)
				debug(BAD_REQUEST)
				return
			
			username, password = request_parts
			response = auth(clientSoc, username, password)
			send_message_to_client(clientSoc, response)
		
		else:
			if request_type == QUIT_RQST:
				close_connection_with_client(clientSoc)
				debug(BAD_REQUEST)
				return
			
			elif request_type == COMMAND_RQST:
				command, *params = request_parts
				response = route(command, params)
			
			else:
				response = BAD_REQUEST

			send_message_to_client(clientSoc, response)
		
	except Exception as e:
		debug(f"ERROR in general_request_handler: {e}")
		return

def close_connection_with_client(clientSoc: socket):
	# TODO
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
		return FAIL_LOGIN

def check_message_validity_v2(msg: bytes):
	debug("inside check_message_validity_v2")
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
	if content.startswith("User:") and "\nPassword:" in content:
		parts = content.split("\nPassword:", 1)
		if len(parts) == 2:
			user_part = parts[0][6:]
			pass_part = parts[1][1:]

			if user_part != "" and pass_part != "":
				return AUTH_RQST, [user_part, pass_part]

		debug("falied to analyze the request as AUTH-request")
		return ERROR_RQST, []

	# ---- Check for COMMAND message ----
	if ":" in content:
		command_part, rest = content.split(":", 1)
		command = command_part.strip()

		if command == "":
			debug("command request with no command-name")
			return ERROR_RQST, []

		rest = rest.strip()
		params = rest.split(" ") if rest else []

		return COMMAND_RQST, [command] + params

	# ---- nothing mached ----
	debug("falied to analyze the request")
	return ERROR_RQST, []


def route(command: str, params: list[str]) -> str:
	return 'Hi'

def compute_lcm(x: int, y: int) -> int:
	pass
def parentheses_check(s: str) -> bool:
	pass
def compute_caesar(text: str, shift: int) -> str:
	pass

def load_users(path: str, registered_users):
	with open(path) as f:
		for user in f:
			print(user.split("\t"))
			username, password = user.split("\t")
			registered_users[username] = password.replace('\n', "")






# +------------------------------------------------------------------------------------------+
# |                                        Deprecated                                        |
# +------------------------------------------------------------------------------------------+
def check_message_validity_v1(msg: bytes, soc_status: str) -> bool:
	'''# **⚠️ Deprecated Function!!** Do Not Use'''
	debug("inside check_message_validity")
	if type(msg) != bytes or len(msg) == 0:
		return False
	msg = msg.decode()
	import re
	eom = re.escape(END_OF_MESSAGE)
	if soc_status == NEW_SOC:
		login_pattern = rf"^User:\s*(.+)\nPassword:\s*(.+){eom}$"
		return re.match(login_pattern, msg) is not None
	if soc_status == AUTHED_SOC:
		return False # TODO
def extract_command_and_params(message: bytes) -> tuple[str, list[str]]:
	'''# **⚠️ Deprecated Function!!** Do Not Use'''
	# decode and remove the END_OF_MESSAGE char
	message = message.decode()[:-len(END_OF_MESSAGE)]

	# split, and remove the colon
	command, *params = message.split(" ")
	command = command[:-1]
		
	return command, params
def extract_username_and_password(message: bytes) -> tuple[str, str]:
	'''# **⚠️ Deprecated Function!!** Do Not Use'''
	new_line_idx = message.find(b'\n')
	username = message[6 : new_line_idx].decode()
	password = message[new_line_idx + 11: -1].decode()
	debug(f"{username} ({len(username)}), {password} ({len(password)})")
	return username, password




# +------------------------------------------------------------------------------------------+
# |                                    Running The Server                                    |
# +------------------------------------------------------------------------------------------+

main(r"F:\ibraheem\TAU\Semester9\computer networking\ex1\users_file.txt")