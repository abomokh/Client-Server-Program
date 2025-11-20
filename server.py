import socket
import select

HOST                = ""    # All computer's network interfaces
PORT                = 1337  # Port to listen on (non-privileged ports are > 1023)
BACK_LOG            = 5     # maximum number of pending, not-yet-accepted connections
SELECT_TIMEOUT      = 100
BUFF_SIZE           = 4     # 
soc_to_msg          = {}    # dict of message buffers
soc_to_status       = {}    # track authenticated clients
registered_users    = {}
END_OF_MESSAGE      = '\x00'
AUTHED_SOC          = "client authenticated"
NEW_SOC             = "new client, not authenticated yet"
WELCOME_MESSAGE     = "Welcome! Please log in."

def main(path):
    load_users(registered_users, path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listenSoc:
        listenSoc.bind((HOST, PORT))
        listenSoc.listen(BACK_LOG)
        print("socket is listening...")
        rlist = [listenSoc]
        while(True):
            readable, _, _ = select.select(rlist, [], [], SELECT_TIMEOUT)
            
            for soc in readable:

                # handle the listening socket
                if soc is listenSoc:
                    clientSoc, clientAddr = listenSoc.accept()
                    soc_to_msg[clientSoc] = b""
                    soc_to_status[clientSoc] = NEW_SOC
                    send_message_to_client(clientSoc, WELCOME_MESSAGE)
                    print('new client connected: ', clientSoc)
                    rlist.append(clientSoc)
                    continue
                    

                # handle other sockets
                soc_to_msg[soc] += soc.recv(BUFF_SIZE)
                print(soc_to_msg[soc])
                if soc_to_msg[soc].decode()[-1] == END_OF_MESSAGE:
                    # end of message. handle it and clear the buffer
                    print("handiling message")
                    general_message_handler(soc, soc_to_msg[soc])
                    soc_to_msg[soc] = b""


def general_message_handler(soc: socket, message: bytes):
    
    try:
        # analyze the message
        check_message_validity(message, soc_to_status[soc])
        
        # handle the message
        if soc_to_status[soc] == NEW_SOC:
            username, password = extract_username_and_password(message)
            auth(soc, username, password)
            soc_to_status[soc] = AUTHED_SOC
            print('sending message')
            send_message_to_client(soc, f"Hi {username}, good to see you.")
        else:
            command, params = extract_command_and_params(message)
            response = route(command, params)
            send_message_to_client(soc, response)
    
    except Exception as e:
        handle_error(e)
        return





def handle_error(e: Exception):
    pass

def send_message_to_client(socket: socket, response: str):
    socket.send(response.encode())

def route(command: str, params: list[str]) -> str:
    return 'Hi'


def extract_command_and_params(message: bytes) -> tuple[str, list[str]]:
    # decode and remove the END_OF_MESSAGE char
    message = message.decode()[:-1]

    # split, and remove the colon
    command, *params = message.split(" ")
    command = command[:-1]
    
    return command, params
def extract_username_and_password(message: bytes) -> tuple[str, str]:
    new_line_idx = message.find('\n')
    username = message[7 : new_line_idx].decode()
    password = message[new_line_idx + 11: -1].decode()
    return username, password


def check_message_validity(message: bytes, soc_status: str) -> bool:
    return

def auth(soc, username, password):
    return

def compute_lcm(x: int, y: int) -> int:
    pass
def parentheses_check(s: str) -> bool:
    pass
def compute_caesar(text: str, shift: int) -> str:
    pass

def load_users(registered_users: dict, path: str):
    registered_users['aya'] = 'pass'


main(r"F:\ibraheem\TAU\Semester9\computer networking\ex1\users_file.txt")