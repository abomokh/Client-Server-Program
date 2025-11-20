import socket
import select

HOST            = ""    # All computer's network interfaces
PORT            = 1337  # Port to listen on (non-privileged ports are > 1023)
BACK_LOG        = 5     # maximum number of connected clients
SELECT_TIMEOUT  = 10
BUFF_SIZE       = 4     # maximum number of pending, not-yet-accepted connections
soc_to_msg      = {}    # dict of message buffers
soc_to_status   = {}    # track authenticated clients
END_OF_MESSAGE  = '\x00'
AUTHED_SOC      = "client authenticated"
NEW_SOC         = "new client, not authenticated yet"
WELCOME_MESSAGE = "Welcome! Please log in."


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listenSoc:
        listenSoc.bind((HOST, PORT))
        listenSoc.listen(BACK_LOG)
        print("socket is listening...")

        while(True):
            readable, _, _ = select(rlist=[listenSoc], wlist = [], xlist = [], timeout = SELECT_TIMEOUT)
            
            for soc in readable:

                # handle the listening socket
                if soc is listenSoc:
                    clientSoc, clientAddr = listenSoc.accept()
                    soc_to_msg[clientSoc] = b""
                    soc_to_status = NEW_SOC
                    send_message_to_client(WELCOME_MESSAGE)
                    continue

                # handle other sockets
                soc_to_msg[soc] += soc.recv(BUFF_SIZE)
                if soc_to_msg[soc][-1] == END_OF_MESSAGE:
                    # end of message. handle it and clear the buffer
                    general_message_handler(soc, soc_to_msg[soc])
                    soc_to_msg[soc] = b""


def general_message_handler(soc: socket, message: bytes):
    try:
        # analyze the message
        check_message_validity(message, soc_to_status[soc])
        command, params = extract_command_and_params(message)
        
        # handle the message
        if soc_to_status[soc] == NEW_SOC:
            auth(soc, message)
            soc_to_status[soc] = AUTHED_SOC
        else:
            response = route(command, params)
            send_message_to_client(soc, response)
    
    except Exception as e:
        handle_error(e)
        return





def handle_error(e: Exception):
    pass

def send_message_to_client(socket: socket, response: bytes):
    pass

def route(command: str, params: list[str]):
    pass

def extract_command_and_params(message: bytes) -> tuple[str, list[str]]:
    pass

def check_message_validity(message: bytes, soc_status: str) -> bool:
    pass

def auth(soc, username, password):
    pass

def compute_lcm(x: int, y: int) -> int:
    pass
def parentheses_check(s: str) -> bool:
    pass
def compute_caesar(text: str, shift: int) -> str:
    pass