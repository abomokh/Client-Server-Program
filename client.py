import socket

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 1337         # The port used by the server
END_OF_MESSAGE  = '\x00'
BUFF_SIZE = 4     
FAIL_LOGIN =    "Failed to login."
QUIT_CM = "quit"
DEBUG = True        # debug mode

# custom errors
BAD_REQUEST			= "command type is invalid or disallowed for this client"

def debug(log_msg):
    if DEBUG:
        print(f"DEBUG > {log_msg}")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSock:
        clientSock.connect((HOST, PORT))
        print('connected!')
        
        # Authentication stage
        while True:
            debug("inside the auth loop")
            User = input('User: ')
            Password = input('Password: ')

            Authentication = f"User: {User}\nPassword: {Password}{END_OF_MESSAGE}"
            debug('sending auth message...')
            clientSock.send(Authentication.encode())
            
            debug('wating response from the server...')
            response = recvall(clientSock).decode()
            if (response != FAIL_LOGIN):
                debug("the response is not FAIL_LOGIN")
                debug(f"response type is {type(response)}")
                debug(f"saved_response type is {type(FAIL_LOGIN)}")
                break
            #maybe should handle the case where client's connection is closed while trying to login
        
        # Commands
        while True: 
            command = input() + END_OF_MESSAGE

            clientSock.send(command.encode())

            if command == QUIT_CM + END_OF_MESSAGE: 
                break

            response = recvall(clientSock).decode()

            print(response)
            
            if response == BAD_REQUEST:
                break


def recvall(sock):
    debug("inside recvall")
    data = b""
    while True:
        part = sock.recv(BUFF_SIZE)
        debug(f"receved: {part}")
        if not part:          # connection closed
            break
        data += part
        if END_OF_MESSAGE.encode() in data:
            break
    debug(f"response: {data}")
    # strip the END_OF_MESSAGE from the end if present
    return data.replace(END_OF_MESSAGE.encode(), b"")

main()