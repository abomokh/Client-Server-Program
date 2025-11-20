import socket

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 1337          # The port used by the server
END_OF_MESSAGE  = '\x00'
BUFF_SIZE = 4     
FAIL_LOGIN = "Failed to login."
QUIT_CM = "quit"

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSock:
        clientSock.connect((HOST, PORT))

        # Authentication stage
        while True:
            User = input()
            Password = input()

            Authentication = User + "\n" + Password + END_OF_MESSAGE

            clientSock.send(Authentication.encode())

            response = recvall(clientSock).decode()
            if (response != FAIL_LOGIN):
                break
            #maybe should handle the case where client's connection is closed while trying to login
        
        # Commands
        while True: 
            command = input()

            if (command == QUIT_CM):
                break

            command += END_OF_MESSAGE
            clientSock.send(command.encode())

            response = recvall(clientSock).decode()

            print(response)


def recvall(sock):
    data = b""
    while True:
        part = sock.recv(BUFF_SIZE)
        if not part:          # connection closed
            break
        data += part
        if END_OF_MESSAGE.encode() in data:
            break
    # strip the END_OF_MESSAGE from the end if present
    return data.replace(END_OF_MESSAGE.encode(), b"")
