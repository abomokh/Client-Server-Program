import socket

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 1337          # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSock:
    clientSock.connect((HOST, PORT))
    clientSock.send(b"Hello, world")
    data = clientSock.recv(1024)

print(f"Received {data}")

