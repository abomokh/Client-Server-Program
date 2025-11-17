# Example: echo-server.py

import socket

HOST = ""  # All computer's network interfaces
PORT = 1337  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serverSock:
    serverSock.bind((HOST, PORT))
    serverSock.listen()
    print("socket is listening...")
    connectionSock, addr = serverSock.accept()
    with connectionSock:
        print(f"Connected by {addr}")
        while True:
            data = connectionSock.recv(1024)
            if not data:
                break
            connectionSock.send(data)