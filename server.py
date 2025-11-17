# Example: echo-server.py

import socket

HOST            = ""    # All computer's network interfaces
PORT            = 1337  # Port to listen on (non-privileged ports are > 1023)
back_log        = 5
SELECT_TIMEOUT  = 10
BUFF_SIZE       = 4
soc_to_msg      = {}


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listenSoc:
    listenSoc.bind((HOST, PORT))
    listenSoc.listen(back_log)
    print("socket is listening...")

    while(True):
        readable, _, _ = select(
            rlist=[listenSoc]
            wlist = []
            xlist = []
            timeout = SELECT_TIMEOUT
        )
        
        if listenSoc in readable:
            clientSoc, clientAddr = listenSoc.accept()
            soc_to_message[clientSoc] = b""

        for soc in readable:
            soc_to_message[soc] += soc.recv(BUFF_SIZE)
            if soc_to_message[soc][-1] = '\n':
                
                # end of message. handle it
                handler(soc, soc_to_message[soc])

                # delete the message
                soc_to_message[soc] = b""