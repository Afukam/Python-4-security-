import socket 

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostbyname()
port = 23

serversocket.bind((host, port))

serversocket.listen(5)

while True:
    clientsocket, address = serversocket.accept()

    print('received connection from ' % str(address))
    message = 'Thank you for connecting to the server' + "\r\n"
    clientsocket.send(message.encode('UTF-8'))
    clientsocket.close()
