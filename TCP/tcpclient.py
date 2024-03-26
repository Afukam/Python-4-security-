import socket

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()

port = 23

clientsocket.connect(("", port ))

message = clientsocket.receive(1024)

clientsocket.close()

print(message.decode('UTF-8'))


