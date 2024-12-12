import time
import socket
import random

host, port = "127.0.0.1", 25001
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

while True:
    time.sleep(0.5) #sleep 0.5 sec
    random_msg = str(random.getrandbits(64)) # random guid
    print(random_msg)

    sock.sendall(random_msg.encode("UTF-8")) #Converting string to Byte, and sending it to C#/powershell/dotnet
    receivedData = sock.recv(1024).decode("UTF-8") #receiveing data in Byte fron C#, and converting it to String
    print(receivedData)