import socket

localIP     = "127.0.0.1"
localPort   = 1813
bufferSize  = 1024

msgFromServer       = "Hello UDP Client"

bytesToSend         = str.encode(msgFromServer)

# Create a datagram socket
UDPServerSocket = socket.socket(socket.AF_INET, type=socket.SOCK_DGRAM)

# ~ UDPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))

print("UDP server up and listening")

while(True):
	bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)

	message = bytesAddressPair[0]
	address = bytesAddressPair[1]

	clientMsg = "Message from Client:{}".format(message)
	clientIP  = "Client IP Address:{}".format(address)

	print(message)
	print(clientIP)

	# ~ UDPServerSocket.sendto(bytesToSend, address)
