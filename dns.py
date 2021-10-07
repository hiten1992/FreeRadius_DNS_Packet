# https://www.binarytides.com/category/programming/sockets/python-sockets-sockets/

import socket
import sys
import binascii
import codecs

import re

import socket, sys
from struct import *

ip = "127.0.0.1"
port = 1813

# Create a UDP socket
# ~ s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

# Bind the socket to the port
server_address = (ip, port)
s.bind(server_address)



while True:
	print("####### Server is listening #######")
	data = s.recvfrom(65565)

	#data string from tuple
	data = data[0]

	#take first 20 characters for the ip header
	ip_header = data[0:20]

	#now unpack them :)
	iph = unpack('!BBHHHBBH4s4s' , ip_header)

	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF

	iph_length = ihl * 4

	ttl = iph[5]
	protocol = iph[6]
	s_addr = socket.inet_ntoa(iph[8]);
	d_addr = socket.inet_ntoa(iph[9]);

	print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

	tcp_header = data[iph_length:iph_length+20]

	#now unpack them :)
	tcph = unpack('!HHLLBBHHH' , tcp_header)

	source_port = tcph[0]
	dest_port = tcph[1]
	sequence = tcph[2]
	acknowledgement = tcph[3]
	doff_reserved = tcph[4]
	tcph_length = doff_reserved >> 4


	print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

	# ~ print("\n\nServer received: ", data.decode('latin-1'), "\n\n")
	print("\n\nServer received: ", format(data), "\n\n")
	# ~ print("\n\nServer received: ", data.decode('utf-8'), "\n\n")
	# ~ print(repr(data))
	print

	b = bytearray(data)
	test  = binascii.hexlify(b)

	print ('-----------------------------------------------------')
	print
	print (test)
	
	# ~ s=data.decode('cp855')
	
	# ~ print(type(s))
	# ~ print(s)
	
	
