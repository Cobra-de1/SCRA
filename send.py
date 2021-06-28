from pwn import *
import sys

if (len(sys.argv) < 2):
	print('Usage: python send.py "message_file"')
	exit(0)

f = open(sys.argv[1], 'rb')
data = f.read()
f.close()

ip = '192.168.100.4'
port = 8888

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.sendto(data, (ip, port))
