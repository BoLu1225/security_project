import sys
with open(sys.argv[1])as file:
 pattern=bytes(map(lambda hex:int(hex,16),file.read().split()))

import socket
sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.bind(("",5000))
sock.listen(1)
while True:
 conn,addr=sock.accept()
 received=conn.recv(len(pattern))
 response=bytes([0x00if received==pattern else 0xff])
 conn.send(response)
 try:
  while True:
   conn.recv(1)
 except:
  pass
 conn.close()