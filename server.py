flag=False
def routine():
 global flag
 input()
 flag=True

import threading
thread=threading.Thread(target=routine)
thread.start()

import sys
port=int(sys.argv[1])
with open(sys.argv[2])as file:
 pattern=bytes(map(lambda hex:int(hex,16),file.read().split()))

import socket
sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.bind(("",port))
sock.listen(1)
sock.setblocking(False)
valid=0
invalid=0
while True:
 while True:
  try:
   conn,addr=sock.accept()
   break
  except:
   if flag:
    thread.join()
    sock.close()
    print("valid:\t\t%d\ninvalid:\t%d"%(valid,invalid))
    sys.exit(0)
 received=conn.recv(len(pattern))
 if received==pattern:
  valid+=1
  response=bytes([0x00])
 else:
  invalid+=1
  response=bytes([0xff])
 conn.send(response)
 try:
  while True:
   conn.recv(1)
 except:
  pass
 conn.close()
