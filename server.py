#print error message and exit
def die(message):
 print(message)
 sys.exit()

import sys
argv_message="incorrect number of arguments"
file_message="cannot read file %s"

#validate byte string and return parsed byte
def check_byte(file,byte):
 message="in %s: %s is not a byte (8 bits)"%(file,byte)
 try:
  x=int(byte,16)
 except ValueError:
  die(message)
 if x not in range(1<<8):
  die(message)
 return x

if len(sys.argv)!=4:
 die(argv_message)

#set flag when EOF or input is available
flag=False
def routine():
 global flag
 try:
  input()
 except EOFError:
  pass
 flag=True

import sys

#validate port number
message="%s is not a port number"%sys.argv[1]
try:
 port = int(sys.argv[1])
 if port not in range(1<<16):
  die(message)
except ValueError:
 die(message)

#validate timeout
message="%s is not a timeout"%sys.argv[2]
try:
 timeout = float(sys.argv[2])
 if timeout<0:
  die(message)
except ValueError:
 die(message)

#read pattern from file
try:
 with open(sys.argv[3])as file:
  strings=file.read().split()
  pattern=[None]*len(strings)
  for i in range(len(strings)):
   pattern[i]=check_byte(sys.argv[3],strings[i])
  pattern=bytes(pattern)
except IOError:
 die(file_message%sys.argv[3])

#maxmimum payload length = MTU (1500 bytes) - length of ip + tcp headers
maxlen = 1460
maxlen_message = "in %s: payload length exceeds 1460 bytes"

if len(pattern)>maxlen:
 die(maxlen_message%sys.argv[3])

import socket
sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
 sock.bind(("",port))
except OSError:
 die("port %d unavailable"%port)

import threading
thread=threading.Thread(target=routine)
thread.start()

sock.listen(1)
sock.setblocking(False)
valid=0
invalid=0

while True:
 while True:
  try:
   conn,addr=sock.accept()
   break
  except OSError:
   if flag:#input available means user wants to terminate server
    thread.join()
    sock.close()
    print("valid:\t\t%d\ninvalid:\t%d"%(valid,invalid))
    sys.exit()
 conn.settimeout(timeout)
 try:
  received=conn.recv(len(pattern))
 except OSError:
  conn.close()
  invalid+=1
  continue
 if received==pattern:
  valid+=1
  response=bytes([0x00])
 else:
  invalid+=1
  response=bytes([0xff])
 conn.send(response)
 conn.setblocking(False)
 try:
  while True:
   conn.recv(1)
 except OSError:
  conn.close()
