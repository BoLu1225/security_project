from socket import *

PORT=1234
server=socket(AF_INET, SOCK_STREAM)

server.bind(('',PORT))



server.listen(5)

valid_count=0

invalid_count=0

f=open("pattern.txt")

pattern=f.read()

f.close()

start=True






while start :

	server.settimeout(5.0)




	try:

		CliSock, addr=server.accept()
	except timeout:
		print "timeout exception\n"
		start=False
		continue

	

	CliSock.settimeout(None)




	received=CliSock.recv(4096)



	if(received.startswith(pattern)):
		valid_count=valid_count+1

		CliSock.send('0x00')

	else:

		invalid_count=invalid_count+1

		CliSock.send('0xff')



f=open("record.txt","w")

result="Valid: "+str(valid_count)+ "\nInvalid: "+ str(invalid_count)

f.write(result)

f.close()









