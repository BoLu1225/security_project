#print error message and exit
def die(message):
 print(message)
 sys.exit()

import sys
argv_message="incorrect number of arguments"
file_message="cannot read file %s"

#validate number of tests string and return parsed number
def check_num(num):
 message="%s is not a number of tests"%num
 try:
  x=int(num)
  if x<0:
   die(message)
 except ValueError:
  die(message)
 return x

#validate field value string and return parsed value
def check_value(file,value,field,size):
 message="in %s: %s is not a value for field %s (%d bits)"%(file,value,field,size)
 try:
  x=int(value,16)
 except ValueError:
  die(message)
 if x not in range(1<<size):
  die(message)
 return x

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

if len(sys.argv)<8:
 die(argv_message)

#validate IP address string
def check_ip(addr):
 message="%s is not an IP address"%addr
 addr=addr.split(".")
 if len(addr)!=4:
  die(message)
 for i in addr:
  try:
   if int(i)not in range(1<<8):
    die(message)
  except ValueError:
   die(message)

src = sys.argv[1]
check_ip(src)

#validate source port number
message="%s is not a port number"%sys.argv[2]
try:
 sport = int(sys.argv[2])
 if sport not in range(1<<16):
  die(message)
except ValueError:
 die(message)

dst = sys.argv[3]
check_ip(dst)

#validate destination port number
message="%s is not a port number"%sys.argv[4]
try:
 dport = int(sys.argv[4])
 if dport not in range(1<<16):
  die(message)
except ValueError:
 die(message)

#validate timeout string
message="%s is not a valid timeout"%sys.argv[5]
try:
 timeout=float(sys.argv[5])
except ValueError:
 die(message)

#validate retry number
retry="%s is not a number of times to retry"%sys.argv[6]
try:
 retry = int(sys.argv[6])
except ValueError:
 die(message)

#application layer fuzzing with user-specified tests
if sys.argv[7]=="app_specify":
 if len(sys.argv)!=9:
  die(argv_message)
 patterns=[]
 try:
  with open(sys.argv[8])as file:
   for line in file:
    strings=line.split()
    values=[None]*len(strings)
    for i in range(len(strings)):
     values[i]=check_byte(sys.argv[8],strings[i])
    patterns.append(bytes(values))
 except IOError:
  die(file_message%sys.argv[8])

 results=""

 for field in("load",):
  valid=0
  invalid=0
  other=0
  total=0
  for pattern in patterns:
   total+=1
   from scapy.all import *
   ip=IP(dst=dst)
   SYN=TCP(sport=sport,dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout,retry=retry)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(sport=sport,dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout,retry=retry)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(sport=sport,dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(sport=sport,dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

#application layer fuzzing with default tests
elif sys.argv[7]=="app_default":
 if len(sys.argv)!=11:
  die(argv_message)
 num_message="%s is not a number of tests"%sys.argv[8]
 try:
  num=int(sys.argv[8])
  if num<0:
   die(num_message)
 except ValueError:
  die(num_message)
 bound_message="%s is not a payload length"
 try:
  lbound=int(sys.argv[9])
  if lbound<0:
   die(bound_message%sys.argv[9])
 except ValueError:
  die(bound_message%sys.argv[9])
 try:
  ubound=int(sys.argv[10])
  if ubound<lbound:
   die("maximum payload length cannot be less than mininum payload length")
 except ValueError:
  die(bound_message%sys.argv[10])

 results=""

 for field in("load",):
  valid=0
  invalid=0
  other=0
  total=0
  for _ in range(num):
   total+=1
   from scapy.all import *
   ip=IP(dst=dst)
   SYN=TCP(sport=sport,dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout,retry=retry)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(sport=sport,dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   n=random.randint(lbound,ubound)
   pattern=[None]*n
   import random
   for i in range(n):
    pattern[i]=random.getrandbits(8)
   pattern=bytes(pattern)
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout,retry=retry)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(sport=sport,dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(sport=sport,dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

#tcp layer fuzzing with user-specified tests
elif sys.argv[7]=="tcp_specify":
 if len(sys.argv)!=10:
  die(argv_message)

 try:
  with open(sys.argv[8])as file:
   strings=file.read().split()
   pattern=[None]*len(strings)
   for i in range(len(strings)):
    pattern[i]=check_byte(sys.argv[8],strings[i])
   pattern=bytes(pattern)
 except IOError:
  die(file_message%sys.argv[8])


 check={
 "dataofs":4,
 "reserved":3,
 "flags":9,
 "seq":32,
 "ack":32,
 "window":16,
 "urgptr":16
 }

 tcp_fields={}
 try:
  with open(sys.argv[9])as file:
   for line in file:
    line=line.split()
    if not line:
     continue
    if line[0]not in check:
     die("in %s: %s is not a tcp header field"%(sys.argv[9],line[0]))
    if line[0]in tcp_fields:
     die("in %s: multiple lines for field %s"%(sys.argv[9],line[0]))
    values=[None]*(len(line)-1)
    for i in range(len(line)-1):
     values[i]=check_value(sys.argv[9],line[i+1],line[0],check[line[0]])
    tcp_fields[line[0]]=values
 except IOError:
  die(file_message%sys.argv[9])

 results=""

 for field in tcp_fields:
  valid=0
  invalid=0
  other=0
  total=0
  for value in tcp_fields[field]:
   total+=1
   from scapy.all import *
   ip=IP(dst=dst)
   SYN=TCP(sport=sport,dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout,retry=retry)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   fields={"dport":dport, "flags":'A', "seq":SYNACK.ack, "ack":SYNACK.seq + 1, field:value}
   ACK=TCP(**fields)
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout,retry=retry)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(sport=sport,dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(sport=sport,dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

#tcp layer fuzzing with default tests
elif sys.argv[7]=="tcp_default":
 if len(sys.argv)!=13:
  die(argv_message)

 try:
  with open(sys.argv[8])as file:
   strings=file.read().split()
   pattern=[None]*len(strings)
   for i in range(len(strings)):
    pattern[i]=check_byte(sys.argv[8],strings[i])
   pattern=bytes(pattern)
 except IOError:
  die(file_message%sys.argv[8])

 tcp_field_lengths={
 "dataofs":4,
 "reserved":3,
 "flags":9,
 }

 tcp_field_randoms={
 "seq":(check_num(sys.argv[9]),32),
 "ack":(check_num(sys.argv[10]),32),
 "window":(check_num(sys.argv[11]),16),
 "urgptr":(check_num(sys.argv[12]),16),
 }

 results=""

 for field in tcp_field_randoms:
  valid=0
  invalid=0
  other=0
  total=0
  for _ in range(tcp_field_randoms[field][0]):
   total+=1
   from scapy.all import *
   ip=IP(dst=dst)
   SYN=TCP(sport=sport,dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout,retry=retry)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   import random
   fields={"sport":sport, "dport":dport, "flags":'A', "seq":SYNACK.ack, "ack":SYNACK.seq + 1, field:random.getrandbits(tcp_field_randoms[field][1])}
   ACK=TCP(**fields)
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout,retry=retry)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(sport=sport,dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(sport=sport,dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 for field in tcp_field_lengths:
  valid=0
  invalid=0
  other=0
  total=0
  for value in range(1<<tcp_field_lengths[field]):
   total+=1
   from scapy.all import *
   ip=IP(dst=dst)
   SYN=TCP(sport=sport,dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout,retry=retry)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   fields={"sport":sport, "dport":dport, "flags":'A', "seq":SYNACK.ack, "ack":SYNACK.seq + 1, field:value}
   ACK=TCP(**fields)
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout,retry=retry)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(sport=sport,dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(sport=sport,dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

#ip layer fuzzing with user-specified tests
elif sys.argv[7]=="ip_specify":
 if len(sys.argv)!=10:
  die(argv_message)

 try:
  with open(sys.argv[8])as file:
   strings=file.read().split()
   pattern=[None]*len(strings)
   for i in range(len(strings)):
    pattern[i]=check_byte(sys.argv[8],strings[i])
   pattern=bytes(pattern)
 except IOError:
  die(file_message%sys.argv[8])


 check={
 "version":4,
 "ihl":4,
 "tos":8,
 "flags":3,
 "ttl":8,
 "proto":8,
 "len":16,
 "id":16,
 "frag":13
 }

 ip_fields={}
 try:
  with open(sys.argv[9])as file:
   for line in file:
    line=line.split()
    if not line:
     continue
    if line[0]not in check:
     die("in %s: %s is not an ip header field"%(sys.argv[9],line[0]))
    if line[0]in ip_fields:
     die("in %s: multiple lines for field %s"%(sys.argv[9],line[0]))
    values=[None]*(len(line)-1)
    for i in range(len(line)-1):
     values[i]=check_value(sys.argv[9],line[i+1],line[0],check[line[0]])
    ip_fields[line[0]]=values
 except IOError:
  die(file_message%sys.argv[9])

 results=""

 for field in ip_fields:
  valid=0
  invalid=0
  other=0
  total=0
  for value in ip_fields[field]:
   total+=1
   from scapy.all import *
   ip=IP(dst=dst)
   SYN=TCP(sport=sport,dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout,retry=retry)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(sport=sport,dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   fields={"dst":dst,field:value}
   RESPONSE=sr1(IP(**fields)/ACK/Raw(load=pattern),timeout=timeout,retry=retry)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(sport=sport,dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(sport=sport,dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

#ip layer fuzzing with default tests
elif sys.argv[7]=="ip_default":
 if len(sys.argv)!=12:
  die(argv_message)

 try:
  with open(sys.argv[8])as file:
   strings=file.read().split()
   pattern=[None]*len(strings)
   for i in range(len(strings)):
    pattern[i]=check_byte(sys.argv[8],strings[i])
   pattern=bytes(pattern)
 except IOError:
  die(file_message%sys.argv[8])

 ip_field_lengths={
 "version":4,
 "ihl":4,
 "tos":8,
 "flags":3,
 "ttl":8,
 "proto":8
 }

 ip_field_randoms={
 "len":(check_num(sys.argv[9]),16),
 "id":(check_num(sys.argv[10]),16),
 "frag":(check_num(sys.argv[11]),13),
 }

 results=""

 for field in ip_field_randoms:
  valid=0
  invalid=0
  other=0
  total=0
  for _ in range(ip_field_randoms[field][0]):
   total+=1
   from scapy.all import *
   ip=IP(dst=dst)
   SYN=TCP(sport=sport,dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout,retry=retry)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(sport=sport,dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   import random
   fields={"dst":dst,field:random.getrandbits(ip_field_randoms[field][1])}
   RESPONSE=sr1(IP(**fields)/ACK/Raw(load=pattern),timeout=timeout,retry=retry)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(sport=sport,dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(sport=sport,dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 for field in ip_field_lengths:
  valid=0
  invalid=0
  other=0
  total=0
  for value in range(1<<ip_field_lengths[field]):
   total+=1
   from scapy.all import *
   ip=IP(dst=dst)
   SYN=TCP(sport=sport,dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout,retry=retry)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(sport=sport,dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   fields={"dst":dst,field:value}
   RESPONSE=sr1(IP(**fields)/ACK/Raw(load=pattern),timeout=timeout,retry=retry)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(sport=sport,dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(sport=sport,dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

else:
 die("%s is not a test mode"%sys.argv[7])