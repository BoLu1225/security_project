import sys
src = sys.argv[1]
dst = sys.argv[2]
dport = int(sys.argv[3])
timeout=float(sys.argv[4])

if sys.argv[5]=="app_specify":
 patterns=[]
 with open(sys.argv[6])as file:
  for line in file:
   patterns.append(bytes(map(lambda hex:int(hex,16),line.split())))

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
   SYN=TCP(dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

elif sys.argv[5]=="app_default":
 num=int(sys.argv[6])
 lbound=int(sys.argv[7])
 ubound=int(sys.argv[8])

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
   SYN=TCP(dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   n=random.randint(lbound,ubound)
   pattern=[None]*n
   import random
   for i in range(n):
    pattern[i]=random.getrandbits(8)
   pattern=bytes(pattern)
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

elif sys.argv[5]=="tcp_specify":
 with open(sys.argv[6])as file:
  pattern=bytes(map(lambda hex:int(hex,16),file.read().split()))
 tcp_fields={}
 with open(sys.argv[7])as file:
  for line in file:
   line=line.split()
   tcp_fields[line[0]]=list(map(lambda hex:int(hex,16),line[1:]))

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
   SYN=TCP(dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   fields={"dport":dport, "flags":'A', "seq":SYNACK.ack, "ack":SYNACK.seq + 1, field:value}
   ACK=TCP(**fields)
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

elif sys.argv[5]=="tcp_default":
 with open(sys.argv[6])as file:
  pattern=bytes(map(lambda hex:int(hex,16),file.read().split()))
 tcp_field_lengths={
  "dataofs":4,
  "reserved":3,
  "flags":9,
 }

 tcp_field_randoms={
 "seq":(int(sys.argv[7]),32),
 "ack":(int(sys.argv[8]),32),
 "window":(int(sys.argv[9]),16),
 "urgptr":(int(sys.argv[10]),16),
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
   SYN=TCP(dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   import random
   fields={"dst":dst,field:random.getrandbits(tcp_field_randoms[field][1])}
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
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
   SYN=TCP(dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   fields={"dst":dst,field:value}
   RESPONSE=sr1(ip/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

elif sys.argv[5]=="ip_specify":
 with open(sys.argv[6])as file:
  pattern=bytes(map(lambda hex:int(hex,16),file.read().split()))
 ip_fields={}
 with open(sys.argv[7])as file:
  for line in file:
   line=line.split()
   ip_fields[line[0]]=list(map(lambda hex:int(hex,16),line[1:]))

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
   SYN=TCP(dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   fields={"dst":dst,field:value}
   RESPONSE=sr1(IP(**fields)/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)

elif sys.argv[5]=="ip_default":
 with open(sys.argv[6])as file:
  pattern=bytes(map(lambda hex:int(hex,16),file.read().split()))
 ip_field_lengths={
 "version":4,
 "ihl":4,
 "tos":8,
 "flags":3,
 "ttl":8,
 "proto":8
 }

 ip_field_randoms={
 "len":(int(sys.argv[7]),16),
 "id":(int(sys.argv[8]),16),
 "frag":(int(sys.argv[9]),13),
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
   SYN=TCP(dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   import random
   fields={"dst":dst,field:random.getrandbits(ip_field_randoms[field][1])}
   RESPONSE=sr1(IP(**fields)/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
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
   SYN=TCP(dport=dport,flags='S')
   SYNACK=sr1(ip/SYN,timeout=timeout)
   if not SYNACK or not SYNACK.ack or not SYNACK.seq:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   fields={"dst":dst,field:value}
   RESPONSE=sr1(IP(**fields)/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE or not RESPONSE.ack or not RESPONSE.seq or not RESPONSE.haslayer(Raw):
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)
