import sys
src = sys.argv[1]
dst = sys.argv[2]
dport = int(sys.argv[3])
timeout=float(sys.argv[4])
with open(sys.argv[5])as file:
 pattern=bytes(map(lambda hex:int(hex,16),file.read().split()))

if sys.argv[6]=="ip_specify":
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
   if not SYNACK:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   fields={"dst":dst,field:value}
   RESPONSE=sr1(IP(**fields)/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE:
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   if not RESPONSE.ack or not RESPONSE.seq:
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)


elif sys.argv[6]=="ip_default":
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
   if not SYNACK:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   import random
   fields={"dst":dst,field:random.getrandbits(ip_field_randoms[field][1])}
   RESPONSE=sr1(IP(**fields)/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE:
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   if not RESPONSE.ack or not RESPONSE.seq:
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
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
   if not SYNACK:
    continue
   ACK=TCP(dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
   fields={"dst":dst,field:value}
   RESPONSE=sr1(IP(**fields)/ACK/Raw(load=pattern),timeout=timeout)
   if not RESPONSE:
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   load=RESPONSE[Raw].load
   if load==bytes([0x00]):
    valid+=1
   elif load==bytes([0xff]):
    invalid+=1
   else:
    other+=1
   if not RESPONSE.ack or not RESPONSE.seq:
    send(ip/TCP(dport=dport, flags='RA', seq=SYNACK.ack, ack=SYNACK.seq + 1))
    continue
   RESPONSE_ACK=TCP(dport=dport, flags='RA', seq=RESPONSE.ack, ack=RESPONSE.seq + len(load))
   send(ip/RESPONSE_ACK)
  results+="%s\n\tvalid:\t\t%d\n\tinvalid:\t%d\n\tother:\t\t%d\n\ttotal:\t\t%d\n\n"%(field,valid,invalid,other,total)

 print(results)
