#! /usr/bin/python

from scapy.all import *
import sys

try:
	interface = input("[*] Enter Desired Interface: ")
except KeyboardInterrupt:
	print("[*] User Requested Shutdown...")
	print("[*] Exiting...")
	sys.exit(1)

def querysniff(pkt):
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst	
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			print(str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname.decode() + ")")

sniff(iface = interface,filter = "port 53", prn = querysniff, store = 0)
print("\n[*] Shutting Down...")
