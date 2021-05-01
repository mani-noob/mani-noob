#!/usr/bin/env python3

import scapy.all as sc
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='ip', help='Specify the IP range you want to scan.')
    options = parser.parse_args()
    return options

def scan_ip(ip):
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = sc.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for elements in answered_list:
        client_dict = {'ip':elements[1].psrc, 'mac':elements[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_results(result_list):
    print('IP\t\t\tMAC\n----------------------------------------------')
    for client in result_list:
        print(str(client['ip'])+'\t\t'+str(client['mac']))

options = get_arguments()
scan_results = scan_ip(options.ip)
print_results(scan_results)