#!/usr/bin/env python3

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target", dest="ip", help="Target IP or or range of IPs you want to scan\n e.q: '**.**.**.1/24'")
    (options, arguments) = parser.parse_args()

    if not options.ip:
        parser.error("[-] Please specify an IP or range of IPs, use --help for more info.")

    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    target_client_list = list()
    for answer in answered_list:
        target_client_list.append({"ip":answer[1].psrc, "mac":answer[1].hwsrc})

    return target_client_list

def ls(my_list_of_dicts):
    print("IP\t\t\tMAC")
    for i_dict in my_list_of_dicts:
        print(i_dict["ip"] + "\t\t" + i_dict["mac"])


options = get_arguments()

target_client_list = scan(options.ip)

ls(target_client_list)