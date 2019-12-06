#!/usr/bin/env python3

import subprocess
import optparse
import re

MAC = '08:00:27:33:75:72'

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", '--mac', dest="new_mac", help="New MAC address")
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.new_mac:
        parser.error("[-] Please specify a new MAC address, use --help for more info.")

    return options


def change_mac(interface, new_mac):
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw', 'ether', new_mac])
    subprocess.call(['ifconfig', interface, 'up'])


def get_current_mac(interface):
    ifconfig_output = subprocess.check_output(['ifconfig', options.interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_output)

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could NOT read MAC address !")

def mac_change_validation(options):
    mac_before = get_current_mac(options.interface)
    print("Current MAC address = " + str(mac_before))

    if mac_before == options.new_mac:
        print("[-] That MAC address is already set !")
    else:
        change_mac(options.interface, options.new_mac)
        mac_after = get_current_mac(options.interface)
        if mac_after == options.new_mac:
            print("[+] MAC Adress SUCCESSFULY changed from " + str(mac_before) + " to " + str(mac_after))



options = get_arguments()

mac_change_validation(options)