#!/usr/bin/env python3

import scapy.all as scapy


def get_mac(ip):
    ans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip),timeout=2,verbose=False)[0]
    return ans[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        real_mac = get_mac(packet[scapy.ARP].psrc)
        response_mac = packet[scapy.ARP].hwsrc
        if real_mac != response_mac:
            print("[+] you are under ARP spoof attack!")
        else:
            print("you are safe")

sniff("eth0")
