from arp_scan import *
from utils import *
from scapy.all import sniff
import threading
import psutil


check_root_access()

ip_range = "192.168.1.30"
hosts = arp_scan(ip_range)

for host in hosts:
    print(f"IP: {host}")

hosts = ping_scan(ip_range, packet_timeout=5)
for host in hosts:
    print(f"IP: {host}")

print(local_network())