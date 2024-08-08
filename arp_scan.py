import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
log = logging.getLogger("mmapy")

from scapy.all import ARP, ICMP, IP, sr, sr1, Ether, srp, conf
import time
import utils
import ipaddress
import netifaces

def local_network():
    """
    Get the local network IP address and netmask.

    Returns:
        IPv4Network: The local network IP address and netmask as an IPv4Network object.
    """
    default_iface = str(conf.iface)
    ip = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]['addr']
    netmask = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]['netmask']
    return ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)

def valid_ip(ip:str):
    """
    Check if the given IP address is valid.

    Args:
        ip (str): The IP address to check.

    Returns:
        bool: True if the IP address is valid, False otherwise.
    """
    try:
        ipaddress.IPv4Network(ip, strict=False)
        return True
    except ValueError:
        return False

    
def validate_ip(ip_range:str):
    """
    Check if the given IP range is valid.

    Args:
        ip_range (str): The IP range to check in CIDR notation.

    Returns:
        bool: True if the IP range is valid, False otherwise.
    
    Raises:
        ValueError: If the IP range is invalid.
    """
    if not valid_ip(ip_range):
        raise ValueError(f"Invalid IP address:{ip_range}.")


def ip_on_local_network(ip:str):
    """
    Check if the given IP address is on the local network.

    Args:
        ip (str | IPv4Address): The IP address to check.

    Returns:
        bool: True if the IP address is on the local network, False otherwise.
    
    Raises:
        ValueError: If the IP address is invalid.
    """

    validate_ip(ip)
    lan = ipaddress.IPv4Network(ip)
        
    network = local_network()
    return all(ip in network for ip in lan.hosts())


def ping_scan(ip_range:str, packet_timeout:int=1):
    """
    Perform a ping scan on the given IP range. May not report all available hosts.

    Args:
        ip_range (str): The IP range to scan in CIDR notation.
        packet_timeout (int, optional): The timeout for each packet sent.

    Returns:
        list[str]: A list of discovered host ips.
        
    Raises:
        ValueError: If the IP range is not on the local network.
    """
    # utils.check_root_access()
    validate_ip(ip_range)
    live_hosts = []

    # Perform the ping scan
    for ip in IP(dst=ip_range):
        print(ip)
        pkt = IP(dst=str(ip))/ICMP()
        reply = sr1(pkt, timeout=1)
        if reply:
            print(f"{ip} is up")
        else:
            print(f"{ip} is down")
    # pkt = IP(dst=ip_range)/ICMP()
    # print(pkt)
    # reply = sr(pkt, timeout=packet_timeout)
    # print(reply)

    # return live_hosts
    
    
    
def arp_scan(ip_range, packet_timeout:int=1):
    """
    Perform an ARP scan on the given IP range.

    Args:
        ip_range (str): The IP range to scan in CIDR notation.
        packet_timeout (int, optional): The timeout for each packet sent.

    Returns:
        list[str]: A list of discovered host ips.
    
    Raises:
        ValueError: If the IP range is invalid or not on the local network.
        ValueError: If the IP range is not on the local network.
    """
    utils.check_root_access()
    validate_ip(ip_range)

    if not ip_on_local_network(ip_range):
        raise ValueError(f"IP: {ip_range} is not on the local network.")
    
    arp_request = ARP(pdst=ip_range)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request
    
    start_time = time.time()
    result = srp(packet, timeout=1, verbose=False)[0]
    end_time = time.time()

    log.info(f"{ip_range} scanned in {end_time - start_time:.2f} seconds.")

    return [received.psrc for _, received in result]

