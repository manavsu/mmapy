import socket
import struct
import os
from tcp_flags import *

MAX_WORD = int(0xFFFF)
MAX_BYTE = int(0xFF)
MAX_2_BYTE = int(0xFFFFFFFF)

INITIAL_WIN_SIZE = 5840


def tcp_header(src_port, dst_port, seq_num, ack_num, data_offset, flags, win_size, urg_ptr):
    '''
    Create a TCP header, which consists of the following:
    - Source Port: 16 bits
    - Destination Port: 16 bits
    - Sequence Number: 32 bits - The sequence number of the first data byte in this segment (except when SYN is present). The ISN(Initial Sequence Number) should generally be random.
    - Acknowledgment Number: 32 bits - If the ACK flag is set, this field contains the value of the next sequence number the sender of the segment is expecting to receive. Once a connection is established this is always sent.
    - Data Offset: 4 bits - The number of 32-bit words in the TCP header. 5 with no options.
    - Flags: 8 bits - The flags field contains 8 bits, each of which is used to control a specific aspect of the connection.
    - Window Size: 16 bits - The size of the receive window, which specifies the number of bytes the sender is currently willing to receive.
    - Checksum: 16 bits - The checksum field is used to detect errors in the TCP header, the payload, and the IP header.
    - Urgent Pointer: 16 bits - The urgent pointer field is only used in conjunction with the URG flag, and it contains a pointer to the last urgent data byte.
    
    Args:
        src_port (int): The source port number.
        dst_port (int): The destination port number.
        seq_num (int): The sequence number.
        ack_num (int): The acknowledgment number.
        data_offset (int): The data offset.
        flags (int): The flags.
        win_size (int): The window size.
        checksum (int): The checksum.
        urg_ptr (int): The urgent pointer.
    '''
    return struct.pack('!HHLLBBHHH', src_port, dst_port, seq_num, ack_num, data_offset << 4, flags, win_size, checksum, urg_ptr)


def IPV4_header(dscp, ecn, length, iden, flags, frag_offset, ttl, proto, checksum, src_ip, dst_ip):
    '''
    Version: 4 bits - The version of the IP protocol being used.
    IHL: 4 bits - The length of the IP header in 32-bit words.
    DSCP: 6 bits - The Differentiated Services Code Point (DSCP) field is used to request a level of service from the network.
    ECN: 2 bits - The Explicit Congestion Notification (ECN) field is used to indicate congestion in the network.
    length: 16 bits - The total length of the IP packet.
    ID: 16 bits - The identification field is used to help reassemble the packet.
    Flags: 3 bits - The flags field is used to control or identify fragments.
    Fragment Offset: 13 bits - The fragment offset field is used to reassemble the original packet.
    TTL: 8 bits - The time to live field is used to prevent packets from circulating indefinitely.
    Protocol: 8 bits - The protocol field is used to identify the next level protocol.
    Header Checksum: 16 bits - The header checksum field is used to detect errors in the IP header.
    Source IP Address: 32 bits - The source IP address.
    Destination IP Address: 32 bits - The destination IP address.
    
    Args:
        dscp (int): The Differentiated Services Code Point (DSCP) field.
        ecn (int): The Explicit Congestion Notification (ECN) field.
        length (int): The total length of the IP packet.
        id (int): The identification field.
        flags (int): The flags field.
        frag_offset (int): The fragment offset field.
        ttl (int): The time to live field.
        proto (int): The protocol field.
        checksum (int): The header checksum field.
        src_ip (str): The source IP address.
        dst_ip (str): The destination IP address.
    '''
    ver = 4
    ihl = 5
    version_ihl = (ver << 4) + ihl
    dscp_ecn = (dscp << 2) + ecn
    flags_frag_offset = (flags << 13) + frag_offset

    header = struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, length, iden, flags_frag_offset, ttl, proto, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

    checksum_value = checksum(header)

    return struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, length, iden, flags_frag_offset, ttl, proto, checksum_value, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i + 1])
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def create_syn_packet(source_ip, dest_ip, dest_port, src_port):
    '''
        Creates a SYN packet for TCP communication.
        Args:
            source_ip (str): The source IP address.
            dest_ip (str): The destination IP address.
            dest_port (int): The destination port number.
            src_port (int): The source port number.
        Returns:
            bytes: The SYN packet.
    '''
    seq = os.urandom(4)
    ack_seq = 0
    doff = 5
    flags = TCPFlags.SYN
    window = socket.htons(INITIAL_WIN_SIZE)
    check = 0
    urg_ptr = 0
    
    tcp_header = tcp_header(src_port, dest_port, seq, ack_seq, doff, flags, window, check, urg_ptr)
    
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(source_ip), socket.inet_aton(dest_ip), placeholder, protocol, tcp_length)
    pseudo_tcp_hdr = pseudo_header + tcp_header
    
    tcp_checksum = checksum(pseudo_tcp_hdr)
    
    tcp_header = tcp_header(src_port, dest_port, seq, ack_seq, doff, flags, window, tcp_checksum, urg_ptr)
    
    total_length = 20 + len(tcp_header)
    
    ip_hdr = IPV4_header(0, 0, total_length, 54321, 0, 0, 255, socket.IPPROTO_TCP, source_ip, dest_ip)
    
    packet = ip_hdr + tcp_header
    return packet

def send_syn_packet(packet, dest_ip, dest_port, sock):
    '''
        Sends a SYN packet to the specified destination IP address and port number.
        Args:
            packet (bytes): The SYN packet to send.
            dest_ip (str): The destination IP address.
            dest_port (int): The destination port number.
            socket (socket): The socket to use for sending the packet.
    '''
    packet = create_syn_packet(sock.getsockname()[0], dest_ip, dest_port, sock.getsockname()[1])
    sock.sendto(packet, (dest_ip, 0))



