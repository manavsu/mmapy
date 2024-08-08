# def get_pid_from_packet(packet):
#     connections = psutil.net_connections(kind='inet')
#     for conn in connections:
        
#         if (hasattr(packet, "sport") and conn.laddr.port == packet.sport) or (conn.raddr and hasattr(packet, 'dport') and conn.raddr.port == packet.dport):
#             return conn.pid
#     return None

# def packet_sniffer():
#     pid = os.getpid()
#     def process_packet(packet):
#         pid = get_pid_from_packet(packet)
#         if pid != os.getpid():
#             return
#         process = psutil.Process(pid)
#         print(f"Packet: {packet.summary()}, PID: {pid}, Process Name: {process.name()}")

#     sniff(filter="ip", prn=process_packet)