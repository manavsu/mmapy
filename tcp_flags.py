import enum

class TCPFlags(enum.IntFlag):
    FIN << 0
    SYN << 1
    RST << 2
    PSH << 3
    ACK << 4
    URG << 5
    ECE << 6
    CWR << 7
    