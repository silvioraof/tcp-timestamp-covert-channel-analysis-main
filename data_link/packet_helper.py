from scapy.all import TCP, wrpcap

def getPacketTimestamp(pkt):
    if TCP in pkt:
        for opt, val in pkt[TCP].options:
            if opt == 'Timestamp':
                return val
    return None, None

def changeTimestamp(pkt, newTimestamp):
    for idx in range(len(pkt[TCP].options)):
        if pkt[TCP].options[idx][0] == 'Timestamp':
            pkt[TCP].options[idx] = (
                'Timestamp', (newTimestamp, pkt[TCP].options[idx][1][1]))
            break

def writePcap(pkts, path):
    wrpcap(path, pkts)

def genKey(pkt):
    tcp = pkt[TCP]
    return str(tcp.dport)+','+str(tcp.sport)+','+str(tcp.seq)+','+str(tcp.ack)+','+str(getPacketTimestamp(pkt)[0])