from scapy.all import TCP, rdpcap
from data_link.packet_helper import getPacketTimestamp

class Extractor:
    def __init__(self, pcapConfig):
        self.pcapConfig = pcapConfig

    def extract(self):
        count = 1

        serverPcap = rdpcap(self.pcapConfig['CLIENT_PCAP_PATH_OUTPUT'])
        output = []
        lastTimestamp = 0
        serverPcap.sort(key=self.getKeySort)
        last_seq = 0
        limit = 0
        for pkt in serverPcap:
            if pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                timestamp = getPacketTimestamp(pkt)[0]
                if timestamp == None:
                    continue
                seq = pkt[TCP].seq

                if lastTimestamp != timestamp and limit < timestamp  and seq!= last_seq:
                    output.append(timestamp%2)
                    count += 1
                    lastTimestamp = timestamp
                    limit = max(limit, timestamp)
                last_seq = seq

        finale = ""
        for i in output:
            finale = finale + str(i)
        return finale

    def getKeySort(self, pkt):
        seq = pkt[TCP].seq
        timestamp = getPacketTimestamp(pkt)[0]
        if timestamp == None:
            return int(str(seq)+'0')
        return int(str(seq)+str(timestamp))



    
# if __name__ == '__main__':
#     readMessage()