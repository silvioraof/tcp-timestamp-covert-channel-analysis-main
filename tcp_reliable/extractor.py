import hashlib
from scapy.all import IP, TCP, PcapReader, rdpcap, wrpcap
from tcp_reliable.packet_helper import getPacketTimestamp, changeTimestamp, writePcap, genKey


class Extractor:
    def __init__(self, pcapConfig, BUFFER_SIZE):
        self.pcapConfig = pcapConfig
        self.BUFFER_SIZE = BUFFER_SIZE

    def extract(self):
        serverPcap = rdpcap(self.pcapConfig['CLIENT_PCAP_PATH_OUTPUT'])
        output = []
        lastTimestamp = 0
        serverPcap.sort(key=self.getKeySort)
        last_seq = 0
        limit = 0
        buff = [None]* self.BUFFER_SIZE
        sol = []
        for pkt in serverPcap:
            if pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                timestamp = getPacketTimestamp(pkt)[0]
                if timestamp == None:
                    continue
                seq = pkt[TCP].seq

                if lastTimestamp != timestamp and limit < timestamp  and seq!= last_seq:
                    # if count >= 179 and count <= 281:
                    #     print('seq:', pkt[TCP].seq, 'timestamp', timestamp, 'value', timestamp%2,'last_tm:', lastTimestamp)
                    #     text+=str(timestamp%2)
                    # print("seq:", seq, "timestamp:", timestamp, "bit:", timestamp%2)
                    output.append(timestamp%2)
                    idx = self.getBufferIdx(seq)
                    buff[idx] = timestamp%2
                    # print("******",len(sol)+1,"***** seq",seq,"*****","idx",idx,"******* bit:",timestamp%2)
                    if idx == 0 and timestamp%2 == 1:
                        has_none = False
                        for i in buff[1:]:
                            if i == None:
                                has_none = True
                        if not has_none:
                            sol.append(buff[1:])
                            buff = [None]* self.BUFFER_SIZE
                    lastTimestamp = timestamp
                    limit = max(limit, timestamp)
                last_seq = seq

        return sol


    def getKeySort(self, pkt):
        seq = pkt[TCP].seq
        timestamp = getPacketTimestamp(pkt)[0]
        if timestamp == None:
            return int(str(seq)+'0')
        return int(str(timestamp)+str(seq))

    def genHashNumber(self, num):
        return int(hashlib.sha256(str(num).encode()).hexdigest(), base=16)

    def getBufferIdx(self, seq):
        return self.genHashNumber(seq) % self.BUFFER_SIZE



# if __name__ == '__main__':
#     readMessage()