import math
from scapy.all import TCP, rdpcap
from tcp_reliable.injector import Injector
from tcp_reliable.extractor import Extractor
from tcp_reliable.utils import Utils
from tcp_reliable.packet_helper import getPacketTimestamp, changeTimestamp, writePcap, genKey


class TcpRealible:
    def __init__(self, pcapConfig, bufferSize):
        self.pcapConfig = pcapConfig
        self.bufferSize = bufferSize
        self.extractor = Extractor(pcapConfig, self.bufferSize)
        self.utils = Utils()

    def getLoad(self, pkt):
        try:
            return len(pkt[TCP].load)
        except:
            return 0
    """
    Server will send modified packet to client!
    1) Analysis server pcap to find packets that should be modified
    2) Change same packet in client pcap
    """
    def modifyPktsTimestamp(self, timestamp, pkt, pktRelation, clientPkts, clientKeyPkt):
        key = genKey(pkt)
        changeTimestamp(pkt, timestamp)
        
        for clientKey in pktRelation[key]:
            idx = clientKeyPkt[clientKey]
            changeTimestamp(clientPkts[idx], timestamp)
        
    def insertMessage(self):
            
        print('Start loading server pcap:')
        serverPkts = rdpcap(self.pcapConfig['SERVER_PCAP_PATH_INPUT'])
        print('success read server pcap!')

        print('Start loading client pcap:')
        clientPkts = rdpcap(self.pcapConfig['CLIENT_PCAP_PATH_INPUT'])
        print('success read client pcap!')

        # Create map for unique key to pkt

        serverKeyPkt = {}
        for idx in range(len(serverPkts)):
            pkt = serverPkts[idx]
            if pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                key = genKey(pkt)
                # if key in serverKeyPkt:
                #     print(pkt[TCP].seq)
                #     raise ValueError('Server has duplicated key')
                serverKeyPkt[key] = idx

        clientKeyPkt = {}
        for idx in range(len(clientPkts)):
            pkt = clientPkts[idx]
            if pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                key = genKey(pkt)
                # if key in clientKeyPkt:
                #     raise ValueError('Client has duplicated key')
                clientKeyPkt[key] = idx
        

        # Find related timestamp packets

        ## Order sequence number
        seqNumbers = list(set(map(lambda pkt: pkt[TCP].seq, serverPkts)))
        seqNumbers.sort()

        ## Find relations
        timestampRelation = {}
        for idx in range(len(serverPkts)):
            pkt = serverPkts[idx]
            if pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                seq = pkt[TCP].seq
                timestamp, _ = getPacketTimestamp(pkt)

                # Get next seq number
                next_seq = math.inf
                seqIdx = seqNumbers.index(seq)
                if seqIdx + 1 < len(seqNumbers):
                    next_seq = seqNumbers[seqIdx + 1]

                value = { 'end_seq': next_seq, 'ini_seq': seq, 'src_pkt': genKey(pkt), 'dst_pkt':[]}
                if timestamp in timestampRelation:
                    timestampRelation[timestamp].append(value)
                else:
                    timestampRelation[timestamp] = [value]

        for idx in range(len(clientPkts)):
            pkt = clientPkts[idx]
            if pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                seq = pkt[TCP].seq
                timestamp, _ = getPacketTimestamp(pkt)

                if timestamp in timestampRelation:
                    for value in timestampRelation[timestamp]:
                        if seq >= value['ini_seq'] and seq < value['end_seq']:
                            value['dst_pkt'].append(genKey(pkt))

        pktRelation = {}
        for timestamp in timestampRelation:
            relationArray = timestampRelation[timestamp]
            for relation in relationArray:
                pktRelation[relation['src_pkt']] = relation['dst_pkt']


        # Insert secret message
        insert = Injector(self.bufferSize)
        counter = 0
        counter_send = 0

        last_seq = 0
        for idx in range(len(serverPkts)):
            pkt = serverPkts[idx]
            seq = pkt[TCP].seq

            if pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                seq = pkt[TCP].seq
                counter_send+=1
                # if seq <= last_seq:
                #     continue
                timestamp, _ = getPacketTimestamp(pkt)
                change, new_timestamp = insert.timestamp(timestamp, seq, self.getLoad(pkt))
                if change:
                    counter += 1
                    self.modifyPktsTimestamp(new_timestamp, pkt, pktRelation, clientPkts,clientKeyPkt)
                last_seq = max(seq, last_seq)
            else:
                # print("ack",pkt[TCP].ack)
                insert.ackPkt(pkt[TCP].ack)

        print('Modified %:', 100*(counter/counter_send))
        
        # Create a output pcap with modified timestamp
        writePcap(serverPkts, self.pcapConfig['SERVER_PCAP_PATH_OUTPUT'])
        writePcap(clientPkts, self.pcapConfig['CLIENT_PCAP_PATH_OUTPUT'])

        return insert.allSecrets,  100*(counter/counter_send),counter_send

    def extractMessage(self):
        return self.extractor.extract()

    def compare(self, send, receive):
        return self.utils.compare(send, receive)

