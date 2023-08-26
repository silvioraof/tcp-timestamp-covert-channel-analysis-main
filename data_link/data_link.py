import math
from scapy.all import TCP, rdpcap
from data_link.injector import Injector
from data_link.extractor import Extractor
from data_link.utils import Utils
from data_link.packet_helper import getPacketTimestamp, changeTimestamp, writePcap, genKey


class DataLink:
    def __init__(self, pcapConfig, messageSize,flag):
        self.pcapConfig = pcapConfig
        self.messageSize = messageSize
        self.flag = flag
        self.extractor = Extractor(self.pcapConfig)
        self.utils = Utils(self.flag, self.messageSize)
    
    def modifyPktsTimestamp(self, timestamp, pkt, pktRelation, clientPkts, clientKeyPkt):
        key = genKey(pkt)
        changeTimestamp(pkt, timestamp)
        for clientKey in pktRelation[key]:
            idx = clientKeyPkt[clientKey]
            changeTimestamp(clientPkts[idx], timestamp)

    """
    Server will send modified packet to client!
    1) Analysis server pcap to find packets that should be modified
    2) Change same packet in client pcap
    """ 
    def insertMessage(self):
        serverPkts = rdpcap(self.pcapConfig['SERVER_PCAP_PATH_INPUT'])
        clientPkts = rdpcap(self.pcapConfig['CLIENT_PCAP_PATH_INPUT'])

        # Create map for unique key to pkt
        serverKeyPkt = {}
        for idx in range(len(serverPkts)):
            pkt = serverPkts[idx]
            timestamp,_ = getPacketTimestamp(pkt)
            if timestamp != None and pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                key = genKey(pkt)
                # if key in serverKeyPkt:
                #     # print(timestamp)
                #     print("check",pkt[TCP].seq)
                #     # raise ValueError('Server has duplicated key')
                serverKeyPkt[key] = idx

        clientKeyPkt = {}
        for idx in range(len(clientPkts)):
            pkt = clientPkts[idx]
            if pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                key = genKey(pkt)
                # if key in clientKeyPkt:
                #     print("check2",pkt[TCP].seq)
                #     #raise ValueError('Client has duplicated key')
                clientKeyPkt[key] = idx
        

        # Find related timestamp packets

        ## Order sequence number
        seqNumbers = list(set(map(lambda pkt: pkt[TCP].seq, serverPkts)))
        seqNumbers.sort()

        ## Find relations
        timestampRelation = {}
        for idx in range(len(serverPkts)):
            pkt = serverPkts[idx]
            timestamp, _ = getPacketTimestamp(pkt)
            if timestamp != None and pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
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
            timestamp, _ = getPacketTimestamp(pkt)
            if timestamp != None and pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
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
        insert = Injector(self.flag, self.messageSize)
        modified_counter = 0
        total_counter = 0

        last_seq = 0
        for idx in range(len(serverPkts)):
            pkt = serverPkts[idx]
            seq = pkt[TCP].seq
            timestamp, _ = getPacketTimestamp(pkt)
            timestamp, _ = getPacketTimestamp(pkt)
            if timestamp != None and pkt[TCP].dport == self.pcapConfig['CLIENT_PORT']:
                total_counter += 1
                seq = pkt[TCP].seq
                if seq <= last_seq:
                    continue
                timestamp, _ = getPacketTimestamp(pkt)
                change, new_timestamp = insert.timestamp(timestamp)
                if change:
                    modified_counter += 1
                    self.modifyPktsTimestamp(new_timestamp, pkt, pktRelation, clientPkts,clientKeyPkt)
                last_seq = max(seq, last_seq)

        print('Total packets send by server', total_counter)
        print('Modified %:', 100*(modified_counter/total_counter))

        

        # Create a output pcap with modified timestamp
        writePcap(serverPkts, self.pcapConfig['SERVER_PCAP_PATH_OUTPUT'])
        writePcap(clientPkts, self.pcapConfig['CLIENT_PCAP_PATH_OUTPUT'])

        messages = []
        for i in insert.sentData:
            m = ""
            for j in i:
                m = m + str(j)
            messages.append(m)
        return messages, 100*(modified_counter/total_counter), total_counter
    
    def extractMessage(self):
        return self.extractor.extract()
    
    def parser(self,rawMessage):
        return self.utils.parse(rawMessage)
    
    def compare(self,sendMessage,receivedMessage):
        return self.utils.compare(sendMessage,receivedMessage)

