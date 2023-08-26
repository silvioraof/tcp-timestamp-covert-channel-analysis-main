import random
import hashlib



def genHashNumber(num):
    return int(hashlib.sha256(str(num).encode()).hexdigest(), base=16)

def generateRandomData(size):
    rand = []
    for _ in range(size):
        rand.append(random.randint(0, 1))
    return rand

class Injector:
    
    def __init__(self, BUFFER_SIZE):
        self.allSecrets = []

        self.bufferSize = BUFFER_SIZE
        self.actualSecret = generateRandomData(self.bufferSize - 1)
        # First element is NEXT flag
        self.actualBuffer = [0] + self.actualSecret
        self.validateBuffer = set(range(self.bufferSize))
        self.validateSeqBuffArray = [[] for _ in range(self.bufferSize) ]
        self.lastTimestamp = 0 

    def generateNextSecret(self):
        self.allSecrets.append(self.actualSecret)
        self.actualSecret = generateRandomData(self.bufferSize - 1)
        self.actualBuffer = [0] + self.actualSecret
        self.validateBuffer = set(range(self.bufferSize))
        self.validateSeqBuffArray = [[] for _ in range(self.bufferSize) ]

    def getBufferIdx(self, seq):
        return genHashNumber(seq) % self.bufferSize

    def validateBufferIdx(self, sendIdx):
        if sendIdx in self.validateBuffer:
            self.validateBuffer.remove(sendIdx)
        if len(self.validateBuffer) == 0:
            self.generateNextSecret()
        elif len(self.validateBuffer) == 1:
            self.actualBuffer[0] = 1

    
    def getInsertedSecret(self):
        total = []
        for secret in self.allSecrets:
            total = total + secret
        return total
    
    def addCheck(self,sendIdx,seq, load):
        if self.actualBuffer[0] == 0 and sendIdx == 0:
            return
        if self.actualBuffer[0] == 1 and sendIdx == 0 and len(self.validateSeqBuffArray[0]) > 0:
            return
        self.validateSeqBuffArray[sendIdx].append((seq,seq+load))
    
    def removeLost(self, seq):

        if len(self.validateSeqBuffArray[0]) > 0 and self.validateSeqBuffArray[0][0] == seq:
            self.validateSeqBuffArray[0] = []
        

    """
    Receive packet timestamp, sequence number and loadValue
    Return if is modified and the next value
    """
    def timestamp(self, pktTimestamp, seq, load):
        self.removeLost(seq)

        oldTimestamp = self.lastTimestamp
        self.lastTimestamp = pktTimestamp

        # Timestamp did no change do not send value
        if oldTimestamp == pktTimestamp:
            return False, None
        
        # Adjust Timestamp to correct value
        if oldTimestamp > pktTimestamp:
            self.lastTimestamp = oldTimestamp
            return True, oldTimestamp

        sendIdx = self.getBufferIdx(seq)
        sendBit = self.actualBuffer[sendIdx]

        if sendIdx == 0 and sendBit == 1 and len(self.validateSeqBuffArray[0]) > 0:
            sendBit = 0
        self.addCheck(sendIdx, seq, load)
        if sendBit == pktTimestamp%2:
            # print("seq:", seq, "timestamp:", pktTimestamp, "bit:", sendBit)
            return False, None
    
        self.lastTimestamp = pktTimestamp +1
        # print("seq:", seq, "timestamp:", pktTimestamp+1, "bit:", sendBit)
        return True, pktTimestamp+1
    
    def ackPkt(self, ackSeq):
        for idx in range(len(self.validateSeqBuffArray)):
            if idx in self.validateBuffer:
                for val in self.validateSeqBuffArray[idx]:
                    seq = val[0]
                    seqLoad = val[1]
                    if seqLoad <= ackSeq:
                        # print("******",len(self.allSecrets)+1,"***** seq",seq,"*****","idx",idx)
                        self.validateBufferIdx(idx)
                        break



