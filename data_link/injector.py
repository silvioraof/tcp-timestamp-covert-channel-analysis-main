import random

class Injector:
    def __init__(self, FLAG, MESSAGE_SIZE):
        self.FLAG = FLAG
        self.MESSAGE_SIZE = MESSAGE_SIZE
        self.MESSAGE_SLEEP = 0
        self.sentData = []
        self.message = self.generateRandomDataWithFlag(self.MESSAGE_SIZE)

        # Flag control
        self.flagIdx = 0
        self.flagInitialized = False
        
        # Message control
        self.messageIdx = 0
        self.lastTimestamp = 0

        # Idle control
        self.sleep = self.MESSAGE_SLEEP

    def generateNewMessage(self):
        self.sentData.append(self.message)
        self.message = self.generateRandomDataWithFlag(self.MESSAGE_SIZE)
        self.messageIdx = 0
        self.sleep = self.MESSAGE_SLEEP
    
    def flagCheck(self, timestamp):
        bit = timestamp % 2
        return self.FLAG[self.flagIdx] == bit and self.flagIdx == (len(self.FLAG) - 1)
    
    def sleepCheck(self):
        return self.sleep > 0
    
    def flagProcess(self, timestamp):
        bit = timestamp % 2
        if self.FLAG[self.flagIdx] == bit:
            self.flagIdx += 1
        else:
            self.flagIdx = 0
        
        if self.flagIdx == len(self.FLAG):
            self.flagIdx = 0
            self.flagInitialized = not self.flagInitialized


    def bitBuffer(self, message):
        count = 0
        addZero = []
        for idx in range(len(message)):
            num = message[idx]
            if count == 3 and num == 1:
                addZero.append(idx)
                count = 0 
            if num == 1:
                count += 1
            else:
                count = 0
        addZero.reverse()
        for idx in addZero:
            message.insert(idx,0)

    def generateRandomData(self, size):
        rand = []
        for _ in range(size):
            rand.append(random.randint(0, 1))
        return rand

    def generateRandomDataWithFlag(self, size):
        message = self.generateRandomData(size)
        self.bitBuffer(message)
        newMessage = self.FLAG + message + self.FLAG
        return newMessage

    """
    Receive packet timestamp
    Return if is modified and the next value
    """
    def timestamp(self, pktTimestamp):

        oldTimestamp = self.lastTimestamp
        self.lastTimestamp = pktTimestamp

        # Timestamp did no change do not send value
        if oldTimestamp == pktTimestamp:
            return False, None
        
        # Adjust Timestamp to correct value
        if oldTimestamp > pktTimestamp:
            self.lastTimestamp = oldTimestamp
            return True, oldTimestamp

        isCheck = self.flagCheck(pktTimestamp)
        isSleep = self.sleepCheck()

        if isSleep:
            self.sleep -= 1
            if isCheck:
                # Bit stuffing
                self.lastTimestamp = pktTimestamp + 1
                self.flagProcess(pktTimestamp + 1)
                return True, pktTimestamp + 1
            else:
                self.flagProcess(pktTimestamp)
                return False, None

        # Message already send
        if self.messageIdx >= len(self.message):
            self.generateNewMessage()
        
        # Verify if is necessary modification
        nextValue = self.message[self.messageIdx]
        
        # Send new value '0'
        if pktTimestamp % 2 == nextValue:
            self.messageIdx += 1
            return False, None
        
        # Send new value '1'
        self.messageIdx += 1
        self.lastTimestamp = pktTimestamp +1
        return True, pktTimestamp + 1