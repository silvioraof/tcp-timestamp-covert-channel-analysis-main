from config import ConfigPcap
from data_link.data_link import DataLink
from tcp_reliable.tcp_reliable import TcpRealible
 
# Configuration of pcap
CONFIG_PCAP_FILE  = 'pcap.ini'

# datalink configuration
FLAG = [0,1,1,1,1,0]
MESSAGE_SIZE = 20

# tcp realible
BUFFER_SIZE = 16


def RunCovertChannel(country, method):
    file = open('result.csv','a')

    # Get configuration
    print(country)
    configPcap = ConfigPcap(CONFIG_PCAP_FILE)
    if not configPcap.hasCountryPcap(country):
        raise Exception('Country config info not found')
    pcapInfo = configPcap.getCountryInfo(country)

    # Run covert channel
    if  method == 'data_link':
        print('Data Link model')
        dataLink = DataLink(pcapInfo, MESSAGE_SIZE, FLAG)
        sendMessages,modifyRate,totalSendPackets  = dataLink.insertMessage()
        totalMessagesSent = len(sendMessages)
        bitsSend = MESSAGE_SIZE*totalMessagesSent
        print("Total send",totalMessagesSent)
        rawExtractBits = dataLink.extractMessage()
        extractMessages = dataLink.parser(rawExtractBits)
        totalValid = dataLink.compare(sendMessages, extractMessages)
        validBits = MESSAGE_SIZE*totalValid
        print("Valid messages",totalValid)
        successRate = 100*(totalValid/totalMessagesSent)
        print("Sucess %:",successRate)
        file.write(country+','+method+','+str(successRate)+','+str(bitsSend)+','+str(validBits)+','+str(modifyRate)+','+str(totalSendPackets)+'\n')
    elif method == 'tcp_reliable':
        print('TCP realible model')
        tcpRealible = TcpRealible(pcapInfo, BUFFER_SIZE)
        sendMessages,modifyRate,totalSendPackets = tcpRealible.insertMessage()
        totalMessagesSent = len(sendMessages)
        bitsSend = (BUFFER_SIZE-1)*totalMessagesSent
        print("Total send",totalMessagesSent)
        print(sendMessages)
        extractMessages = tcpRealible.extractMessage()
        print(extractMessages)
        totalValid = tcpRealible.compare(sendMessages, extractMessages)
        validBits = totalValid*(BUFFER_SIZE-1)
        print("Valid messages",totalValid)
        successRate = 100*(totalValid/totalMessagesSent)
        print("Sucess %:",successRate)
        file.write(country+','+method+','+str(successRate)+','+str(bitsSend)+','+str(validBits)+','+str(modifyRate)+','+str(totalSendPackets)+'\n')
    else:
        raise Exception('Method not found')
    file.close()

if __name__== '__main__':
    for country in ['japan', 'belgica', 'toronto']:
        for method in ['data_link', 'tcp_reliable']:
            RunCovertChannel(country, method)

    

