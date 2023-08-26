import configparser

class ConfigPcap:
    def __init__(self, configPathFile):
        self.config = configparser.ConfigParser()
        self.config.read(configPathFile)


    def hasCountryPcap(self, country):
        return country in self.config
    
    def getCountryInfo(self, country):
        countryInfo = self.config[country]
        return {
            'CLIENT_PCAP_PATH_INPUT': countryInfo['client_pcap_path_input'],
            'CLIENT_PCAP_PATH_OUTPUT': countryInfo['client_pcap_path_output'],
            'SERVER_PCAP_PATH_INPUT': countryInfo['server_pcap_path_input'],
            'SERVER_PCAP_PATH_OUTPUT': countryInfo['server_pcap_path_output'],
            'SERVER_PORT': int(countryInfo['server_port']),
            'CLIENT_PORT': int(countryInfo['client_port']),
        }

if __name__ == '__main__':
    CONFIG_FILE  = 'pcap.ini'
    config = ConfigPcap(CONFIG_FILE)
    print(config.hasCountryPcap('japan'))
    print(config.getCountryInfo('japan'))