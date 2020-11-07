class ARPCacheTable:
    def __init__(self, name):
        self.name = name
        self.arpcachetable = []

    def getTable(self):
        return self.arpcachetable

    def insert(self, arp_ip, arp_eth):
        print('ARP_INSERT')
        self.arpcachetable.append([arp_ip, arp_eth])

    def update(self, i, arp_eth):
        print('ARP_UPDATE')
        self.arpcachetable[i][1] = arp_eth

    def delete(self):
        pass

    def search(self, arp_ip):
        for i in range(len(self.arpcachetable)):
            if self.arpcachetable[i][0] == arp_ip:
                return i
        return None

    def get_ip(self, i):
        return self.arpcachetable[i][0]

    def get_mac(self, i):
        return self.arpcachetable[i][1]