import struct

class FowardingTable:
    def __init__(self, name):
        self.name = name
        self.fowardingtable = []

    def getTable(self):
        return self.fowardingtable

    def search(self, dst_ip):
        print('탐색 시작 : ', dst_ip)
        for i in range(len(self.fowardingtable)):
            address = self.fowardingtable[i][0]
            netmask = self.fowardingtable[i][1]

            print('어드레스 :', address, '넷마스크 :', netmask)

            if self.byte_and_operator(dst_ip, netmask) == address:
                print('일치하는 튜플 : ', i)
                return i
        print('탐색 실패')
        return None

    def byte_and_operator(self, address, netmask):
        (addr0, addr1, addr2, addr3) = struct.unpack('!4B', address)
        (net0, net1, net2, net3) = struct.unpack('!4B', netmask)

        ret_val = struct.pack('!4B', addr0 & net0, addr1 & net1, addr2 & net2, addr3 & net3)
        print('리턴벨류 :', ret_val)
        return ret_val

    def insert(self, dst_ip, netmask, gateway_ip, flag, interface, metric):
        print('ROUTING TABLE_INSERT')
        self.fowardingtable.append([dst_ip, netmask, gateway_ip, flag, interface, metric])
        print(self.fowardingtable)

    def update(self, i, netmask, gateway_ip, flag, interface, metric):
        print('ROUTING TABLE_UPDATE')
        self.fowardingtable[i][1:] = [netmask, gateway_ip, flag, interface, metric]

    def delete(self):
        pass

    def get_tuple(self, i):
        if i == None:
            return None
        return self.fowardingtable[i][0], self.fowardingtable[i][1], \
               self.fowardingtable[i][2], self.fowardingtable[i][3], \
               self.fowardingtable[i][4], self.fowardingtable[i][5]