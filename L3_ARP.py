from Dictionary import *
import struct
from ARPCacheTable import *

class L3_ARP:
    def __init__(self, name, my_mac, my_ip):
        self.name = name
        self.underLayer = None
        self.upperLayer = None

        self._hard_type = b'\x00\x01'
        self._proto_type = b'\x08\x00'
        self._hard_len = b'\x06'
        self._proto_len = b'\x04'
        self._opcode = None
        self._sender_mac = my_mac
        self._sender_ip = my_ip
        self._target_mac = None
        self._target_ip = None

        self.arptable = None

    def connectTable(self, arptable):
        self.arptable = arptable

    def connectLayer(self, underLayer, upperLayer):
        self.underLayer = underLayer
        self.upperLayer = upperLayer

    def receive(self, payload):
        print('[Layer ' + self.name + '] Called receive()')

        self.extractHeader(payload)

        #proxy_i = self.arptable.proxysearch(self._ptarget_ip)
        proxy_i = self.arptable.search(self._ptarget_ip)
        if proxy_i != None:
            #self.sendPARPReply(self.arptable.proxy_get_ip(proxy_i))
            self.sendPARPReply(self.arptable.get_ip(proxy_i))

        if self._ptarget_ip != self._sender_ip:
            return
        if self._psender_ip == self._sender_ip:
            return
        if self._popcode == ARP_OPCODE_REQUEST:
            index = self.arptable.search(self._psender_ip)
            if index == None:
                self.arptable.insert(self._psender_ip, self._psender_mac)
            else:
                self.arptable.update(index, self._psender_mac)

            if self._psender_ip != self._ptarget_ip:
                self.sendARPReply()

        if self._popcode == ARP_OPCODE_REPLY:
            index = self.arptable.search(self._psender_ip)
            if index == None:
                self.arptable.insert(self._psender_ip, self._psender_mac)
            else:
                self.arptable.update(index, self._psender_mac)

    def send(self, data):
        print('[Layer ' + self.name + '] Called send()')
        self.underLayer.send(data, ETHERNET_TYPE_ARP)

    def extractHeader(self, raw):
        self._phard_type = raw[:2]
        self._pproto_type = raw[2:4]
        self._phard_len = raw[4:5]
        self._pproto_len = raw[5:6]
        self._popcode = raw[6:8]
        self._psender_mac = raw[8:14]
        self._psender_ip = raw[14:18]
        self._ptarget_mac = raw[18:24]
        self._ptarget_ip = raw[24:28]
        self._pheader = raw[:28]

    # todo ARP cache table에서 정보 찾기
    def search(self, ipdst):
        index = self.arptable.search(ipdst)
        if index != None:
            return self.arptable.get_ip(index)
        else:
            return None


    def checkARPCacheTable(self, ipdst):
        print("TODO: ARP cache table 확인", ipdst)

        index = self.arptable.search(ipdst)
        if index != None:
            print('[Layer ' + self.name + '] ARP cache entry 찾기 성공')
            eth_dst = self.arptable.get_mac(index)
            self.underLayer.set_dst(eth_dst)
            return True
        else:
            print('[Layer ' + self.name + '] ARP cache entry 찾기 실패')
            self.sendARPRequest(ipdst)
            return False

    def sendARPRequest(self, ipdst):
        print('[Layer ' + self.name + '] Called sendARPReqeust()')

        self._hard_type = b'\x00\x01'
        self._proto_type = b'\x08\x00'
        self._hard_len = b'\x06'
        self._proto_len = b'\x04'
        self._opcode = ARP_OPCODE_REQUEST
        self._target_mac = b'\x00\x00\x00\x00\x00\x00'
        self._target_ip = ipdst

        self.underLayer.set_dst(b'\xff\xff\xff\xff\xff\xff')
        print(self.generatePayload())

        self.send(self.generatePayload())

    def sendARPReply(self):
        print('[Layer ' + self.name + '] Called sendARPReply()')

        self._hard_type = self._phard_type
        self._proto_type = self._pproto_type
        self._hard_len = self._phard_len
        self._proto_len = self._pproto_len
        self._opcode = self._popcode
        self._target_mac = self._ptarget_mac
        self._target_ip = self._ptarget_ip

        self.underLayer.set_dst(self._psender_mac)
        self.send(self.generatePayload())

    def generatePayload(self):
        return self._hard_type + self._proto_type + self._hard_len + \
               self._proto_len + self._opcode + self._sender_mac + \
               self._sender_ip + self._target_mac + self._target_ip

