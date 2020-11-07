from Dictionary import *
import struct
from FowardingTable import *

class L3_IP:
    def __init__(self, name):
        self.name = name
        self.underLayers = None
        self.upperLayer = None
        self.arpLayers = None

        self._verlen = None
        self._service = None
        self._total = None
        self._id = None
        self._flag_and_offset = None
        self._ttl = None
        self._type = None
        self._check_sum = None
        self._src = None
        self._dst = None

        self.fowardingtable = None

    def connectLayers(self, underLayers, upperLayer, arpLayers):
        self.underLayers = underLayers
        self.upperLayer = upperLayer
        self.arpLayers = arpLayers

    def connectTable(self, fowardingtable):
        self.fowardingtable = fowardingtable

    def receive(self, ppayload):
        self.extractHeader(ppayload)
        index = self.fowardingtable.search(self._pdst)
        if index != None:
            self.send(index)

    def send(self, index):
        print('튜플: ', self.fowardingtable.get_tuple((index)))

        address, netmask, gateway, flag, ifnum, metric = self.fowardingtable.get_tuple((index))
        if flag == FLAG_UH:
            result = self.arpLayers[ifnum].checkARPCacheTable(self._pdst)
        elif flag == FLAG_UG:
            result = self.arpLayers[ifnum].checkARPCacheTable(gateway)

        if result == True:
            self.underLayers[ifnum].send(self.generatePayload(), ETHERNET_TYPE_IP)


    def extractHeader(self, raw):
        self._pverlen = raw[:1]
        self._pservice = raw[1:2]
        self._ptotal = raw[2:4]
        self._pid = raw[4:6]
        self._pflag_and_offset = raw[6:8]
        self._pttl = raw[8:9]
        self._ptype = raw[9:10]
        self._pcheck_sum = raw[10:12]
        self._psrc = raw[12:16]
        self._pdst = raw[16:20]
        self._data = raw[20:]
        self._pheader = raw[:20]

    def generatePayload(self):
        return self._pverlen + self._pservice + self._ptotal + self._pid + \
               self._pflag_and_offset + self._pttl + self._ptype + \
               self._pcheck_sum + self._psrc + self._pdst + self._data