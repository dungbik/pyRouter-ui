from scapy.sendrecv import sendp
from Dictionary import *
import struct
import pcap
import threading

class L1_NI:
    def __init__(self, name):
        self.name = name
        self.underLayer = None
        self.upperLayer = None
        self.devices = None
        self.ifnum = -1

    def connectLayers(self, underLayer, upperLayer):
        self.underLayer = underLayer
        self.upperLayer = upperLayer

    def getAdapterList(self):
        print('[Layer ' + self.name + '] Called setAdapter()')
        print('TODO Sniffer를 이용한 네트워크 어뎁터 설정')

        self.devices = pcap.findalldevs()
        i = 0
        buf = ''
        for dev in self.devices:
            buf = buf + (str(i) + ') ' + dev + ', ')
            i = i + 1
        print(buf)

    def setAdapter(self, ifnum):
        self.ifnum = ifnum
        print("Selected " + ifnum + "th device: " + self.devices[int(self.ifnum)])

    def execute(self):
        print(threading.currentThread().getName(), self.name)
        packets = pcap.pcap(name=self.devices[int(self.ifnum)], promisc=True, immediate=True, timeout_ms=50)

        for ts, payload in packets:
            self.receive(payload)

    def startAdapter(self):
        my_thread = threading.Thread(target=self.execute, args=())
        my_thread.start()

    def receive(self, payload):
        self.upperLayer.receive(payload)

    def send(self, data):
        sendp(data, iface=self.devices[int(self.ifnum)])
        pass