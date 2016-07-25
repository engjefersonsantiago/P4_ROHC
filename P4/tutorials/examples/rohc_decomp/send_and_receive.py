from scapy.all import *
import sys
import threading 
from threading import Lock
from struct import *

ip_comps = [b'\xFD\x00\x01\xD6\x40\x11\x7F\x00\x00\x01\x7F\x00\x00\x01\x04\xD3\x04\xD2\x00\x00\x00\x00\x00\x40\x00\x00\x20\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00\x00\x04',
b'\xFD\x00\x01\xEA\x40\x11\x7F\x00\x00\x01\x7F\x00\x00\x01\x04\xD3\x04\xD2\x00\x00\x00\x00\x00\x40\x00\x00\x30\x00\x00\x00\x90\x00\x00\x01\x00\x00\x01\x2C\x00\x05\x81\x2C',
b'\xFD\x00\x01\xAB\x40\x11\x7F\x00\x00\x01\x7F\x00\x00\x01\x04\xD3\x04\xD2\x00\x00\x00\x00\x00\x40\x00\x00\x30\x00\x00\x00\x90\x00\x00\x02\x00\x00\x02\x58\x00\x05\x81\x2C',
b'\xFD\x00\x01\x27\x40\x11\x7F\x00\x00\x01\x7F\x00\x00\x01\x04\xD3\x04\xD2\x00\x00\x00\x00\x00\x40\x00\x00\x30\x00\x00\x00\x90\x00\x00\x03\x00\x00\x03\x84\x00\x05\x81\x2C',
b'\x27\x00',
b'\x2A\x00',
b'\x37\x00',
b'\x39\x00',
b'\x43\x00',
b'\x4E\x00']


#ip_comps = [b'\xFD\x00\x01\xD6\x40\x11\x7F\x00\x00\x01\x7F\x00\x00\x01\x04\xD3\x04\xD2\x00\x00\x00\x00\x00\x40\x00\x00\x20\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00\x00\x04']

RTP_PAYLOAD = 'hello, Python world!'
mutex = Lock()
class Receiver(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def received(self, p):
        mutex.acquire()
        print "Received packet on port 3, exiting"
        hexdump(p)
        print "End packet\n"
        mutex.release()
	sys.exit(0)

    def run(self):
        sniff(iface="veth7", prn=lambda x: self.received(x))
        sniff(iface="veth5", prn=lambda x: self.received(x))


def main():
    ####Receiver().start()

    ####ip_comp = b'\xfd\x00\x04\xf7\x40\x02\xc0\xa8\x13\x01\xc0\xa8\x13\x05\x00\x40\x00\x00\xa0\x00\x00\x01'
    ####ip_comp += RTP_PAYLOAD

    #### #p = Ether(src="aa:aa:aa:aa:aa:aa") / IP(dst="10.0.1.10") / TCP() / "aaaaaaaaaaaaaaaaaaa"
    ####p = Ether(src="aa:aa:aa:aa:aa:aa") / ip_comp

    ####print "Sending packet on port 0, listening on port 3"
    ####time.sleep(1)
    ####hexdump(p)
    ####sendp(p, iface="veth1", verbose=0)

    for ip_comp in ip_comps:
        mutex.acquire()
        Receiver().start()
        
        ip_comp = pack('b',(0<<8)+len(ip_comp)) + ip_comp + RTP_PAYLOAD
        p = Ether(src="aa:aa:aa:aa:aa:aa",type=0xdd00)/ip_comp
        print "Sending packet on port 0, listening on port 3"
        hexdump(p)
        sendp(p, iface="veth1", verbose=0)
        mutex.release()
        time.sleep(1)

if __name__ == '__main__':
    main()
