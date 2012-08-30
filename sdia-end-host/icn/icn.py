import pickle
import threading
import time
import sys

from dpkt import *
from socket import *



def listen(srcAddr):
  import pcap

  global pathlets

  pc = pcap.pcap()
  pc.setfilter('ip6')

  for ts, pkt in pc:
    eth = ethernet.Ethernet(pkt)
    ethDst = int((eth.dst).encode('hex'), 16)
    if (ethDst == 0):
      unpacked = pickle.loads(  pkt[len(eth):] )
      pathlets = map(lambda x: x, unpacked)
    else:
      if eth.data.nxt == 3:
        print 'pong'
      if eth.data.nxt == 1:
        if eth.data.src == srcAddr: continue
        ping(srcAddr, eth.data.src, 3)



class MessageType:
  PUB = 0xaa
  SUB = 0xbb



def send(srcAddr, subtype, content):
  
  s = socket(AF_PACKET, SOCK_RAW)
  s.bind( ('eth0', 0) )

  upper = ip6.IP6()
  upper.src = srcAddr
  upper.nxt = subtype
  upper.data = pickle.dumps(content)

  ethSrc = '\x00\xff\x00\x00\x00\x00'
  ethDst = '\x00\xff\x00\x00\x00\x01'

  e = ethernet.Ethernet(
    src = ethSrc, dst = ethDst,
    type = 34525, data = upper
  )

  e.data._set_flow(3)
  s.send( str(e) )



def pub(srcAddr, content):
  send(srcAddr, MessageType.PUB, content)

def sub(srcAddr, content):
  send(srcAddr, MessageType.SUB, content)
src = sys.argv[1]
content = sys.argv[2]

srcAddr = inet_pton(AF_INET6, src)

#pub(srcAddr, content)
sub(srcAddr, content)

#t1 = threading.Thread(target = listen, args = (srcAddr,))
#t1.run()

