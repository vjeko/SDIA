import pickle
import threading
import time
import sys

from dpkt import *
from socket import *


pathlets = None


def find(where, what):
  for (key, value) in where:
    if type(value) == list:
      result = find(value, what)
      if result == None: continue
      else:
        result.append(key)
        return result
    else:
      if value == what:
        return [key]
      else: return None



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

  

def ping(srcAddr, dstAddr, i):
  
  global pathlets
  if pathlets == None: return

  dstAddrInt = int((dstAddr).encode('hex'), 16)

  path = find(pathlets, dstAddrInt)
  if path == None:
    print 'unable to find a path'
    return

  path.reverse()
  path = map(lambda x: int(x), path)
  print i, path

  s = socket(AF_PACKET, SOCK_RAW)
  s.bind( ('eth0', 0) )

  upper = ip6.IP6()
  upper.src = srcAddr
  upper.dst = str(bytearray(path))
  upper.nxt = 1

  ethSrc = '\x00\xff\x00\x00\x00\x01'
  ethDst = '\x00\xff\x00\x00\x00\x00'

  e = ethernet.Ethernet(
    src = ethSrc, dst = ethDst,
    type = 34525, data = upper
  )

  e.data._set_flow(2)
  s.send( str(e) )



def main():
  rc = sys.argv[1]
  dst = sys.argv[2]

  srcAddr = inet_pton(AF_INET6, src)
  dstAddr = inet_pton(AF_INET6, dst)

  t1 = threading.Thread(target = listen, args = (srcAddr,))
  t1.start()

  for x in range(10):
    ping(srcAddr, dstAddr, 1)
    time.sleep(1)



if __name__ == '__main__':
  main()
