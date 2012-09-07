from dpkt import *
from socket import *

import os
import sys
import uuid
import pickle
import time

myUUID = uuid.getnode()

class MessageType:
  ANNOUNCE = 0xaa
  REQUEST = 0xbb
  RESPONSE = 0xcc


def getInterfaces():
  result = []
  for line in os.popen("/sbin/ifconfig"):
    if line.find('HWaddr') > -1:
      tokens = line.split()
      interface = tokens[0]
      result.append(interface)

  return result


def send(interface, srcEther, srcIP, dstIP, nxt, content):
  
  s = socket(AF_PACKET, SOCK_RAW)
  s.bind( (interface, 0) )

  upper = ip6.IP6()
  upper.data = pickle.dumps(content)
  upper.src = srcIP
  upper.dst = dstIP
  upper.nxt = nxt


  eth = ethernet.Ethernet(
    src = srcEther,
    type = 34525,
    data = upper
  )

  eth.data._set_flow(4)
  s.send( str(eth) )



def request(srcIP, dstIP):
  
  interfaces = getInterfaces()
  hexUUID = hex(myUUID)
  send(
    interfaces[0], hexUUID, 
    srcIP, dstIP, 
    MessageType.REQUEST, 'firewall')



def announce():
  interfaces = getInterfaces()
  hexUUID = hex(myUUID)
  for interface in interfaces:
    send(interface, hexUUID, 0, 0, MessageType.ANNOUNCE, 'firewall')



def main():
  src = sys.argv[1]
  dst = sys.argv[2]

  srcAddr = inet_pton(AF_INET6, src)
  dstAddr = inet_pton(AF_INET6, dst)

  request(srcAddr, dstAddr)

  #for none in xrange(1000):
  #  announce()
  #  time.sleep(1)


main()
