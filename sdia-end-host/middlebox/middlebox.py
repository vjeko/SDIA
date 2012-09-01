from dpkt import *

import socket
import os
import sys
import uuid
import pickle
import time

myUUID = uuid.getnode()

class MessageType:
  ANNOUNCE = 0xaa


def getInterfaces():
  result = []
  for line in os.popen("/sbin/ifconfig"):
    if line.find('HWaddr') > -1:
      tokens = line.split()
      interface = tokens[0]
      result.append(interface)

  return result


def send(interface, srcEther, content):
  
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind( (interface, 0) )

  upper = ip6.IP6()
  upper.data = pickle.dumps(content)
  upper.nxt = MessageType.ANNOUNCE


  eth = ethernet.Ethernet(
    src = srcEther,
    type = 34525,
    data = upper
  )

  eth.data._set_flow(4)
  s.send( str(eth) )




def main():
  interfaces = getInterfaces()
  hexUUID = hex(myUUID)
  for interface in interfaces:
    send(interface, hexUUID, 'firewall')


for none in xrange(1000):
  main()
  time.sleep(1)
