#!/usr/bin/python

from twisted.internet import reactor, threads, defer
from twisted.protocols.basic import Int32StringReceiver

from ipaddr import IPv6Network, IPv6Address
from ctypes import c_uint16, c_uint32, c_uint64

from interface_pb2 import *
from openflow import *

import bgp
import pydot
import pygraphviz
import dpkt
import networkx
import pickle



class MessageType:
  ANNOUNCE = 0xaa



protocol = bgp.BGP



class Middlebox( protocol ):

  def __init__(self, conf):
    protocol.__init__(self, conf)

    self.services = {}
 

  def pushData(self):
    protocol.pushData(self)



  def handleDataReceive(self, rpc):
    data = rpc.Extensions[DataReceive.msg].data
    srcV = rpc.Extensions[DataReceive.msg].srcV

    eth = dpkt.ethernet.Ethernet(data)

    if eth.data.nxt != MessageType.ANNOUNCE:
      protocol.handleDataReceive(self, rpc)

    serviceType = pickle.loads(  data[len(eth):] )
    print 'received an announcement for a service of type', serviceType
    return




  def handlePacketIn(self, rpc):
    packet = rpc.Extensions[PacketInRequest.msg].packet
    srcV = rpc.Extensions[PacketInRequest.msg].srcV
    cookie = rpc.Extensions[PacketInRequest.msg].cookie
    eth = dpkt.ethernet.Ethernet( packet )
    ip6 = eth.data

    print eth.data.nxt

    if eth.data.nxt == MessageType.SUB:
      self.handleSub( srcV, packet )
    elif eth.data.nxt == MessageType.PUB:
      self.handlePub( srcV, packet )
    else:
      protocol.handlePacketIn(self, rpc)


  def connectionMade(self):
    self.sendInit()


  def handleInitResponse(self, rpc):
    protocol.handleInitResponse(self, rpc)


  def handleTopology(self, rpc):
    protocol.handleTopology(self, rpc)
