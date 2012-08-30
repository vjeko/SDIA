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
  PUB = 0xaa
  SUB = 0xbb



protocol = bgp.BGP



class ICN( protocol ):

  def __init__(self, conf):
    protocol.__init__(self, conf)

    self.pub = {}
    self.sub = {}
 

  def pushData(self):
    protocol.pushData(self)


  def handleDataReceive(self, rpc):
    protocol.handleDataReceive(self, rpc)



  def handleSub(self, srcV, packet):

    eth = dpkt.ethernet.Ethernet( packet )
    data = pickle.loads(  packet[len(eth):] )
    print 'node', srcV, 'has subscribed to', data

    result = self.pub.get(data)
    if result == None:
      print 'unable to find the request... forwarding...'
      self.fwdSub(srcV, packet)



  def handlePub(self, srcV, packet):
    eth = dpkt.ethernet.Ethernet( packet )
    data = pickle.loads(  packet[len(eth):] )
    print 'node', srcV, 'has published', data

    self.pub[data] = srcV



  def fwdSub(self, srcV, packet):
    fwdVertecies = filter(
      lambda (vertex, attribute): attribute['type'] == NodeType.REMOTE_DOMAIN,
      self.attr.iteritems()
    )

    fwdVertecies = filter(
      lambda (vertex, attribute): int(vertex) != int(srcV),
      fwdVertecies
    )
    
    print fwdVertecies

    for (dstV, value) in fwdVertecies:
      srcV_it = networkx.all_neighbors(self.graph, dstV)
      try:
        srcV = srcV_it.next()
        self.icnPush(srcV, dstV, packet)
      except StopIteration: pass



  def icnPush(self, srcV, dstV, packet):

    rpc = RPC()
    rpc.type = RPC.DataPush
    update = rpc.Extensions[DataPush.msg]
    update.srcV = int(srcV)
    update.dstV = int(dstV)

    update.data = packet
    self.sendToController( rpc.SerializeToString() )

    print srcV, '--', dstV




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
