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

  def __init__(self, conf, parentConf):
    protocol.__init__(self, parentConf)

    self.conf = conf
    print self.conf
    self.findService = {}
    self.whatService = {}
 

  def pushData(self):
    protocol.pushData(self)


  def handlePacketIn(self, rpc):
    packet = rpc.Extensions[PacketInRequest.msg].packet
    srcV = rpc.Extensions[PacketInRequest.msg].srcV
    cookie = rpc.Extensions[PacketInRequest.msg].cookie
    eth = dpkt.ethernet.Ethernet( packet )
    ip6 = eth.data

    self.mapping[ip6.src] = srcV
    dstAddrInt = int((ip6.dst).encode('hex'), 16)
    dstAddr = IPv6Address( dstAddrInt )

    print dstAddr,
    for (network, (domainId, vertex)) in self.remote.items():
      if dstAddr not in IPv6Network(network): continue

      print 'remote address'
      dstV = vertex

      if (self.conf == 'middlebox.conf'):
        midV = self.findService['firewall']
        self.packetInResponse(srcV, dstV, cookie, ip6.dst, midV)
        print 'middlebox service vertex', midV
        return

      self.packetInResponse(srcV, dstV, cookie, ip6.dst)
      return

    dstV = self.mapping.get(ip6.dst)
    if dstV is not None:
      print 'local address'
      
      if (self.conf == 'middlebox.conf'):
        midV = self.findService['firewall']
        self.packetInResponse(srcV, dstV, cookie, ip6.dst, midV)
        print 'middlebox service vertex', midV
        return

      self.packetInResponse(srcV, dstV, cookie, ip6.dst)
      return

    print 'unknown destionation'



  def packetInResponse(self, srcV, dstV, cookie, address, midV = None):
    rpc = RPC()
    rpc.type = RPC.PacketInResponse
    response = rpc.Extensions[PacketInResponse.msg]
    response.srcV = srcV
    response.dstV = dstV
    response.cookie = cookie
    if midV is not None:
      response.midV = midV

    match = match_header( address )
    response.match = str(match)
    self.sendToController( rpc.SerializeToString() )
    




  def handleDataReceive(self, rpc):
    data = rpc.Extensions[DataReceive.msg].data
    srcV = rpc.Extensions[DataReceive.msg].srcV

    eth = dpkt.ethernet.Ethernet(data)

    if eth.data.nxt != MessageType.ANNOUNCE:
      protocol.handleDataReceive(self, rpc)
      return

    serviceType = pickle.loads( data[len(eth):] )
    self.findService[serviceType] = srcV
    self.whatService[srcV] = serviceType
    print 'service type', serviceType, 'from vertex', srcV
    return


  def connectionMade(self):
    self.sendInit()


  def handleInitResponse(self, rpc):
    protocol.handleInitResponse(self, rpc)


  def handleTopology(self, rpc):
    protocol.handleTopology(self, rpc)
