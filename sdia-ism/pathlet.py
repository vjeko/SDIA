#!/usr/bin/python

from twisted.internet import reactor, threads, defer
from twisted.protocols.basic import Int32StringReceiver

from ipaddr import IPv6Network, IPv6Address
from ctypes import c_uint16, c_uint32, c_uint64

from interface_pb2 import *
from openflow import *

import pydot
import pygraphviz
import dpkt
import networkx
import pickle



conf = None


class Pathlet( Int32StringReceiver ):

  
  def __init__(self):
  
    self.attr =     {}
    self.mapping =  {}
    self.remote =   {}
    self.local =    []
    self.topology = {}

    self.lock = defer.DeferredLock()
    self.graph = networkx.Graph()
    self.updateInterval = 4
    self.domain = 0

    global conf
    self.local = map(lambda x: x.strip('\n'), open(conf))



  def handleTopology(self, rpc):
    dotStr     = rpc.Extensions[Topology.msg].dot
    pyGraph    = pydot.graph_from_dot_data(dotStr)
    aGraph     = pygraphviz.AGraph(string = dotStr)
    self.graph = networkx.from_agraph(aGraph)

    for node in pyGraph.get_nodes():
      self.attr[node.get_name()] = node.obj_dict['attributes']



  def handleDataReceive(self, rpc):
    data = rpc.Extensions[DataReceive.msg].data
    srcV = rpc.Extensions[DataReceive.msg].srcV

    eth = dpkt.ethernet.Ethernet(data)
    unpacked = pickle.loads(eth.data)
    addresses = map(lambda (x, y): (IPv6Network(x), y), unpacked)
    for (prefix, domainId) in addresses:
      self.remote[prefix] = (domainId, srcV)



  def pushData(self):
    remoteDomains = filter(
      lambda (key, value): value['type'] == NodeType.REMOTE_DOMAIN,
      self.attr.iteritems()
    )

    for (dstV, value) in remoteDomains:
      srcV_it = networkx.all_neighbors(self.graph, dstV)
      try:
        srcV = srcV_it.next()
        self.pushData(srcV, dstV)
      except StopIteration: pass

    reactor.callLater(self.updateInterval, self.pushData)



  def pushData(self, srcV, dstV):
    remoteDomains = filter(
      lambda (key, value): value['type'] != NodeType.OPENFLOW,
      self.attr.iteritems()
    )


  def sendToController(self, data):
    self.lock.acquire()
    self.sendString( data )
    self.lock.release()



  def handlePacketIn(self, rpc):
    pass



  def handleInitResponse(self, rpc):
    print 'initialization complete...'
    self.domain = rpc.Extensions[InitResponse.msg].domain
    print 'our domain number is', self.domain

    reactor.callLater(0, self.pushData)



  def sendInit(self):
    rpc = RPC()
    rpc.type = RPC.InitRequest
    request = rpc.Extensions[InitRequest.msg]
    request.ism = "Pathlet"
    self.sendToController( rpc.SerializeToString() )



  def connectionMade(self):
    self.sendInit()
  


  def dataReceived(self, data):
    rpc = RPC()
    rpc.ParseFromString(data)
    if rpc.type is RPC.InitResponse:
      self.handleInitResponse(rpc)
    elif rpc.type is RPC.Topology:
      self.handleTopology(rpc)
    elif rpc.type is RPC.PacketInRequest:
      self.handlePacketIn(rpc)
    elif rpc.type is RPC.DataReceive:
      self.handleDataReceive(rpc)
    else:
      print 'unknown RPC...'
