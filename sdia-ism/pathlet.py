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
    self.topology = {}
    self.pathlets  = {}

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
    unpacked = pickle.loads(  data[len(eth):] )
    self.stich(srcV, unpacked)



  def stich(self, srcV, data):
    self.pathlets[str(srcV)] = data



  def pushData(self):

    print self.pathlets

    remoteDomains = filter(
      lambda (key, value): value['type'] == NodeType.REMOTE_DOMAIN,
      self.attr.iteritems()
    )

    for (dstV, value) in remoteDomains:
      srcV_it = networkx.all_neighbors(self.graph, dstV)
      try:
        srcV = srcV_it.next()
        self.pushData2(srcV, dstV)
      except StopIteration: pass

    reactor.callLater(self.updateInterval, self.pushData)



  def pushData2(self, srcV, dstV):

    rpc = RPC()
    rpc.type = RPC.DataPush
    update = rpc.Extensions[DataPush.msg]
    update.srcV = int(srcV)
    update.dstV = int(dstV)

    nodes = filter(
      lambda (vertex, attributes): attributes['type'] != NodeType.OPENFLOW,
      self.attr.iteritems()
    )

    nodes = filter(
      lambda (vertex, attributes): int(vertex) != int(dstV),
      nodes
    )

    advertisedPathlets = []
    for (vertex, attributes) in nodes:
      pathlet = self.pathlets.get(vertex)
      if pathlet is not None:
        advertisedPathlets.append( (vertex, pathlet) )
      if attributes['type'] == NodeType.HOST:
        advertisedPathlets.append( vertex )

    print 'pathlets:', advertisedPathlets
    eth = self.encapsulate( advertisedPathlets )
    update.data = str(eth)
    self.sendToController( rpc.SerializeToString() )



  def encapsulate(self, data):
    ip6 = dpkt.ip6.IP6(
      data = pickle.dumps( data, pickle.HIGHEST_PROTOCOL )
    )

    eth = dpkt.ethernet.Ethernet(
      type = 34525,
      data = ip6
    )
    
    return eth



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
