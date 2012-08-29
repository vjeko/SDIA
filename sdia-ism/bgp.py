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



class BGP( Int32StringReceiver ):

  
  def __init__(self, conf):
  
    self.attr =     {}
    self.mapping =  {}
    self.remote =   {}
    self.local =    []
    self.topology = {}

    self.lock = defer.DeferredLock()
    self.graph = networkx.Graph()
    self.updateInterval = 4
    self.domain = 0

    self.local = map(lambda x: x.strip('\n'), open(conf))



  def handleTopology(self, rpc):
    dotStr     = rpc.Extensions[Topology.msg].dot
    pyGraph    = pydot.graph_from_dot_data(dotStr)
    aGraph     = pygraphviz.AGraph(string = dotStr)
    self.graph = networkx.from_agraph(aGraph)

    for node in pyGraph.get_nodes():
      self.attr[node.get_name()] = node.obj_dict['attributes']




  def pushData(self):
    remoteDomains = filter(
      lambda (key, value): value['type'] == NodeType.REMOTE_DOMAIN,
      self.attr.iteritems()
    )

    for (dstV, value) in remoteDomains:
      srcV_it = networkx.all_neighbors(self.graph, dstV)
      try:
        srcV = srcV_it.next()
        self.dataPush(srcV, dstV)
      except StopIteration: pass

    reactor.callLater(self.updateInterval, self.pushData)



  def handleDataReceive(self, rpc):
    data = rpc.Extensions[DataReceive.msg].data
    srcV = rpc.Extensions[DataReceive.msg].srcV

    eth = dpkt.ethernet.Ethernet(data)
    unpacked = pickle.loads(  data[len(eth):] )

    addresses = map(lambda (x, y): (IPv6Network(x), y), unpacked)
    for (prefix, domainId) in addresses:
      self.remote[prefix] = (domainId, srcV)

    self.printPrefixes()



  def dataPush(self, srcV, dstV):
    rpc = RPC()
    rpc.type = RPC.DataPush
    update = rpc.Extensions[DataPush.msg]
    update.srcV = int(srcV)
    update.dstV = int(dstV)

    remotePrefixes = dict( filter(
      lambda (prefix, (domainID, vertex)): int(vertex) != int(dstV),
      self.remote.iteritems()) )

    remotePrefixes = map(
      lambda (prefix, (domainID, vertex)): (str(prefix), domainID),
      remotePrefixes.iteritems())

    localPrefixes = map(
      lambda prefix: (str(prefix), self.domain),
      self.local)

    advertisedPrefixes = remotePrefixes + localPrefixes

    eth = self.encapsulate( advertisedPrefixes )
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


  def printPrefixes(self):
    print '------------------------'
    for prefix in self.local: print prefix
    for prefix in self.remote: print prefix
    print '------------------------'


  def handlePacketIn(self, rpc):
    packet = rpc.Extensions[PacketInRequest.msg].packet
    srcV = rpc.Extensions[PacketInRequest.msg].srcV
    cookie = rpc.Extensions[PacketInRequest.msg].cookie
    eth = dpkt.ethernet.Ethernet( packet )
    ip6 = eth.data

    self.mapping[ip6.src] = srcV
    dstAddrInt = int((ip6.dst).encode('hex'), 16)
    dstAddr = IPv6Address( dstAddrInt )

    print dstAddr
    for (network, (domainId, vertex)) in self.remote.items():
      if dstAddr not in IPv6Network(network): continue

      print 'remote address'
      dstV = vertex
      self.packetInResponse(srcV, dstV, cookie, ip6.dst)
      return

    dstV = self.mapping.get(ip6.dst)
    if dstV is not None:
      print 'local address'
      self.packetInResponse(srcV, dstV, cookie, ip6.dst)
      return

    print 'unknown destionation'



  def packetInResponse(self, srcV, dstV, cookie, address):
    rpc = RPC()
    rpc.type = RPC.PacketInResponse
    response = rpc.Extensions[PacketInResponse.msg]
    response.srcV = srcV
    response.dstV = dstV
    response.cookie = cookie

    match = match_header( address )
    response.match = str(match)
    self.sendToController( rpc.SerializeToString() )
    



  def handleInitResponse(self, rpc):
    print 'initialization complete...'
    self.domain = rpc.Extensions[InitResponse.msg].domain
    print 'our domain number is', self.domain

    reactor.callLater(0, self.pushData)



  def sendInit(self):
    rpc = RPC()
    rpc.type = RPC.InitRequest
    request = rpc.Extensions[InitRequest.msg]
    request.ism = "BGP"
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
