#!/usr/bin/python

from twisted.internet import reactor, threads, defer
from twisted.protocols.basic import Int32StringReceiver

from ipaddr import IPv6Network, IPv6Address
from ctypes import c_uint16, c_uint32, c_uint64

from interface_pb2 import *
from openflow import *
from bgp import *

import pydot
import pygraphviz
import dpkt
import networkx
import pickle



conf = None


class MessageType:
  PUB = 0xaa
  SUB = 0xbb



class ICN( BGP ):

  def __init__(self, conf):
    BGP.__init__(self, conf)
 

  def pushData(self):
    BGP.pushData(self)


  def handleDataReceive(self, rpc):
    BGP.handleDataReceive(self, rpc)


  def handlePacketIn(self, rpc):
    BGP.handlePacketIn(self, rpc)


  def connectionMade(self):
    self.sendInit()


  def handleInitResponse(self, rpc):
    BGP.handleInitResponse(self, rpc)


  def handleTopology(self, rpc):
    BGP.handleTopology(self, rpc)
