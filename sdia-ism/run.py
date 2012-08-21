#!/usr/bin/python

from twisted.internet import reactor, threads, defer
from twisted.internet.protocol import ClientFactory
from twisted.internet.defer import inlineCallbacks, returnValue, DeferredLock
from twisted.internet.task import deferLater
from twisted.protocols.basic import LineReceiver, Int32StringReceiver

import sys
import socket
import bgp


class ISMFactory(ClientFactory):
  protocol = bgp.BGP

  def clientConnectionFailed(self, connector, reason):
    print 'connection failed:', reason.getErrorMessage()
    reactor.stop()

  def clientConnectionLost(self, connector, reason):
    print 'connection lost:', reason.getErrorMessage()
    reactor.stop()


def main():

  bgp.conf = str(sys.argv[1])
  addr = str(sys.argv[2])
  port = int(sys.argv[3])

  factory = ISMFactory()
  reactor.connectTCP(addr, port, factory)
  reactor.run()


if __name__ == '__main__':
  main()
