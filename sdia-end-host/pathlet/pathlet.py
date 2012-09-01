from dpkt import *
from socket import *

s = socket(AF_PACKET, SOCK_RAW)
s.bind( ('eth0', 0) )

path = [2,0,3]

upper = ip6.IP6()
upper.dst = str(bytearray(path))

ethSrc = '\x00\xff\x00\x00\x00\x01'
ethDst = '\x00\xff\x00\x00\x00\x00'

e = ethernet.Ethernet(
        src = ethSrc, dst = ethDst,
        type = 34525, data = upper
)

e.data._set_flow(1)

s.send( str(e) )
