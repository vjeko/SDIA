from ctypes import c_uint16, c_uint32, c_uint64
from socket import ntohs, ntohl, htons, htonl, inet_pton, AF_INET6

def NXM_HEADER__(VENDOR, FIELD, HASMASK, LENGTH):
  return (((VENDOR) << 16) | ((FIELD) << 9) | ((HASMASK) << 8) | (LENGTH))
def NXM_HEADER(VENDOR, FIELD, LENGTH):
  return NXM_HEADER__(VENDOR, FIELD, 0, LENGTH)
def NXM_HEADER_W(VENDOR, FIELD, LENGTH):
    NXM_HEADER__(VENDOR, FIELD, 1, (LENGTH) * 2)
def NXM_VENDOR(HEADER): ((HEADER) >> 16)
def NXM_FIELD(HEADER): (((HEADER) >> 9) & 0x7f)
def NXM_TYPE(HEADER): (((HEADER) >> 9) & 0x7fffff)
def NXM_HASMASK(HEADER): (((HEADER) >> 8) & 1)
def NXM_LENGTH(HEADER): ((HEADER) & 0xff)

def NXM_NX_IPV6_SRC():    return NXM_HEADER  (0x0001, 19, 16)
def NXM_NX_IPV6_SRC_W():  return NXM_HEADER_W(0x0001, 19, 16)
def NXM_NX_IPV6_DST():    return NXM_HEADER  (0x0001, 20, 16)
def NXM_NX_IPV6_DST_W():  return NXM_HEADER_W(0x0001, 20, 16)

def NXM_OF_ETH_TYPE():    return NXM_HEADER  (0x0000,  3, 2)



class NodeType:
  REMOTE_DOMAIN = '-4'
  OPENFLOW      = '-2'



def match_header(address):

  match_eth = bytearray( c_uint32( htonl( NXM_OF_ETH_TYPE() ) ) )
  eth_type  = bytearray( c_uint16( htons( 0x86dd ) ) )
  match_ip6 = bytearray( c_uint32( htonl( NXM_NX_IPV6_DST() ) ) )

  result = match_eth + eth_type + match_ip6 + address
  return result

