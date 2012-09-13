#include <linux/module.h>
#include <linux/version.h>

#include <linux/byteorder/generic.h>
#include <linux/netdevice.h>
#include <net/protocol.h>
#include <net/pkt_sched.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <asm/uaccess.h>


struct packet_type otp_proto;

/* Packet Handler Function */
int otp_func(struct sk_buff *skb, struct device *dv, struct packet_type *pt) {

  int result = strnicmp(skb->dev->name, "eth", 3);

  if (result) {
    return 0;
  }

  struct ethhdr* eth = (struct ethhdr*) skb_mac_header(skb);
  if ( (skb->pkt_type == PACKET_OUTGOING) && (ntohs(eth->h_proto) == 0x86DD) ) {
    eth->h_proto = htons(0x8847);
  }

  return 0;
}


int init_module() {

  otp_proto.type = htons(ETH_P_ALL);

  otp_proto.func = otp_func;
  dev_add_pack(&otp_proto);

  return 0;
}

void cleanup_module() {
  dev_remove_pack(&otp_proto);
    printk("Pathlet unloaded\n");
}


MODULE_AUTHOR("ICSI");
MODULE_DESCRIPTION("Pathlet Layer");
MODULE_LICENSE("GPL");

