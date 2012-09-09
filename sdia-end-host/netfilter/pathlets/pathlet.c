
#define MODULE
#define __KERNEL__

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

#define MPLS_LABEL_MASK    0xfffff000
#define MPLS_QOS_MASK      0x00000e00
#define MPLS_TTL_MASK      0x000000ff
#define MPLS_LABEL_SHIFT   12
#define MPLS_QOS_SHIFT     9
#define MPLS_TTL_SHIFT     0
#define MPLS_STACK_BOTTOM  0x0100


struct packet_type otp_proto;

struct ethhdr* eth;
struct ethhdr* eth_new;


struct shim_hdr {
  u_int32_t shim_label;   /* 20 bit label, 4 bit exp & BoS, 8 bit TTL */
};

struct shim_hdr* mpls;

void push_pathlets(struct sk_buff *skb, struct device *dv, struct packet_type *pt) {

  const size_t mpls_size = sizeof(struct shim_hdr);
  if (0 != pskb_expand_head(skb, mpls_size, 0,  GFP_ATOMIC)) {
    printk(KERN_INFO "Unable to expand!\n");
    return;
  }

  eth_new = (struct ethhdr*) skb_push(skb, mpls_size);
  memmove(eth_new, eth, sizeof(struct ethhdr));

  /*
  print_hex_dump(KERN_DEBUG, "PRE0: ", DUMP_PREFIX_ADDRESS, 16, 1,
      eth,
      sizeof(struct shim_hdr),
      false);


  memset(mpls, 0x00, sizeof(struct shim_hdr));

  u_int32_t label = 2;

  mpls->shim_label = (label << MPLS_LABEL_SHIFT);
  mpls->shim_label |= MPLS_STACK_BOTTOM;
  mpls->shim_label = htonl(mpls->shim_label);
*/
}

/* Packet Handler Function */
int otp_func(struct sk_buff *skb, struct device *dv, struct packet_type *pt) {
  eth = (struct ethhdr*) skb_mac_header(skb);
  if (ntohs(eth->h_proto) == 0x86DD) {
    printk("IP6\n");
    eth->h_proto = htons(0x8847);
  }


  return 0;
}


int init_module() {

  otp_proto.type = htons(ETH_P_ALL);

  otp_proto.func = otp_func;
  dev_add_pack(&otp_proto);

  return(0);
}

void cleanup_module() {
  dev_remove_pack(&otp_proto);
    printk("OTP unloaded\n");
}


MODULE_AUTHOR("ICSI");
MODULE_DESCRIPTION("Omega Layer");
MODULE_LICENSE("GPL");

