#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/socket.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/in6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/proc_fs.h>    /* Necessary because we use the proc fs */
#include <asm/uaccess.h>	  /* For copy_from_user  */


#include <boost/utility/binary.hpp>
#include "omega.h"

/* The Option Type Field, the first byte of the Options fields,
 * contains information about how this option must be treated
 * in case the processing node does not recognize the option.
 * - 00: Skip and continue processing.
 * - 01: Discard the packet.
 * - 10: Discard the packet and send ICMP Parameter Problem,
 *       Code 2 message to the packet's Source address pointing to
 *       the unrecognized
 *       option type.
 * - 11: Discard the packet and send ICMP Parameter Problem,
 *       Code 2 message to the packet's Source address only if the
 *       destination is not a multicast address.
 *
 *
 * The third bit of the Options Type field specifies whether the option
 * information can change en route (value 1) or does not change en route
 * (value 0).
 * */

struct nf_hook_ops nfho;      //net filter hook option struct
struct nf_hook_ops nfho_pre;      //net filter hook option struct
struct nf_hook_ops nfho_local_in;
struct nf_hook_ops nfho_forward;

struct sk_buff *sock_buff;
struct ipv6hdr *ip6_header;      // IP header struct
struct ipv6hdr *ip6_header_new;      // IP header struct
struct icmp6hdr *icmp6_header;  // ICMP Header
struct ip6_hbh_omega *oh;
struct tcphdr * tcp_header;
struct ethhdr* eh;

#define omega_proc_name "omega"
static struct proc_dir_entry *omega_proc;
static int idr_value = 0;


unsigned int hook_pre_routing(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn) (struct sk_buff *) ) {

  sock_buff = skb;
  if (!sock_buff)
    return NF_ACCEPT;

  ip6_header = (struct ipv6hdr*) skb_network_header(sock_buff);
  if (!ip6_header)
    return NF_ACCEPT;


  if (ip6_header->nexthdr == IPPROTO_HOPOPTS) {

#ifdef OMEGA_DUMP_HEX
    print_hex_dump(KERN_DEBUG, "PRE0: ", DUMP_PREFIX_ADDRESS, 16, 1,
        skb_network_header(sock_buff),
        sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr),
        false);
#endif

    oh = skb_header_pointer(skb,
        sizeof(struct ipv6hdr),
        sizeof(struct ip6_hbh_omega),
        NULL);

    printk(KERN_INFO "A1:  %x\n", oh->ip6_opt_omegah.ip6_opt_omega.a0);
    printk(KERN_INFO "SRC: %016llX\n", oh->ip6_opt_omegah.ip6_opt_omega.src);


  }


  return NF_ACCEPT;

}

unsigned int hook_post_routing(
		unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn) (struct sk_buff *) ) {

  printk(KERN_INFO "\tPOST_ROUTING HOOK\n");

	sock_buff = skb;
  if (!sock_buff)
    return NF_ACCEPT;

  ip6_header = (struct ipv6hdr*) skb_network_header(sock_buff);
  if (!ip6_header)
    return NF_ACCEPT;

  printk(KERN_INFO "Next Header: %u\n", ip6_header->nexthdr);
	if (ip6_header->nexthdr == IPPROTO_ICMPV6) {

    icmp6_header = (struct icmp6hdr *)
        (skb_transport_header(sock_buff) + sizeof(struct ipv6hdr));

    if (icmp6_header->icmp6_type == 0x136) return NF_ACCEPT;
    if (icmp6_header->icmp6_type == 0x135) return NF_ACCEPT;

#ifdef OMEGA_DUMP_HEX
    print_hex_dump(KERN_DEBUG, "POST0: ", DUMP_PREFIX_ADDRESS, 16, 1,
        skb_network_header(sock_buff),
        sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr),
        false);
#endif

    if (!icmp6_header)
      return NF_DROP;

    const size_t oh_size = sizeof(struct ip6_hbh_omega);

    if (0 != pskb_expand_head(skb, oh_size, 0,  GFP_ATOMIC)) {
      printk(KERN_INFO "Unable to expand!\n");
      return NF_DROP;
    }

    printk(KERN_INFO "Expanding ICMPv6 Header.\n");
    ip6_header_new = (struct ipv6hdr*) skb_push(skb, oh_size);
    memmove(ip6_header_new, ip6_header, sizeof(struct ipv6hdr));

    uint8_t old_nexthdr = ip6_header_new->nexthdr;
    oh = skb_header_pointer(skb,
        sizeof(struct ipv6hdr),
        sizeof(struct ip6_hbh_omega),
        NULL);

    memset(oh, 0x00, sizeof(struct ip6_hbh_omega));
    ip6_header_new->nexthdr = 0;
    ip6_header_new->payload_len = htons(ntohs(
        ip6_header_new->payload_len) + sizeof(struct ip6_hbh_omega));

    ip6_header_new->flow_lbl[2] = idr_value;

    oh->ip6h_nxt = old_nexthdr;
    oh->ip6h_len = sizeof(struct ip6_hbh_omega)/8 - 1;

    oh->ip6_opt_omegah.ip6oj_type = BOOST_BINARY(00 0 00001);
    oh->ip6_opt_omegah.ip6oj_len = sizeof(struct ip6_opt_omega);
    oh->ip6_opt_omegah.ip6_opt_omega.a0 = 0xff;
    oh->ip6_opt_omegah.ip6_opt_omega.src = 0x00ff00ff00ff00ff;

#ifdef OMEGA_DUMP_HEX
    print_hex_dump(KERN_DEBUG, "POST1: ", DUMP_PREFIX_ADDRESS, 16, 1,
        ip6_header_new,
        sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr),
        false);
#endif

    skb_reset_transport_header(skb);
    skb_reset_network_header(skb);
    skb_reset_mac_header(skb);

	} else if (ip6_header->nexthdr == 6) {

    tcp_header = (struct tcphdr *)
        (skb_transport_header(sock_buff) + sizeof(struct ipv6hdr));

    if (!tcp_header)
      return NF_DROP;

    const size_t oh_size = sizeof(struct ip6_hbh_omega);

    if (0 != pskb_expand_head(skb, oh_size, 0,  GFP_ATOMIC)) {
      printk(KERN_DEBUG "Unable to expand!\n");
      return NF_DROP;
    }

    printk(KERN_DEBUG "Expanding TCP Header.\n");
    ip6_header_new = (struct ipv6hdr*) skb_push(skb, oh_size);
    memmove(ip6_header_new, ip6_header, sizeof(struct ipv6hdr))
    ;
    uint8_t old_nexthdr = ip6_header_new->nexthdr;
    oh = skb_header_pointer(skb,
        sizeof(struct ipv6hdr),
        sizeof(struct ip6_hbh_omega),
        NULL);

    memset(oh, 0x00, sizeof(struct ip6_hbh_omega));
    ip6_header_new->nexthdr = 0;
    ip6_header_new->payload_len = htons(ntohs(
        ip6_header_new->payload_len) + sizeof(struct ip6_hbh_omega));

    oh->ip6h_nxt = old_nexthdr;
    oh->ip6h_len = sizeof(struct ip6_hbh_omega)/8 - 1;

    //oh->ip6_opt_omegah.ip6oj_type = BOOST_BINARY(11 0 00000);
    oh->ip6_opt_omegah.ip6oj_type = BOOST_BINARY(00 0 00001);
    oh->ip6_opt_omegah.ip6oj_len = sizeof(struct ip6_opt_omega);;
    oh->ip6_opt_omegah.ip6_opt_omega.a0 = 0xff;
    oh->ip6_opt_omegah.ip6_opt_omega.src = 0x00ff00ff00ff00ff;

#ifdef OMEGA_DUMP_HEX
    print_hex_dump(KERN_DEBUG, "POST1: ", DUMP_PREFIX_ADDRESS, 16, 1,
        ip6_header_new,
        sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr),
        false);
#endif

    skb_reset_transport_header(skb);
    skb_reset_network_header(skb);
    skb_reset_mac_header(skb);
  }

  return NF_ACCEPT;
}


int skb_read(char *page, char **start, off_t off,
    int count, int *eof,void *data) {

  int len;

  if (off > 0) {
    *eof = 1;
    return 0;
  }

  if (count < sizeof(int)) {
    *eof = 1;
    return -ENOSPC;
  }

  /* cpy to userspace */
  memcpy(page, &idr_value, sizeof(int));
  len = sizeof(int);

  return len;
}

int skb_write(struct file *file, const char *buffer, unsigned long len,
    void *data) {

  unsigned char userData;

  if (len > PAGE_SIZE || len < 0) {
    return -ENOSPC;
  }

  if (copy_from_user(&userData, buffer, 1)) {
    return -EFAULT;
  }

  idr_value = simple_strtol(&userData, NULL, 10);

  return len;
}


int init_module() {
  // Netfilter hook information, specify where and when we get the SKB
  nfho.hook = hook_post_routing;
  nfho.hooknum = NF_INET_POST_ROUTING;
  nfho.pf = PF_INET6;
  nfho.priority = NF_IP_PRI_LAST;
  nf_register_hook(&nfho);


  nfho_pre.hook = hook_pre_routing;
  nfho_pre.hooknum = NF_INET_PRE_ROUTING;
  nfho_pre.pf = PF_INET6;
  nfho_pre.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&nfho_pre);


  struct proc_dir_entry proc_root;
  int ret = 0;

  omega_proc = create_proc_entry( omega_proc_name, 0644, NULL);

  // If we cannot create the proc entry
  if(omega_proc == NULL){
      ret = -ENOMEM;
      if( omega_proc )
          remove_proc_entry( omega_proc_name, &proc_root);

      printk(KERN_INFO "SKB Filter: Could not allocate memory.\n");
      goto error;

  } else {
    omega_proc->read_proc = skb_read;
    omega_proc->write_proc = skb_write;
  }

  printk(KERN_INFO "Registering Omega module.\n");

error:
  return ret;
}



void cleanup_module() {
	nf_unregister_hook(&nfho);
	nf_unregister_hook(&nfho_pre);

  if ( omega_proc )
      remove_proc_entry(omega_proc_name, NULL);

  //nf_unregister_hook(&nfho_forward);
  //nf_unregister_hook(&nfho_local_in);

	printk(KERN_INFO "Unregistered the Omega module.\n");
}



MODULE_AUTHOR("ICSI");
MODULE_DESCRIPTION("Omega Layer");
MODULE_LICENSE("GPL");
