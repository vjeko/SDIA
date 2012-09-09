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
#include <asm/uaccess.h>    /* For copy_from_user  */


struct shim_hdr {
  u_int32_t shim_label;   /* 20 bit label, 4 bit exp & BoS, 8 bit TTL */
};

struct nf_hook_ops nfho;
struct sk_buff *sock_buff;
struct shim_hdr* mpls;

static struct proc_dir_entry *omega_proc;
static u_int32_t path = 0;
unsigned char userData[8];

#define omega_proc_name "pathlet"
#define PATHLET_SIZE 4

#define MPLS_LABEL_MASK    0xfffff000
#define MPLS_QOS_MASK      0x00000e00
#define MPLS_TTL_MASK      0x000000ff
#define MPLS_LABEL_SHIFT   12
#define MPLS_QOS_SHIFT     9
#define MPLS_TTL_SHIFT     0
#define MPLS_STACK_BOTTOM  0x0100




void set_mpls(const void *buf, u_int32_t label, u_int32_t bottom_stack) {
  mpls->shim_label = (label << MPLS_LABEL_SHIFT);
  mpls->shim_label |= bottom_stack;
  mpls->shim_label = htonl(mpls->shim_label);
}



unsigned int push_mpls(struct sk_buff* skb, u_int32_t label, u_int32_t bottom_stack) {
  const size_t mpls_size = sizeof(struct shim_hdr);
  if (0 != pskb_expand_head(skb, mpls_size, 0,  GFP_ATOMIC)) {
    return NF_DROP;
  }

  mpls = (struct shim_hdr*) skb_push(skb, mpls_size);
  memset(mpls, 0x00, sizeof(struct shim_hdr));

  set_mpls(mpls, label, bottom_stack);

  return NF_ACCEPT;
}



unsigned int pathlet_post_routing(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn) (struct sk_buff *) ) {

  printk(KERN_INFO "Path entire: %x\n", path);

  const char* hops = (const char*) &path;

  sock_buff = skb;
  if (!sock_buff) return NF_ACCEPT;

  //push_mpls(sock_buff, 2, MPLS_STACK_BOTTOM);

  printk(KERN_INFO "Path: %x\n", hops[PATHLET_SIZE - 1]);
  push_mpls(sock_buff, hops[PATHLET_SIZE - 1], MPLS_STACK_BOTTOM);


  for(int i = PATHLET_SIZE - 2; i >= 0; i--) {
    u_int32_t label = hops[i];
    push_mpls(sock_buff, label, 0);
    printk(KERN_INFO "Path: %x\n", label);
  }


  skb_reset_transport_header(skb);
  skb_reset_network_header(skb);
  skb_reset_mac_header(skb);

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
  memcpy(page, &path, sizeof(int));
  len = sizeof(int);

  return len;
}



int skb_write(struct file *file, const char *buffer, unsigned long len,
    void *data) {

  if (len > PAGE_SIZE || len < 0) {
    return -ENOSPC;
  }

  if (copy_from_user(userData, buffer, PATHLET_SIZE * 2)) {
    return -EFAULT;
  }

  path = simple_strtol(userData, NULL, 16);

  return len;
}


int init_module() {
  // Netfilter hook information, specify where and when we get the SKB
  nfho.hook = pathlet_post_routing;
  nfho.hooknum = NF_INET_POST_ROUTING;
  nfho.pf = PF_INET6;
  nfho.priority = NF_IP_PRI_LAST;
  nf_register_hook(&nfho);

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

  if ( omega_proc )
      remove_proc_entry(omega_proc_name, NULL);

  printk(KERN_INFO "Unregistered the Omega module.\n");
}



MODULE_AUTHOR("ICSI");
MODULE_DESCRIPTION("Omega Layer");
MODULE_LICENSE("GPL");
