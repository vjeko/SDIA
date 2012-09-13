#ifndef OMEGA_H_
#define OMEGA_H_



struct shim_hdr {
  u_int32_t shim_label;   /* 20 bit label, 4 bit exp & BoS, 8 bit TTL */
};


#define PATHLET_SIZE 8
#define NUM_PATHLETS 4
#define STRING_SIZE PATHLET_SIZE * 2
#define MEM_SIZE (STRING_SIZE * PATHLET_SIZE)
#define omega_proc_name "pathlet"

#define MPLS_LABEL_MASK    0xfffff000
#define MPLS_QOS_MASK      0x00000e00
#define MPLS_TTL_MASK      0x000000ff
#define MPLS_LABEL_SHIFT   12
#define MPLS_QOS_SHIFT     9
#define MPLS_TTL_SHIFT     0
#define MPLS_STACK_BOTTOM  0x0100



#endif /* OMEGA_H_ */
