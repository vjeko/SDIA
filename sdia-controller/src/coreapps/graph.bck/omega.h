/*
 * omega.h
 *
 *  Created on: Apr 1, 2012
 *      Author: vjeko
 */

#ifndef OMEGA_H_
#define OMEGA_H_

enum idr_type {
  IDR_BGP = 0,
  IDR_PATHLETS = 1,
  IDR_DONA = 2,
  IDR_OPTICAL = 3
};


struct ip6_opt_omega {
  uint8_t a0;
  uint8_t a1;

  uint8_t a2;
  uint8_t a3;

  uint64_t src;
  uint64_t dst;
}__attribute__ ((__packed__));

struct ip6_opt_omegah {
  uint8_t ip6oj_type;
  uint8_t ip6oj_len;
  struct ip6_opt_omega ip6_opt_omega;
}__attribute__ ((__packed__));

struct ip6_hbh_omega {
  uint8_t ip6h_nxt; // next header.
  uint8_t ip6h_len; // length in units of 8 octets.
  struct ip6_opt_omegah ip6_opt_omegah;
}__attribute__ ((__packed__));

#endif /* OMEGA_H_ */
