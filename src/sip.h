#ifndef SIP_H
#define SIP_H

#include <stddef.h>
#include <stdint.h>

#if __STDC_VERSION__ < 202311L
  #error "this is a C23 program"
#endif

// Unsigned 128-bit integer.
typedef unsigned _BitInt(128) uint128_t;

// Returns the SipHash tag of the data.
[[gnu::pure]]
uint64_t sip_hash(uint128_t key, const void *data, size_t data_len);

#endif // SIP_H
