#pragma once

#include <stddef.h>
#include <stdint.h>

// Returns the SipHash tag of the data.
[[gnu::leaf, gnu::pure]]
uint64_t sip_hash(__uint128_t key, const void* data, size_t data_len);
