// Package sip implements the SipHash pseudorandom function.
package sip

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// ErrKeyLen is returned when the provided key is not 16 bytes long.
var ErrKeyLen = errors.New("sip: len(key) != 16")

// Sum64 returns the SipHash digest of the data. The key must be 16
// bytes long.
func Sum64(key, data []byte) (uint64, error) {
	if len(key) != 16 {
		return 0, ErrKeyLen
	}

	v := [4]uint64{0x736f6d6570736575, 0x646f72616e646f6d, 0x6c7967656e657261, 0x7465646279746573}
	k := [2]uint64{binary.LittleEndian.Uint64(key[:8]), binary.LittleEndian.Uint64(key[8:])}

	v[0] ^= k[0]
	v[1] ^= k[1]
	v[2] ^= k[0]
	v[3] ^= k[1]

	n := len(data)
	head := n - (n % 8)

	m := [2]uint64{}

	i := 0
	for ; i < head; i += 8 {
		m[0] = binary.LittleEndian.Uint64(data[i:])
		v[3] ^= m[0]

		for range 2 {
			v[0] += v[1]
			v[1] = bits.RotateLeft64(v[1], 13)
			v[1] ^= v[0]
			v[0] = bits.RotateLeft64(v[0], 32)
			v[2] += v[3]
			v[3] = bits.RotateLeft64(v[3], 16)
			v[3] ^= v[2]
			v[0] += v[3]
			v[3] = bits.RotateLeft64(v[3], 21)
			v[3] ^= v[0]
			v[2] += v[1]
			v[1] = bits.RotateLeft64(v[1], 17)
			v[1] ^= v[2]
			v[2] = bits.RotateLeft64(v[2], 32)
		}

		v[0] ^= m[0]
	}

	m[1] = uint64(n) << 56
	switch tail := int(uint(n) & 7); tail {
	case 7:
		m[1] |= uint64(data[i+6]) << 48
		fallthrough
	case 6:
		m[1] |= uint64(data[i+5]) << 40
		fallthrough
	case 5:
		m[1] |= uint64(data[i+4]) << 32
		fallthrough
	case 4:
		m[1] |= uint64(data[i+3]) << 24
		fallthrough
	case 3:
		m[1] |= uint64(data[i+2]) << 16
		fallthrough
	case 2:
		m[1] |= uint64(data[i+1]) << 8
		fallthrough
	case 1:
		m[1] |= uint64(data[i])
	}

	v[3] ^= m[1]

	for range 2 {
		v[0] += v[1]
		v[1] = bits.RotateLeft64(v[1], 13)
		v[1] ^= v[0]
		v[0] = bits.RotateLeft64(v[0], 32)
		v[2] += v[3]
		v[3] = bits.RotateLeft64(v[3], 16)
		v[3] ^= v[2]
		v[0] += v[3]
		v[3] = bits.RotateLeft64(v[3], 21)
		v[3] ^= v[0]
		v[2] += v[1]
		v[1] = bits.RotateLeft64(v[1], 17)
		v[1] ^= v[2]
		v[2] = bits.RotateLeft64(v[2], 32)
	}

	v[0] ^= m[1]

	v[2] ^= 0xff

	for range 4 {
		v[0] += v[1]
		v[1] = bits.RotateLeft64(v[1], 13)
		v[1] ^= v[0]
		v[0] = bits.RotateLeft64(v[0], 32)
		v[2] += v[3]
		v[3] = bits.RotateLeft64(v[3], 16)
		v[3] ^= v[2]
		v[0] += v[3]
		v[3] = bits.RotateLeft64(v[3], 21)
		v[3] ^= v[0]
		v[2] += v[1]
		v[1] = bits.RotateLeft64(v[1], 17)
		v[1] ^= v[2]
		v[2] = bits.RotateLeft64(v[2], 32)
	}

	return v[0] ^ v[1] ^ v[2] ^ v[3], nil
}
