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

	var (
		v = [4]uint64{
			0x736f6d6570736575,
			0x646f72616e646f6d,
			0x6c7967656e657261,
			0x7465646279746573,
		}
		k = [2]uint64{
			binary.LittleEndian.Uint64(key[:8]),
			binary.LittleEndian.Uint64(key[8:]),
		}
	)

	v[0] ^= k[0]
	v[1] ^= k[1]
	v[2] ^= k[0]
	v[3] ^= k[1]

	var (
		n    = len(data)
		tail = int(uint(n) & 7)
		head = n - tail
	)

	m := [2]uint64{}

	i := 0
	for ; i < head; i += 8 {
		m[0] = binary.LittleEndian.Uint64(data[i:])
		v[3] ^= m[0]

		for range 2 {
			v[0] += v[1]
			v[2] += v[3]
			v[1] = bits.RotateLeft64(v[1], 13)
			v[3] = bits.RotateLeft64(v[3], 16)
			v[1] ^= v[0]
			v[3] ^= v[2]
			v[0] = bits.RotateLeft64(v[0], 32)
			v[2] += v[1]
			v[0] += v[3]
			v[1] = bits.RotateLeft64(v[1], 17)
			v[3] = bits.RotateLeft64(v[3], 21)
			v[1] ^= v[2]
			v[3] ^= v[0]
			v[2] = bits.RotateLeft64(v[2], 32)
		}

		v[0] ^= m[0]
	}

	m[1] = uint64(n) << 56
	if tail != 0 {
		buf := [8]byte{}
		copy(buf[:], data[i:])
		m[1] |= binary.LittleEndian.Uint64(buf[:])
	}

	v[3] ^= m[1]

	for range 2 {
		v[0] += v[1]
		v[2] += v[3]
		v[1] = bits.RotateLeft64(v[1], 13)
		v[3] = bits.RotateLeft64(v[3], 16)
		v[1] ^= v[0]
		v[3] ^= v[2]
		v[0] = bits.RotateLeft64(v[0], 32)
		v[2] += v[1]
		v[0] += v[3]
		v[1] = bits.RotateLeft64(v[1], 17)
		v[3] = bits.RotateLeft64(v[3], 21)
		v[1] ^= v[2]
		v[3] ^= v[0]
		v[2] = bits.RotateLeft64(v[2], 32)
	}

	v[0] ^= m[1]

	v[2] ^= 0xff

	for range 4 {
		v[0] += v[1]
		v[2] += v[3]
		v[1] = bits.RotateLeft64(v[1], 13)
		v[3] = bits.RotateLeft64(v[3], 16)
		v[1] ^= v[0]
		v[3] ^= v[2]
		v[0] = bits.RotateLeft64(v[0], 32)
		v[2] += v[1]
		v[0] += v[3]
		v[1] = bits.RotateLeft64(v[1], 17)
		v[3] = bits.RotateLeft64(v[3], 21)
		v[1] ^= v[2]
		v[3] ^= v[0]
		v[2] = bits.RotateLeft64(v[2], 32)
	}

	return v[0] ^ v[1] ^ v[2] ^ v[3], nil
}
