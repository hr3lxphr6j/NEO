package main

import (
	"crypto/cipher"
)

type XorStream struct {
	idx uint
	key []byte
}

func NewXorStream(key []byte) cipher.Stream {
	return &XorStream{key: key}
}

func (s *XorStream) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if len(dst) < len(src) {
		panic("xor: len(dst) < len(src)")
	}
	for i, v := range src {
		dst[i] = v ^ s.key[s.idx%uint(len(s.key))]
	}
}
