package main

import (
	"errors"
	"math/big"
)

func SampleToString(sample []byte, charset []rune) ([]rune, error) {
	base := len(charset)
	if base < 2 || base > 256 {
		return nil, errors.New("invalid base")
	}
	n := new(big.Int).SetBytes(sample)
	if n.Sign() == 0 {
		return []rune{charset[0]}, nil
	}
	b := big.NewInt(int64(base))
	r := new(big.Int)
	var s []rune
	for n.Sign() > 0 {
		n.DivMod(n, b, r)
		s = append(s, charset[r.Int64()])
	}
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s, nil
}
