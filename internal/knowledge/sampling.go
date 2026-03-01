package main

// func Blake2XbSample(key *[KeySize]byte, m []byte, base int, size int) ([]byte, error) {
// 	if base < 2 || base > 256 {
// 		return nil, errors.New("invalid base")
// 	}
// 	if size <= 0 {
// 		return nil, errors.New("invalid size")
// 	}
// 	b256 := big.NewInt(256)
// 	m256 := big.NewInt(KeySize)
// 	bX := big.NewInt(int64(base))
// 	mX := big.NewInt(int64(size))
// 	S := new(big.Int).Exp(b256, m256, nil)
// 	T := new(big.Int).Exp(bX, mX, nil)
// 	R := new(big.Int).Mul(new(big.Int).Div(S, T), T)
// 	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, key[:])
// 	if err != nil {
// 		return nil, err
// 	}
// 	if _, err := xof.Write(m); err != nil {
// 		return nil, err
// 	}
// 	sampleSize := int(math.Ceil(float64(size) * math.Log2(float64(base)) / 8))
// 	sample := make([]byte, sampleSize)
// 	for {
// 		if _, err := xof.Read(sample); err != nil {
// 			return nil, err
// 		}
// 		N := new(big.Int).SetBytes(sample)
// 		if N.Cmp(R) < 0 {
// 			return new(big.Int).Mod(N, T).Bytes(), nil
// 		}
// 	}
// }

// func PasswordExpand(password string)
