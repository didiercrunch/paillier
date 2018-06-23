package bson

import (
	"errors"
	"fmt"
	"math/big"
)

func fromHex(hex string) (*big.Int, error) {
	n, err := new(big.Int).SetString(hex, 16)
	if !err {
		msg := fmt.Sprintf("Cannot convert %s to int as hexadecimal", hex)
		return nil, errors.New(msg)
	}
	return n, nil
}

func all(oks []bool) bool {
	for _, ok := range oks {
		if !ok {
			return false
		}
	}
	return true
}

func b(i int) *big.Int {
	return big.NewInt(int64(i))
}
