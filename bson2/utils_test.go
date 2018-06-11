package bson2

import (
	"math/big"
)

func b(i int) *big.Int {
	return big.NewInt(int64(i))
}
