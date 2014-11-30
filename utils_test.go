package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func b(i int) *big.Int {
	return big.NewInt(int64(i))
}

func n(i *big.Int) int {
	return int(i.Int64())
}

func areRelativelyPrime(a, b int) bool {
	if b == 0 {
		return a == 1
	}
	return areRelativelyPrime(b, a%b)
}

func TestConstants(t *testing.T) {
	if n(ZERO) != 0 {
		t.Fail()
	}

	if n(ONE) != 1 {
		t.Fail()
	}

	if n(TWO) != 2 {
		t.Fail()
	}

	if n(FOUR) != 4 {
		t.Fail()
	}
}

func TestGetRandomNumberInMultiplicativeGroup(t *testing.T) {
	k := b(2 * 3 * 5 * 7)
	for i := 0; i < 100; i++ {
		m, err := GetRandomNumberInMultiplicativeGroup(k, rand.Reader)
		if err != nil {
			t.Error(err)
			return
		}
		if !areRelativelyPrime(n(k), n(m)) {
			t.Fail()
		}
	}

}
