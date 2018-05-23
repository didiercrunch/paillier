package paillier

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"
)

func TestLCM(t *testing.T) {
	a := big.NewInt(1350)
	b := big.NewInt(141075)
	expected := big.NewInt(282150)

	if !reflect.DeepEqual(expected, LCM(a, b)) {
		t.Fail()
	}
}

func TestL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)
	exp := big.NewInt(6)
	if !reflect.DeepEqual(exp, L(u, n)) {
		t.Error("L function is not good")
	}
}

func TestComputeMu(t *testing.T) {
	p := big.NewInt(13)
	q := big.NewInt(11)

	lambda := computeLamda(p, q)
	g := big.NewInt(5000)
	n := new(big.Int).Mul(p, q)

	exp := big.NewInt(3)
	if !reflect.DeepEqual(computeMu(g, lambda, n), exp) {
		t.Error("mu is not well computed")
	}
}

func TestEncryptDecryptSmall(t *testing.T) {
	p := big.NewInt(13)
	q := big.NewInt(11)
	for i := 1; i < 10; i++ {
		privateKey := CreatePrivateKey(p, q)

		inicialValue := big.NewInt(100)
		cypher, err := privateKey.Encrypt(inicialValue, rand.Reader)
		if err != nil {
			t.Error(err)
		}
		returnedValue := privateKey.Decrypt(cypher)
		if !reflect.DeepEqual(inicialValue, returnedValue) {
			t.Error("wrond decryption ", returnedValue, " is not ", inicialValue)
		}
	}

}

func TestAddCypher(t *testing.T) {
	privateKey := CreatePrivateKey(big.NewInt(13), big.NewInt(11))
	cypher1, _ := privateKey.Encrypt(big.NewInt(12), rand.Reader)
	cypher2, _ := privateKey.Encrypt(big.NewInt(13), rand.Reader)
	cypher3 := privateKey.Add(cypher1, cypher2)
	m := privateKey.Decrypt(cypher3)
	if !reflect.DeepEqual(m, big.NewInt(25)) {
		t.Error(m)
	}
}
