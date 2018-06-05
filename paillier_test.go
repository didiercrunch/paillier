package paillier

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"
)

func TestComputeL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)

	expected := big.NewInt(6)
	actual := L(u, n)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Unexpected L function result [%v]", actual)
	}
}

func TestComputePhi(t *testing.T) {
	a := big.NewInt(5)
	b := big.NewInt(7)

	expected := big.NewInt(24)
	actual := computePhi(a, b)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Unexpected phi value [%v]", actual)
	}
}

func TestCreatePrivateKey(t *testing.T) {
	p := big.NewInt(463)
	q := big.NewInt(631)

	privateKey := CreatePrivateKey(p, q)

	if !reflect.DeepEqual(privateKey.N, big.NewInt(292153)) {
		t.Errorf("Unexpected N PublicKey value [%v]", privateKey.N)
	}

	if !reflect.DeepEqual(privateKey.Lambda, big.NewInt(291060)) {
		t.Errorf("Unexpected Lambda Public key value [%v]", privateKey.Lambda)
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
			t.Error("wrong decryption ", returnedValue, " is not ", inicialValue)
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
