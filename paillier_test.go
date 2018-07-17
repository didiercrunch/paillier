package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestComputeL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)

	expected := big.NewInt(6)
	actual := L(u, n)

	if expected.Cmp(actual) != 0 {
		t.Errorf("Unexpected L function result [%v]", actual)
	}
}

func TestComputePhi(t *testing.T) {
	a := big.NewInt(5)
	b := big.NewInt(7)

	expected := big.NewInt(24)
	actual := computePhi(a, b)

	if expected.Cmp(actual) != 0 {
		t.Errorf("Unexpected phi value [%v]", actual)
	}
}

func TestCreatePrivateKey(t *testing.T) {
	p := big.NewInt(463)
	q := big.NewInt(631)

	privateKey := CreatePrivateKey(p, q)

	if privateKey.N.Cmp(big.NewInt(292153)) != 0 {
		t.Errorf("Unexpected N PublicKey value [%v]", privateKey.N)
	}

	if privateKey.Lambda.Cmp(big.NewInt(291060)) != 0 {
		t.Errorf("Unexpected Lambda Public key value [%v]", privateKey.Lambda)
	}
}

func TestEncryptDecryptSmall(t *testing.T) {
	p := big.NewInt(13)
	q := big.NewInt(11)
	for i := 1; i < 10; i++ {
		privateKey := CreatePrivateKey(p, q)

		initialValue := big.NewInt(100)
		cypher, err := privateKey.Encrypt(initialValue, rand.Reader)
		if err != nil {
			t.Error(err)
		}
		returnedValue := privateKey.Decrypt(cypher)
		if initialValue.Cmp(returnedValue) != 0 {
			t.Error("wrong decryption ", returnedValue, " is not ", initialValue)
		}
	}
}

func TestAddCyphers(t *testing.T) {
	privateKey := CreatePrivateKey(big.NewInt(17), big.NewInt(13))

	cypher1, _ := privateKey.Encrypt(big.NewInt(5), rand.Reader)
	cypher2, _ := privateKey.Encrypt(big.NewInt(6), rand.Reader)
	cypher3, _ := privateKey.Encrypt(big.NewInt(7), rand.Reader)
	cypher4, _ := privateKey.Encrypt(big.NewInt(8), rand.Reader)
	cypher5 := privateKey.Add(cypher1, cypher2, cypher3, cypher4)

	m := privateKey.Decrypt(cypher5)
	if m.Cmp(big.NewInt(26)) != 0 {
		t.Errorf("Unexpected decrypted value [%v]", m)
	}
}

func TestAddCypherWithSmallKeyModulus(t *testing.T) {
	privateKey := CreatePrivateKey(big.NewInt(7), big.NewInt(5))

	cypher1, _ := privateKey.Encrypt(big.NewInt(41), rand.Reader)
	cypher2, _ := privateKey.Encrypt(big.NewInt(219), rand.Reader)
	cypher3, _ := privateKey.Encrypt(big.NewInt(54), rand.Reader)
	cypher4 := privateKey.Add(cypher1, cypher2, cypher3)

	m := privateKey.Decrypt(cypher4)
	if m.Cmp(big.NewInt(34)) != 0 {
		t.Errorf("Unexpected decrypted value [%v]", m)
	}
}

func TestMulCypher(t *testing.T) {
	privateKey := CreatePrivateKey(big.NewInt(17), big.NewInt(13))

	cypher, err := privateKey.Encrypt(big.NewInt(3), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cypherMultiple := privateKey.Mul(cypher, big.NewInt(7))
	multiple := privateKey.Decrypt(cypherMultiple)

	// 3 * 7 = 21
	if multiple.Cmp(big.NewInt(21)) != 0 {
		t.Errorf("Unexpected decrypted value [%v]", multiple)
	}
}

func TestMulCypherWithSmallKeyModulus(t *testing.T) {
	privateKey := CreatePrivateKey(big.NewInt(7), big.NewInt(5))

	cypher, err := privateKey.Encrypt(big.NewInt(30), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cypherMultiple := privateKey.Mul(cypher, big.NewInt(93))
	multiple := privateKey.Decrypt(cypherMultiple)

	// (30*93) mod (7*5) = 25
	if multiple.Cmp(big.NewInt(25)) != 0 {
		t.Errorf("Unexpected decrypted value [%v]", multiple)
	}
}
