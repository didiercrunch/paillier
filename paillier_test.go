package paillier

import (
	"crypto/rand"
	"errors"
	"math/big"
	"reflect"
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

func TestCheckPlaintextSpace(t *testing.T) {
	p := big.NewInt(13)
	q := big.NewInt(11)

	// N = pq = 143 so the plaintext space is [0, 143)
	privateKey := CreatePrivateKey(p, q)

	var tests = map[string]struct {
		plaintext     *big.Int
		expectedError error
	}{
		"plaintext less than 0": {
			plaintext:     big.NewInt(-1),
			expectedError: errors.New("-1 is out of allowed plaintext space [0, 143)"),
		},
		"plaintext equal 0": {
			plaintext: big.NewInt(0),
		},
		"plaintext equal 1": {
			plaintext: big.NewInt(1),
		},
		"plaintext equal 142": {
			plaintext: big.NewInt(142),
		},
		"plaintext equal 143": {
			plaintext:     big.NewInt(143),
			expectedError: errors.New("143 is out of allowed plaintext space [0, 143)"),
		},
		"plaintext equal 144": {
			plaintext:     big.NewInt(144),
			expectedError: errors.New("144 is out of allowed plaintext space [0, 143)"),
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			cypher, err := privateKey.Encrypt(test.plaintext, rand.Reader)
			if !reflect.DeepEqual(err, test.expectedError) {
				t.Errorf(
					"Unexpected error\nExpected: %v\nActual: %v",
					test.expectedError,
					err,
				)
			}

			if test.expectedError == nil {
				decrypted := privateKey.Decrypt(cypher)
				if test.plaintext.Cmp(decrypted) != 0 {
					t.Errorf(
						"Unexpected decryption\nExpected: %v\nActual: %v",
						test.plaintext,
						decrypted,
					)
				}
			}
		})
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
