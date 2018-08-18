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

func TestCreateSecretKey(t *testing.T) {
	p := big.NewInt(463)
	q := big.NewInt(631)

	sk := CreateSecretKey(p, q)

	if sk.N.Cmp(big.NewInt(292153)) != 0 {
		t.Errorf("Unexpected N PublicKey value [%v]", sk.N)
	}

	if sk.Lambda.Cmp(big.NewInt(291060)) != 0 {
		t.Errorf("Unexpected Lambda Public key value [%v]", sk.Lambda)
	}
}

func TestEncryptDecryptSmall(t *testing.T) {
	for i := 1; i < 100; i++ {

		p, q := GenKeyPrimes(10)
		sk := CreateSecretKey(p, q)

		initialValue := big.NewInt(100)
		ct, err := sk.Encrypt(initialValue, rand.Reader)
		if err != nil {
			t.Error(err)
		}
		returnedValue := sk.Decrypt(ct)
		if initialValue.Cmp(returnedValue) != 0 {
			t.Error("wrong decryption ", returnedValue, " is not ", initialValue)
		}
	}
}

func TestCheckPlaintextSpace(t *testing.T) {
	p := big.NewInt(13)
	q := big.NewInt(11)

	// N = pq = 143 so the plaintext space is [0, 143)
	sk := CreateSecretKey(p, q)

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
			ct, err := sk.Encrypt(test.plaintext, rand.Reader)
			if !reflect.DeepEqual(err, test.expectedError) {
				t.Errorf(
					"Unexpected error\nExpected: %v\nActual: %v",
					test.expectedError,
					err,
				)
			}

			if test.expectedError == nil {
				decrypted := sk.Decrypt(ct)
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
	p, q := GenKeyPrimes(10)
	sk := CreateSecretKey(p, q)

	ct1, _ := sk.Encrypt(big.NewInt(5), rand.Reader)
	ct2, _ := sk.Encrypt(big.NewInt(6), rand.Reader)
	ct3, _ := sk.Encrypt(big.NewInt(7), rand.Reader)
	ct4, _ := sk.Encrypt(big.NewInt(8), rand.Reader)
	ct5 := sk.Add(ct1, ct2, ct3, ct4)

	m := sk.Decrypt(ct5)
	if m.Cmp(big.NewInt(26)) != 0 {
		t.Errorf("Unexpected decrypted value [%v]", m)
	}
}

func TestAddCypherWithSmallKeyModulus(t *testing.T) {
	sk := CreateSecretKey(big.NewInt(7), big.NewInt(5))

	ct1, _ := sk.Encrypt(big.NewInt(30), rand.Reader)
	ct2, _ := sk.Encrypt(big.NewInt(25), rand.Reader)
	ct3, _ := sk.Encrypt(big.NewInt(11), rand.Reader)
	ct4 := sk.Add(ct1, ct2, ct3)

	m := sk.Decrypt(ct4)
	if m.Cmp(big.NewInt(31)) != 0 {
		t.Errorf("Unexpected decrypted value [%v]", m)
	}
}

func TestMulCypher(t *testing.T) {
	p, q := GenKeyPrimes(10)
	sk := CreateSecretKey(p, q)

	ct, err := sk.Encrypt(big.NewInt(3), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ctMultiple := sk.Mul(ct, big.NewInt(7))
	multiple := sk.Decrypt(ctMultiple)

	// 3 * 7 = 21
	if multiple.Cmp(big.NewInt(21)) != 0 {
		t.Errorf("Unexpected decrypted value [%v]", multiple)
	}
}

func TestMulCypherWithSmallKeyModulus(t *testing.T) {
	sk := CreateSecretKey(big.NewInt(7), big.NewInt(5))

	ct, err := sk.Encrypt(big.NewInt(30), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ctMultiple := sk.Mul(ct, big.NewInt(93))
	multiple := sk.Decrypt(ctMultiple)

	// (30*93) mod (7*5) = 25
	if multiple.Cmp(big.NewInt(25)) != 0 {
		t.Errorf("Unexpected decrypted value [%v]", multiple)
	}
}

func GenKeyPrimes(bits int) (p, q *big.Int) {
	var err error
	for {
		p, err = rand.Prime(rand.Reader, bits)
		if err != nil {
			continue
		}
		q, err = rand.Prime(rand.Reader, bits)
		if err != nil {
			continue
		}

		break
	}

	return p, q
}
