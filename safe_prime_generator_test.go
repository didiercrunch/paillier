package paillier

import (
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestAsyncGenerator(t *testing.T) {
	concurrencyLevel := 4

	var tests = map[string]struct {
		bitLen        int
		timeout       time.Duration
		expectedError error
	}{
		"primes successfully generated": {
			bitLen:        512,
			timeout:       60 * time.Second,
			expectedError: nil,
		},
		"generator timed out": {
			bitLen:        8192,
			timeout:       1 * time.Second,
			expectedError: errors.New("generator timed out after 1s"),
		},
		"bit length is 5": {
			bitLen:        5,
			timeout:       1 * time.Second,
			expectedError: errors.New("safe prime size must be at least 6 bits"),
		},
		"bit length is 6": {
			bitLen:        6,
			timeout:       60 * time.Second,
			expectedError: nil,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			p, q, err := GenerateSafePrime(
				test.bitLen,
				concurrencyLevel,
				test.timeout,
			)

			if test.expectedError != nil {
				if !reflect.DeepEqual(test.expectedError, err) {
					t.Fatalf(
						"Unexpected error\nActual: %v\nExpected: %v",
						err,
						test.expectedError,
					)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}

				if !p.ProbablyPrime(20) {
					t.Errorf("p is not prime; p = %v", p)
				}

				if !q.ProbablyPrime(20) {
					t.Errorf("q is not prime; q = %v", q)
				}

				// p = 2q + 1 ?
				expectedP := new(big.Int)
				expectedP.Mul(big.NewInt(2), q)
				expectedP.Add(expectedP, big.NewInt(1))

				if expectedP.Cmp(p) != 0 {
					t.Errorf("2q + 1 != p")
				}

				if p.BitLen() != test.bitLen {
					t.Fatalf(
						"Unexpected p bit length\nActual: %v\nExpected: %v",
						p.BitLen(),
						test.bitLen,
					)
				}

				if q.BitLen() != test.bitLen-1 {
					t.Fatalf(
						"Unexpected q bit length\nActual: %v\nExpected: %v",
						q.BitLen(),
						test.bitLen-1,
					)
				}
			}
		})
	}
}
