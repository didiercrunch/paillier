package paillier

import (
	"crypto/rand"
	"errors"
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
				rand.Reader,
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

				IsSafePrime(p, q, test.bitLen, t)
			}
		})
	}
}
