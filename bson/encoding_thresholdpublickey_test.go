package bson

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/keep-network/paillier"
)

func TestThresholdKeySerialization(t *testing.T) {
	key := &paillier.ThresholdPublicKey{
		PublicKey:                      paillier.PublicKey{b(9)},
		TotalNumberOfDecryptionServers: 7,
		Threshold:                      6,
		V:                              b(3),
		Vi:                             []*big.Int{b(2), b(34)},
	}

	serialized, err := SerializeThresholdPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := DeserializeThresholdPublicKey(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(key, deserialized) {
		t.Errorf(
			"Unexpected serialization result\nActual: %v\nExpected: %v\n",
			deserialized,
			key,
		)
	}
}
