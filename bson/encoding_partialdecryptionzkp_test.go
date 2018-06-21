package bson

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/keep-network/paillier"
)

var pdzkp = &paillier.PartialDecryptionZKP{
	PartialDecryption: paillier.PartialDecryption{
		Id:         1,
		Decryption: b(171),
	},
	Key: &paillier.ThresholdPublicKey{
		PublicKey: paillier.PublicKey{
			N: (b(345)),
		},
		TotalNumberOfDecryptionServers: 7,
		Threshold:                      98,
		V:                              b(101),
		Vi:                             []*big.Int{b(77), b(67)},
	},
	E: b(112),
	Z: b(88),
	C: b(99),
}

func TestPdzkpBsonSerialization(t *testing.T) {
	serialized, err := SerializePartialDecryptionZKP(pdzkp)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := DeserializePartialDecryptionZKP(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(pdzkp, deserialized) {
		t.Errorf(
			"Unexpected serialization result\nActual: %v\nExpected: %v\n",
			deserialized,
			pdzkp,
		)
	}
}

func TestPdzkpJsonSerialization(t *testing.T) {
	serialized, err := JsonSerializePartialDecryptionZKP(pdzkp)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := JsonDeserializePartialDecryptionZKP(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(pdzkp, deserialized) {
		t.Errorf(
			"Unexpected serialization result\nActual: %v\nExpected: %v\n",
			deserialized,
			pdzkp,
		)
	}
}
