package bson

import (
	"reflect"
	"testing"

	"github.com/keep-network/paillier"
)

func TestPrivateKeyBsonSerialization(t *testing.T) {
	key := &paillier.PrivateKey{
		PublicKey: paillier.PublicKey{
			N: (b(345)),
		},
		Lambda: b(5),
	}

	serialized, err := SerializePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := DeserializePrivateKey(serialized)
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
