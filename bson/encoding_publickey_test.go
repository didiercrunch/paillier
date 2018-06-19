package bson

import (
	"reflect"
	"testing"

	"github.com/keep-network/paillier"
)

func TestSetPublicKeyBson(t *testing.T) {
	key := &paillier.PublicKey{
		N: (b(345)),
	}

	serialized, err := SerializePublicKey(key)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := DeserializePublicKey(serialized)
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
