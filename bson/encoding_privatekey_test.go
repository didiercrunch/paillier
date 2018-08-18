package bson

import (
	"reflect"
	"testing"

	"github.com/keep-network/paillier"
)

func TestSecretKeyBsonSerialization(t *testing.T) {
	key := &paillier.SecretKey{
		PublicKey: paillier.PublicKey{
			N: (b(345)),
		},
		Lambda: b(5),
	}

	serialized, err := SerializeSecretKey(key)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := DeserializeSecretKey(serialized)
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
