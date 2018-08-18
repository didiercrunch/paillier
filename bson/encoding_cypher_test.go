package bson

import (
	"reflect"
	"testing"

	"github.com/keep-network/paillier"
)

func TestCypherBsonSerialization(t *testing.T) {
	ct := &paillier.Ciphertext{
		C: b(5),
	}

	serialized, err := SerializeCypher(ct)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := DeserializeCypher(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ct, deserialized) {
		t.Errorf(
			"Unexpected serialization result\nActual: %v\nExpected: %v\n",
			deserialized,
			ct,
		)
	}
}
