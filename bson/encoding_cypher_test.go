package bson

import (
	"reflect"
	"testing"

	"github.com/keep-network/paillier"
)

func TestCypherBsonSerialization(t *testing.T) {
	cypher := &paillier.Cypher{
		C: b(5),
	}

	serialized, err := SerializeCypher(cypher)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := DeserializeCypher(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(cypher, deserialized) {
		t.Errorf(
			"Unexpected serialization result\nActual: %v\nExpected: %v\n",
			deserialized,
			cypher,
		)
	}
}
