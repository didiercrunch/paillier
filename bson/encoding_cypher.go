// Package bson provides functions for serialization and deserialization between
// paillier objects and BSON
package bson

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/keep-network/paillier"
	"gopkg.in/mgo.v2/bson"
)

type Cypher paillier.Cypher

// Serializes Cypher to BSON
func SerializeCypher(cypher *paillier.Cypher) ([]byte, error) {
	return bson.Marshal(toSerializableCypher(cypher))
}

// Deserializes BSON to Cypher
func DeserializeCypher(data []byte) (*paillier.Cypher, error) {
	serializable := new(Cypher)
	if err := bson.Unmarshal(data, serializable); err != nil {
		return nil, err
	}

	return toOriginalCypher(serializable), nil
}

// Changes original Cypher to serializable Cypher
func toSerializableCypher(cypher *paillier.Cypher) *Cypher {
	serializable := Cypher(*cypher)
	return &serializable
}

// Changes serializable Cypher to original Cypher
func toOriginalCypher(serializable *Cypher) *paillier.Cypher {
	original := paillier.Cypher(*serializable)
	return &original
}

type dbCypher struct {
	C string
}

func (cypher *Cypher) GetBSON() (interface{}, error) {
	return &dbCypher{fmt.Sprintf("%x", cypher.C)}, nil
}

func (cypher *Cypher) SetBSON(raw bson.Raw) error {
	c := dbCypher{}
	if err := raw.Unmarshal(&c); err != nil {
		return err
	}
	var ok bool
	cypher.C, ok = new(big.Int).SetString(c.C, 16)
	if !ok {
		return errors.New("big int not in hexadecimal format")
	}
	return nil
}
