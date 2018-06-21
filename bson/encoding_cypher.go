package bson

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/keep-network/paillier"
	"gopkg.in/mgo.v2/bson"
)

type SerializableCypher paillier.Cypher

// Serializes Cypher to BSON
func SerializeCypher(cypher *paillier.Cypher) ([]byte, error) {
	return bson.Marshal(toSerializableCypher(cypher))
}

// Deserializes BSON to Cypher
func DeserializeCypher(data []byte) (*paillier.Cypher, error) {
	serializable := new(SerializableCypher)
	if err := bson.Unmarshal(data, serializable); err != nil {
		return nil, err
	}

	return toOriginalCypher(serializable), nil
}

func toSerializableCypher(cypher *paillier.Cypher) *SerializableCypher {
	serializable := SerializableCypher(*cypher)
	return &serializable
}

func toOriginalCypher(serializable *SerializableCypher) *paillier.Cypher {
	original := paillier.Cypher(*serializable)
	return &original
}

type dbCypher struct {
	C string
}

func (cypher *SerializableCypher) GetBSON() (interface{}, error) {
	return &dbCypher{fmt.Sprintf("%x", cypher.C)}, nil
}

func (cypher *SerializableCypher) SetBSON(raw bson.Raw) error {
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
