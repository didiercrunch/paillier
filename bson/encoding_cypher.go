package bson

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/keep-network/paillier"
	"gopkg.in/mgo.v2/bson"
)

type SerializableCypher paillier.Ciphertext

// Serializes Ciphertext to BSON
func SerializeCypher(ct *paillier.Ciphertext) ([]byte, error) {
	return bson.Marshal(toSerializableCypher(ct))
}

// Deserializes BSON to Ciphertext
func DeserializeCypher(data []byte) (*paillier.Ciphertext, error) {
	serializable := new(SerializableCypher)
	if err := bson.Unmarshal(data, serializable); err != nil {
		return nil, err
	}

	return toOriginalCypher(serializable), nil
}

func toSerializableCypher(ct *paillier.Ciphertext) *SerializableCypher {
	serializable := SerializableCypher(*ct)
	return &serializable
}

func toOriginalCypher(serializable *SerializableCypher) *paillier.Ciphertext {
	original := paillier.Ciphertext(*serializable)
	return &original
}

type dbCypher struct {
	C string
}

func (ct *SerializableCypher) GetBSON() (interface{}, error) {
	return &dbCypher{fmt.Sprintf("%x", ct.C)}, nil
}

func (ct *SerializableCypher) SetBSON(raw bson.Raw) error {
	c := dbCypher{}
	if err := raw.Unmarshal(&c); err != nil {
		return err
	}
	var ok bool
	ct.C, ok = new(big.Int).SetString(c.C, 16)
	if !ok {
		return errors.New("big int not in hexadecimal format")
	}
	return nil
}
