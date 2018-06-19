// Package bson provides functions for serialization and deserialization between
// paillier objects and BSON
package bson

import (
	"fmt"

	"github.com/keep-network/paillier"
	"gopkg.in/mgo.v2/bson"
)

type PrivateKey paillier.PrivateKey

// Serializes PrivateKey to BSON
func SerializePrivateKey(key *paillier.PrivateKey) ([]byte, error) {
	return bson.Marshal(toSerializablePrivateKey(key))
}

// Deserializes BSON to PrivateKey
func DeserializePrivateKey(data []byte) (*paillier.PrivateKey, error) {
	serializable := new(PrivateKey)
	if err := bson.Unmarshal(data, serializable); err != nil {
		return nil, err
	}

	return toOriginalPrivateKey(serializable), nil
}

// Changes original PrivateKey to serializable PrivateKey
func toSerializablePrivateKey(key *paillier.PrivateKey) *PrivateKey {
	serializable := PrivateKey(*key)
	return &serializable
}

// Changes serializable PrivateKey to original PrivateKey
func toOriginalPrivateKey(serializable *PrivateKey) *paillier.PrivateKey {
	original := paillier.PrivateKey(*serializable)
	return &original
}

type dbPrivateKey struct {
	N      string `bson:",omitempty"`
	Lambda string `bson:",omitempty"`
	Mu     string `bson:",omitempty"`
}

func (privateKey *PrivateKey) GetBSON() (interface{}, error) {
	m := make(map[string]string)

	if privateKey.N != nil {
		m["n"] = fmt.Sprintf("%x", privateKey.N)
	}
	if privateKey.Lambda != nil {
		m["lambda"] = fmt.Sprintf("%x", privateKey.Lambda)
	}
	return m, nil
}

func (privateKey *PrivateKey) SetBSON(raw bson.Raw) error {
	var err error = nil
	c := new(dbPrivateKey)
	raw.Unmarshal(c)

	if c.N != "" {
		privateKey.N, err = fromHex(c.N)
		if err != nil {
			return err
		}
	}

	if c.Lambda != "" {
		privateKey.Lambda, err = fromHex(c.Lambda)
		if err != nil {
			return err
		}
	}

	return err
}
