// Package bson provides functions for serialization and deserialization between
// paillier objects and BSON
package bson

import (
	"fmt"

	"github.com/keep-network/paillier"
	"gopkg.in/mgo.v2/bson"
)

type PublicKey paillier.PublicKey

// Serializes PublicKey to BSON
func SerializePublicKey(publicKey *paillier.PublicKey) ([]byte, error) {
	return bson.Marshal(toSerializablePublicKey(publicKey))
}

// Deserializes BSON to PublicKey
func DeserializePublicKey(data []byte) (*paillier.PublicKey, error) {
	serializable := new(PublicKey)
	if err := bson.Unmarshal(data, serializable); err != nil {
		return nil, err
	}

	return toOriginalPublicKey(serializable), nil
}

// Changes original PublicKey to serializable PublicKey
func toSerializablePublicKey(publicKey *paillier.PublicKey) *PublicKey {
	serializable := PublicKey(*publicKey)
	return &serializable
}

// Changes serializable PublicKey to original PublicKey
func toOriginalPublicKey(serializable *PublicKey) *paillier.PublicKey {
	original := paillier.PublicKey(*serializable)
	return &original
}

type dbPublicKey struct {
	N string `bson:",omitempty"`
}

func (publicKey *PublicKey) GetBSON() (interface{}, error) {
	m := make(map[string]string)
	m["n"] = fmt.Sprintf("%x", publicKey.N)
	return m, nil
}

func (publicKey *PublicKey) SetBSON(raw bson.Raw) error {
	var err error = nil
	c := new(dbPublicKey)
	raw.Unmarshal(c)

	if c.N != "" {
		publicKey.N, err = fromHex(c.N)
		if err != nil {
			return err
		}
	}

	return err
}
