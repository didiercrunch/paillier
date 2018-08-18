package bson

import (
	"fmt"

	"github.com/keep-network/paillier"
	"gopkg.in/mgo.v2/bson"
)

type SerializableSecretKey paillier.SecretKey

// Serializes SecretKey to BSON
func SerializeSecretKey(key *paillier.SecretKey) ([]byte, error) {
	return bson.Marshal(toSerializableSecretKey(key))
}

// Deserializes BSON to SecretKey
func DeserializeSecretKey(data []byte) (*paillier.SecretKey, error) {
	serializable := new(SerializableSecretKey)
	if err := bson.Unmarshal(data, serializable); err != nil {
		return nil, err
	}

	return toOriginalSecretKey(serializable), nil
}

func toSerializableSecretKey(key *paillier.SecretKey) *SerializableSecretKey {
	serializable := SerializableSecretKey(*key)
	return &serializable
}

func toOriginalSecretKey(serializable *SerializableSecretKey) *paillier.SecretKey {
	original := paillier.SecretKey(*serializable)
	return &original
}

type dbSecretKey struct {
	N      string `bson:",omitempty"`
	Lambda string `bson:",omitempty"`
	Mu     string `bson:",omitempty"`
}

func (SecretKey *SerializableSecretKey) GetBSON() (interface{}, error) {
	m := make(map[string]string)

	if SecretKey.N != nil {
		m["n"] = fmt.Sprintf("%x", SecretKey.N)
	}
	if SecretKey.Lambda != nil {
		m["lambda"] = fmt.Sprintf("%x", SecretKey.Lambda)
	}
	return m, nil
}

func (SecretKey *SerializableSecretKey) SetBSON(raw bson.Raw) error {
	var err error = nil
	c := new(dbSecretKey)
	raw.Unmarshal(c)

	if c.N != "" {
		SecretKey.N, err = fromHex(c.N)
		if err != nil {
			return err
		}
	}

	if c.Lambda != "" {
		SecretKey.Lambda, err = fromHex(c.Lambda)
		if err != nil {
			return err
		}
	}

	return err
}
