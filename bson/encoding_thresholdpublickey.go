package bson

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/keep-network/paillier"
	"gopkg.in/mgo.v2/bson"
)

type SerializableThresholdPublicKey paillier.ThresholdPublicKey

// Serializes ThresholdPublicKey to BSON
func SerializeThresholdPublicKey(key *paillier.ThresholdPublicKey) ([]byte, error) {
	return bson.Marshal(toSerializableThresholdPublicKey(key))
}

// Deserializes BSON to ThresholdPublicKey
func DeserializeThresholdPublicKey(data []byte) (*paillier.ThresholdPublicKey, error) {
	serializable := new(SerializableThresholdPublicKey)
	if err := bson.Unmarshal(data, serializable); err != nil {
		return nil, err
	}

	return toOriginalThresholdPublicKey(serializable), nil
}

func toSerializableThresholdPublicKey(key *paillier.ThresholdPublicKey) *SerializableThresholdPublicKey {
	serializable := SerializableThresholdPublicKey(*key)
	return &serializable
}

func toOriginalThresholdPublicKey(serializable *SerializableThresholdPublicKey) *paillier.ThresholdPublicKey {
	original := paillier.ThresholdPublicKey(*serializable)
	return &original
}

func (thresholdPublicKey *SerializableThresholdPublicKey) GetBSON() (interface{}, error) {
	r := new(dbThresholdKey)
	r.fromThresholdPublicKey(thresholdPublicKey)
	return r, nil
}

func (thresholdPublicKey *SerializableThresholdPublicKey) SetBSON(raw bson.Raw) error {
	r := new(dbThresholdKey)
	if err := raw.Unmarshal(r); err != nil {
		return err
	}
	return r.toThresholdPublicKey(thresholdPublicKey)
}

type dbThresholdKey struct {
	TotalNumberOfDecryptionServers int
	Threshold                      int
	V                              string
	Vi                             []string
	N                              string
}

func (dbThresholdKey *dbThresholdKey) fromThresholdPublicKey(key *SerializableThresholdPublicKey) {
	dbThresholdKey.TotalNumberOfDecryptionServers = key.TotalNumberOfDecryptionServers
	dbThresholdKey.Threshold = key.Threshold
	dbThresholdKey.V = fmt.Sprintf("%x", key.V)
	dbThresholdKey.N = fmt.Sprintf("%x", key.N)
	dbThresholdKey.Vi = make([]string, len(key.Vi))
	for i, vi := range key.Vi {
		dbThresholdKey.Vi[i] = fmt.Sprintf("%x", vi)
	}
}

func (dbThresholdKey *dbThresholdKey) toThresholdPublicKey(key *SerializableThresholdPublicKey) error {
	key.TotalNumberOfDecryptionServers = dbThresholdKey.TotalNumberOfDecryptionServers
	key.Threshold = dbThresholdKey.Threshold
	oks := make([]bool, 2)
	key.V, oks[0] = new(big.Int).SetString(dbThresholdKey.V, 16)
	key.N, oks[1] = new(big.Int).SetString(dbThresholdKey.N, 16)
	if !all(oks) {
		return errors.New("not hexadecimal")
	}
	key.Vi = make([]*big.Int, len(dbThresholdKey.Vi))
	var ok bool
	for i, vi := range dbThresholdKey.Vi {
		key.Vi[i], ok = new(big.Int).SetString(vi, 16)
		if !ok {
			return errors.New("not hexadecimal")
		}

	}
	return nil
}
