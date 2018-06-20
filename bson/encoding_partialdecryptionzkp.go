package bson

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/keep-network/paillier"
	"gopkg.in/mgo.v2/bson"
)

type SerializablePartialDecryptionZKP paillier.PartialDecryptionZKP

// Serializes PartialDecryptionZKP to BSON
func SerializePartialDecryptionZKP(pdzkp *paillier.PartialDecryptionZKP) ([]byte, error) {
	return bson.Marshal(toSerializablePartialDecryptionZKP(pdzkp))
}

// Deserializes BSON to PartialDecryptionZKP
func DeserializePartialDecryptionZKP(data []byte) (*paillier.PartialDecryptionZKP, error) {
	serializable := new(SerializablePartialDecryptionZKP)
	if err := bson.Unmarshal(data, serializable); err != nil {
		return nil, err
	}

	return toOriginalPartialDecryptionZKP(serializable), nil
}

// Serializes PartialDecryptionZKP to JSON
func JsonSerializePartialDecryptionZKP(pdzkp *paillier.PartialDecryptionZKP) ([]byte, error) {
	return json.Marshal(toSerializablePartialDecryptionZKP(pdzkp))
}

// Deserializes JSON to PartialDecryptionZKP
func JsonDeserializePartialDecryptionZKP(data []byte) (*paillier.PartialDecryptionZKP, error) {
	serializable := new(SerializablePartialDecryptionZKP)
	if err := json.Unmarshal(data, serializable); err != nil {
		return nil, err
	}

	return toOriginalPartialDecryptionZKP(serializable), nil
}

func toSerializablePartialDecryptionZKP(pdzkp *paillier.PartialDecryptionZKP) *SerializablePartialDecryptionZKP {
	serializable := SerializablePartialDecryptionZKP(*pdzkp)
	return &serializable
}

func toOriginalPartialDecryptionZKP(serializable *SerializablePartialDecryptionZKP) *paillier.PartialDecryptionZKP {
	original := paillier.PartialDecryptionZKP(*serializable)
	return &original
}

type dbPartialDecryptionZKP struct {
	Z                              string   `json:"z"`
	E                              string   `json:"e"`
	C                              string   `json:"c"`
	V                              string   `json:"v"`
	N                              string   `json:"n"`
	Vi                             []string `json:"vi"`
	Decryption                     string   `json:"decryption"`
	Id                             int      `json:"id"`
	TotalNumberOfDecryptionServers int      `json:"total_number_of_decryption_servers"`
	Threshold                      int      `json:"threshold"`
}

func (pdzkp *SerializablePartialDecryptionZKP) GetBSON() (interface{}, error) {
	db := new(dbPartialDecryptionZKP)
	db.fromPartialDecryptionZKP(pdzkp)
	return db, nil
}

func (pdzkp *SerializablePartialDecryptionZKP) SetBSON(raw bson.Raw) error {
	db := new(dbPartialDecryptionZKP)
	if err := raw.Unmarshal(db); err != nil {
		return err
	}
	return db.toPartialDecryptionZKP(pdzkp)
}

func (dbPDZKP *dbPartialDecryptionZKP) fromPartialDecryptionZKP(pdzkp *SerializablePartialDecryptionZKP) {
	dbPDZKP.Id = pdzkp.Id
	dbPDZKP.TotalNumberOfDecryptionServers = pdzkp.Key.TotalNumberOfDecryptionServers
	dbPDZKP.Threshold = pdzkp.Key.Threshold
	dbPDZKP.Z = fmt.Sprintf("%x", pdzkp.Z)
	dbPDZKP.E = fmt.Sprintf("%x", pdzkp.E)
	dbPDZKP.N = fmt.Sprintf("%x", pdzkp.Key.N)
	dbPDZKP.C = fmt.Sprintf("%x", pdzkp.C)
	dbPDZKP.V = fmt.Sprintf("%x", pdzkp.Key.V)
	dbPDZKP.Decryption = fmt.Sprintf("%x", pdzkp.Decryption)
	dbPDZKP.Vi = make([]string, len(pdzkp.Key.Vi))
	for i, vi := range pdzkp.Key.Vi {
		dbPDZKP.Vi[i] = fmt.Sprintf("%x", vi)
	}
}

func (dbPDZKP *dbPartialDecryptionZKP) toPartialDecryptionZKP(pdzkp *SerializablePartialDecryptionZKP) error {
	pdzkp.Key = new(paillier.ThresholdPublicKey)

	var oks = make([]bool, 6)

	pdzkp.Id = dbPDZKP.Id
	pdzkp.Key.TotalNumberOfDecryptionServers = dbPDZKP.TotalNumberOfDecryptionServers
	pdzkp.Key.Threshold = dbPDZKP.Threshold
	pdzkp.Z, oks[0] = new(big.Int).SetString(dbPDZKP.Z, 16)
	pdzkp.E, oks[1] = new(big.Int).SetString(dbPDZKP.E, 16)
	pdzkp.C, oks[2] = new(big.Int).SetString(dbPDZKP.C, 16)
	pdzkp.Key.V, oks[3] = new(big.Int).SetString(dbPDZKP.V, 16)
	pdzkp.Key.N, oks[4] = new(big.Int).SetString(dbPDZKP.N, 16)
	pdzkp.Decryption, oks[5] = new(big.Int).SetString(dbPDZKP.Decryption, 16)

	if !all(oks) {
		fmt.Println(oks)
		fmt.Println(dbPDZKP.E, "|", dbPDZKP.Z, "|", dbPDZKP.C, "|", dbPDZKP.V, "|", dbPDZKP.Decryption)
		return errors.New("numbers not in hexadecimal format")
	}

	pdzkp.Key.Vi = make([]*big.Int, len(dbPDZKP.Vi))
	var ok bool
	for i, vi := range dbPDZKP.Vi {
		pdzkp.Key.Vi[i], ok = new(big.Int).SetString(vi, 16)
		if !ok {
			return errors.New("numbers not in hexadecimal format")
		}
	}

	return nil
}
