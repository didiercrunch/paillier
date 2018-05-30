package paillier

//  all the methods relative to the set/get json/bson should be stored
//  in this file.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"gopkg.in/mgo.v2/bson"
)

func fromHex(hex string) (*big.Int, error) {
	n, err := new(big.Int).SetString(hex, 16)
	if !err {
		msg := fmt.Sprintf("Cannot convert %s to int as hexadecimal", hex)
		return nil, errors.New(msg)
	}
	return n, nil
}

func all(oks []bool) bool {
	for _, ok := range oks {
		if !ok {
			return false
		}
	}
	return true
}

type dbCypher struct {
	C string
}

func (this *Cypher) GetBSON() (interface{}, error) {
	return &dbCypher{fmt.Sprintf("%x", this.C)}, nil
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

type dbThresholdKey struct {
	TotalNumberOfDecryptionServers int
	Threshold                      int
	V                              string
	Vi                             []string
	N                              string
}

func (this *dbThresholdKey) FromThresholdKey(key *ThresholdKey) {
	this.TotalNumberOfDecryptionServers = key.TotalNumberOfDecryptionServers
	this.Threshold = key.Threshold
	this.V = fmt.Sprintf("%x", key.V)
	this.N = fmt.Sprintf("%x", key.N)
	this.Vi = make([]string, len(key.Vi))
	for i, vi := range key.Vi {
		this.Vi[i] = fmt.Sprintf("%x", vi)
	}
}

func (this *dbThresholdKey) ToThresholdKey(key *ThresholdKey) error {
	key.TotalNumberOfDecryptionServers = this.TotalNumberOfDecryptionServers
	key.Threshold = this.Threshold
	oks := make([]bool, 2)
	key.V, oks[0] = new(big.Int).SetString(this.V, 16)
	key.N, oks[1] = new(big.Int).SetString(this.N, 16)
	if !all(oks) {
		return errors.New("not hexadecimal")
	}
	key.Vi = make([]*big.Int, len(this.Vi))
	var ok bool
	for i, vi := range this.Vi {
		key.Vi[i], ok = new(big.Int).SetString(vi, 16)
		if !ok {
			return errors.New("not hexadecimal")
		}

	}
	return nil
}

func (this *ThresholdKey) GetBSON() (interface{}, error) {
	r := new(dbThresholdKey)
	r.FromThresholdKey(this)
	return r, nil
}

func (this *ThresholdKey) SetBSON(raw bson.Raw) error {
	r := new(dbThresholdKey)
	if err := raw.Unmarshal(r); err != nil {
		return err
	}
	return r.ToThresholdKey(this)
}

type dbPrivateKey struct {
	N      string `bson:",omitempty"`
	Lambda string `bson:",omitempty"`
	Mu     string `bson:",omitempty"`
}

func (this *PrivateKey) GetBSON() (interface{}, error) {
	m := make(map[string]string)

	if this.N != nil {
		m["n"] = fmt.Sprintf("%x", this.N)
	}
	if this.Lambda != nil {
		m["lambda"] = fmt.Sprintf("%x", this.Lambda)
	}
	return m, nil
}

func (this *PrivateKey) SetBSON(raw bson.Raw) error {
	var err error = nil
	c := new(dbPrivateKey)
	raw.Unmarshal(c)

	if c.N != "" {
		this.N, err = fromHex(c.N)
		if err != nil {
			return err
		}
	}

	if c.Lambda != "" {
		this.Lambda, err = fromHex(c.Lambda)
		if err != nil {
			return err
		}
	}

	return err
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

func (this *dbPartialDecryptionZKP) FromPartialDecryptionZKP(pd *PartialDecryptionZKP) {
	this.Id = pd.Id
	this.TotalNumberOfDecryptionServers = pd.Key.TotalNumberOfDecryptionServers
	this.Threshold = pd.Key.Threshold
	this.Z = fmt.Sprintf("%x", pd.Z)
	this.E = fmt.Sprintf("%x", pd.E)
	this.N = fmt.Sprintf("%x", pd.Key.N)
	this.C = fmt.Sprintf("%x", pd.C)
	this.V = fmt.Sprintf("%x", pd.Key.V)
	this.Decryption = fmt.Sprintf("%x", pd.Decryption)
	this.Vi = make([]string, len(pd.Key.Vi))
	for i, vi := range pd.Key.Vi {
		this.Vi[i] = fmt.Sprintf("%x", vi)
	}
}

func (this *dbPartialDecryptionZKP) ToPartialDecryptionZKP(pd *PartialDecryptionZKP) error {
	pd.Key = new(ThresholdKey)

	var oks = make([]bool, 6)

	pd.Id = this.Id
	pd.Key.TotalNumberOfDecryptionServers = this.TotalNumberOfDecryptionServers
	pd.Key.Threshold = this.Threshold
	pd.Z, oks[0] = new(big.Int).SetString(this.Z, 16)
	pd.E, oks[1] = new(big.Int).SetString(this.E, 16)
	pd.C, oks[2] = new(big.Int).SetString(this.C, 16)
	pd.Key.V, oks[3] = new(big.Int).SetString(this.V, 16)
	pd.Key.N, oks[4] = new(big.Int).SetString(this.N, 16)
	pd.Decryption, oks[5] = new(big.Int).SetString(this.Decryption, 16)

	if !all(oks) {
		fmt.Println(oks)
		fmt.Println(this.E, "|", this.Z, "|", this.C, "|", this.V, "|", this.Decryption)
		return errors.New("numbers not in hexadecimal format")
	}

	pd.Key.Vi = make([]*big.Int, len(this.Vi))
	var ok bool
	for i, vi := range this.Vi {
		pd.Key.Vi[i], ok = new(big.Int).SetString(vi, 16)
		if !ok {
			return errors.New("numbers not in hexadecimal format")
		}
	}

	return nil
}

func (this *PartialDecryptionZKP) MarshalJSON() ([]byte, error) {
	db := new(dbPartialDecryptionZKP)
	db.FromPartialDecryptionZKP(this)
	return json.Marshal(db)
}

func (this *PartialDecryptionZKP) UnmarshalJSON(data []byte) error {
	db := new(dbPartialDecryptionZKP)
	if err := json.Unmarshal(data, db); err != nil {
		return err
	}
	return db.ToPartialDecryptionZKP(this)
}

func (this *PartialDecryptionZKP) GetBSON() (interface{}, error) {
	db := new(dbPartialDecryptionZKP)
	db.FromPartialDecryptionZKP(this)
	return db, nil
}

func (this *PartialDecryptionZKP) SetBSON(raw bson.Raw) error {
	db := new(dbPartialDecryptionZKP)
	if err := raw.Unmarshal(db); err != nil {
		return err
	}
	return db.ToPartialDecryptionZKP(this)
}
