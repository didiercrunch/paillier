package paillier

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"

	"gopkg.in/mgo.v2/bson"
)

func AssertBSONIsGood(object, dump interface{}, t *testing.T) {
	data, err := bson.Marshal(object)
	if err != nil {
		t.Error(err)
		return
	}
	if err = bson.Unmarshal(data, dump); err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(object, dump) {
		t.Fail()
	}
}

func AssertJSONIsGood(object, dump interface{}, t *testing.T) {
	data, err := json.Marshal(object)
	if err != nil {
		t.Error(err)
		return
	}
	if err = json.Unmarshal(data, dump); err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(object, dump) {
		t.Fail()
	}
}

func TestCypherGetBSON(t *testing.T) {
	key := CreatePrivateKey(big.NewInt(101), big.NewInt(113))
	cypher, err := key.Encrypt(big.NewInt(100), rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	data, err := bson.Marshal(cypher)
	if err != nil {
		t.Error(err)
		return
	}
	cypher2 := new(Cypher)
	if err = bson.Unmarshal(data, cypher2); err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(cypher, cypher2) {
		t.Fail()
	}
}

func TestSetPrivateKeyBson(t *testing.T) {
	key := CreatePrivateKey(big.NewInt(101), big.NewInt(113))
	AssertBSONIsGood(key, new(PrivateKey), t)

}

func TestGetBSONEmptyKey(t *testing.T) {
	key := new(PrivateKey)
	m, err := key.GetBSON()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(make(map[string]string), m) {
		t.Error(m)
	}
}

func TestPartialDecryptionZKPJsonification(t *testing.T) {
	pd := new(PartialDecryptionZKP)
	pd.Key = new(ThresholdKey)
	pd.Key.Threshold = 98
	pd.Key.TotalNumberOfDecryptionServers = 230
	pd.Id = 1
	pd.Key.Vi = []*big.Int{b(77), b(67)} // vi is 67
	pd.Key.N = b(131)
	pd.Key.V = b(101)
	pd.Decryption = b(171)
	pd.E = b(112)
	pd.C = b(99)
	pd.Key.N = b(345)
	pd.Key.G = b(99)
	pd.Z = b(88)

	AssertJSONIsGood(pd, new(PartialDecryptionZKP), t)
}

func TestPartialDecryptionZKPBSONification(t *testing.T) {
	pd := new(PartialDecryptionZKP)
	pd.Key = new(ThresholdKey)
	pd.Key.Threshold = 98
	pd.Key.TotalNumberOfDecryptionServers = 230
	pd.Id = 1
	pd.Key.Vi = []*big.Int{b(77), b(67)} // vi is 67
	pd.Key.N = b(131)
	pd.Key.V = b(101)
	pd.Decryption = b(171)
	pd.E = b(112)
	pd.C = b(99)
	pd.Key.N = b(345)
	pd.Key.G = b(99)
	pd.Z = b(88)

	AssertBSONIsGood(pd, new(PartialDecryptionZKP), t)
}

func TestThresholdKeyBSON(t *testing.T) {
	key := &ThresholdKey{PublicKey{b(9), b(8), nil}, 7, 6, b(3), []*big.Int{b(2), b(34)}}
	AssertBSONIsGood(key, new(ThresholdKey), t)
}
