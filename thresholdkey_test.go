package paillier

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"
)

func GetThresholdPrivateKey() *ThresholdPrivateKey {
	tkh := GetThresholdKeyGenerator(32, 10, 6, rand.Reader)
	tpks, err := tkh.Generate()
	if err != nil {
		panic(err)
	}
	return tpks[6]
}

func TestDelta(t *testing.T) {
	tk := new(ThresholdKey)
	tk.TotalNumberOfDecryptionServers = 6
	if delta := tk.Delta(); 720 != n(delta) {
		t.Error("Delta is not 720 but", delta)
	}
}

func TestCombineSharesConstant(t *testing.T) {
	tk := new(ThresholdKey)
	tk.N = big.NewInt(101 * 103)
	tk.TotalNumberOfDecryptionServers = 6

	if c := tk.CombineSharesConstant(); !reflect.DeepEqual(big.NewInt(4558), c) {
		t.Error("wrong combined key.  ", c)
	}
}

func TestDecrypt(t *testing.T) {
	key := new(ThresholdPrivateKey)
	key.TotalNumberOfDecryptionServers = 10
	key.N = b(101 * 103)
	key.Share = b(862)
	key.Id = 9
	c := b(56)

	partial := key.Decrypt(c)

	if partial.Id != 9 {
		t.Fail()
	}
	if n(partial.Decryption) != 40644522 {
		t.Error("wrong decryption ", partial.Decryption)
	}
}

func TestCopyVi(t *testing.T) {
	key := new(ThresholdPrivateKey)
	key.Vi = []*big.Int{b(34), b(2), b(29)}
	vi := key.copyVi()
	if !reflect.DeepEqual(vi, key.Vi) {
		t.Fail()
	}
	key.Vi[1] = b(89)
	if reflect.DeepEqual(vi, key.Vi) {
		t.Fail()
	}
}

func TestEncryptWithThresholdKey(t *testing.T) {
	pd := GetThresholdPrivateKey()
	_, err := pd.Encrypt(big.NewInt(876), rand.Reader)
	if err != nil {
		t.Fail()
	}
}

func TestDecryptWithThresholdKey(t *testing.T) {
	pd := GetThresholdPrivateKey()
	c, err := pd.Encrypt(big.NewInt(876), rand.Reader)
	if err != nil {
		t.Fail()
	}
	pd.Decrypt(c.C)
}

func TestVerifyPart1(t *testing.T) {
	pd := new(PartialDecryptionZKP)
	pd.Key = new(ThresholdKey)
	pd.Key.N = b(131)
	pd.Decryption = b(101)
	pd.C = b(99)
	pd.E = b(112)
	pd.Z = b(88)

	if a := pd.verifyPart1(); n(a) != 11986 {
		t.Error("wrong a ", a)
	}
}

func TestVerifyPart2(t *testing.T) {
	pd := new(PartialDecryptionZKP)
	pd.Key = new(ThresholdKey)
	pd.Id = 1
	pd.Key.Vi = []*big.Int{b(77), b(67)} // vi is 67
	pd.Key.N = b(131)
	pd.Key.V = b(101)
	pd.E = b(112)
	pd.Z = b(88)
	if b := pd.verifyPart2(); n(b) != 14602 {
		t.Error("wrong b ", b)
	}
}

func TestDecryptAndProduceZNP(t *testing.T) {
	pd := GetThresholdPrivateKey()
	c, err := pd.Encrypt(big.NewInt(876), rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	znp, err := pd.DecryptAndProduceZNP(c.C, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	if !znp.Verify() {
		t.Fail()
	}
}

func TestMakeVerificationBeforeCombiningPartialDecryptions(t *testing.T) {
	tk := new(ThresholdKey)
	tk.Threshold = 2
	if tk.MakeVerificationBeforeCombiningPartialDecryptions([]*PartialDecryption{}) == nil {
		t.Fail()
	}
	prms := []*PartialDecryption{new(PartialDecryption), new(PartialDecryption)}
	prms[1].Id = 1
	if tk.MakeVerificationBeforeCombiningPartialDecryptions(prms) != nil {
		t.Fail()
	}
	prms[1].Id = 0
	if tk.MakeVerificationBeforeCombiningPartialDecryptions(prms) == nil {
		t.Fail()
	}
}

func TestUpdateLambda(t *testing.T) {
	tk := new(ThresholdKey)
	lambda := b(11)
	share1 := &PartialDecryption{3, b(5)}
	share2 := &PartialDecryption{7, b(3)}
	res := tk.UpdateLambda(share1, share2, lambda)
	if n(res) != 20 {
		t.Error("wrong lambda", n(res))
	}
}

func TestupdateCprime(t *testing.T) {
	tk := new(ThresholdKey)
	tk.N = b(99)
	cprime := b(77)
	lambda := b(52)
	share := &PartialDecryption{3, b(5)}
	cprime = tk.updateCprime(cprime, lambda, share)
	if n(cprime) != 8558 {
		t.Error("wrong cprime", cprime)
	}

}

func TestEncryptingDecryptingSimple(t *testing.T) {
	tkh := GetThresholdKeyGenerator(10, 2, 1, rand.Reader)
	tpks, err := tkh.Generate()
	if err != nil {
		t.Error(err)
		return
	}
	message := b(100)
	c, err := tpks[1].Encrypt(message, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	share1 := tpks[0].Decrypt(c.C)
	message2, err := tpks[0].CombinePartialDecryptions([]*PartialDecryption{share1})
	if err != nil {
		t.Error(err)
	}
	if n(message) != n(message2) {
		t.Error("decrypted message is not the same one than the input one ", message2)
	}
}

func TestEncryptingDecrypting(t *testing.T) {
	tkh := GetThresholdKeyGenerator(10, 2, 2, rand.Reader)
	tpks, err := tkh.Generate()
	if err != nil {
		t.Error(err)
		return
	}
	message := b(100)
	c, err := tpks[1].Encrypt(message, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	share1 := tpks[0].Decrypt(c.C)
	share2 := tpks[1].Decrypt(c.C)
	message2, err := tpks[0].CombinePartialDecryptions([]*PartialDecryption{share1, share2})
	if err != nil {
		t.Error(err)
	}
	if n(message) != n(message2) {
		t.Error("The decrypted cyphered is not original massage but ", message2)
	}
}

func TestDecryption(t *testing.T) {
	// test the correct decryption of '100'.
	share1 := &PartialDecryption{1, b(384111638639)}
	share2 := &PartialDecryption{2, b(235243761043)}
	tk := new(ThresholdKey)
	tk.Threshold = 2
	tk.TotalNumberOfDecryptionServers = 2
	tk.N = b(637753)
	tk.G = b(637754)
	tk.V = b(70661107826)
	if msg, err := tk.CombinePartialDecryptions([]*PartialDecryption{share1, share2}); err != nil {
		t.Error(err)
	} else if n(msg) != 100 {
		t.Error("decrypted message was not 100 but ", msg)
	}

}

func TestDivide(t *testing.T) {
	tk := new(ThresholdKey)
	if r := tk.divide(b(77), b(4)); n(r) != 19 {
		t.Error("77 / 4 != 19 ( ", r, " )")
	}
	if r := tk.divide(b(-77), b(-4)); n(r) != 19 {
		t.Error("-77 / -4 != 19 ( ", r, " )")
	}
	if r := tk.divide(b(-77), b(4)); n(r) != -19 {
		t.Error("-77 / 4 != -19 ( ", r, " )")
	}
	if r := tk.divide(b(77), b(-4)); n(r) != -19 {
		t.Error("77 / -4 != -19 ( ", r, " )")
	}
}

func TestValidate(t *testing.T) {
	pk := GetThresholdPrivateKey()
	if err := pk.Validate(rand.Reader); err != nil {
		t.Error(err)
	}
	pk.Id++
	if err := pk.Validate(rand.Reader); err == nil {
		t.Fail()
	}
}

func TestCombinePartialDecryptionsZKP(t *testing.T) {
	tkh := GetThresholdKeyGenerator(10, 2, 2, rand.Reader)
	tpks, err := tkh.Generate()
	if err != nil {
		t.Error(err)
		return
	}
	message := b(100)
	c, err := tpks[1].Encrypt(message, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	share1, err := tpks[0].DecryptAndProduceZNP(c.C, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	share2, err := tpks[1].DecryptAndProduceZNP(c.C, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	message2, err := tpks[0].CombinePartialDecryptionsZKP([]*PartialDecryptionZKP{share1, share2})
	if err != nil {
		t.Error(err)
	}
	if n(message) != n(message2) {
		t.Error("The decrypted cyphered is not original massage but ", message2)
	}
	share1.E = b(687687678)
	_, err = tpks[0].CombinePartialDecryptionsZKP([]*PartialDecryptionZKP{share1, share2})
	if err == nil {
		t.Fail()
	}
}

func TestCombinePartialDecryptionsWith100Shares(t *testing.T) {
	tkh := GetThresholdKeyGenerator(10, 100, 50, rand.Reader)
	tpks, err := tkh.Generate()
	if err != nil {
		t.Error(err)
		return
	}
	message := b(100)
	c, err := tpks[1].Encrypt(message, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	shares := make([]*PartialDecryption, 75)
	for i := 0; i < 75; i++ {
		shares[i] = tpks[i].Decrypt(c.C)
	}

	message2, err := tpks[0].CombinePartialDecryptions(shares)
	if err != nil {
		t.Error(err)
	}
	if n(message) != n(message2) {
		t.Error("The decrypted cyphered is not original massage but ", message2)
	}
}

func TestVerifyDecryption(t *testing.T) {
	tkh := GetThresholdKeyGenerator(10, 2, 2, rand.Reader)
	tpks, err := tkh.Generate()

	pk := &tpks[0].ThresholdKey
	if err != nil {
		t.Error(err)
		return
	}
	expt := b(101)
	cypher, err := tpks[0].Encrypt(expt, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	pd1, err := tpks[0].DecryptAndProduceZNP(cypher.C, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	pd2, err := tpks[1].DecryptAndProduceZNP(cypher.C, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	pds := []*PartialDecryptionZKP{pd1, pd2}
	if err != nil {
		t.Error(err)
		return
	}

	if err = pk.VerifyDecryption(cypher.C, b(101), pds); err != nil {
		t.Error(err)
	}
	if err = pk.VerifyDecryption(cypher.C, b(100), pds); err == nil {
		t.Error(err)
	}
	if err = pk.VerifyDecryption(new(big.Int).Add(b(1), cypher.C), b(101), pds); err == nil {
		t.Error(err)
	}

}
