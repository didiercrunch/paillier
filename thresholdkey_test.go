package paillier

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"
)

func getThresholdSecretKey() *ThresholdSecretKey {
	tkh, err := GetThresholdKeyGenerator(32, 10, 6, rand.Reader)
	if err != nil {
		panic(err)
	}

	tpks, err := tkh.Generate()
	if err != nil {
		panic(err)
	}
	return tpks[6]
}

func TestDelta(t *testing.T) {
	tk := new(ThresholdPublicKey)
	tk.TotalNumberOfDecryptionServers = 6
	if delta := tk.delta(); 720 != n(delta) {
		t.Error("Delta is not 720 but", delta)
	}
}

func TestExp(t *testing.T) {
	tk := new(ThresholdPublicKey)

	if exp := tk.exp(big.NewInt(720), big.NewInt(10), big.NewInt(49)); 43 != n(exp) {
		t.Error("Unexpected exponent. Expected 43 but got", exp)
	}

	if exp := tk.exp(big.NewInt(720), big.NewInt(0), big.NewInt(49)); 1 != n(exp) {
		t.Error("Unexpected exponent. Expected 0 but got", exp)
	}

	if exp := tk.exp(big.NewInt(720), big.NewInt(-10), big.NewInt(49)); 8 != n(exp) {
		t.Error("Unexpected exponent. Expected 8 but got", exp)
	}
}

func TestCombineSharesConstant(t *testing.T) {
	tk := new(ThresholdPublicKey)
	tk.N = big.NewInt(101 * 103)
	tk.TotalNumberOfDecryptionServers = 6

	if c := tk.combineSharesConstant(); !reflect.DeepEqual(big.NewInt(4558), c) {
		t.Error("wrong combined key.  ", c)
	}
}

func TestDecrypt(t *testing.T) {
	key := new(ThresholdSecretKey)
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
	key := new(ThresholdSecretKey)
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
	pd := getThresholdSecretKey()
	_, err := pd.Encrypt(big.NewInt(876), rand.Reader)
	if err != nil {
		t.Fail()
	}
}

func TestDecryptWithThresholdKey(t *testing.T) {
	pd := getThresholdSecretKey()
	c, err := pd.Encrypt(big.NewInt(876), rand.Reader)
	if err != nil {
		t.Fail()
	}
	pd.Decrypt(c.C)
}

func TestVerifyPart1(t *testing.T) {
	pd := new(PartialDecryptionZKP)
	pd.Key = new(ThresholdPublicKey)
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
	pd.Key = new(ThresholdPublicKey)
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
	pd := getThresholdSecretKey()
	c, err := pd.Encrypt(big.NewInt(876), rand.Reader)
	if err != nil {
		t.Error(err)
	}
	znp, err := pd.DecryptAndProduceZNP(c.C, rand.Reader)
	if err != nil {
		t.Error(err)
	}

	if !znp.Verify() {
		t.Fail()
	}
}

func TestMakeVerificationBeforeCombiningPartialDecryptions(t *testing.T) {
	tk := new(ThresholdPublicKey)
	tk.Threshold = 2
	if tk.verifyPartialDecryptions([]*PartialDecryption{}) == nil {
		t.Fail()
	}
	prms := []*PartialDecryption{new(PartialDecryption), new(PartialDecryption)}
	prms[1].Id = 1
	if tk.verifyPartialDecryptions(prms) != nil {
		t.Fail()
	}
	prms[1].Id = 0
	if tk.verifyPartialDecryptions(prms) == nil {
		t.Fail()
	}
}

func TestUpdateLambda(t *testing.T) {
	tk := new(ThresholdPublicKey)
	lambda := b(11)
	share1 := &PartialDecryption{3, b(5)}
	share2 := &PartialDecryption{7, b(3)}
	res := tk.updateLambda(share1, share2, lambda)
	if n(res) != 20 {
		t.Error("wrong lambda", n(res))
	}
}

func TestupdateCprime(t *testing.T) {
	tk := new(ThresholdPublicKey)
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
	tkh, err := GetThresholdKeyGenerator(32, 2, 1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.Generate()
	if err != nil {
		t.Error(err)
	}
	message := b(100)
	c, err := tpks[1].Encrypt(message, rand.Reader)
	if err != nil {
		t.Error(err)
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
	tkh, err := GetThresholdKeyGenerator(32, 2, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.Generate()
	if err != nil {
		t.Error(err)
	}
	message := b(100)
	c, err := tpks[1].Encrypt(message, rand.Reader)
	if err != nil {
		t.Error(err)
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

func TestHomomorphicThresholdEncryption(t *testing.T) {
	tkh, err := GetThresholdKeyGenerator(32, 2, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, _ := tkh.Generate()

	plainText1 := b(13)
	plainText2 := b(19)

	cypher1, _ := tpks[0].Encrypt(plainText1, rand.Reader)
	cypher2, _ := tpks[1].Encrypt(plainText2, rand.Reader)

	cypher3 := tpks[0].Add(cypher1, cypher2)

	share1 := tpks[0].Decrypt(cypher3.C)
	share2 := tpks[1].Decrypt(cypher3.C)

	combined, _ := tpks[0].CombinePartialDecryptions([]*PartialDecryption{share1, share2})

	expected := big.NewInt(32) // 13 + 19

	if !reflect.DeepEqual(combined, expected) { // 13 + 19
		t.Errorf("Unexpected decryption result. Expected %v but got %v", expected, combined)
	}
}

func TestDecryption(t *testing.T) {
	// test the correct decryption of '100'.
	share1 := &PartialDecryption{1, b(384111638639)}
	share2 := &PartialDecryption{2, b(235243761043)}
	tk := new(ThresholdPublicKey)
	tk.Threshold = 2
	tk.TotalNumberOfDecryptionServers = 2
	tk.N = b(637753)
	tk.V = b(70661107826)
	if msg, err := tk.CombinePartialDecryptions([]*PartialDecryption{share1, share2}); err != nil {
		t.Error(err)
	} else if n(msg) != 100 {
		t.Error("decrypted message was not 100 but ", msg)
	}
}

func TestValidate(t *testing.T) {
	pk := getThresholdSecretKey()
	if err := pk.Validate(rand.Reader); err != nil {
		t.Error(err)
	}
	pk.Id++
	if err := pk.Validate(rand.Reader); err == nil {
		t.Fail()
	}
}

func TestCombinePartialDecryptionsZKP(t *testing.T) {
	tkh, err := GetThresholdKeyGenerator(32, 2, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.Generate()
	if err != nil {
		t.Error(err)
	}
	message := b(100)
	c, err := tpks[1].Encrypt(message, rand.Reader)
	if err != nil {
		t.Error(err)
	}
	share1, err := tpks[0].DecryptAndProduceZNP(c.C, rand.Reader)
	if err != nil {
		t.Error(err)
	}
	share2, err := tpks[1].DecryptAndProduceZNP(c.C, rand.Reader)
	if err != nil {
		t.Error(err)
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
	tkh, err := GetThresholdKeyGenerator(32, 100, 50, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

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
	tkh, err := GetThresholdKeyGenerator(32, 2, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tpks, err := tkh.Generate()

	pk := &tpks[0].ThresholdPublicKey
	if err != nil {
		t.Error(err)
	}
	expt := b(101)
	ct, err := tpks[0].Encrypt(expt, rand.Reader)
	if err != nil {
		t.Error(err)
	}
	pd1, err := tpks[0].DecryptAndProduceZNP(ct.C, rand.Reader)
	if err != nil {
		t.Error(err)
	}
	pd2, err := tpks[1].DecryptAndProduceZNP(ct.C, rand.Reader)
	if err != nil {
		t.Error(err)
	}
	pds := []*PartialDecryptionZKP{pd1, pd2}
	if err != nil {
		t.Error(err)
	}

	if err = pk.VerifyDecryption(ct.C, b(101), pds); err != nil {
		t.Error(err)
	}
	if err = pk.VerifyDecryption(ct.C, b(100), pds); err == nil {
		t.Error(err)
	}
	if err = pk.VerifyDecryption(new(big.Int).Add(b(1), ct.C), b(101), pds); err == nil {
		t.Error(err)
	}
}
