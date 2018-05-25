package paillier

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"
)

var MockGenerateSafePrimes = func() (*big.Int, *big.Int, error) {
	return big.NewInt(887), big.NewInt(443), nil
}

func TestGenerateSafePrimesOfThresholdKeyGenerator(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.nbits = 10
	tkh.Random = rand.Reader
	p, q, err := tkh.generateSafePrimes()
	if err != nil {
		t.Error(err)
	}
	AreSafePrimes(p, q, 10, t)
}

func TestInitPandP1(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.nbits = 10
	tkh.Random = rand.Reader

	tkh.initPandP1()
	AreSafePrimes(tkh.p, tkh.p1, 10, t)
}

func TestInitQandQ1(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.nbits = 10
	tkh.Random = rand.Reader

	tkh.initQandQ1()
	AreSafePrimes(tkh.q, tkh.q1, 10, t)
}

func TestInitPsAndQs(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.nbits = 10
	tkh.Random = rand.Reader

	tkh.initPsAndQs()

	AreSafePrimes(tkh.p, tkh.p1, 10, t)
	AreSafePrimes(tkh.q, tkh.q1, 10, t)
}

func TestArePsAndQsGood(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(887), b(443), b(839), b(419)
	if !tkh.arePsAndQsGood() {
		t.Fail()
	}

	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(887), b(443), b(887), b(443)
	if tkh.arePsAndQsGood() {
		t.Fail()
	}

	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(887), b(443), b(443), b(221)
	if tkh.arePsAndQsGood() {
		t.Fail()
	}
}

func TestInitShortcuts(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(839), b(419), b(887), b(443)
	tkh.initShortcuts()

	if !reflect.DeepEqual(tkh.n, b(744193)) {
		t.Error("wrong n", tkh.n)
	}
	if !reflect.DeepEqual(tkh.m, b(185617)) {
		t.Error("wrong m", tkh.m)
	}
	if !reflect.DeepEqual(tkh.nm, new(big.Int).Mul(b(744193), b(185617))) {
		t.Error("wrong nm", tkh.nm)
	}
	if !reflect.DeepEqual(tkh.nSquare, new(big.Int).Mul(b(744193), b(744193))) {
		t.Error("wrong nSquare", tkh.nSquare)
	}
}

func TestInitD(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.p, tkh.p1, tkh.q, tkh.q1 = b(863), b(431), b(839), b(419)
	tkh.initShortcuts()
	tkh.initD()
	if n(tkh.d)%n(tkh.m) != 0 {
		t.Fail()
	}
	if n(tkh.d)%n(tkh.n) != 1 {
		t.Fail()
	}
}

func TestInitNumerialValues(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.nbits = 10
	tkh.Random = rand.Reader

	if err := tkh.initNumerialValues(); err != nil {
		t.Error(err)
	}
}

func TestGenerateHidingPolynomial(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.nbits = 10
	tkh.Threshold = 10
	tkh.Random = rand.Reader
	if err := tkh.initNumerialValues(); err != nil {
		t.Error(err)
		return
	}
	if err := tkh.generateHidingPolynomial(); err != nil {
		t.Error(err)
	}
	p := tkh.polynomialCoefficients
	if len(p) != tkh.Threshold {
		t.Fail()
		return
	}
	if n(p[0]) != n(tkh.d) {
		t.Fail()
	}
	for i := 1; i < len(p); i++ {
		if j := n(p[i]); j < 0 || j >= n(tkh.nm) {
			t.Fail()
		}
	}
}

func TestComputeShare(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.nbits = 10
	tkh.Threshold = 3
	tkh.TotalNumberOfDecryptionServers = 5
	tkh.nm = b(103)
	tkh.polynomialCoefficients = []*big.Int{b(29), b(88), b(51)}
	share := tkh.computeShare(2)
	if n(share) != 31 {
		t.Error("error computing a share.  ", share)
	}
}

func TestCreateShares(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.nbits = 10
	tkh.Threshold = 10
	tkh.TotalNumberOfDecryptionServers = 100
	tkh.Random = rand.Reader
	if err := tkh.initNumerialValues(); err != nil {
		t.Error(err)
		return
	}
	if err := tkh.generateHidingPolynomial(); err != nil {
		t.Error(err)
		return
	}

	if shares := tkh.createShares(); len(shares) != 100 {
		t.Fail()
	}
}

func TestCreateViArray(t *testing.T) {
	tkh := new(ThresholdKeyGenerator)
	tkh.TotalNumberOfDecryptionServers = 10
	tkh.v = b(54)
	tkh.nSquare = b(101 * 101)
	vArr := tkh.createViArray([]*big.Int{b(12), b(90), b(103)})
	exp := []*big.Int{b(6162), b(304), b(2728)}
	if !reflect.DeepEqual(vArr, exp) {
		t.Fail()
	}
}

func TestGetThresholdKeyGenerator(t *testing.T) {
	tkh := GetThresholdKeyGenerator(50, 10, 6, rand.Reader)
	if err := tkh.initNumerialValues(); err != nil {
		t.Error(nil)
	}
}

func TestGenerate(t *testing.T) {
	tkh := GetThresholdKeyGenerator(32, 10, 6, rand.Reader)
	tpks, err := tkh.Generate()
	if err != nil {
		t.Error(err)
		return
	}
	if len(tpks) != 10 {
		t.Fail()
	}
	for i, tpk := range tpks {
		if tpk.Id != i+1 {
			t.Fail()
		}
		if len(tpk.Vi) != 10 {
			t.Fail()
		}
		if tpk.G == nil || tpk.N == nil {
			t.Fail()
		}
		if tpk.Threshold != 6 || tpk.TotalNumberOfDecryptionServers != 10 {
			t.Fail()
		}
	}
}

func TestComputeV(t *testing.T) {
	tkh := GetThresholdKeyGenerator(32, 10, 6, rand.Reader)
	tkh.n = b(1907 * 1823)
	tkh.nSquare = new(big.Int).Mul(tkh.n, tkh.n)
	for i := 0; i < 100; i++ {
		if err := tkh.computeV(); err != nil {
			t.Error(err)
			return
		}
		if tkh.v.Cmp(tkh.nSquare) > 0 {
			t.Error("v is too big")
		}
		if tkh.v.Cmp(tkh.n) > 0 {
			return
		}
	}
	t.Error(`v has never been bigger than n.  It is suspicious in the sense<
	than it was taken in the range 0...n**2 -1
	`)

}
