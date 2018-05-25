package paillier

import (
	"crypto/rand"
	"io"
	"math/big"
)

type ThresholdKeyGenerator struct {
	nbits                          int
	TotalNumberOfDecryptionServers int
	Threshold                      int
	Random                         io.Reader

	//Both p1 and q1 are primes of length nbits - 1
	p1 *big.Int
	q1 *big.Int

	p       *big.Int //p is prime and p=2*p1+1
	q       *big.Int //q is prime and q=2*q1+1
	n       *big.Int // n=p*q
	m       *big.Int //m = p1*q1
	nSquare *big.Int //nSquare = n*n
	nm      *big.Int // nm = n*m

	// As specified in the paper, d must satify d=1 mod n and d=0 mod m
	d *big.Int

	// A generator of QR in Z_{n^2}
	v *big.Int

	// the polynomial coefficients to hide a secret.  See Shamir.
	polynomialCoefficients []*big.Int
}

//  preferable way to counstruct the ThresholdKeyGenerator.  No verification
//  is done on the input values.  You need to bu sure that nbits is big enough
//  and that Threshold > TotalNumberOfDecryptionServers / 2
func GetThresholdKeyGenerator(nbits, TotalNumberOfDecryptionServers, Threshold int, random io.Reader) *ThresholdKeyGenerator {
	ret := new(ThresholdKeyGenerator)
	ret.nbits = nbits
	ret.TotalNumberOfDecryptionServers = TotalNumberOfDecryptionServers
	ret.Threshold = Threshold
	ret.Random = random
	return ret
}

func (this *ThresholdKeyGenerator) GenerateSafePrimes() (*big.Int, *big.Int, error) {
	return GenerateSafePrimes(this.nbits, this.Random)
}

func (this *ThresholdKeyGenerator) InitPandP1() error {
	var err error
	this.p, this.p1, err = this.GenerateSafePrimes()
	return err
}

func (this *ThresholdKeyGenerator) InitQandQ1() error {
	var err error
	this.q, this.q1, err = this.GenerateSafePrimes()
	return err
}

func (this *ThresholdKeyGenerator) InitShortcuts() {
	this.n = new(big.Int).Mul(this.p, this.q)
	this.m = new(big.Int).Mul(this.p1, this.q1)
	this.nSquare = new(big.Int).Mul(this.n, this.n)
	this.nm = new(big.Int).Mul(this.n, this.m)

}

func (this *ThresholdKeyGenerator) ArePsAndQsGood() bool {
	if this.p.Cmp(this.q) == 0 {
		return false
	}
	if this.p.Cmp(this.q1) == 0 {
		return false
	}
	if this.p1.Cmp(this.q) == 0 {
		return false
	}
	return true
}

func (this *ThresholdKeyGenerator) InitPsAndQs() error {
	if err := this.InitPandP1(); err != nil {
		return err
	}
	if err := this.InitQandQ1(); err != nil {
		return err
	}
	if !this.ArePsAndQsGood() {
		return this.InitPsAndQs()
	}
	return nil
}

func (this *ThresholdKeyGenerator) ComputeV() error {
	var err error
	this.v, err = GetRandomGeneratorOfTheQuadraticResidue(this.nSquare, this.Random)
	return err
}

// Choose d such that d=0 (mod m) and d=1 (mod n).
// See [DJN 10], section 5.1, "Key generation"
//
// From Chinese Remainder Theorem:
// x = a1 (mod n1)
// x = a2 (mod n2)
//
// N = n1*n2
// y1 = N/n1
// y2 = N/n2
// z1 = y1^-1 mod n1
// z2 = y2^-1 mod n2
// Solution is x = a1*y1*z1 + a2*y2*z2
//
// In our case:
// x = 0 (mod m)
// x = 1 (mod n)
//
// Since a1 = 0, it's enough to compute a2*y2*z2 to get x.
//
// a2 = 1
// y2 = mn/n = m
// z2 = m^-1 mod n
//
// x = a2*y2*z2 = 1 * m * [m^-1 mod n]
func (this *ThresholdKeyGenerator) InitD() {
	mInverse := new(big.Int).ModInverse(this.m, this.n)
	this.d = new(big.Int).Mul(mInverse, this.m)
}

func (this *ThresholdKeyGenerator) InitNumerialValues() error {
	if err := this.InitPsAndQs(); err != nil {
		return err
	}
	this.InitShortcuts()
	this.InitD()
	return this.ComputeV()
}

func (this *ThresholdKeyGenerator) GenerateHidingPolynomial() error {
	this.polynomialCoefficients = make([]*big.Int, this.Threshold)
	this.polynomialCoefficients[0] = this.d
	var err error
	for i := 1; i < this.Threshold; i++ {
		this.polynomialCoefficients[i], err = rand.Int(this.Random, this.nm)
		if err != nil {
			return err
		}
	}
	return nil
}

func (this *ThresholdKeyGenerator) ComputeShare(index int) *big.Int {
	share := big.NewInt(0)
	for i := 0; i < this.Threshold; i++ {
		a := this.polynomialCoefficients[i]
		b := new(big.Int).Exp(big.NewInt(int64(index+1)), big.NewInt(int64(i)), nil)
		tmp := new(big.Int).Mul(a, b)
		share = new(big.Int).Add(share, tmp)
	}
	return new(big.Int).Mod(share, this.nm)
}

func (this *ThresholdKeyGenerator) CreateShares() []*big.Int {
	shares := make([]*big.Int, this.TotalNumberOfDecryptionServers)
	for i := 0; i < this.TotalNumberOfDecryptionServers; i++ {
		shares[i] = this.ComputeShare(i)
	}
	return shares
}

func (this *ThresholdKeyGenerator) Delta() *big.Int {
	return Factorial(this.TotalNumberOfDecryptionServers)
}

func (this *ThresholdKeyGenerator) CreateViArray(shares []*big.Int) (viArray []*big.Int) {
	viArray = make([]*big.Int, len(shares))
	delta := this.Delta()
	for i, share := range shares {
		tmp := new(big.Int).Mul(share, delta)
		viArray[i] = new(big.Int).Exp(this.v, tmp, this.nSquare)
	}
	return viArray
}

func (this *ThresholdKeyGenerator) CreatePrivateKey(i int, share *big.Int, viArray []*big.Int) *ThresholdPrivateKey {
	ret := new(ThresholdPrivateKey)
	ret.N = this.n
	ret.G = new(big.Int).Add(ret.N, ONE)
	ret.V = this.v

	ret.TotalNumberOfDecryptionServers = this.TotalNumberOfDecryptionServers
	ret.Threshold = this.Threshold
	ret.Share = share
	ret.Id = i + 1
	ret.Vi = viArray
	return ret
}

func (this *ThresholdKeyGenerator) CreatePrivateKeys() []*ThresholdPrivateKey {
	shares := this.CreateShares()
	viArray := this.CreateViArray(shares)
	ret := make([]*ThresholdPrivateKey, this.TotalNumberOfDecryptionServers)
	for i := 0; i < this.TotalNumberOfDecryptionServers; i++ {
		ret[i] = this.CreatePrivateKey(i, shares[i], viArray)
	}
	return ret
}

func (this *ThresholdKeyGenerator) Generate() ([]*ThresholdPrivateKey, error) {
	if err := this.InitNumerialValues(); err != nil {
		return nil, err
	}
	if err := this.GenerateHidingPolynomial(); err != nil {
		return nil, err
	}
	return this.CreatePrivateKeys(), nil
}
