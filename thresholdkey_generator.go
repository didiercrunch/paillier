package paillier

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"time"
)

// Generates a threshold Paillier key with an algorithm based on [DJN 10],
// section 5.1, "Key generation".
//
// Bear in mind that the algorithm assumes an existence of a trusted dealer
// to generate and distribute the keys.
//
//
//     [DJN 10]: Ivan Damgard, Mads Jurik, Jesper Buus Nielsen, (2010)
//               A Generalization of Paillier’s Public-Key System
//               with Applications to Electronic Voting
//               Aarhus University, Dept. of Computer Science, BRICS
type ThresholdKeyGenerator struct {
	publicKeyBitLength             int
	TotalNumberOfDecryptionServers int
	Threshold                      int
	Random                         io.Reader

	// Both p1 and q1 are primes of length nbits - 1
	p1 *big.Int
	q1 *big.Int

	p       *big.Int // p is prime and p=2*p1+1
	q       *big.Int // q is prime and q=2*q1+1
	n       *big.Int // n=p*q
	m       *big.Int // m = p1*q1
	nSquare *big.Int // nSquare = n*n
	nm      *big.Int // nm = n*m

	// As specified in the paper, d must satify d=1 mod n and d=0 mod m
	d *big.Int

	// A generator of QR in Z_{n^2}
	v *big.Int

	// The polynomial coefficients to hide a secret. See Shamir.
	polynomialCoefficients []*big.Int
}

// GetThresholdKeyGenerator is a preferable way to construct the
// ThresholdKeyGenerator.
// Due to the various properties that must be met for the threshold key to be
// considered valid, the minimum public key `N` bit length is 18 bits.
// The plaintext space for the key will be `Z_N`.
func GetThresholdKeyGenerator(
	publicKeyBitLength int,
	totalNumberOfDecryptionServers int,
	threshold int,
	random io.Reader,
) (*ThresholdKeyGenerator, error) {
	if publicKeyBitLength < 18 {
		return nil, errors.New("Public key bit length must be at least 18 bits")
	}

	generator := new(ThresholdKeyGenerator)
	generator.publicKeyBitLength = publicKeyBitLength
	generator.TotalNumberOfDecryptionServers = totalNumberOfDecryptionServers
	generator.Threshold = threshold
	generator.Random = random
	return generator, nil
}

func (tkg *ThresholdKeyGenerator) generateSafePrimes() (*big.Int, *big.Int, error) {
	concurrencyLevel := 4
	timeout := 120 * time.Second
	safePrimeBitLength := tkg.publicKeyBitLength / 2

	return GenerateSafePrime(safePrimeBitLength, concurrencyLevel, timeout, tkg.Random)
}

func (tkg *ThresholdKeyGenerator) initPandP1() error {
	var err error
	tkg.p, tkg.p1, err = tkg.generateSafePrimes()
	return err
}

func (tkg *ThresholdKeyGenerator) initQandQ1() error {
	var err error
	tkg.q, tkg.q1, err = tkg.generateSafePrimes()
	return err
}

func (tkg *ThresholdKeyGenerator) initShortcuts() {
	tkg.n = new(big.Int).Mul(tkg.p, tkg.q)
	tkg.m = new(big.Int).Mul(tkg.p1, tkg.q1)
	tkg.nSquare = new(big.Int).Mul(tkg.n, tkg.n)
	tkg.nm = new(big.Int).Mul(tkg.n, tkg.m)
}

func (tkg *ThresholdKeyGenerator) arePsAndQsGood() bool {
	if tkg.p.Cmp(tkg.q) == 0 {
		return false
	}
	if tkg.p.Cmp(tkg.q1) == 0 {
		return false
	}
	if tkg.p1.Cmp(tkg.q) == 0 {
		return false
	}
	return true
}

func (tkg *ThresholdKeyGenerator) initPsAndQs() error {
	if err := tkg.initPandP1(); err != nil {
		return err
	}
	if err := tkg.initQandQ1(); err != nil {
		return err
	}
	if !tkg.arePsAndQsGood() {
		return tkg.initPsAndQs()
	}
	return nil
}

// v generates a cyclic group of squares in Zn^2.
func (tkg *ThresholdKeyGenerator) computeV() error {
	var err error
	tkg.v, err = GetRandomGeneratorOfTheQuadraticResidue(tkg.nSquare, tkg.Random)
	return err
}

// Choose d such that d=0 (mod m) and d=1 (mod n).
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
func (tkg *ThresholdKeyGenerator) initD() {
	mInverse := new(big.Int).ModInverse(tkg.m, tkg.n)
	tkg.d = new(big.Int).Mul(mInverse, tkg.m)
}

func (tkg *ThresholdKeyGenerator) initNumerialValues() error {
	if err := tkg.initPsAndQs(); err != nil {
		return err
	}
	tkg.initShortcuts()
	tkg.initD()
	return tkg.computeV()
}

// f(X) = a_0 X^0 + a_1 X^1 + ... + a_(w-1) X^(w-1)
//
// where:
// `w` - threshold
// `a_i` - random value from {0, ... nm - 1} for 0<i<w
// `a_0` is always equal `d`
func (tkg *ThresholdKeyGenerator) generateHidingPolynomial() error {
	tkg.polynomialCoefficients = make([]*big.Int, tkg.Threshold)
	tkg.polynomialCoefficients[0] = tkg.d
	var err error
	for i := 1; i < tkg.Threshold; i++ {
		tkg.polynomialCoefficients[i], err = rand.Int(tkg.Random, tkg.nm)
		if err != nil {
			return err
		}
	}
	return nil
}

// The secred share of the i'th authority is `f(i) mod nm`, where `f` is
// the polynomial we generated in `GenerateHidingPolynomial` function.
func (tkg *ThresholdKeyGenerator) computeShare(index int) *big.Int {
	share := big.NewInt(0)
	for i := 0; i < tkg.Threshold; i++ {
		a := tkg.polynomialCoefficients[i]
		// we index authorities from 1, that's why we do index+1 here
		b := new(big.Int).Exp(big.NewInt(int64(index+1)), big.NewInt(int64(i)), nil)
		tmp := new(big.Int).Mul(a, b)
		share = new(big.Int).Add(share, tmp)
	}
	return new(big.Int).Mod(share, tkg.nm)
}

func (tkg *ThresholdKeyGenerator) createShares() []*big.Int {
	shares := make([]*big.Int, tkg.TotalNumberOfDecryptionServers)
	for i := 0; i < tkg.TotalNumberOfDecryptionServers; i++ {
		shares[i] = tkg.computeShare(i)
	}
	return shares
}

func (tkg *ThresholdKeyGenerator) delta() *big.Int {
	return Factorial(tkg.TotalNumberOfDecryptionServers)
}

// Generates verification keys for actions of decryption servers.
//
// For each decryption server `i`, we generate
// v_i = v^(l! s_i) mod n^2
//
// where:
// `l` is the number of decryption servers
// `s_i` is a secret share for server `i`.
// Secret shares were previously generated in the `CrateShares` function.
func (tkg *ThresholdKeyGenerator) createViArray(shares []*big.Int) (viArray []*big.Int) {
	viArray = make([]*big.Int, len(shares))
	delta := tkg.delta()
	for i, share := range shares {
		tmp := new(big.Int).Mul(share, delta)
		viArray[i] = new(big.Int).Exp(tkg.v, tmp, tkg.nSquare)
	}
	return viArray
}

func (tkg *ThresholdKeyGenerator) createPrivateKey(i int, share *big.Int, viArray []*big.Int) *ThresholdPrivateKey {
	ret := new(ThresholdPrivateKey)
	ret.N = tkg.n
	ret.V = tkg.v

	ret.TotalNumberOfDecryptionServers = tkg.TotalNumberOfDecryptionServers
	ret.Threshold = tkg.Threshold
	ret.Share = share
	ret.Id = i + 1
	ret.Vi = viArray
	return ret
}

func (tkg *ThresholdKeyGenerator) createPrivateKeys() []*ThresholdPrivateKey {
	shares := tkg.createShares()
	viArray := tkg.createViArray(shares)
	ret := make([]*ThresholdPrivateKey, tkg.TotalNumberOfDecryptionServers)
	for i := 0; i < tkg.TotalNumberOfDecryptionServers; i++ {
		ret[i] = tkg.createPrivateKey(i, shares[i], viArray)
	}
	return ret
}

func (tkg *ThresholdKeyGenerator) Generate() ([]*ThresholdPrivateKey, error) {
	if err := tkg.initNumerialValues(); err != nil {
		return nil, err
	}
	if err := tkg.generateHidingPolynomial(); err != nil {
		return nil, err
	}
	return tkg.createPrivateKeys(), nil
}
