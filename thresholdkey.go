package paillier

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
)

// Public key for a threshold Paillier scheme.
//
// `V` is a generator in  the cyclic group of squares Z_n^2 and is used to
// execute a zero-knowledge proof of a received share decryption.
//
// `Vi` is an array of verification keys for each decryption server `i`.
//
// Key generation, encryption, share decryption and combining for the threshold
// Paillier scheme has been described in [DJN 10], section 5.1.
//
//     [DJN 10]: Ivan Damgard, Mads Jurik, Jesper Buus Nielsen, (2010)
//               A Generalization of Paillier’s Public-Key System
//               with Applications to Electronic Voting
//               Aarhus University, Dept. of Computer Science, BRICS
type ThresholdKey struct {
	PublicKey
	TotalNumberOfDecryptionServers int
	Threshold                      int
	V                              *big.Int
	Vi                             []*big.Int
}

// Returns the value of [(4*delta^2)]^-1  mod n.
// It is a constant value for the given `ThresholdKey` and is used in the last
// step of share combining.
func (this *ThresholdKey) combineSharesConstant() *big.Int {
	tmp := new(big.Int).Mul(FOUR, new(big.Int).Mul(this.delta(), this.delta()))
	return (&big.Int{}).ModInverse(tmp, this.N)
}

// Returns the factorial of the number of `TotalNumberOfDecryptionServers`.
// It is a contant value for the given `ThresholdKey`.
func (this *ThresholdKey) delta() *big.Int {
	return Factorial(this.TotalNumberOfDecryptionServers)
}

// Checks if the number of received, unique shares is less than the
// required threshold.
// This method does not execute ZKP on received shares.
func (this *ThresholdKey) makeVerificationBeforeCombiningPartialDecryptions(shares []*PartialDecryption) error {
	if len(shares) < this.Threshold {
		return errors.New("Threshold not meet")
	}
	tmp := make(map[int]bool)
	for _, share := range shares {
		tmp[share.Id] = true
	}
	if len(tmp) != len(shares) {
		return errors.New("two shares has been created by the same server")
	}
	return nil
}

func (this *ThresholdKey) updateLambda(share1, share2 *PartialDecryption, lambda *big.Int) *big.Int {
	num := new(big.Int).Mul(lambda, big.NewInt(int64(-share2.Id)))
	denom := big.NewInt(int64(share1.Id - share2.Id))
	return new(big.Int).Div(num, denom)
}

// Evaluates lambda parameter for each decrypted share. See second figure in the
// "Share combining" paragraph in [DJK 10], section 5.2.
func (this *ThresholdKey) computeLambda(share *PartialDecryption, shares []*PartialDecryption) *big.Int {
	lambda := this.delta()
	for _, share2 := range shares {
		if share2.Id != share.Id {
			lambda = this.updateLambda(share, share2, lambda)
		}
	}
	return lambda
}

func (this *ThresholdKey) updateCprime(cprime, lambda *big.Int, share *PartialDecryption) *big.Int {
	twoLambda := new(big.Int).Mul(TWO, lambda)
	ret := this.exp(share.Decryption, twoLambda, this.GetNSquare())
	ret = new(big.Int).Mul(cprime, ret)
	return new(big.Int).Mod(ret, this.GetNSquare())
}

// TODO: unused? kill?
func (this *ThresholdKey) divide(a, b *big.Int) *big.Int {
	if a.Cmp(ZERO) == -1 {
		if b.Cmp(ZERO) == -1 {
			return new(big.Int).Div(new(big.Int).Neg(a), new(big.Int).Neg(b))
		}
		return new(big.Int).Neg(new(big.Int).Div(new(big.Int).Neg(a), b))
	}
	return new(big.Int).Div(a, b)
}

func (this *ThresholdKey) exp(a, b, c *big.Int) *big.Int {
	if b.Cmp(ZERO) == -1 {
		ret := new(big.Int).Exp(a, new(big.Int).Neg(b), c)
		return new(big.Int).ModInverse(ret, c)
	}
	return new(big.Int).Exp(a, b, c)

}

// Executes the last step of message decryption. Takes `cprime` value computed
// from valid shares provided by decryption servers and multiplies this value
// by `combineSharesContant` which is specific to the given public `ThresholdKey`.
func (this *ThresholdKey) computeDecryption(cprime *big.Int) *big.Int {
	l := L(cprime, this.N)
	return new(big.Int).Mod(new(big.Int).Mul(this.combineSharesConstant(), l), this.N)
}

// Combines partial decryptions provided by decryption servers and returns
// decrypted message.
// This function does not verify zero knowledge proofs. Returned message can be
// incorrectly decrypted if an adversary corrupted partial decryption.
func (this *ThresholdKey) CombinePartialDecryptions(shares []*PartialDecryption) (*big.Int, error) {
	if err := this.makeVerificationBeforeCombiningPartialDecryptions(shares); err != nil {
		return nil, err
	}

	cprime := ONE
	for _, share := range shares {
		lambda := this.computeLambda(share, shares)
		cprime = this.updateCprime(cprime, lambda, share)
	}

	return this.computeDecryption(cprime), nil
}

// Combines partial decryptions provided by decription servers and returns
// decrypted message.
// Function verifies zero knowledge proofs and filters out all shares that failed
// verification.
func (this *ThresholdKey) CombinePartialDecryptionsZKP(shares []*PartialDecryptionZKP) (*big.Int, error) {
	ret := make([]*PartialDecryption, 0)
	for _, share := range shares {
		if share.Verify() {
			ret = append(ret, &share.PartialDecryption)
		}
	}
	return this.CombinePartialDecryptions(ret)
}

//  Verify if the decryption of `encryptedMessage` has well been done.
//  It verifies all the zero-knoledge proofs, the value of the decrypted
//  and decrypted message.
//  The method returns `nil` if everything is good.  Otherwise it returns an
//  explicative message
func (this *ThresholdKey) VerifyDecryption(encryptedMessage, decryptedMessage *big.Int, shares []*PartialDecryptionZKP) error {
	for _, share := range shares {
		if share.C.Cmp(encryptedMessage) != 0 {
			return errors.New("The encrypted message is not the same than the one in the shares")
		}
	}
	res, err := this.CombinePartialDecryptionsZKP(shares)
	if err != nil {
		return err
	}
	if res.Cmp(decryptedMessage) != 0 {
		return errors.New("The decrypted message is not the same than the one in the shares")
	}
	return nil
}

type ThresholdPrivateKey struct {
	ThresholdKey
	Id    int
	Share *big.Int
}

//  Decrypt the cypher text and returns the partial decryption
func (this *ThresholdPrivateKey) Decrypt(c *big.Int) *PartialDecryption {
	ret := new(PartialDecryption)
	ret.Id = this.Id
	exp := new(big.Int).Mul(this.Share, new(big.Int).Mul(TWO, this.delta()))
	ret.Decryption = new(big.Int).Exp(c, exp, this.GetNSquare())

	return ret
}

func (this *ThresholdPrivateKey) copyVi() []*big.Int {
	ret := make([]*big.Int, len(this.Vi))
	for i, vi := range this.Vi {
		ret[i] = new(big.Int).Add(vi, big.NewInt(0))
	}
	return ret
}

func (this *ThresholdPrivateKey) getThresholdKey() *ThresholdKey {
	ret := new(ThresholdKey)
	ret.Threshold = this.Threshold
	ret.TotalNumberOfDecryptionServers = this.TotalNumberOfDecryptionServers
	ret.V = new(big.Int).Add(this.V, big.NewInt(0))
	ret.Vi = this.copyVi()
	ret.N = new(big.Int).Add(this.N, big.NewInt(0))
	return ret
}

func (this *ThresholdPrivateKey) computeZ(r, e *big.Int) *big.Int {
	tmp := new(big.Int).Mul(e, this.delta())
	tmp = new(big.Int).Mul(tmp, this.Share)
	return new(big.Int).Add(r, tmp)
}

func (this *ThresholdPrivateKey) computeHash(a, b, c4, ci2 *big.Int) *big.Int {
	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	hash.Write(c4.Bytes())
	hash.Write(ci2.Bytes())
	return new(big.Int).SetBytes(hash.Sum([]byte{}))
}

func (this *ThresholdPrivateKey) DecryptAndProduceZNP(c *big.Int, random io.Reader) (*PartialDecryptionZKP, error) {
	pd := new(PartialDecryptionZKP)
	pd.Key = this.getThresholdKey()
	pd.C = c
	pd.Id = this.Id
	pd.Decryption = this.Decrypt(c).Decryption

	// choose random number
	r, err := rand.Int(random, this.GetNSquare())
	if err != nil {
		return nil, err
	}
	//  compute a
	c4 := new(big.Int).Exp(c, FOUR, nil)
	a := new(big.Int).Exp(c4, r, this.GetNSquare())

	// compute b
	b := new(big.Int).Exp(this.V, r, this.GetNSquare())

	// compute hash
	ci2 := new(big.Int).Exp(pd.Decryption, big.NewInt(2), nil)

	pd.E = this.computeHash(a, b, c4, ci2)

	pd.Z = this.computeZ(r, pd.E)

	return pd, nil
}

//  Verify if the partial decryption key is well formed.  If well formed,
//  the method return nil else an explicative error is returned.
func (this *ThresholdPrivateKey) Validate(random io.Reader) error {
	m, err := rand.Int(random, this.N)
	if err != nil {
		return err
	}
	c, err := this.Encrypt(m, random)
	if err != nil {
		return err
	}
	proof, err := this.DecryptAndProduceZNP(c.C, random)
	if err != nil {
		return err
	}
	if !proof.Verify() {
		return errors.New("invalid share.")
	}
	return nil
}

type PartialDecryption struct {
	Id         int
	Decryption *big.Int
}

type PartialDecryptionZKP struct {
	PartialDecryption
	Key *ThresholdKey // the public key used to encrypt
	E   *big.Int      // the challenge
	Z   *big.Int      // the value needed to check to verify the decryption
	C   *big.Int      // the input cypher text

}

func (this *PartialDecryptionZKP) verifyPart1() *big.Int {
	c4 := new(big.Int).Exp(this.C, FOUR, nil)
	decryption2 := new(big.Int).Exp(this.Decryption, TWO, nil)

	a1 := new(big.Int).Exp(c4, this.Z, this.Key.GetNSquare())
	a2 := new(big.Int).Exp(decryption2, this.E, this.Key.GetNSquare())
	a2 = new(big.Int).ModInverse(a2, this.Key.GetNSquare())
	a := new(big.Int).Mod(new(big.Int).Mul(a1, a2), this.Key.GetNSquare())
	return a
}

func (this *PartialDecryptionZKP) neg(n *big.Int) *big.Int {
	return new(big.Int).Neg(n)
}

func (this *PartialDecryptionZKP) verifyPart2() *big.Int {
	vi := this.Key.Vi[this.Id-1]
	b1 := new(big.Int).Exp(this.Key.V, this.Z, this.Key.GetNSquare())
	b2 := new(big.Int).Exp(vi, this.E, this.Key.GetNSquare())
	b2 = new(big.Int).ModInverse(b2, this.Key.GetNSquare())
	b := new(big.Int).Mod(new(big.Int).Mul(b1, b2), this.Key.GetNSquare())
	return b
}

func (this *PartialDecryptionZKP) Verify() bool {
	a := this.verifyPart1()
	b := this.verifyPart2()
	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	c4 := new(big.Int).Exp(this.C, FOUR, nil)
	hash.Write(c4.Bytes())
	ci2 := new(big.Int).Exp(this.Decryption, TWO, nil)
	hash.Write(ci2.Bytes())

	expectedE := new(big.Int).SetBytes(hash.Sum([]byte{}))
	return this.E.Cmp(expectedE) == 0
}
