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
// `Vi` is an array of verification keys for each decryption server `i` used to
// execute a zero-knowledge proof of a received share decryption.
//
// Key generation, encryption, share decryption and combining for the threshold
// Paillier scheme has been described in [DJN 10], section 5.1.
//
//     [DJN 10]: Ivan Damgard, Mads Jurik, Jesper Buus Nielsen, (2010)
//               A Generalization of Paillier’s Public-Key System
//               with Applications to Electronic Voting
//               Aarhus University, Dept. of Computer Science, BRICS
type ThresholdPublicKey struct {
	PublicKey
	TotalNumberOfDecryptionServers int
	Threshold                      int
	V                              *big.Int   // needed for ZKP
	Vi                             []*big.Int // needed for ZKP
}

// Returns the value of [(4*delta^2)]^-1  mod n.
// It is a constant value for the given `ThresholdKey` and is used in the last
// step of share combining.
func (tk *ThresholdPublicKey) combineSharesConstant() *big.Int {
	tmp := new(big.Int).Mul(FOUR, new(big.Int).Mul(tk.delta(), tk.delta()))
	return (&big.Int{}).ModInverse(tmp, tk.N)
}

// Returns the factorial of the number of `TotalNumberOfDecryptionServers`.
// It is a contant value for the given `ThresholdKey`.
func (tk *ThresholdPublicKey) delta() *big.Int {
	return Factorial(tk.TotalNumberOfDecryptionServers)
}

// Checks if the number of received, unique shares is less than the
// required threshold.
// This method does not execute ZKP on received shares.
func (tk *ThresholdPublicKey) verifyPartialDecryptions(shares []*PartialDecryption) error {
	if len(shares) < tk.Threshold {
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

func (tk *ThresholdPublicKey) updateLambda(share1, share2 *PartialDecryption, lambda *big.Int) *big.Int {
	num := new(big.Int).Mul(lambda, big.NewInt(int64(-share2.Id)))
	denom := big.NewInt(int64(share1.Id - share2.Id))
	return new(big.Int).Div(num, denom)
}

// Evaluates lambda parameter for each decrypted share. See second figure in the
// "Share combining" paragraph in [DJK 10], section 5.2.
func (tk *ThresholdPublicKey) computeLambda(share *PartialDecryption, shares []*PartialDecryption) *big.Int {
	lambda := tk.delta()
	for _, share2 := range shares {
		if share2.Id != share.Id {
			lambda = tk.updateLambda(share, share2, lambda)
		}
	}
	return lambda
}

// Used to evaluate c' parameter which combines individual share decryptions.
//
// Modulo division is performed on the computed exponent to avoid creating
// large numbers. This is possible because of the following property of modulo:
// A^B mod C = (A mod C)^B mod C
//
// Modulo division is performed on the computed coefficient because of the
// following property of modulo:
// (AB) mod C = (A mod C * B mod C) mod C
// Note, we need to combine coefficients into single c'.
func (tk *ThresholdPublicKey) updateCprime(cprime, lambda *big.Int, share *PartialDecryption) *big.Int {
	twoLambda := new(big.Int).Mul(TWO, lambda)
	ret := tk.exp(share.Decryption, twoLambda, tk.GetNSquare())
	ret = new(big.Int).Mul(cprime, ret)
	return new(big.Int).Mod(ret, tk.GetNSquare())
}

// We use `exp` from `updateCprime` to raise decryption share to the power of lambda
// parameter. Since lambda can be a negative number and we do discrete math here,
// we need to apply multiplicative inverse modulo in this case.
//
// For instance, for b = -18:
// b^{−18} = (b^−1)^18, where b^{−1} is the multiplicative inverse modulo c.
func (tk *ThresholdPublicKey) exp(a, b, c *big.Int) *big.Int {
	if b.Cmp(ZERO) == -1 { // b < 0 ?
		ret := new(big.Int).Exp(a, new(big.Int).Neg(b), c)
		return new(big.Int).ModInverse(ret, c)
	}
	return new(big.Int).Exp(a, b, c)
}

// Executes the last step of message decryption. Takes `cprime` value computed
// from valid shares provided by decryption servers and multiplies this value
// by `combineSharesContant` which is specific to the given public `ThresholdKey`.
func (tk *ThresholdPublicKey) computeDecryption(cprime *big.Int) *big.Int {
	l := L(cprime, tk.N)
	return new(big.Int).Mod(new(big.Int).Mul(tk.combineSharesConstant(), l), tk.N)
}

// Combines partial decryptions provided by decryption servers and returns
// decrypted message.
// This function does not verify zero knowledge proofs. Returned message can be
// incorrectly decrypted if an adversary corrupted partial decryption.
func (tk *ThresholdPublicKey) CombinePartialDecryptions(shares []*PartialDecryption) (*big.Int, error) {
	if err := tk.verifyPartialDecryptions(shares); err != nil {
		return nil, err
	}

	cprime := ONE
	for _, share := range shares {
		lambda := tk.computeLambda(share, shares)
		cprime = tk.updateCprime(cprime, lambda, share)
	}

	return tk.computeDecryption(cprime), nil
}

// Combines partial decryptions provided by decryption servers and returns
// full decrypted message.
// Function verifies zero knowledge proofs and filters out all shares that failed
// verification.
func (tk *ThresholdPublicKey) CombinePartialDecryptionsZKP(shares []*PartialDecryptionZKP) (*big.Int, error) {
	ret := make([]*PartialDecryption, 0)
	for _, share := range shares {
		if share.Verify() {
			ret = append(ret, &share.PartialDecryption)
		}
	}
	return tk.CombinePartialDecryptions(ret)
}

// Verifies if the decryption of `encryptedMessage` has been done properly.
// It verifies all the zero-knoledge proofs, the value of the encrypted
// and decrypted message. The method returns `nil` if everything is fine.
// Otherwise, it returns an explicative message.
func (tk *ThresholdPublicKey) VerifyDecryption(encryptedMessage, decryptedMessage *big.Int, shares []*PartialDecryptionZKP) error {
	for _, share := range shares {
		if share.C.Cmp(encryptedMessage) != 0 {
			return errors.New("The encrypted message is not the same than the one in the shares")
		}
	}
	res, err := tk.CombinePartialDecryptionsZKP(shares)
	if err != nil {
		return err
	}
	if res.Cmp(decryptedMessage) != 0 {
		return errors.New("The decrypted message is not the same than the one in the shares")
	}
	return nil
}

// Secret key for a threshold Paillier scheme. Holds skate information
// for the given decryption server.
// `Id` is the unique identifier of a decryption server and `Share` is a secret
// share generated from hiding polynomial and is used for a partial share decryption.
type ThresholdSecretKey struct {
	ThresholdPublicKey
	Id    int
	Share *big.Int
}

// Decrypts the ct text and returns the partial decryption
func (tpk *ThresholdSecretKey) Decrypt(c *big.Int) *PartialDecryption {
	ret := new(PartialDecryption)
	ret.Id = tpk.Id
	exp := new(big.Int).Mul(tpk.Share, new(big.Int).Mul(TWO, tpk.delta()))
	ret.Decryption = new(big.Int).Exp(c, exp, tpk.GetNSquare())

	return ret
}

func (tpk *ThresholdSecretKey) copyVi() []*big.Int {
	ret := make([]*big.Int, len(tpk.Vi))
	for i, vi := range tpk.Vi {
		ret[i] = new(big.Int).Add(vi, big.NewInt(0))
	}
	return ret
}

func (tpk *ThresholdSecretKey) getThresholdKey() *ThresholdPublicKey {
	ret := new(ThresholdPublicKey)
	ret.Threshold = tpk.Threshold
	ret.TotalNumberOfDecryptionServers = tpk.TotalNumberOfDecryptionServers
	ret.V = new(big.Int).Add(tpk.V, big.NewInt(0))
	ret.Vi = tpk.copyVi()
	ret.N = new(big.Int).Add(tpk.N, big.NewInt(0))
	return ret
}

func (tpk *ThresholdSecretKey) computeZ(r, e *big.Int) *big.Int {
	tmp := new(big.Int).Mul(e, tpk.delta())
	tmp = new(big.Int).Mul(tmp, tpk.Share)
	return new(big.Int).Add(r, tmp)
}

func (tpk *ThresholdSecretKey) computeHash(a, b, c4, ci2 *big.Int) *big.Int {
	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	hash.Write(c4.Bytes())
	hash.Write(ci2.Bytes())
	return new(big.Int).SetBytes(hash.Sum([]byte{}))
}

func (tpk *ThresholdSecretKey) DecryptAndProduceZKP(c *big.Int, random io.Reader) (*PartialDecryptionZKP, error) {
	pd := new(PartialDecryptionZKP)
	pd.Key = tpk.getThresholdKey()
	pd.C = c
	pd.Id = tpk.Id
	pd.Decryption = tpk.Decrypt(c).Decryption

	// choose random number
	r, err := rand.Int(random, tpk.GetNSquare())
	if err != nil {
		return nil, err
	}
	//  compute a
	c4 := new(big.Int).Exp(c, FOUR, nil)
	a := new(big.Int).Exp(c4, r, tpk.GetNSquare())

	// compute b
	b := new(big.Int).Exp(tpk.V, r, tpk.GetNSquare())

	// compute hash
	ci2 := new(big.Int).Exp(pd.Decryption, big.NewInt(2), nil)

	pd.E = tpk.computeHash(a, b, c4, ci2)

	pd.Z = tpk.computeZ(r, pd.E)

	return pd, nil
}

// Verifies if the partial decryption key is well formed.  If well formed,
// the method return nil else an explicative error is returned.
func (tpk *ThresholdSecretKey) Validate(random io.Reader) error {
	m, err := rand.Int(random, tpk.N)
	if err != nil {
		return err
	}
	c, err := tpk.Encrypt(m, random)
	if err != nil {
		return err
	}
	proof, err := tpk.DecryptAndProduceZKP(c.C, random)
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

// A non-interactive ZKP based on the Fiat–Shamir heuristic. This algorithm
// proves that the decryption server indeed raised secret to his secret exponent
// (`ThresholdSecretKey.Share`) by comparison with the public verification key
// (`ThresholdKey.Vi`). Recall that v_i = v^(delta s_i).
//
// The Fiat-Shamir is a non-interactive proof of knowledge heuristic.
// The general algorithm is as follows:
//
// - Alice wants to prove that she knows x: the discrete logarithm of y = g^x
//   to the base g
// - Alice picks a random r from Z_q and computes t = g^r
// - Alice computes E = H(t, g, y), where H is a cryptographic hash function
// - Alice computes Z = Ex + r.
//   The resulting proof is the pair (t, Z).
// - Anyone can check whether t = g^Z y^E (mod q)
//
// In our case:
//
// Decryption server i wants to prove that he indeed raised the ciphertext to
// his secret exponent s_i during partial decryption.
// This is essentialy a protocol for the equality of discrete logs,
// log_{c^4}(c_i^2) = log_v(v_i).
//
// ZKP construction
//
// - Pick random r mod n
// - Compute E as:
//   E = HASH(a, b, c^4, c_i^2), where
//     a = (c^4)^r mod n^2
//     b = V^r mod n^2
//     c is a ciphertext,
//     V is a generator from ThresholdKey.V
//     c_i is a partial decryption for this server
// - Compute Z as:
//    delta * E * s_i + r, where
//      delta is the factorial of the number of decryption servers
//      s_i is a secret share for this server
//
// ZKP verification
//
// - Compute the original a from
//   a = a1 * a2 mod n^2
//   a1 = (c^4)^Z
//   a2 = [ (c_i^2)^E ]^-1 mod n^2
// - Compute the original b from
//   b = b1 * b2 mod n^2
//   b1 = V^Z
//   b2 = [ v_i^E ] -1 mod n^2
// - Rehash H(a, b, c^4, c_i^2)
// - Compare ZKP hash with the one just computed
type PartialDecryptionZKP struct {
	PartialDecryption
	Key *ThresholdPublicKey // the public key used to encrypt
	E   *big.Int            // the challenge
	Z   *big.Int            // the value needed to check to verify the decryption
	C   *big.Int            // the input ct text
}

func (pd *PartialDecryptionZKP) verifyPart1() *big.Int {
	c4 := new(big.Int).Exp(pd.C, FOUR, nil)                  // c^4
	decryption2 := new(big.Int).Exp(pd.Decryption, TWO, nil) // c_i^2

	a1 := new(big.Int).Exp(c4, pd.Z, pd.Key.GetNSquare())          // (c^4)^Z
	a2 := new(big.Int).Exp(decryption2, pd.E, pd.Key.GetNSquare()) // (c_i^2)^E
	a2 = new(big.Int).ModInverse(a2, pd.Key.GetNSquare())
	a := new(big.Int).Mod(new(big.Int).Mul(a1, a2), pd.Key.GetNSquare())
	return a
}

func (pd *PartialDecryptionZKP) verifyPart2() *big.Int {
	vi := pd.Key.Vi[pd.Id-1]                                    // servers are indexed from 1
	b1 := new(big.Int).Exp(pd.Key.V, pd.Z, pd.Key.GetNSquare()) // V^Z
	b2 := new(big.Int).Exp(vi, pd.E, pd.Key.GetNSquare())       // (v_i)^E
	b2 = new(big.Int).ModInverse(b2, pd.Key.GetNSquare())
	b := new(big.Int).Mod(new(big.Int).Mul(b1, b2), pd.Key.GetNSquare())
	return b
}

func (pd *PartialDecryptionZKP) Verify() bool {
	a := pd.verifyPart1()
	b := pd.verifyPart2()
	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	c4 := new(big.Int).Exp(pd.C, FOUR, nil)
	hash.Write(c4.Bytes())
	ci2 := new(big.Int).Exp(pd.Decryption, TWO, nil)
	hash.Write(ci2.Bytes())

	expectedE := new(big.Int).SetBytes(hash.Sum([]byte{}))
	return pd.E.Cmp(expectedE) == 0
}
