package paillier

import (
	"fmt"
	"io"
	"math/big"
)

type PublicKey struct {
	N *big.Int
}

func (this *PublicKey) GetNSquare() *big.Int {
	return new(big.Int).Mul(this.N, this.N)
}

// Encode a plaintext in a cypher one. The plain text must be smaller that
// N and bigger or equal than zero. random is usually rand.Reader from the
// package crypto/rand.
//
// m - plaintext to encrypt
// E(m, r) = [(1 + N) r^N] mod N^2
//
// See [KL 08] construction 11.32, page 414.
//
// Returns an error if an error has be returned by io.Reader.
func (pub *PublicKey) Encrypt(m *big.Int, random io.Reader) (*Cypher, error) {
	r, err := GetRandomNumberInMultiplicativeGroup(pub.N, random)
	if err != nil {
		return nil, err
	}
	nSquare := pub.GetNSquare()

	// g is _always_ equal n+1
	// Threshold encryption is safe only for g=n+1 choice.
	// See [DJN 10], section 5.1
	g := new(big.Int).Add(pub.N, big.NewInt(1))
	gm := new(big.Int).Exp(g, m, nSquare)
	rn := new(big.Int).Exp(r, pub.N, nSquare)
	return &Cypher{new(big.Int).Mod(new(big.Int).Mul(rn, gm), nSquare)}, nil
}

// Add takes an arbitrary number of cyphertexts and returns one that encodes
// their sum.
//
// It's possible because Paillier is a homomorphic encryption scheme, where
// E(m1) * E(m2) = E(m1 + m2)
func (pub *PublicKey) Add(cypher ...*Cypher) *Cypher {
	accumulator := big.NewInt(1)

	for _, c := range cypher {
		accumulator = new(big.Int).Mod(
			new(big.Int).Mul(accumulator, c.C),
			pub.GetNSquare(),
		)
	}

	return &Cypher{
		C: accumulator,
	}
}

type PrivateKey struct {
	PublicKey
	Lambda *big.Int
}

// Decodes ciphertext into a plaintext message.
//
// c - cyphertext to decrypt
// N, lambda - key attributes
//
// D(c) = [ ((c^lambda) mod N^2) - 1) / N ] lambda^-1 mod N
//
// See [KL 08] construction 11.32, page 414.
func (priv *PrivateKey) Decrypt(cypher *Cypher) (msg *big.Int) {
	mu := new(big.Int).ModInverse(priv.Lambda, priv.N)
	tmp := new(big.Int).Exp(cypher.C, priv.Lambda, priv.GetNSquare())
	msg = new(big.Int).Mod(new(big.Int).Mul(L(tmp, priv.N), mu), priv.N)
	return
}

type Cypher struct {
	C *big.Int
}

func (this *Cypher) String() string {
	return fmt.Sprintf("%x", this.C)
}

func L(u, n *big.Int) *big.Int {
	t := new(big.Int).Add(u, big.NewInt(-1))
	return new(big.Int).Div(t, n)
}

func minusOne(x *big.Int) *big.Int {
	return new(big.Int).Add(x, big.NewInt(-1))
}

func computePhi(p, q *big.Int) *big.Int {
	return new(big.Int).Mul(minusOne(p), minusOne(q))
}

// CreatePrivateKey generates a Paillier private key accepting two large prime
// numbers of equal length or other such that gcd(pq, (p-1)(q-1)) = 1.
//
// Algorithm is based on approach described in [KL 08], construction 11.32,
// page 414 which is compatible with one described in [DJN 10], section 3.2
// except that instead of generating Lambda private key component from LCM
// of p and q we use Euler's totient function as suggested in [KL 08].
//
//     [KL 08]:  Jonathan Katz, Yehuda Lindell, (2008)
//               Introduction to Modern Cryptography: Principles and Protocols,
//               Chapman & Hall/CRC
//
//     [DJN 10]: Ivan Damgard, Mads Jurik, Jesper Buus Nielsen, (2010)
//               A Generalization of Paillier’s Public-Key System
//               with Applications to Electronic Voting
//               Aarhus University, Dept. of Computer Science, BRICS
func CreatePrivateKey(p, q *big.Int) *PrivateKey {
	n := new(big.Int).Mul(p, q)
	lambda := computePhi(p, q)

	return &PrivateKey{
		PublicKey: PublicKey{
			N: n,
		},
		Lambda: lambda,
	}
}
