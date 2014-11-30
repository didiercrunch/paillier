package paillier

import (
	"fmt"
	"io"
	"math/big"
)

type PublicKey struct {
	N, G *big.Int // usually G is set to N+1
	n2   *big.Int // the cache value of N^2
}

func (this *PublicKey) GetBSON() (interface{}, error) {
	m := make(map[string]string)
	m["g"] = fmt.Sprintf("%x", this.G)
	m["n"] = fmt.Sprintf("%x", this.N)
	return m, nil
}

func (this *PublicKey) GetNSquare() *big.Int {
	if this.n2 != nil {
		return this.n2
	}
	this.n2 = new(big.Int).Mul(this.N, this.N)
	return this.n2
}

// Encode a plain text in a cypher one.  The plain text must be smaller that
// N and bigger or equal than zero.  random is usually rand.Reader from the
// package crypto/rand.
//
// Returns an error if an error has be returned by io.Reader.
func (pub *PublicKey) Encrypt(m *big.Int, random io.Reader) (*Cypher, error) {
	r, err := GetRandomNumberInMultiplicativeGroup(pub.N, random)
	if err != nil {
		return nil, err
	}
	nSquare := pub.GetNSquare()

	gm := new(big.Int).Exp(pub.G, m, nSquare)
	rn := new(big.Int).Exp(r, pub.N, nSquare)
	return &Cypher{new(big.Int).Mod(new(big.Int).Mul(rn, gm), nSquare)}, nil
}

// Takes two cypher texts and returns a 3rd one that encode
// the sum of the two plain texts.
func (this *PublicKey) Add(cypher1, cypher2 *Cypher) *Cypher {
	m := new(big.Int).Mul(cypher1.C, cypher2.C)
	return &Cypher{new(big.Int).Mod(m, this.GetNSquare())}
}

type PrivateKey struct {
	PublicKey
	Lambda, Mu *big.Int
}

func (this *PrivateKey) String() string {
	ret := fmt.Sprintf("g     :  %x", this.G)
	ret += fmt.Sprintf("n     :  %x", this.N)
	ret += fmt.Sprintf("lambda:  %x", this.Lambda)
	ret += fmt.Sprintf("mu    :  %x", this.Mu)
	return ret
}

func (priv *PrivateKey) Decrypt(cypher *Cypher) (msg *big.Int) {
	tmp := new(big.Int).Exp(cypher.C, priv.Lambda, priv.GetNSquare())
	msg = new(big.Int).Mod(new(big.Int).Mul(L(tmp, priv.N), priv.Mu), priv.N)
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

func LCM(x, y *big.Int) *big.Int {
	return new(big.Int).Mul(new(big.Int).Div(x, new(big.Int).GCD(nil, nil, x, y)), y)
}

func minusOne(x *big.Int) *big.Int {
	return new(big.Int).Add(x, big.NewInt(-1))
}

func computeMu(g, lambda, n *big.Int) *big.Int {
	n2 := new(big.Int).Mul(n, n)
	u := new(big.Int).Exp(g, lambda, n2)
	return new(big.Int).ModInverse(L(u, n), n)
}

func computeLamda(p, q *big.Int) *big.Int {
	return LCM(minusOne(p), minusOne(q))
}

func CreatePrivateKey(p, q *big.Int) *PrivateKey {
	n := new(big.Int).Mul(p, q)
	lambda := new(big.Int).Mul(minusOne(p), minusOne(q))
	g := new(big.Int).Add(n, big.NewInt(1))
	mu := new(big.Int).ModInverse(lambda, n)
	return &PrivateKey{
		PublicKey: PublicKey{
			N: n,
			G: g,
		},
		Lambda: lambda,
		Mu:     mu,
	}
}
