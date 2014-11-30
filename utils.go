package paillier

import (
	"crypto/rand"
	"io"
	"math/big"
)

var ZERO = big.NewInt(0)
var ONE = big.NewInt(1)
var TWO = big.NewInt(2)
var FOUR = big.NewInt(4)

//  returns n! = n*(n-1)*(n-2)...3*2*1
func Factorial(n int) *big.Int {
	ret := big.NewInt(1)
	for i := 1; i <= n; i++ {
		ret = new(big.Int).Mul(ret, big.NewInt(int64(i)))
	}
	return ret
}

//  Returns 2 primes such that p = 2 * q + 1 and that the length of
//  p is nbits.  `p` is called a safe prime
func GenerateSafePrimes(nbits int, random io.Reader) (p, q *big.Int, err error) {
	for {
		q, err = rand.Prime(random, nbits-1)
		if err != nil {
			return
		}
		p = (new(big.Int)).Mul(q, big.NewInt(2))
		p = p.Add(p, big.NewInt(1))
		if p.ProbablyPrime(50) { //a probability of 2**-100 of not being prime
			return
		}
	}
}

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomNumberInMultiplicativeGroup(n *big.Int, random io.Reader) (*big.Int, error) {
	r, err := rand.Int(random, n)
	if err != nil {
		return nil, err
	}
	zero := big.NewInt(0)
	one := big.NewInt(1)
	if zero.Cmp(r) == 0 || one.Cmp(new(big.Int).GCD(nil, nil, n, r)) != 0 {
		return GetRandomNumberInMultiplicativeGroup(n, random)
	}
	return r, nil

}

//  Return a random generator of RQn with high probability.  THIS METHOD
//  ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES! This heuristic is used
//  threshold signature paper in the Victor Shoup
func GetRandomGeneratorOfTheQuadraticResidue(n *big.Int, rand io.Reader) (*big.Int, error) {
	r, err := GetRandomNumberInMultiplicativeGroup(n, rand)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mod(new(big.Int).Mul(r, r), n), nil
}
