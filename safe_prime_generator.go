// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The code is the original Go implementation of rand.Prime optimized for
// generating safe (Sophie Germain) primes.
// A safe prime is a prime number of the form 2p + 1, where p is also a prime.

package paillier

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"
)

// smallPrimes is a list of small, prime numbers that allows us to rapidly
// exclude some fraction of composite candidates when searching for a random
// prime. This list is truncated at the point where smallPrimesProduct exceeds
// a uint64. It does not include two because we ensure that the candidates are
// odd by construction.
var smallPrimes = []uint8{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

// smallPrimesProduct is the product of the values in smallPrimes and allows us
// to reduce a candidate prime by this number and then determine whether it's
// coprime to all the elements of smallPrimes without further big.Int
// operations.
var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)

// GenerateSafePrime tries to find a safe prime concurrently.
// The returned result is a safe prime `p` and prime `q` such that `p=2q+1`.
// Concurrency level can be controlled with the `concurrencyLevel` parameter.
// If a safe prime could not be found in the specified `timeout`, the error
// is returned. Also, if at least one search process failed, error is returned
// as well.
//
// How fast we generate a prime number is mostly a matter of luck and it depends
// on how lucky we are with drawing the first bytes.
// With today's multicore processors, we can execute the process on multiple
// cores concurrently, accept the first valid result and cancel the rest of
// work. This way, with the same finding algorithm, we can get the result
// faster.
//
// Concurrency level should be set depending on what `bitLen` of prime is
// expected. For example, as of today, on a typical workstation, for 512-bit
// safe prime, `concurrencyLevel` should be set to `1` as generating the prime
// of this length is a matter of milliseconds for a single core.
// For 1024-bit safe prime, `concurrencyLevel` should be usually set to at least
// `2` and for 2048-bit safe prime, `concurrencyLevel` must be set to at least
// `4` to get the result in a reasonable time.
//
// This function generates safe primes of at least 6 `bitLen`. For every
// generated safe prime, the two most significant bits are always set to `1`
// - we don't want the generated number to be too small.
func GenerateSafePrime(
	bitLen int,
	concurrencyLevel int,
	timeout time.Duration,
) (p *big.Int, q *big.Int, err error) {
	if bitLen < 6 {
		return nil, nil, errors.New("safe prime size must be at least 6 bits")
	}

	primeChan := make(chan safePrime, 1)
	errChan := make(chan error, 1)

	defer close(primeChan)
	defer close(errChan)

	mutex := &sync.Mutex{}
	waitGroup := &sync.WaitGroup{}
	waitGroup.Add(concurrencyLevel)

	ctx, cancel := context.WithCancel(context.Background())

	for i := 0; i < concurrencyLevel; i++ {
		runGenPrimeRoutine(
			ctx, primeChan, errChan, mutex, waitGroup, rand.Reader, bitLen,
		)
	}

	// Cancel after the specified timeout.
	go func() {
		time.Sleep(timeout)
		mutex.Lock()
		cancel()
		mutex.Unlock()
	}()

	select {
	case result := <-primeChan:
		mutex.Lock()
		cancel()
		mutex.Unlock()
		p, q, err = result.p, result.q, nil
	case err := <-errChan:
		mutex.Lock()
		cancel()
		mutex.Unlock()
		p, q, err = nil, nil, err
	case <-ctx.Done():
		p, q, err = nil, nil, fmt.Errorf("generator timed out after %v", timeout)
	}

	waitGroup.Wait()
	return
}

type safePrime struct {
	p *big.Int // p = 2q + 1
	q *big.Int
}

// Starts a Goroutine searching for a safe prime of the specified `pBitLen`.
// If succeeds, writes prime `p` and prime `q` such that `p = 2q+1` to the
// `primeChan`. Prime `p` has a bit length equal to `pBitLen` and prime `q` has
// a bit length equal to `pBitLen-1`.
//
// The algorithm is as follows:
// 1. Generate a random odd number `q` of length `pBitLen-1` with two the most
//    significant bytes set to `1`.
// 2. Execute preliminary primality test on `q` checking whether it is coprime
//    to all the elements of `smallPrimes`. It allows to eliminate trivial
//    cases quickly, when `q` is obviously no prime, without running an
//    expensive final primality tests.
//    If `q` is coprime to all of the `smallPrimes`, then go to the point 3.
//    If not, add `2` and try again. Do it at most 10 times.
// 3. Check the potentially prime `q`, whether `q = 1 (mod 3)`. This will
//    happen for 50% of cases.
//    If it is, then `p = 2q+1` will be a multiple of 3, so it will be obviously
//    not a prime number. In this case, add `2` and try again. Do it at most 10
//    times. If `q != 1 (mod 3)`, go to the point 4.
// 4. Now we know `q` is potentially prime and `p = 2q+1` is not a multiple of
//    3. We execute a preliminary primality test on `p`, checking whether
//    it is coprime to all the elements of `smallPrimes` just like we did for
//    `q` in point 2. If `p` is not coprime to at least one element of the
//    `smallPrimes`, then go back to point 1.
//    If `p` is coprime to all the elements of `smallPrimes`, go to point 5.
// 5. At this point, we know `q` is potentially prime, and `p=q+1` is also
//    potentially prime. We need to execute a final primality test for `q`.
//    We apply Miller-Rabin and Baillie-PSW tests. If they succeeds, it means
//    that `q` is prime with a very high probability. Knowing `q` is prime,
//    we use Pocklington's criterion to prove the primality of `p=2q+1`, that
//    is, we execute Fermat primality test to base 2 checking whether
//    `2^{p-1} = 1 (mod p)`. It's significantly faster than running full
//    Miller-Rabin and Baillie-PSW for `p`.
//    If `q` and `p` are found to be prime, return them as a result. If not, go
//    back to the point 1.
func runGenPrimeRoutine(
	ctx context.Context,
	primeChan chan safePrime,
	errChan chan error,
	mutex *sync.Mutex,
	waitGroup *sync.WaitGroup,
	rand io.Reader,
	pBitLen int,
) {
	qBitLen := pBitLen - 1
	b := uint(qBitLen % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (qBitLen+7)/8)
	p := new(big.Int)
	q := new(big.Int)

	bigMod := new(big.Int)

	go func() {
		for {
			select {
			case <-ctx.Done():
				waitGroup.Done()
				return
			default:
				_, err := io.ReadFull(rand, bytes)
				if err != nil {
					errChan <- err
					return
				}

				// Clear bits in the first byte to make sure the candidate has
				// a size <= bits.
				bytes[0] &= uint8(int(1<<b) - 1)
				// Don't let the value be too small, i.e, set the most
				// significant two bits.
				// Setting the top two bits, rather than just the top bit,
				// means that when two of these values are multiplied together,
				// the result isn't ever one bit short.
				if b >= 2 {
					bytes[0] |= 3 << (b - 2)
				} else {
					// Here b==1, because b cannot be zero.
					bytes[0] |= 1
					if len(bytes) > 1 {
						bytes[1] |= 0x80
					}
				}
				// Make the value odd since an even number this large certainly
				// isn't prime.
				bytes[len(bytes)-1] |= 1

				q.SetBytes(bytes)

				// Calculate the value mod the product of smallPrimes. If it's
				// a multiple of any of these primes we add two until it isn't.
				// The probability of overflowing is minimal and can be ignored
				// because we still perform Miller-Rabin tests on the result.
				bigMod.Mod(q, smallPrimesProduct)
				mod := bigMod.Uint64()

			NextDelta:
				for delta := uint64(0); delta < 1<<20; delta += 2 {
					m := mod + delta
					for _, prime := range smallPrimes {
						if m%uint64(prime) == 0 && (qBitLen > 6 || m != uint64(prime)) {
							continue NextDelta
						}
					}

					if delta > 0 {
						bigMod.SetUint64(delta)
						q.Add(q, bigMod)
					}

					qMod3 := new(big.Int).Mod(q, big.NewInt(3))
					if qMod3.Cmp(big.NewInt(1)) == 0 {
						continue NextDelta
					}

					// p = 2q+1
					p.Mul(q, big.NewInt(2))
					p.Add(p, big.NewInt(1))
					if !isPrimeCandidate(p) {
						continue NextDelta
					}

					break
				}

				// There is a tiny possibility that, by adding delta, we caused
				// the number to be one bit too long. Thus we check BitLen
				// here.
				if q.ProbablyPrime(20) &&
					isPocklingtonCriterionSatisfied(p) &&
					q.BitLen() == qBitLen {

					mutex.Lock()
					if ctx.Err() == nil {
						primeChan <- safePrime{p, q}
					}
					mutex.Unlock()

					waitGroup.Done()
					return
				}
			}
		}
	}()
}

func isPocklingtonCriterionSatisfied(p *big.Int) bool {
	return new(big.Int).Exp(
		big.NewInt(2),
		new(big.Int).Sub(p, big.NewInt(1)),
		p,
	).Cmp(big.NewInt(1)) == 0
}

func isPrimeCandidate(number *big.Int) bool {
	m := new(big.Int).Mod(number, smallPrimesProduct).Uint64()

	for _, prime := range smallPrimes {
		if m%uint64(prime) == 0 && m != uint64(prime) {
			return false
		}
	}

	return true
}
