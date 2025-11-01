package secretsharing

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Point represents a (x, y) coordinate in finite field arithmetic
type Point struct {
	X *big.Int
	Y *big.Int
}

// SecretSharing implements Shamir's Secret Sharing scheme
type SecretSharing struct {
	// Prime modulus for finite field arithmetic
	prime *big.Int
}

// NewSecretSharing creates a new SecretSharing instance
func NewSecretSharing() *SecretSharing {
	// Using a 256-bit prime for security
	// This is a well-known prime: 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
	prime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	return &SecretSharing{
		prime: prime,
	}
}

// Share splits a secret into n shares such that any k shares can reconstruct it
// Returns shares (points) that can be distributed to parties
func (ss *SecretSharing) Share(secret *big.Int, n, k int) ([]Point, error) {
	if k > n {
		return nil, fmt.Errorf("threshold k (%d) cannot be greater than n (%d)", k, n)
	}
	if k < 2 {
		return nil, fmt.Errorf("threshold k must be at least 2")
	}

	// Ensure secret is in valid range
	secret.Mod(secret, ss.prime)

	// Generate k-1 random coefficients for polynomial of degree k-1
	coefficients := make([]*big.Int, k)
	coefficients[0] = new(big.Int).Set(secret) // a0 = secret

	for i := 1; i < k; i++ {
		coefficients[i], _ = rand.Int(rand.Reader, ss.prime)
	}

	// Evaluate polynomial at n points (x = 1, 2, ..., n)
	shares := make([]Point, n)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		y := ss.evaluatePolynomial(coefficients, x)
		shares[i] = Point{X: x, Y: y}
	}

	return shares, nil
}

// evaluatePolynomial evaluates polynomial at point x using Horner's method
// f(x) = a0 + a1*x + a2*x^2 + ... + ak*x^k
func (ss *SecretSharing) evaluatePolynomial(coefficients []*big.Int, x *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[len(coefficients)-1])

	for i := len(coefficients) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Mod(result, ss.prime)
		result.Add(result, coefficients[i])
		result.Mod(result, ss.prime)
	}

	return result
}

// Reconstruct recovers the secret from k shares using Lagrange interpolation
func (ss *SecretSharing) Reconstruct(shares []Point) (*big.Int, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("need at least 2 shares to reconstruct secret")
	}

	k := len(shares)
	result := big.NewInt(0)

	// Lagrange interpolation: sum(yi * Li(0))
	for i := 0; i < k; i++ {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		// Calculate Li(0) = product((0 - xj) / (xi - xj)) for j != i
		for j := 0; j < k; j++ {
			if i != j {
				// numerator *= (0 - xj) = -xj
				numerator.Mul(numerator, new(big.Int).Neg(shares[j].X))
				numerator.Mod(numerator, ss.prime)

				// denominator *= (xi - xj)
				diff := new(big.Int).Sub(shares[i].X, shares[j].X)
				denominator.Mul(denominator, diff)
				denominator.Mod(denominator, ss.prime)
			}
		}

		// Calculate Li(0) = numerator / denominator mod prime
		invDenominator := new(big.Int).ModInverse(denominator, ss.prime)
		lagrangeCoeff := new(big.Int).Mul(numerator, invDenominator)
		lagrangeCoeff.Mod(lagrangeCoeff, ss.prime)

		// Add yi * Li(0) to result
		term := new(big.Int).Mul(shares[i].Y, lagrangeCoeff)
		term.Mod(term, ss.prime)
		result.Add(result, term)
		result.Mod(result, ss.prime)
	}

	return result, nil
}

// Prime returns the prime modulus used for finite field arithmetic
func (ss *SecretSharing) Prime() *big.Int {
	return ss.prime
}
