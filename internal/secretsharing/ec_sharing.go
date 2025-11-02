package secretsharing

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// ECSecretSharing implements secret sharing modulo curve order (for ECDSA scalars)
type ECSecretSharing struct {
	order *big.Int // Curve order
}

// NewECSecretSharing creates a new EC secret sharing instance
// Works modulo curve order instead of field prime
func NewECSecretSharing(curveOrder *big.Int) *ECSecretSharing {
	return &ECSecretSharing{
		order: curveOrder,
	}
}

// Share splits a secret (scalar) into n shares modulo curve order
func (ecss *ECSecretSharing) Share(secret *big.Int, n, k int) ([]Point, error) {
	if k > n {
		return nil, fmt.Errorf("threshold k (%d) cannot be greater than n (%d)", k, n)
	}
	if k < 2 {
		return nil, fmt.Errorf("threshold k must be at least 2")
	}

	// Ensure secret is in valid range (mod curve order)
	secret.Mod(secret, ecss.order)

	// Generate k-1 random coefficients for polynomial of degree k-1
	coefficients := make([]*big.Int, k)
	coefficients[0] = new(big.Int).Set(secret) // a0 = secret

	for i := 1; i < k; i++ {
		coefficients[i], _ = rand.Int(rand.Reader, ecss.order)
	}

	// Evaluate polynomial at n points (x = 1, 2, ..., n)
	shares := make([]Point, n)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		y := ecss.evaluatePolynomial(coefficients, x)
		shares[i] = Point{X: x, Y: y}
	}

	return shares, nil
}

// evaluatePolynomial evaluates polynomial at point x modulo curve order
func (ecss *ECSecretSharing) evaluatePolynomial(coefficients []*big.Int, x *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[len(coefficients)-1])

	for i := len(coefficients) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Mod(result, ecss.order)
		result.Add(result, coefficients[i])
		result.Mod(result, ecss.order)
	}

	return result
}

// Reconstruct recovers the secret from k shares using Lagrange interpolation modulo curve order
func (ecss *ECSecretSharing) Reconstruct(shares []Point) (*big.Int, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("need at least 2 shares to reconstruct secret")
	}

	k := len(shares)
	result := big.NewInt(0)

	// Lagrange interpolation: sum(yi * Li(0)) mod curve_order
	for i := 0; i < k; i++ {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		// Calculate Li(0) = product((0 - xj) / (xi - xj)) for j != i
		for j := 0; j < k; j++ {
			if i != j {
				// numerator *= (0 - xj) = -xj
				numerator.Mul(numerator, new(big.Int).Neg(shares[j].X))
				numerator.Mod(numerator, ecss.order)

				// denominator *= (xi - xj)
				diff := new(big.Int).Sub(shares[i].X, shares[j].X)
				denominator.Mul(denominator, diff)
				denominator.Mod(denominator, ecss.order)
			}
		}

		// Calculate Li(0) = numerator / denominator mod order
		invDenominator := new(big.Int).ModInverse(denominator, ecss.order)
		lagrangeCoeff := new(big.Int).Mul(numerator, invDenominator)
		lagrangeCoeff.Mod(lagrangeCoeff, ecss.order)

		// Add yi * Li(0) to result
		term := new(big.Int).Mul(shares[i].Y, lagrangeCoeff)
		term.Mod(term, ecss.order)
		result.Add(result, term)
		result.Mod(result, ecss.order)
	}

	return result, nil
}

// Order returns the curve order
func (ecss *ECSecretSharing) Order() *big.Int {
	return ecss.order
}



