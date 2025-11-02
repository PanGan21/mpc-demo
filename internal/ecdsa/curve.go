package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

// Curve wraps standard elliptic curve operations for MPC
type Curve struct {
	curve elliptic.Curve
	order *big.Int
}

// NewCurve creates a new curve instance (using P-256 for simplicity)
// For Bitcoin compatibility, would use secp256k1
func NewCurve() *Curve {
	curve := elliptic.P256()
	return &Curve{
		curve: curve,
		order: curve.Params().N,
	}
}

// Params returns the curve parameters
func (c *Curve) Params() *elliptic.CurveParams {
	return c.curve.Params()
}

// Order returns the order of the curve
func (c *Curve) Order() *big.Int {
	return c.order
}

// ScalarBaseMult performs scalar multiplication k * G where G is the generator
func (c *Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return c.curve.ScalarBaseMult(k)
}

// ScalarMult performs scalar multiplication k * (Px, Py)
func (c *Curve) ScalarMult(Px, Py *big.Int, k []byte) (x, y *big.Int) {
	return c.curve.ScalarMult(Px, Py, k)
}

// Add performs point addition: P1 + P2
func (c *Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return c.curve.Add(x1, y1, x2, y2)
}

// IsOnCurve checks if a point (x, y) is on the curve
func (c *Curve) IsOnCurve(x, y *big.Int) bool {
	return c.curve.IsOnCurve(x, y)
}

// GenerateKeyPair generates a standard ECDSA key pair (for verification/testing)
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	// This is for reference/testing, not used in threshold protocol
	// Individual nodes don't have full key pairs
	return ecdsa.GenerateKey(elliptic.P256(), nil)
}


