package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Signature represents an ECDSA signature (r, s)
type Signature struct {
	R *big.Int
	S *big.Int
}

// NewSignature creates a new signature
func NewSignature(r, s *big.Int) *Signature {
	return &Signature{
		R: new(big.Int).Set(r),
		S: new(big.Int).Set(s),
	}
}

// String returns a string representation of the signature
func (sig *Signature) String() string {
	return fmt.Sprintf("(r=%s, s=%s)", sig.R.String(), sig.S.String())
}

// Verify verifies an ECDSA signature (for testing/reference)
// In threshold setting, signature verification is done publicly
func (sig *Signature) Verify(publicKey *ecdsa.PublicKey, message []byte) bool {
	// This is for reference/testing
	// In threshold protocol, we verify using the shared public key
	hash := hashMessage(message)
	return ecdsa.Verify(publicKey, hash, sig.R, sig.S)
}

// ToStandard converts to standard library signature format
func (sig *Signature) ToStandard() (*big.Int, *big.Int) {
	return sig.R, sig.S
}

// hashMessage hashes a message using SHA256
func hashMessage(message []byte) []byte {
	// Use proper SHA256 hashing
	hasher := sha256.New()
	hasher.Write(message)
	return hasher.Sum(nil)
}

// VerifyWithCurve verifies signature with explicit curve and public key point
func VerifyWithCurve(curve elliptic.Curve, pubX, pubY *big.Int, message []byte, r, s *big.Int) bool {
	hash := hashMessage(message)

	// Standard ECDSA verification
	e := new(big.Int).SetBytes(hash)
	e.Mod(e, curve.Params().N)
	if e.Sign() == 0 {
		e = big.NewInt(1)
	}

	// Compute w = s^(-1) mod n
	w := new(big.Int).ModInverse(s, curve.Params().N)

	// Compute u1 = e * w mod n and u2 = r * w mod n
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, curve.Params().N)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, curve.Params().N)

	// Compute point (x1, y1) = u1*G + u2*Q
	x1, y1 := curve.ScalarBaseMult(u1.Bytes())
	x2, y2 := curve.ScalarMult(pubX, pubY, u2.Bytes())
	x1, y1 = curve.Add(x1, y1, x2, y2)

	// Verify r == x1 mod n
	return x1.Mod(x1, curve.Params().N).Cmp(r) == 0
}
