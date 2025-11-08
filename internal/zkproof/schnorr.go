package zkproof

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"mpc-demo/internal/ecdsa"
)

// SchnorrProof represents a Schnorr-like zero-knowledge proof
// Proves knowledge of a discrete logarithm without revealing it
// Proof structure: (R, c, z) where R is commitment, c is challenge, z is response
type SchnorrProof struct {
	R         *ecdsa.Point // R = r * G (commitment)
	Challenge *big.Int     // c (challenge)
	Response  *big.Int     // z = r + c * s (response)
}

// SchnorrProver can generate proofs of knowledge
type SchnorrProver struct {
	curve *ecdsa.Curve
	G     *ecdsa.Point // Generator
}

// NewSchnorrProver creates a new Schnorr proof prover
func NewSchnorrProver(curve *ecdsa.Curve) *SchnorrProver {
	gx, gy := curve.ScalarBaseMult(big.NewInt(1).Bytes())
	G := ecdsa.NewPoint(gx, gy)

	return &SchnorrProver{
		curve: curve,
		G:     G,
	}
}

// ProveKnowledge generates a Schnorr proof of knowledge of secret s
// where public value is P = s * G
// Protocol:
//  1. Prover chooses random r, computes R = r * G
//  2. Verifier sends challenge c = H(R || P || context)
//  3. Prover computes z = r + c * s mod n
//  4. Verifier checks: z * G = R + c * P
func (sp *SchnorrProver) ProveKnowledge(secret *big.Int, publicPoint *ecdsa.Point, context []byte) (*SchnorrProof, *ecdsa.Point, error) {
	order := sp.curve.Order()

	// Step 1: Choose random r
	r, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate randomness: %v", err)
	}

	// Compute R = r * G
	rx, ry := sp.curve.ScalarBaseMult(r.Bytes())
	R := ecdsa.NewPoint(rx, ry)

	// Step 2: Generate challenge (simplified - in production use proper hash)
	challenge := sp.generateChallenge(R, publicPoint, context, order)

	// Step 3: Compute response z = r + c * s mod n
	z := new(big.Int).Mul(challenge, secret)
	z.Add(z, r)
	z.Mod(z, order)

	return &SchnorrProof{
		R:         R,
		Challenge: challenge,
		Response:  z,
	}, R, nil
}

// VerifyProof verifies a Schnorr proof
// Checks: z * G = R + c * P
func (sp *SchnorrProver) VerifyProof(proof *SchnorrProof, publicPoint *ecdsa.Point, context []byte) bool {
	if proof == nil || proof.R == nil || proof.Challenge == nil || proof.Response == nil {
		return false
	}

	order := sp.curve.Order()

	// Regenerate challenge using R from the proof
	challenge := sp.generateChallenge(proof.R, publicPoint, context, order)

	if challenge.Cmp(proof.Challenge) != 0 {
		return false
	}

	// Compute left side: z * G
	zx, zy := sp.curve.ScalarBaseMult(proof.Response.Bytes())

	// Compute right side: R + c * P
	cx, cy := sp.curve.ScalarMult(publicPoint.X, publicPoint.Y, proof.Challenge.Bytes())
	rightX, rightY := sp.curve.Add(proof.R.X, proof.R.Y, cx, cy)

	// Check: z * G = R + c * P
	return zx.Cmp(rightX) == 0 && zy.Cmp(rightY) == 0
}

// generateChallenge creates a challenge from R, P, and context
// In production, this would be: c = H(R || P || context)
// For simplicity, we use a hash-like function
func (sp *SchnorrProver) generateChallenge(R, P *ecdsa.Point, context []byte, mod *big.Int) *big.Int {
	// Simplified challenge generation (for educational purposes)
	// In production, use proper cryptographic hash (SHA-256, etc.)

	hash := big.NewInt(0)
	if R.X != nil {
		hash.Add(hash, R.X)
		hash.Add(hash, R.Y)
	}
	if P.X != nil {
		hash.Add(hash, P.X)
		hash.Add(hash, P.Y)
	}
	if len(context) > 0 {
		for _, b := range context {
			hash.Add(hash, big.NewInt(int64(b)))
		}
	}
	hash.Mod(hash, mod)
	if hash.Cmp(big.NewInt(0)) == 0 {
		hash.SetInt64(1) // Avoid zero challenge
	}

	return hash
}

// ProveSignatureShare generates a proof that a signature share was computed correctly
// Proves: I know d_i such that my signature share s_i = k^(-1) * (h + r * d_i) mod n
// This is a simplified version - full proof would be more complex
func (sp *SchnorrProver) ProveSignatureShare(
	signatureShare *big.Int,
	privateKeyShare *big.Int,
	r, kInv, messageHash *big.Int,
) (*SchnorrProof, error) {
	// Public point: P = d_i * G (public key share)
	px, py := sp.curve.ScalarBaseMult(privateKeyShare.Bytes())
	publicPoint := ecdsa.NewPoint(px, py)

	// Context includes r, message hash, and signature share for binding
	context := make([]byte, 0)
	context = append(context, r.Bytes()...)
	context = append(context, messageHash.Bytes()...)
	context = append(context, signatureShare.Bytes()...)

	// Generate proof of knowledge of d_i
	proof, _, err := sp.ProveKnowledge(privateKeyShare, publicPoint, context)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %v", err)
	}

	// R is now included in the proof structure
	return proof, nil
}

// VerifySignatureShareProof verifies a signature share proof
func (sp *SchnorrProver) VerifySignatureShareProof(
	proof *SchnorrProof,
	publicKeyShare *ecdsa.Point,
	r, signatureShare, messageHash *big.Int,
) (bool, error) {
	// FULL VERIFICATION: Verify the complete Schnorr proof

	// Step 1: Validate proof structure
	if proof == nil || proof.R == nil || proof.Challenge == nil || proof.Response == nil {
		return false, fmt.Errorf("invalid proof structure")
	}

	if proof.Challenge.Cmp(big.NewInt(0)) == 0 || proof.Response.Cmp(big.NewInt(0)) == 0 {
		return false, fmt.Errorf("proof components cannot be zero")
	}

	// Validate that R is on the curve
	if !sp.curve.IsOnCurve(proof.R.X, proof.R.Y) {
		return false, fmt.Errorf("proof.R is not a valid point on the curve")
	}

	// Validate that publicKeyShare is on the curve
	if !sp.curve.IsOnCurve(publicKeyShare.X, publicKeyShare.Y) {
		return false, fmt.Errorf("publicKeyShare is not a valid point on the curve")
	}

	// Step 2: Regenerate challenge c = H(R || publicKeyShare || context)
	context := make([]byte, 0)
	context = append(context, r.Bytes()...)
	context = append(context, messageHash.Bytes()...)
	context = append(context, signatureShare.Bytes()...)

	order := sp.curve.Order()
	expectedChallenge := sp.generateChallenge(proof.R, publicKeyShare, context, order)

	// Verify challenge matches
	if expectedChallenge.Cmp(proof.Challenge) != 0 {
		return false, fmt.Errorf("challenge mismatch in proof")
	}

	// Step 3: FULL VERIFICATION - Verify: proof.Response * G = R + proof.Challenge * publicKeyShare
	// Left side: z * G
	leftX, leftY := sp.curve.ScalarBaseMult(proof.Response.Bytes())

	// Right side: R + c * publicKeyShare
	// Compute c * publicKeyShare
	cx, cy := sp.curve.ScalarMult(publicKeyShare.X, publicKeyShare.Y, proof.Challenge.Bytes())

	// Add R + (c * publicKeyShare)
	rightX, rightY := sp.curve.Add(proof.R.X, proof.R.Y, cx, cy)

	// Verify they match
	valid := leftX.Cmp(rightX) == 0 && leftY.Cmp(rightY) == 0

	if !valid {
		return false, fmt.Errorf("Schnorr proof verification failed: z*G != R + c*P")
	}

	return true, nil
}
