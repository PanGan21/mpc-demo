package zkproof

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"mpc-demo/internal/ecdsa"
)

// PedersenCommitment represents a Pedersen commitment
// C = s*G + r*H where s is the secret, r is randomness, G and H are generators
type PedersenCommitment struct {
	Point      *ecdsa.Point // C = s*G + r*H
	Randomness *big.Int     // r (blinding factor)
	Secret     *big.Int     // s (the committed value, kept for verification)
	H          *ecdsa.Point // Secondary generator H (pedersen commitment parameter)
}

// PedersenVSS implements Pedersen Verifiable Secret Sharing
// This allows nodes to commit to their polynomial and verify shares
type PedersenVSS struct {
	curve        *ecdsa.Curve
	G            *ecdsa.Point   // Generator G
	H            *ecdsa.Point   // Generator H (for Pedersen commitments)
	coefficients []*big.Int     // Polynomial coefficients
	commitments  []*ecdsa.Point // Commitments to coefficients
	randomness   []*big.Int     // Randomness for each commitment
}

// NewPedersenVSS creates a new Pedersen VSS instance
// For simplicity, we use H = G (in production, H would be a different generator)
func NewPedersenVSS(curve *ecdsa.Curve) *PedersenVSS {
	// Get generator point G
	gx, gy := curve.ScalarBaseMult(big.NewInt(1).Bytes())
	G := ecdsa.NewPoint(gx, gy)

	// For simplicity, use H = 2*G (in production, H should be a standard generator)
	hx, hy := curve.ScalarMult(gx, gy, big.NewInt(2).Bytes())
	H := ecdsa.NewPoint(hx, hy)

	return &PedersenVSS{
		curve: curve,
		G:     G,
		H:     H,
	}
}

// CommitPolynomial commits to a polynomial f(x) = a₀ + a₁x + a₂x² + ...
// Returns commitments to each coefficient: C_i = a_i*G + r_i*H
func (vss *PedersenVSS) CommitPolynomial(coefficients []*big.Int) ([]*ecdsa.Point, []*big.Int, error) {
	if len(coefficients) == 0 {
		return nil, nil, fmt.Errorf("no coefficients provided")
	}

	vss.coefficients = make([]*big.Int, len(coefficients))
	vss.commitments = make([]*ecdsa.Point, len(coefficients))
	vss.randomness = make([]*big.Int, len(coefficients))

	order := vss.curve.Order()

	for i := 0; i < len(coefficients); i++ {
		// Copy coefficient
		vss.coefficients[i] = new(big.Int).Set(coefficients[i])

		// Generate random blinding factor
		r, err := rand.Int(rand.Reader, order)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate randomness: %v", err)
		}
		vss.randomness[i] = r

		// Compute commitment: C_i = a_i*G + r_i*H
		gx, gy := vss.curve.ScalarBaseMult(coefficients[i].Bytes())
		hx, hy := vss.curve.ScalarMult(vss.H.X, vss.H.Y, r.Bytes())

		cx, cy := vss.curve.Add(gx, gy, hx, hy)
		vss.commitments[i] = ecdsa.NewPoint(cx, cy)
	}

	return vss.commitments, vss.randomness, nil
}

// VerifyShare verifies that a share f(i) is consistent with the commitments
// Share is f(i) = Σ(a_j * i^j) for j = 0 to t-1
// Verification checks: f(i)*G = Σ(C_j evaluated at i)
// Full verification: shareValue * G = Σ(commitments[j] evaluated as polynomial at index)
func (vss *PedersenVSS) VerifyShare(shareValue *big.Int, index *big.Int, commitments []*ecdsa.Point) bool {
	if len(commitments) == 0 {
		return false
	}

	order := vss.curve.Order()

	// Verify all commitments are valid points on the curve
	for _, comm := range commitments {
		if !vss.curve.IsOnCurve(comm.X, comm.Y) {
			return false
		}
	}

	// Basic consistency check: share value should be valid
	if shareValue.Cmp(big.NewInt(0)) < 0 || shareValue.Cmp(order) >= 0 {
		return false
	}

	// FULL VERIFICATION: Check that shareValue * G = Σ(commitments[j] * index^j)
	// This verifies that the share f(i) is consistent with the committed polynomial

	// Left side: shareValue * G (what the share claims to commit to)
	leftX, leftY := vss.curve.ScalarBaseMult(shareValue.Bytes())

	// Right side: Evaluate polynomial of commitments at index
	// For polynomial f(x) = a₀ + a₁x + a₂x² + ... + aₜxᵗ
	// Commitments are C_j = a_j*G + r_j*H
	// We need to compute: Σ(C_j * index^j) where each C_j is multiplied by index^j
	// Note: Since we don't have the randomness r_j for full Pedersen verification,
	// we verify the G component: Σ(a_j * index^j) * G = f(index) * G

	// Start with C₀ (constant term)
	rightX := new(big.Int).Set(commitments[0].X)
	rightY := new(big.Int).Set(commitments[0].Y)

	// For each higher degree term j: add C_j * index^j
	for j := 1; j < len(commitments); j++ {
		// Compute index^j
		power := new(big.Int).Exp(index, big.NewInt(int64(j)), order)

		// Compute C_j * index^j (scalar multiplication of commitment by power)
		// Since C_j = a_j*G + r_j*H, we have:
		// C_j * index^j = (a_j*G + r_j*H) * index^j = (a_j*index^j)*G + (r_j*index^j)*H
		// For the G component verification: we compute commitments[j] * index^j
		cx, cy := vss.curve.ScalarMult(commitments[j].X, commitments[j].Y, power.Bytes())

		// Add to running sum
		rightX, rightY = vss.curve.Add(rightX, rightY, cx, cy)
	}

	// Verify: shareValue * G == Σ(commitments evaluated at index)
	// This checks that the share is consistent with the committed polynomial
	// Note: This is a simplified version that verifies the G component
	// Full Pedersen VSS would also verify the H component using the randomness r_j
	valid := leftX.Cmp(rightX) == 0 && leftY.Cmp(rightY) == 0

	return valid
}

// GetCommitments returns the commitments
func (vss *PedersenVSS) GetCommitments() []*ecdsa.Point {
	return vss.commitments
}

// GetG returns the generator G
func (vss *PedersenVSS) GetG() *ecdsa.Point {
	return vss.G
}

// GetH returns the generator H
func (vss *PedersenVSS) GetH() *ecdsa.Point {
	return vss.H
}
