package dkg

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"mpc-demo/internal/ecdsa"
	"mpc-demo/internal/secretsharing"
	"mpc-demo/internal/zkproof"
)

// DKGState represents the state of a node during DKG
type DKGState struct {
	SecretShare    *big.Int              // This node's share of the private key
	ReceivedShares map[int]*big.Int      // Shares received from other nodes
	PublicKeyShare *ecdsa.Point          // Share of public key Q
	SharedPublicKey *ecdsa.Point         // Final shared public key
	Commitments    map[int][]*ecdsa.Point // Commitments received from other nodes (for VSS)
	Ready          bool
}

// NodeDKG represents DKG operations for a node
type NodeDKG struct {
	nodeID       int
	curve        *ecdsa.Curve
	ss           *secretsharing.ECSecretSharing
	vss          *zkproof.PedersenVSS
	state        *DKGState
}

// NewNodeDKG creates a new DKG instance for a node
func NewNodeDKG(nodeID int) *NodeDKG {
	curve := ecdsa.NewCurve()
	ecss := secretsharing.NewECSecretSharing(curve.Order())
	vss := zkproof.NewPedersenVSS(curve)
	
	return &NodeDKG{
		nodeID: nodeID,
		curve:  curve,
		ss:     ecss,
		vss:    vss,
		state: &DKGState{
			ReceivedShares: make(map[int]*big.Int),
			Commitments:    make(map[int][]*ecdsa.Point),
		},
	}
}

// GenerateSecretShare generates this node's secret share for DKG with ZK proofs
// Returns shares and Pedersen commitments for verifiable secret sharing
func (dkg *NodeDKG) GenerateSecretShare(numParties, threshold int) ([]secretsharing.Point, []*ecdsa.Point, error) {
	order := dkg.curve.Order()
	
	// Step 1: Generate polynomial coefficients
	// f(x) = secret + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
	coefficients := make([]*big.Int, threshold)
	
	// Generate random secret scalar (a0)
	secretScalar, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate secret scalar: %v", err)
	}
	coefficients[0] = secretScalar
	
	// Generate random coefficients for higher degree terms
	for i := 1; i < threshold; i++ {
		coeff, err := rand.Int(rand.Reader, order)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate coefficient: %v", err)
		}
		coefficients[i] = coeff
	}

	// Step 2: Create Pedersen commitments to polynomial coefficients
	commitments, _, err := dkg.vss.CommitPolynomial(coefficients)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create commitments: %v", err)
	}

	// Step 3: Evaluate polynomial to generate shares (same logic as ECSecretSharing)
	shares := make([]secretsharing.Point, numParties)
	for i := 0; i < numParties; i++ {
		x := big.NewInt(int64(i + 1))
		y := dkg.evaluatePolynomial(coefficients, x, order)
		shares[i] = secretsharing.Point{X: x, Y: y}
	}

	// Store our own share (at position nodeID)
	if len(shares) > dkg.nodeID {
		dkg.state.SecretShare = new(big.Int).Set(shares[dkg.nodeID].Y)
		log.Printf("[DKG Node %d] Generated secret share: %s", dkg.nodeID, dkg.state.SecretShare.String())
	}

	log.Printf("[DKG Node %d] Generated %d shares and %d commitments for DKG", dkg.nodeID, len(shares), len(commitments))
	return shares, commitments, nil
}

// evaluatePolynomial evaluates polynomial at point x using Horner's method
func (dkg *NodeDKG) evaluatePolynomial(coefficients []*big.Int, x *big.Int, order *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[len(coefficients)-1])

	for i := len(coefficients) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Mod(result, order)
		result.Add(result, coefficients[i])
		result.Mod(result, order)
	}

	return result
}

// ReceiveShare processes a secret share received from another node
func (dkg *NodeDKG) ReceiveShare(fromID int, share *big.Int) {
	dkg.state.ReceivedShares[fromID] = share
	log.Printf("[DKG Node %d] Received secret share from node %d", dkg.nodeID, fromID)
}

// ReceiveCommitments processes Pedersen commitments received from another node
func (dkg *NodeDKG) ReceiveCommitments(fromID int, commitments []*ecdsa.Point) {
	dkg.state.Commitments[fromID] = commitments
	log.Printf("[DKG Node %d] Received commitments from node %d", dkg.nodeID, fromID)
}

// VerifyShare verifies that a received share is consistent with commitments
func (dkg *NodeDKG) VerifyShare(fromID int, share *big.Int) bool {
	commitments, exists := dkg.state.Commitments[fromID]
	if !exists || len(commitments) == 0 {
		log.Printf("[DKG Node %d] No commitments found for node %d, cannot verify", dkg.nodeID, fromID)
		return false
	}

	// Verify share against commitments
	index := big.NewInt(int64(fromID + 1)) // x coordinate (1-indexed for shares)
	valid := dkg.vss.VerifyShare(share, index, commitments)
	
	if valid {
		log.Printf("[DKG Node %d] ✓ Verified share from node %d", dkg.nodeID, fromID)
	} else {
		log.Printf("[DKG Node %d] ✗ Share verification failed for node %d", dkg.nodeID, fromID)
	}
	
	return valid
}

// ComputeSharedPrivateKey computes this node's share of the shared private key
// The shared private key d = sum of all secret shares from all nodes
// But we never reconstruct it - each node only has a share
func (dkg *NodeDKG) ComputeSharedPrivateKey(numParties int) (*big.Int, error) {
	// Check if we have shares from all parties (including ourselves)
	// Own share might be in ReceivedShares[dkg.nodeID] or in SecretShare
	totalShares := len(dkg.state.ReceivedShares)
	if dkg.state.SecretShare != nil {
		// If we have our own share separately and not in ReceivedShares, count it
		if _, found := dkg.state.ReceivedShares[dkg.nodeID]; !found {
			totalShares++
		}
	}
	
	if totalShares < numParties {
		return nil, fmt.Errorf("need shares from all %d nodes, got %d received + own", numParties, totalShares)
	}

	// Compute local share of shared private key = sum of all received shares + own share
	shareSum := big.NewInt(0)
	
	// Add all received shares
	for _, share := range dkg.state.ReceivedShares {
		shareSum.Add(shareSum, share)
	}
	
	// Add own share if we have it separately (not already in ReceivedShares)
	if dkg.state.SecretShare != nil {
		if _, found := dkg.state.ReceivedShares[dkg.nodeID]; !found {
			shareSum.Add(shareSum, dkg.state.SecretShare)
		}
	}
	
	// Mod curve order
	shareSum.Mod(shareSum, dkg.curve.Order())
	
	log.Printf("[DKG Node %d] Computed share of shared private key: %s", dkg.nodeID, shareSum.String())
	return shareSum, nil
}

// ComputePublicKeyShare computes this node's share of the public key
// Public key Q = d * G, where d is the shared private key
// Since d is shared, we compute Q_i = d_i * G as our share
func (dkg *NodeDKG) ComputePublicKeyShare(privateKeyShare *big.Int) (*ecdsa.Point, error) {
	if privateKeyShare == nil {
		return nil, fmt.Errorf("private key share is nil")
	}

	// Compute Q_i = d_i * G (scalar multiplication)
	x, y := dkg.curve.ScalarBaseMult(privateKeyShare.Bytes())
	
	dkg.state.PublicKeyShare = ecdsa.NewPoint(x, y)
	log.Printf("[DKG Node %d] Computed public key share: %s", dkg.nodeID, dkg.state.PublicKeyShare.String())
	
	return dkg.state.PublicKeyShare, nil
}

// CombinePublicKeyShares combines public key shares to get final shared public key
// Q = sum(Q_i) = sum(d_i * G) = (sum d_i) * G = d * G
// This works because EC point addition is additive homomorphic
func (dkg *NodeDKG) CombinePublicKeyShares(shares []*ecdsa.Point) (*ecdsa.Point, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no public key shares provided")
	}

	// Start with identity (point at infinity representation)
	// For simplicity, start with first share
	combinedX := new(big.Int).Set(shares[0].X)
	combinedY := new(big.Int).Set(shares[0].Y)

	// Add all other shares
	for i := 1; i < len(shares); i++ {
		combinedX, combinedY = dkg.curve.Add(combinedX, combinedY, shares[i].X, shares[i].Y)
	}

	result := ecdsa.NewPoint(combinedX, combinedY)
	dkg.state.SharedPublicKey = result
	log.Printf("[DKG Node %d] Combined public key shares to get shared public key: %s", dkg.nodeID, result.String())
	
	return result, nil
}

// GetState returns the DKG state
func (dkg *NodeDKG) GetState() *DKGState {
	return dkg.state
}

// GetPrivateKeyShare returns this node's share of the private key
func (dkg *NodeDKG) GetPrivateKeyShare() *big.Int {
	return dkg.state.SecretShare
}

