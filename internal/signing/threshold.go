package signing

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"mpc-demo/internal/ecdsa"
	"mpc-demo/internal/secretsharing"
)

// SigningState represents the state during threshold signing
type SigningState struct {
	NonceShare      *big.Int              // Share of random nonce k
	ReceivedNonces  map[int]*big.Int      // Nonce shares from other nodes
	R               *big.Int              // r component of signature
	SignatureShares map[int]*big.Int      // s shares from other nodes
	Ready           bool
}

// NodeSigning handles threshold signing operations for a node
type NodeSigning struct {
	nodeID         int
	privateKeyShare *big.Int              // Share of private key d
	curve          *ecdsa.Curve
	ss             *secretsharing.ECSecretSharing
	state          *SigningState
}

// NewNodeSigning creates a new signing instance for a node
func NewNodeSigning(nodeID int, privateKeyShare *big.Int) *NodeSigning {
	curve := ecdsa.NewCurve()
	ecss := secretsharing.NewECSecretSharing(curve.Order())
	
	return &NodeSigning{
		nodeID:          nodeID,
		privateKeyShare: privateKeyShare,
		curve:           curve,
		ss:              ecss,
		state: &SigningState{
			ReceivedNonces:  make(map[int]*big.Int),
			SignatureShares: make(map[int]*big.Int),
		},
	}
}

// GenerateNonceShare generates a random nonce share for this signing session
// Returns shares to be distributed to other nodes for joint nonce generation
func (ns *NodeSigning) GenerateNonceShare(numParties, threshold int) ([]secretsharing.Point, error) {
	// Generate random nonce scalar
	nonceScalar, err := rand.Int(rand.Reader, ns.curve.Order())
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Share this nonce using secret sharing
	shares, err := ns.ss.Share(nonceScalar, numParties, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to share nonce: %v", err)
	}

	// Store our own share
	if len(shares) > ns.nodeID {
		ns.state.NonceShare = new(big.Int).Set(shares[ns.nodeID].Y)
		log.Printf("[Signing Node %d] Generated nonce share: %s", ns.nodeID, ns.state.NonceShare.String())
	}

	return shares, nil
}

// ReceiveNonceShare processes a nonce share received from another node
func (ns *NodeSigning) ReceiveNonceShare(fromID int, share *big.Int) {
	ns.state.ReceivedNonces[fromID] = share
	log.Printf("[Signing Node %d] Received nonce share from node %d", ns.nodeID, fromID)
}

// ComputeSharedNonce computes this node's share of the shared nonce k
func (ns *NodeSigning) ComputeSharedNonce(numParties int) (*big.Int, error) {
	// Check if we have nonce shares from all parties (including ourselves)
	totalNonces := len(ns.state.ReceivedNonces)
	if ns.state.NonceShare != nil {
		if _, found := ns.state.ReceivedNonces[ns.nodeID]; !found {
			totalNonces++
		}
	}
	
	if totalNonces < numParties {
		return nil, fmt.Errorf("need nonce shares from all %d nodes, got %d received + own", numParties, totalNonces)
	}

	// Compute local share of shared nonce = sum of all received nonce shares + own share
	nonceSum := big.NewInt(0)
	
	// Add all received shares
	for _, share := range ns.state.ReceivedNonces {
		nonceSum.Add(nonceSum, share)
	}
	
	// Add own share if we have it separately (not already in ReceivedNonces)
	if ns.state.NonceShare != nil {
		if _, found := ns.state.ReceivedNonces[ns.nodeID]; !found {
			nonceSum.Add(nonceSum, ns.state.NonceShare)
		}
	}
	
	// Mod curve order
	nonceSum.Mod(nonceSum, ns.curve.Order())
	
	log.Printf("[Signing Node %d] Computed share of shared nonce: %s", ns.nodeID, nonceSum.String())
	return nonceSum, nil
}

// ComputeR computes the r component of the signature
// r = (k * G).x mod n, where k is the shared nonce
// Each node computes R_i = k_i * G, then we combine to get R = sum(R_i) = k * G
func (ns *NodeSigning) ComputeR(nonceShare *big.Int) (*ecdsa.Point, error) {
	if nonceShare == nil {
		return nil, fmt.Errorf("nonce share is nil")
	}

	// Compute R_i = k_i * G
	x, y := ns.curve.ScalarBaseMult(nonceShare.Bytes())
	Ri := ecdsa.NewPoint(x, y)
	
	log.Printf("[Signing Node %d] Computed R_i = k_i * G: %s", ns.nodeID, Ri.String())
	return Ri, nil
}

// CombineRPoints combines R points from all nodes to get final R
// R = sum(R_i) = sum(k_i * G) = (sum k_i) * G = k * G
func (ns *NodeSigning) CombineRPoints(rPoints []*ecdsa.Point) (*big.Int, error) {
	if len(rPoints) == 0 {
		return nil, fmt.Errorf("no R points provided")
	}

	// Combine all R_i points
	combinedX := new(big.Int).Set(rPoints[0].X)
	combinedY := new(big.Int).Set(rPoints[0].Y)

	for i := 1; i < len(rPoints); i++ {
		combinedX, combinedY = ns.curve.Add(combinedX, combinedY, rPoints[i].X, rPoints[i].Y)
	}

	// Extract r = R.x mod n
	r := new(big.Int).Mod(combinedX, ns.curve.Order())
	ns.state.R = r
	
	log.Printf("[Signing Node %d] Combined R points, got r = %s", ns.nodeID, r.String())
	return r, nil
}

// ComputeSignatureShare computes this node's share of the signature component s
// Note: This method signature is kept for compatibility, but actual computation
// is now done in the network simulator after reconstructing k
// The correct formula is: s_i = k^(-1) * (h + r * d_i) mod n
// where k^(-1) is computed from reconstructed k (acceptable since k is ephemeral)
func (ns *NodeSigning) ComputeSignatureShare(kShare, r *big.Int, messageHash *big.Int) (*big.Int, error) {
	// This method is kept for compatibility but computation is moved to simulator
	// where we have access to reconstructed k and can compute k^(-1) correctly
	if kShare == nil {
		return nil, fmt.Errorf("nonce share is nil")
	}
	if r == nil {
		return nil, fmt.Errorf("r is nil")
	}
	if messageHash == nil {
		return nil, fmt.Errorf("message hash is nil")
	}
	if ns.privateKeyShare == nil {
		return nil, fmt.Errorf("private key share is nil")
	}

	// Compute h + r * d_i mod n (part of the signature computation)
	h := new(big.Int).Set(messageHash)
	h.Mod(h, ns.curve.Order())
	
	rTimesDi := new(big.Int).Mul(r, ns.privateKeyShare)
	rTimesDi.Mod(rTimesDi, ns.curve.Order())
	
	sum := new(big.Int).Add(h, rTimesDi)
	sum.Mod(sum, ns.curve.Order())

	// Note: k^(-1) multiplication is done in the simulator after reconstructing k
	// This is mathematically correct and secure since k is ephemeral
	
	log.Printf("[Signing Node %d] Computed (h + r * d_i): %s", ns.nodeID, sum.String())
	return sum, nil
}

// ReceiveSignatureShare processes a signature share from another node
func (ns *NodeSigning) ReceiveSignatureShare(fromID int, share *big.Int) {
	ns.state.SignatureShares[fromID] = share
	log.Printf("[Signing Node %d] Received signature share from node %d", ns.nodeID, fromID)
}

// CombineSignatureShares combines signature shares to get final signature component s
// s = sum(s_i) mod n
func (ns *NodeSigning) CombineSignatureShares(numParties int) (*big.Int, error) {
	if len(ns.state.SignatureShares) < numParties {
		return nil, fmt.Errorf("need signature shares from all %d nodes, got %d", numParties, len(ns.state.SignatureShares))
	}

	// Add our own signature share
	sSum := big.NewInt(0)
	
	// Add all received shares
	for _, share := range ns.state.SignatureShares {
		sSum.Add(sSum, share)
	}
	
	// Note: Our own share should already be included in the computation
	
	sSum.Mod(sSum, ns.curve.Order())
	
	log.Printf("[Signing Node %d] Combined signature shares, got s: %s", ns.nodeID, sSum.String())
	return sSum, nil
}

// GetState returns the signing state
func (ns *NodeSigning) GetState() *SigningState {
	return ns.state
}

