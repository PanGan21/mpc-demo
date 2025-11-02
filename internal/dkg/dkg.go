package dkg

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"mpc-demo/internal/ecdsa"
	"mpc-demo/internal/secretsharing"
)

// DKGState represents the state of a node during DKG
type DKGState struct {
	SecretShare    *big.Int              // This node's share of the private key
	ReceivedShares map[int]*big.Int      // Shares received from other nodes
	PublicKeyShare *ecdsa.Point          // Share of public key Q
	SharedPublicKey *ecdsa.Point         // Final shared public key
	Ready          bool
}

// NodeDKG represents DKG operations for a node
type NodeDKG struct {
	nodeID       int
	curve        *ecdsa.Curve
	ss           *secretsharing.ECSecretSharing
	state        *DKGState
}

// NewNodeDKG creates a new DKG instance for a node
func NewNodeDKG(nodeID int) *NodeDKG {
	curve := ecdsa.NewCurve()
	ecss := secretsharing.NewECSecretSharing(curve.Order())
	
	return &NodeDKG{
		nodeID: nodeID,
		curve:  curve,
		ss:     ecss,
		state: &DKGState{
			ReceivedShares: make(map[int]*big.Int),
		},
	}
}

// GenerateSecretShare generates this node's secret share for DKG
// Returns shares to be distributed to other nodes
func (dkg *NodeDKG) GenerateSecretShare(numParties, threshold int) ([]secretsharing.Point, error) {
	// Generate random secret scalar for this node
	secretScalar, err := rand.Int(rand.Reader, dkg.curve.Order())
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret scalar: %v", err)
	}

	// Share this secret scalar using secret sharing
	shares, err := dkg.ss.Share(secretScalar, numParties, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to share secret scalar: %v", err)
	}

	// Store our own share (at position nodeID)
	if len(shares) > dkg.nodeID {
		dkg.state.SecretShare = new(big.Int).Set(shares[dkg.nodeID].Y)
		log.Printf("[DKG Node %d] Generated secret share: %s", dkg.nodeID, dkg.state.SecretShare.String())
	}

	log.Printf("[DKG Node %d] Generated %d shares for DKG", dkg.nodeID, len(shares))
	return shares, nil
}

// ReceiveShare processes a secret share received from another node
func (dkg *NodeDKG) ReceiveShare(fromID int, share *big.Int) {
	dkg.state.ReceivedShares[fromID] = share
	log.Printf("[DKG Node %d] Received secret share from node %d", dkg.nodeID, fromID)
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

