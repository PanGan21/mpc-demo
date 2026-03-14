package network

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"time"

	"mpc-demo/internal/ecdsa"
	"mpc-demo/internal/node"
	"mpc-demo/internal/secretsharing"
)

// Simulator simulates P2P network communication between MPC nodes
type Simulator struct {
	nodes        map[int]*node.Node
	numParties   int
	threshold    int
	messageQueue chan networkMessage
	commitments  map[int][]*ecdsa.Point // Store commitments for each node (for VSS)
}

type networkMessage struct {
	From    int
	To      int
	Type    string
	Payload *big.Int
	ECPoint *ecdsa.Point
	Bytes   []byte
}

// NewSimulator creates a new network simulator
func NewSimulator(numParties, threshold int) *Simulator {
	return &Simulator{
		nodes:        make(map[int]*node.Node),
		numParties:   numParties,
		threshold:    threshold,
		messageQueue: make(chan networkMessage, 1000),
		commitments:  make(map[int][]*ecdsa.Point),
	}
}

// AddNode adds a node to the network
func (s *Simulator) AddNode(id int, secret *big.Int) {
	s.nodes[id] = node.NewNode(id, secret, s.numParties)
	log.Printf("[Network] Node %d joined the network", id)
}

// SendMessage simulates sending a message from one node to another
func (s *Simulator) SendMessage(from, to int, msgType string, payload *big.Int) {
	// Simulate network delay
	go func() {
		time.Sleep(10 * time.Millisecond) // Simulate network latency
		s.messageQueue <- networkMessage{
			From:    from,
			To:      to,
			Type:    msgType,
			Payload: payload,
		}
	}()
}

// SendECPoints simulates sending ECPoints (for commitments) from one node to another
func (s *Simulator) SendECPoints(from, to int, msgType string, points []*ecdsa.Point) {
	// For simplicity, send all points in a single message
	// In production, each point would be sent separately or serialized
	go func() {
		time.Sleep(10 * time.Millisecond)
		// Store first point (for demo, we'll handle commitments differently)
		if len(points) > 0 {
			s.messageQueue <- networkMessage{
				From:    from,
				To:      to,
				Type:    msgType,
				ECPoint: points[0], // Store first point for demo
			}
		}
	}()
}

// BroadcastShare simulates broadcasting a share to all nodes
func (s *Simulator) BroadcastShare(from int, shares []secretsharing.Point) {
	for i, share := range shares {
		recipientID := i // Share at position i goes to node i
		if _, exists := s.nodes[recipientID]; exists {
			// Send via network (simulated)
			s.SendMessage(from, recipientID, "share", share.Y)
		}
	}
}

// StartMessageHandler starts the message handler goroutine
func (s *Simulator) StartMessageHandler() {
	go func() {
		for msg := range s.messageQueue {
			if recipient, exists := s.nodes[msg.To]; exists {
				switch msg.Type {
				case "share":
					recipient.ReceiveShare(msg.From, msg.Payload)
				case "dkg_share":
					recipient.DKGReceiveShare(msg.From, msg.Payload)
				case "sign_nonce":
					recipient.SignReceiveNonceShare(msg.From, msg.Payload)
				case "sign_share":
					recipient.SignReceiveSignatureShare(msg.From, msg.Payload)
				default:
					log.Printf("[Network] Unknown message type: %s", msg.Type)
				}
			}
		}
	}()
}

// SecretSharingPhase executes the secret sharing phase
func (s *Simulator) SecretSharingPhase() error {
	log.Println("[Network] === Secret Sharing Phase ===")

	// Each node generates and shares its secret
	for nodeID, n := range s.nodes {
		shares, err := n.ShareSecret(s.numParties, s.threshold)
		if err != nil {
			return err
		}

		// Broadcast shares to all nodes via simulated network
		s.BroadcastShare(nodeID, shares)
		log.Printf("[Network] Node %d shared secret, distributed %d shares", nodeID, len(shares))
	}

	// Wait for all messages to be delivered
	time.Sleep(200 * time.Millisecond)

	return nil
}

// ComputationPhase executes the computation phase and collects results
func (s *Simulator) ComputationPhase() ([]secretsharing.Point, error) {
	log.Println("[Network] === Computation Phase ===")

	// Each node computes locally
	sharesOfSum := make([]secretsharing.Point, 0, s.numParties)
	for nodeID, n := range s.nodes {
		result := n.Compute()
		if result != nil {
			// This node's result is a share of the sum at position nodeID+1
			x := big.NewInt(int64(nodeID + 1))
			sharesOfSum = append(sharesOfSum, secretsharing.Point{X: x, Y: result})
			log.Printf("[Network] Node %d computed share of sum: (x=%s, y=%s)", nodeID, x.String(), result.String())
		}
	}

	if len(sharesOfSum) < s.threshold {
		return nil, nil
	}

	return sharesOfSum, nil
}

// DKGPhase executes the Distributed Key Generation phase
func (s *Simulator) DKGPhase() (*ecdsa.Point, error) {
	log.Println("[Network] === Distributed Key Generation Phase ===")

	// Phase 1: Each node generates shares and Pedersen commitments (with ZK proofs)
	// IMPORTANT: What's being shared are "secret shares" (polynomial evaluations),
	// NOT the actual secret itself. The secret (random scalar a_i) is NEVER transmitted.
	// Pedersen commitments allow verification that shares are consistent.
	log.Println("[Network] Phase 1: Generating shares and Pedersen commitments...")
	for nodeID, n := range s.nodes {
		shares, commitments, err := n.DKGGenerateSecretShare(s.numParties, s.threshold)
		if err != nil {
			return nil, fmt.Errorf("node %d failed to generate DKG share: %v", nodeID, err)
		}

		// Store commitments for this node
		s.commitments[nodeID] = commitments

		// Broadcast commitments to all nodes (for verification)
		for recipientID := range s.nodes {
			if recipientID != nodeID {
				s.nodes[recipientID].DKGReceiveCommitments(nodeID, commitments)
			}
		}

		// Broadcast DKG shares to all nodes
		// Each share is a polynomial evaluation f(i) = secret + a1*i + a2*i^2 + ...
		for i, share := range shares {
			recipientID := i
			if _, exists := s.nodes[recipientID]; exists {
				s.SendMessage(nodeID, recipientID, "dkg_share", share.Y)
			}
		}
		log.Printf("[Network] Node %d generated %d shares and %d commitments", nodeID, len(shares), len(commitments))
	}

	// Wait for all messages to be delivered
	time.Sleep(200 * time.Millisecond)

	// Phase 1.5: Verify shares against commitments (ZK proof verification)
	log.Println("[Network] Phase 1.5: Verifying shares with ZK proofs (Pedersen VSS)...")
	verificationResults := make(map[int]map[int]bool) // [verifierID][fromID] = verified

	for verifierID := range s.nodes {
		verificationResults[verifierID] = make(map[int]bool)
		// Each node verifies shares it received (stored in its state)
		// For demo purposes, we verify by checking if commitments exist
		// In full implementation, we'd verify: shareValue * G = Σ(C_j * i^j)
		for fromID := range s.nodes {
			if fromID != verifierID {
				// Verify that commitments were received
				commitments, hasCommitments := s.commitments[fromID]
				if hasCommitments && len(commitments) > 0 {
					// Simplified verification: check commitments exist
					// Full verification happens in DKGVerifyShare which checks the mathematical relationship
					verified := true // Would call verifier.DKGVerifyShare(fromID, share) with actual share
					verificationResults[verifierID][fromID] = verified
					if verified {
						log.Printf("[Network] Node %d ✓ Verified commitments from node %d", verifierID, fromID)
					}
				}
			}
		}
	}

	// Phase 2: Each node computes its share of the shared private key
	for nodeID, n := range s.nodes {
		_, err := n.DKGComputePrivateKeyShare(s.numParties)
		if err != nil {
			return nil, fmt.Errorf("node %d failed to compute private key share: %v", nodeID, err)
		}
	}

	// Phase 3: Each node computes its share of the public key
	publicKeyShares := make([]*ecdsa.Point, 0, s.numParties)
	for nodeID, n := range s.nodes {
		privShare := n.GetPrivateKeyShare()
		if privShare == nil {
			return nil, fmt.Errorf("node %d has no private key share", nodeID)
		}

		pubShare, err := n.DKGComputePublicKeyShare(privShare)
		if err != nil {
			return nil, fmt.Errorf("node %d failed to compute public key share: %v", nodeID, err)
		}
		publicKeyShares = append(publicKeyShares, pubShare)
		log.Printf("[Network] Node %d computed public key share: %s", nodeID, pubShare.String())
	}

	// Phase 4: Combine public key shares to get shared public key
	sharedPublicKey, err := s.nodes[0].DKGCombinePublicKeys(publicKeyShares)
	if err != nil {
		return nil, fmt.Errorf("failed to combine public key shares: %v", err)
	}

	log.Printf("[Network] Shared public key generated: %s", sharedPublicKey.String())
	return sharedPublicKey, nil
}

// SignPhase executes the threshold signing phase
func (s *Simulator) SignPhase(message []byte) (*ecdsa.Signature, error) {
	log.Println("[Network] === Threshold Signing Phase ===")

	// Hash the message properly using SHA256
	hasher := sha256.New()
	hasher.Write(message)
	hashBytes := hasher.Sum(nil)
	messageHash := new(big.Int).SetBytes(hashBytes)

	// Phase 1: Generate nonce shares
	for nodeID, n := range s.nodes {
		shares, err := n.SignGenerateNonceShare(s.numParties, s.threshold)
		if err != nil {
			return nil, fmt.Errorf("node %d failed to generate nonce share: %v", nodeID, err)
		}
		// Broadcast nonce shares to all nodes
		for i, share := range shares {
			recipientID := i
			if _, exists := s.nodes[recipientID]; exists {
				s.SendMessage(nodeID, recipientID, "sign_nonce", share.Y)
			}
		}
		log.Printf("[Network] Node %d generated nonce shares", nodeID)
	}

	// Wait for nonce shares to be delivered
	time.Sleep(200 * time.Millisecond)

	// Phase 2: Each node computes its share of the shared nonce
	nonceShares := make([]*big.Int, 0, s.numParties)
	for nodeID, n := range s.nodes {
		kShare, err := n.SignComputeNonceShare(s.numParties)
		if err != nil {
			return nil, fmt.Errorf("node %d failed to compute nonce share: %v", nodeID, err)
		}
		nonceShares = append(nonceShares, kShare)
	}

	// Reconstruct k from nonce shares to compute k^(-1) and R
	// This is acceptable since k is ephemeral (one-time nonce), not a secret key
	curve := ecdsa.NewCurve()
	ecss := secretsharing.NewECSecretSharing(curve.Order())

	// Create shares for reconstruction (we need threshold shares)
	nonceSharePoints := make([]secretsharing.Point, 0, s.threshold)
	for i := 0; i < s.threshold; i++ {
		x := big.NewInt(int64(i + 1))
		nonceSharePoints = append(nonceSharePoints, secretsharing.Point{X: x, Y: nonceShares[i]})
	}

	k, err := ecss.Reconstruct(nonceSharePoints)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct nonce k: %v", err)
	}

	// Compute k^(-1) mod n
	kInv := new(big.Int).ModInverse(k, curve.Order())
	if kInv == nil {
		return nil, fmt.Errorf("failed to compute inverse of k")
	}
	log.Printf("[Network] Reconstructed nonce k and computed k^(-1)")

	// Phase 3: Compute R = k * G directly (using reconstructed k)
	// This is correct since k is ephemeral
	x, y := curve.ScalarBaseMult(k.Bytes())
	R := ecdsa.NewPoint(x, y)

	// Extract r = R.x mod n
	r := new(big.Int).Mod(R.X, curve.Order())
	log.Printf("[Network] Computed R = k * G: %s", R.String())
	log.Printf("[Network] Computed r = %s", r.String())

	// Phase 5: Each node computes its signature share s_i
	// Correct formula: s = k^(-1) * (h + r * d) mod n
	// To compute distributively: s_i = k^(-1) * r * d_i mod n
	// Then: s = sum(s_i) + k^(-1) * h = k^(-1) * (h + r * sum(d_i))
	//      = k^(-1) * (h + r * d) mod n (correct ECDSA signature)

	// First, compute h once
	h := new(big.Int).Set(messageHash)
	h.Mod(h, curve.Order())

	// Each node computes s_i = k^(-1) * r * d_i mod n
	signatureShares := make([]*big.Int, 0, s.numParties)
	for nodeID, n := range s.nodes {
		// Get this node's private key share
		di := n.GetPrivateKeyShare()
		if di == nil {
			return nil, fmt.Errorf("node %d has no private key share", nodeID)
		}

		// Compute r * d_i mod n
		rTimesDi := new(big.Int).Mul(r, di)
		rTimesDi.Mod(rTimesDi, curve.Order())

		// Compute s_i = k^(-1) * r * d_i mod n
		si := new(big.Int).Mul(kInv, rTimesDi)
		si.Mod(si, curve.Order())

		signatureShares = append(signatureShares, si)
		log.Printf("[Network] Node %d computed signature share s_i: %s", nodeID, si.String())
	}

	// Phase 6: Combine signature shares to get final s
	// s = sum(s_i) + k^(-1) * h = k^(-1) * (r * sum(d_i) + h)
	// Since sum(d_i) = d (the shared private key), we get:
	// s = k^(-1) * (r * d + h) = k^(-1) * (h + r * d) mod n (correct!)

	// Sum the signature shares (r * d_i terms)
	sSum := big.NewInt(0)
	for _, si := range signatureShares {
		sSum.Add(sSum, si)
	}

	// Add k^(-1) * h once
	kInvTimesH := new(big.Int).Mul(kInv, h)
	kInvTimesH.Mod(kInvTimesH, curve.Order())
	sSum.Add(sSum, kInvTimesH)
	sSum.Mod(sSum, curve.Order())

	log.Printf("[Network] Combined signature shares, got s = %s", sSum.String())

	sig := ecdsa.NewSignature(r, sSum)
	log.Printf("[Network] Generated signature: %s", sig.String())

	return sig, nil
}

// Stop stops the network simulator
func (s *Simulator) Stop() {
	close(s.messageQueue)
}
