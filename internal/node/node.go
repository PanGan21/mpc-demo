package node

import (
	"log"
	"math/big"
	"sync"

	"mpc-demo/internal/dkg"
	"mpc-demo/internal/ecdsa"
	"mpc-demo/internal/secretsharing"
	"mpc-demo/internal/signing"
)

// Message represents a message that can be sent between nodes
type Message struct {
	From    int
	To      int
	Type    string // "dkg_share", "sign_nonce", "sign_share", "share", "compute", "result"
	Payload *big.Int
	ECPoint *ecdsa.Point // For EC point payloads
	Bytes   []byte       // For arbitrary data (e.g., message hashes)
}

// Node represents an MPC node that would run on each party
type Node struct {
	ID             int
	Secret         *big.Int         // Original secret (for backward compat)
	receivedShares map[int]*big.Int // Shares received (for backward compat)
	share          *big.Int         // Own share (for backward compat)

	// DKG state
	dkg             *dkg.NodeDKG
	hasPrivateKey   bool
	privateKeyShare *big.Int

	// Signing state
	signer *signing.NodeSigning

	mu             sync.RWMutex
	ss             *secretsharing.SecretSharing
	expectedShares int
	ready          chan struct{}
	readyOnce      sync.Once
	result         *big.Int

	// ECDSA-related
	sharedPublicKey *ecdsa.Point
}

// NewNode creates a new MPC node
func NewNode(id int, secret *big.Int, numParties int) *Node {
	return &Node{
		ID:             id,
		Secret:         secret,
		receivedShares: make(map[int]*big.Int),
		expectedShares: numParties,
		ss:             secretsharing.NewSecretSharing(),
		ready:          make(chan struct{}, 1),
		dkg:            dkg.NewNodeDKG(id),
	}
}

// ShareSecret generates shares of this node's secret and returns them
// (Backward compatibility with original sum computation demo)
func (n *Node) ShareSecret(numParties, threshold int) ([]secretsharing.Point, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	shares, err := n.ss.Share(n.Secret, numParties, threshold)
	if err != nil {
		return nil, err
	}

	if len(shares) > n.ID {
		n.share = shares[n.ID].Y
	}

	log.Printf("[Node %d] Generated %d shares for secret", n.ID, len(shares))
	return shares, nil
}

// ReceiveShare processes a share received from another node
// (Backward compatibility)
func (n *Node) ReceiveShare(fromID int, share *big.Int) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.receivedShares[fromID] = share
	log.Printf("[Node %d] Received share from node %d", n.ID, fromID)

	if len(n.receivedShares) >= n.expectedShares {
		n.mu.Unlock()
		n.readyOnce.Do(func() {
			n.ready <- struct{}{}
		})
		n.mu.Lock()
	}
}

// Compute computes the result locally using all received shares
// (Backward compatibility with sum computation)
func (n *Node) Compute() *big.Int {
	select {
	case <-n.ready:
	default:
		<-n.ready
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	result := big.NewInt(0)
	for _, share := range n.receivedShares {
		result.Add(result, share)
	}
	if n.share != nil {
		if _, found := n.receivedShares[n.ID]; !found {
			result.Add(result, n.share)
		}
	}
	result.Mod(result, n.ss.Prime())

	n.result = result
	log.Printf("[Node %d] Computed local result (share of sum): %s", n.ID, result.String())
	return result
}

// GetResult returns the computed result
func (n *Node) GetResult() *big.Int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.result
}

// === DKG Methods ===

// DKGGenerateSecretShare generates secret share for DKG
func (n *Node) DKGGenerateSecretShare(numParties, threshold int) ([]secretsharing.Point, error) {
	return n.dkg.GenerateSecretShare(numParties, threshold)
}

// DKGReceiveShare receives a secret share during DKG
func (n *Node) DKGReceiveShare(fromID int, share *big.Int) {
	n.dkg.ReceiveShare(fromID, share)
}

// DKGComputePrivateKeyShare computes this node's share of the shared private key
func (n *Node) DKGComputePrivateKeyShare(numParties int) (*big.Int, error) {
	share, err := n.dkg.ComputeSharedPrivateKey(numParties)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.privateKeyShare = share
	n.hasPrivateKey = true
	n.mu.Unlock()
	return share, nil
}

// DKGComputePublicKeyShare computes this node's share of the public key
func (n *Node) DKGComputePublicKeyShare(privateKeyShare *big.Int) (*ecdsa.Point, error) {
	return n.dkg.ComputePublicKeyShare(privateKeyShare)
}

// DKGCombinePublicKeys combines public key shares to get shared public key
func (n *Node) DKGCombinePublicKeys(shares []*ecdsa.Point) (*ecdsa.Point, error) {
	result, err := n.dkg.CombinePublicKeyShares(shares)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.sharedPublicKey = result
	n.mu.Unlock()
	return result, nil
}

// GetSharedPublicKey returns the shared public key
func (n *Node) GetSharedPublicKey() *ecdsa.Point {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.sharedPublicKey
}

// GetPrivateKeyShare returns this node's share of the private key
func (n *Node) GetPrivateKeyShare() *big.Int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.privateKeyShare
}

// === Signing Methods ===

// InitSigning initializes signing for this node (requires private key share)
func (n *Node) InitSigning() error {
	n.mu.RLock()
	if !n.hasPrivateKey || n.privateKeyShare == nil {
		n.mu.RUnlock()
		return nil // Will be set later
	}
	privShare := n.privateKeyShare
	n.mu.RUnlock()

	n.signer = signing.NewNodeSigning(n.ID, privShare)
	return nil
}

// SignGenerateNonceShare generates nonce share for signing
func (n *Node) SignGenerateNonceShare(numParties, threshold int) ([]secretsharing.Point, error) {
	if n.signer == nil {
		if err := n.InitSigning(); err != nil {
			return nil, err
		}
	}
	return n.signer.GenerateNonceShare(numParties, threshold)
}

// SignReceiveNonceShare receives a nonce share
func (n *Node) SignReceiveNonceShare(fromID int, share *big.Int) {
	if n.signer == nil {
		n.InitSigning()
	}
	n.signer.ReceiveNonceShare(fromID, share)
}

// SignComputeNonceShare computes share of shared nonce
func (n *Node) SignComputeNonceShare(numParties int) (*big.Int, error) {
	if n.signer == nil {
		if err := n.InitSigning(); err != nil {
			return nil, err
		}
	}
	return n.signer.ComputeSharedNonce(numParties)
}

// SignComputeR computes R_i = k_i * G
func (n *Node) SignComputeR(nonceShare *big.Int) (*ecdsa.Point, error) {
	if n.signer == nil {
		if err := n.InitSigning(); err != nil {
			return nil, err
		}
	}
	return n.signer.ComputeR(nonceShare)
}

// SignCombineR combines R points to get r
func (n *Node) SignCombineR(rPoints []*ecdsa.Point) (*big.Int, error) {
	if n.signer == nil {
		if err := n.InitSigning(); err != nil {
			return nil, err
		}
	}
	return n.signer.CombineRPoints(rPoints)
}

// SignComputeSignatureShare computes signature share s_i
func (n *Node) SignComputeSignatureShare(kShare, r *big.Int, messageHash *big.Int) (*big.Int, error) {
	if n.signer == nil {
		if err := n.InitSigning(); err != nil {
			return nil, err
		}
	}
	return n.signer.ComputeSignatureShare(kShare, r, messageHash)
}

// SignReceiveSignatureShare receives a signature share
func (n *Node) SignReceiveSignatureShare(fromID int, share *big.Int) {
	if n.signer == nil {
		n.InitSigning()
	}
	n.signer.ReceiveSignatureShare(fromID, share)
}

// SignCombineSignatureShares combines signature shares to get final s
func (n *Node) SignCombineSignatureShares(numParties int) (*big.Int, error) {
	if n.signer == nil {
		if err := n.InitSigning(); err != nil {
			return nil, err
		}
	}
	return n.signer.CombineSignatureShares(numParties)
}
