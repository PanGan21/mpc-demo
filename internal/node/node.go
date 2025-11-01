package node

import (
	"log"
	"math/big"
	"sync"

	"mpc-demo/internal/secretsharing"
)

// Message represents a message that can be sent between nodes
type Message struct {
	From    int
	To      int
	Type    string // "share", "compute", "result"
	Payload *big.Int
}

// Node represents an MPC node that would run on each party
type Node struct {
	ID             int
	Secret         *big.Int
	receivedShares map[int]*big.Int // Shares received from other nodes
	share          *big.Int         // Our own share of our secret
	mu             sync.RWMutex
	ss             *secretsharing.SecretSharing
	expectedShares int
	ready          chan struct{}
	readyOnce      sync.Once
	result         *big.Int
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
	}
}

// ShareSecret generates shares of this node's secret and returns them
// Each node would call this and then send shares to other nodes via the network
func (n *Node) ShareSecret(numParties, threshold int) ([]secretsharing.Point, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	shares, err := n.ss.Share(n.Secret, numParties, threshold)
	if err != nil {
		return nil, err
	}

	// Store our own share (at position n.ID)
	if len(shares) > n.ID {
		n.share = shares[n.ID].Y
	}

	log.Printf("[Node %d] Generated %d shares for secret", n.ID, len(shares))
	return shares, nil
}

// ReceiveShare processes a share received from another node
func (n *Node) ReceiveShare(fromID int, share *big.Int) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.receivedShares[fromID] = share
	log.Printf("[Node %d] Received share from node %d", n.ID, fromID)

	// Check if we've received all expected shares
	if len(n.receivedShares) >= n.expectedShares {
		n.mu.Unlock()
		n.readyOnce.Do(func() {
			n.ready <- struct{}{}
		})
		n.mu.Lock()
	}
}

// Compute computes the result locally using all received shares
// Returns a share of the sum (at this node's position)
func (n *Node) Compute() *big.Int {
	// Wait for all shares to be received
	select {
	case <-n.ready:
		// Ready, proceed
	default:
		<-n.ready
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Sum all shares at our position
	// Due to additive homomorphism: sum(shares) = share(sum(secrets))
	result := big.NewInt(0)

	// Sum all received shares
	for _, share := range n.receivedShares {
		result.Add(result, share)
	}

	// Also add our own share if we have it
	if n.share != nil {
		// Check if we already counted it in receivedShares
		if _, found := n.receivedShares[n.ID]; !found {
			result.Add(result, n.share)
		}
	}

	// Ensure result is in valid range
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
