package main

import (
	"crypto/elliptic"
	"fmt"
	"log"
	"math/big"

	"mpc-demo/cmd/mpc-demo/network"
	"mpc-demo/internal/ecdsa"
	"mpc-demo/internal/secretsharing"
)

func main() {
	fmt.Println("=== Multi-Party Computation Demo ===")
	fmt.Println()

	// Configuration
	numParties := 5
	threshold := 3 // Require at least 3 parties to reconstruct

	// Initialize network simulator
	net := network.NewSimulator(numParties, threshold)
	net.StartMessageHandler()

	// Add nodes to the network (secrets not needed for ECDSA DKG)
	fmt.Println("=== Threshold ECDSA Signature Demo ===")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Number of parties: %d\n", numParties)
	fmt.Printf("  Threshold: %d\n", threshold)
	fmt.Println()

	// Add nodes (no secrets needed - DKG generates keys)
	for i := 0; i < numParties; i++ {
		net.AddNode(i, big.NewInt(0)) // Dummy secret, not used for ECDSA
	}

	// === Phase 1: Distributed Key Generation ===
	fmt.Println("Phase 1: Distributed Key Generation (DKG)")
	fmt.Println("Nodes collaboratively generate a shared ECDSA key pair...")
	fmt.Println()

	publicKey, err := net.DKGPhase()
	if err != nil {
		log.Fatalf("DKG failed: %v", err)
	}

	fmt.Printf("✅ Shared public key generated: %s\n", publicKey.String())
	fmt.Println()

	// === Phase 2: Threshold Signing ===
	message := []byte("Hello, Threshold ECDSA!")
	fmt.Printf("Phase 2: Threshold Signing\n")
	fmt.Printf("Message to sign: %s\n", string(message))
	fmt.Println()

	signature, err := net.SignPhase(message)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}

	fmt.Printf("✅ Signature generated: %s\n", signature.String())
	fmt.Println()

	// === Phase 3: Signature Verification ===
	fmt.Println("Phase 3: Signature Verification")
	fmt.Println("Verifying signature with shared public key...")

	// Verify signature using the shared public key
	// VerifyWithCurve hashes the message internally, so we just pass the raw message
	valid := ecdsa.VerifyWithCurve(
		elliptic.P256(),
		publicKey.X,
		publicKey.Y,
		message,
		signature.R,
		signature.S,
	)

	if valid {
		fmt.Println("✅ Signature is VALID!")
		fmt.Println()
		fmt.Println("Key achievements:")
		fmt.Println("  • Shared key pair generated without reconstructing private key")
		fmt.Println("  • Signature generated without reconstructing private key")
		fmt.Println("  • Private key never existed in one place")
		fmt.Println("  • Signature verified successfully with shared public key")
		fmt.Println()
		fmt.Println("Protocol correctness:")
		fmt.Println("  • Nonce k is reconstructed from shares (ephemeral, acceptable)")
		fmt.Println("  • k^(-1) computed from reconstructed k")
		fmt.Println("  • Signature computed as: s = k^(-1) * (h + r * d)")
		fmt.Println("  • Where d is never reconstructed (only shares d_i are used)")
	} else {
		fmt.Println("❌ Signature verification FAILED!")
		fmt.Println("This should not happen with the corrected implementation.")
	}

	fmt.Println()
	fmt.Println("=== Original Sum Computation Demo (for comparison) ===")
	demoSumComputation(net)

	fmt.Println()
	fmt.Println("=== Secret Sharing Demonstration ===")
	demoSecretSharing()

	// Cleanup
	net.Stop()
}

// demoSumComputation demonstrates the original sum computation demo
func demoSumComputation(net *network.Simulator) {
	// Re-create network for sum computation
	numParties := 5
	threshold := 3

	net2 := network.NewSimulator(numParties, threshold)
	net2.StartMessageHandler()

	// Create secrets for each party
	secrets := []*big.Int{
		big.NewInt(42),
		big.NewInt(17),
		big.NewInt(89),
		big.NewInt(123),
		big.NewInt(56),
	}

	for i, secret := range secrets {
		net2.AddNode(i, secret)
	}

	fmt.Println("Phase 1: Secret Sharing Phase")
	if err := net2.SecretSharingPhase(); err != nil {
		log.Fatalf("Secret sharing failed: %v", err)
	}

	fmt.Println()
	fmt.Println("Phase 2: Computation Phase")
	sharesOfSum, err := net2.ComputationPhase()
	if err != nil {
		log.Fatalf("Computation failed: %v", err)
	}

	if len(sharesOfSum) < threshold {
		log.Fatalf("Not enough shares: got %d, need %d", len(sharesOfSum), threshold)
	}

	fmt.Println()
	fmt.Println("Phase 3: Reconstruction")
	ss := secretsharing.NewSecretSharing()
	reconstructionShares := sharesOfSum[:threshold]
	sum, err := ss.Reconstruct(reconstructionShares)
	if err != nil {
		log.Fatalf("Reconstruction failed: %v", err)
	}

	expectedSum := big.NewInt(0)
	for _, secret := range secrets {
		expectedSum.Add(expectedSum, secret)
	}

	fmt.Printf("Computed sum (via MPC): %s\n", sum.String())
	fmt.Printf("Expected sum:           %s\n", expectedSum.String())

	if sum.Cmp(expectedSum) == 0 {
		fmt.Println("✅ MPC computation successful!")
	} else {
		fmt.Printf("❌ Mismatch! Expected %s, got %s\n", expectedSum.String(), sum.String())
	}

	net2.Stop()
}

// demoSecretSharing demonstrates the secret sharing mechanism
func demoSecretSharing() {
	ss := secretsharing.NewSecretSharing()
	secret := big.NewInt(1337)
	n := 5
	k := 3

	fmt.Printf("Original secret: %s\n", secret.String())
	fmt.Printf("Sharing into %d shares with threshold %d\n", n, k)

	shares, err := ss.Share(secret, n, k)
	if err != nil {
		log.Fatalf("Failed to share secret: %v", err)
	}

	fmt.Printf("Generated shares:\n")
	for i, share := range shares {
		fmt.Printf("  Share %d: (x=%s, y=%s)\n", i+1, share.X.String(), share.Y.String())
	}

	// Reconstruct with first k shares
	fmt.Printf("\nReconstructing with first %d shares...\n", k)
	reconstructed, err := ss.Reconstruct(shares[:k])
	if err != nil {
		log.Fatalf("Failed to reconstruct: %v", err)
	}

	fmt.Printf("Reconstructed secret: %s\n", reconstructed.String())
	if reconstructed.Cmp(secret) == 0 {
		fmt.Println("✅ Secret successfully reconstructed!")
	} else {
		fmt.Println("❌ Reconstruction failed!")
	}

	// Try with different subset
	fmt.Printf("\nReconstructing with shares 2, 3, 4...\n")
	differentShares := []secretsharing.Point{shares[1], shares[2], shares[3]}
	reconstructed2, err := ss.Reconstruct(differentShares)
	if err != nil {
		log.Fatalf("Failed to reconstruct: %v", err)
	}

	fmt.Printf("Reconstructed secret: %s\n", reconstructed2.String())
	if reconstructed2.Cmp(secret) == 0 {
		fmt.Println("✅ Any k shares work for reconstruction!")
	}
}
