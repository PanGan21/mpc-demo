# Threshold ECDSA Multi-Party Computation Demo

A demonstration of threshold ECDSA signature generation using Multi-Party Computation (MPC) in Go. Multiple parties collaboratively generate an ECDSA key pair and sign messages without ever reconstructing the private key.

## Overview

This project implements **threshold ECDSA signatures** where:

- **n parties** collaborate to generate a shared ECDSA key pair
- **t+1 parties** (threshold) must cooperate to create a signature
- The **private key is never reconstructed** - it only exists as shares
- Individual parties cannot sign alone or learn the private key

The implementation includes:

- **Shamir's Secret Sharing** for distributing secrets
- **Distributed Key Generation (DKG)** for collaborative key generation
- **Threshold Signing Protocol** for distributed signature creation
- **Zero-Knowledge Proofs** (Pedersen VSS and Schnorr proofs) for malicious security
- **Network Simulator** for multi-party communication

## Architecture

```mermaid
graph TB
    subgraph Network[Network Simulator]
        Net[Simulator<br/>Orchestrates Protocol]
    end

    subgraph Nodes[MPC Nodes]
        N0[Node 0<br/>DKG + Signing]
        N1[Node 1<br/>DKG + Signing]
        N2[Node 2<br/>DKG + Signing]
        N3[Node N<br/>DKG + Signing]
    end

    subgraph Components[Core Components]
        DKG[DKG Module<br/>Key Generation]
        Sign[Signing Module<br/>Signature Generation]
        SS[Secret Sharing<br/>Shamir's SSS]
        EC[ECDSA<br/>Curve Operations]
    end

    Net --> Nodes
    N0 --> DKG
    N1 --> DKG
    N2 --> DKG
    N3 --> DKG

    N0 --> Sign
    N1 --> Sign
    N2 --> Sign
    N3 --> Sign

    DKG --> SS
    Sign --> SS
    Sign --> EC
    DKG --> EC

    style Network fill:#e1f5ff
    style Nodes fill:#fff4e1
    style Components fill:#e8f5e9
```

### Core Components

1. **Secret Sharing** (`internal/secretsharing/`)

   - Shamir's Secret Sharing over finite fields
   - Supports threshold-based reconstruction (k-out-of-n)
   - Polynomial-based secret distribution

2. **ECDSA Operations** (`internal/ecdsa/`)

   - Elliptic curve point arithmetic
   - Point addition and scalar multiplication
   - Signature generation and verification

3. **Distributed Key Generation** (`internal/dkg/`)

   - Collaborative key pair generation
   - Private key shares computation
   - Public key aggregation

4. **Threshold Signing** (`internal/signing/`)

   - Distributed nonce generation
   - Signature share computation
   - Share combination into final signature

5. **Zero-Knowledge Proofs** (`internal/zkproof/`)
   - Pedersen commitments for Verifiable Secret Sharing
   - Schnorr proofs for signature share verification
   - Malicious security guarantees

6. **Network Simulator** (`cmd/mpc-demo/network/`)
   - Simulates P2P communication
   - Message routing between nodes
   - Protocol orchestration

## How It Works

### Distributed Key Generation (DKG)

```mermaid
sequenceDiagram
    participant N0 as Node 0
    participant N1 as Node 1
    participant N2 as Node 2
    participant N3 as Node N

    Note over N0,N3: Phase 1: Generate and Share Secret Scalar
    N0->>N1: Share f₀(1)
    N0->>N2: Share f₀(2)
    N0->>N3: Share f₀(N)
    N1->>N0: Share f₁(0)
    N1->>N2: Share f₁(2)
    N1->>N3: Share f₁(N)
    Note over N0,N3: ... (all nodes share)

    Note over N0,N3: Phase 2: Compute Private Key Share
    N0->>N0: d₀ = Σ fᵢ(0)
    N1->>N1: d₁ = Σ fᵢ(1)
    N2->>N2: d₂ = Σ fᵢ(2)
    N3->>N3: dₙ = Σ fᵢ(N)

    Note over N0,N3: Phase 3: Compute Public Key Shares
    N0->>N0: Q₀ = d₀ · G
    N1->>N1: Q₁ = d₁ · G
    N2->>N2: Q₂ = d₂ · G
    N3->>N3: Qₙ = dₙ · G

    Note over N0,N3: Phase 4: Combine Public Key
    N0->>N0: Q = Q₀ + Q₁ + Q₂ + ... + Qₙ
    Note over N0,N3: Shared Public Key = d · G<br/>(where d never reconstructed)
```

**Important Security Note**: The actual secret scalars (`a_i`) are **never transmitted**. Only polynomial evaluations (shares) are shared. A single share reveals nothing about the secret - you need threshold+1 shares to reconstruct.

### Threshold Signing Protocol

```mermaid
sequenceDiagram
    participant N0 as Node 0
    participant N1 as Node 1
    participant N2 as Node 2
    participant N3 as Node N

    Note over N0,N3: Phase 1: Generate Random Nonce k
    N0->>N1: Share k₀(1)
    N0->>N2: Share k₀(2)
    N1->>N0: Share k₁(0)
    Note over N0,N3: ... (all nodes share nonce)
    N0->>N0: k₀ = Σ kᵢ(0)
    N1->>N1: k₁ = Σ kᵢ(1)

    Note over N0,N3: Phase 2: Compute R = k · G
    N0->>N0: R₀ = k₀ · G
    N1->>N1: R₁ = k₁ · G
    N0->>N1: R₀
    N1->>N0: R₁
    N0->>N0: R = R₀ + R₁ + ...
    N0->>N0: r = R.x mod n

    Note over N0,N3: Phase 3: Compute Signature Shares
    N0->>N0: s₀ = k₀⁻¹ · (h + r · d₀)
    N1->>N1: s₁ = k₁⁻¹ · (h + r · d₁)

    Note over N0,N3: Phase 4: Combine Signature
    N0->>N0: s = s₀ + s₁ + ...
    Note over N0,N3: Final Signature: (r, s)
```

## Running the Demo

### Prerequisites

- Go 1.21 or later
- Make (optional, but recommended)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd mpc-demo

# Install dependencies
make tidy
```

### Using the Makefile

The project includes a `Makefile` with common tasks. Run `make help` to see all available targets:

```
  build          Build the binary
  run            Run the demo directly
  fmt            Format all Go source files
  tidy           Tidy module dependencies
  clean          Remove build artifacts
```

**Quick start:**

```bash
# Run the demo directly (no build step)
make run

# Or build a binary first, then run it
make build && ./bin/mpc-demo
```

### Without Make

If you don't have `make` installed, you can use `go` directly:

```bash
go run cmd/mpc-demo/main.go
```

### Example Output

```
=== Threshold ECDSA Signature Demo ===
Configuration:
  Number of parties: 5
  Threshold: 3

Phase 1: Distributed Key Generation (DKG)
✅ Shared public key generated: (x: ..., y: ...)

Phase 2: Threshold Signing
Message to sign: Hello, Threshold ECDSA!
✅ Signature generated: (r: ..., s: ...)

Phase 3: Signature Verification
✅ Signature is VALID!

Key achievements:
  • Shared key pair generated without reconstructing private key
  • Signature generated without reconstructing private key
  • Private key never existed in one place
  • Signature verified successfully with shared public key
```

## Security Properties

1. **Privacy**: Private key is never reconstructed - only shares exist
2. **Threshold Security**: Requires t+1 parties to sign (resistant to up to t malicious parties)
3. **Correctness**: All honest parties compute the same public key and signature
4. **Additive Homomorphism**: Public key aggregation works without private key reconstruction

## Zero-Knowledge Proofs

This implementation includes **zero-knowledge proofs (ZK proofs)** to provide **malicious security** - meaning nodes can verify that others are following the protocol correctly, even if they try to cheat.

### What are Zero-Knowledge Proofs?

Zero-knowledge proofs allow one party (the **prover**) to convince another party (the **verifier**) that they know a secret value, **without revealing the secret itself**. The verifier learns nothing about the secret except that the prover knows it.

### Pedersen Verifiable Secret Sharing (VSS)

In the DKG phase, we use **Pedersen commitments** to make secret sharing verifiable:

```mermaid
sequenceDiagram
    participant Prover as Node i (Prover)
    participant Verifier as Node j (Verifier)
    
    Note over Prover: Generate polynomial<br/>f(x) = a₀ + a₁x + ... + aₜxᵗ
    Note over Prover: Create commitments<br/>Cⱼ = aⱼ·G + rⱼ·H
    Prover->>Verifier: Commitments C₀, C₁, ..., Cₜ
    Prover->>Verifier: Share f(j)
    
    Note over Verifier: Verify:<br/>f(j)·G = Σ(Cⱼ·j^j)
    Verifier->>Verifier: ✓ Share is consistent<br/>with commitments
    
    Note over Verifier: Secret a₀ remains<br/>HIDDEN (only commitments revealed)
```

**How it works:**

1. **Commitment Phase**: Each node creates Pedersen commitments to polynomial coefficients:
   - `C_j = a_j·G + r_j·H` where:
     - `a_j` = polynomial coefficient (secret)
     - `r_j` = random blinding factor
     - `G, H` = elliptic curve generators

2. **Share Distribution**: Nodes send both:
   - Shares: `f(i)` = polynomial evaluation at point `i`
   - Commitments: Public commitments to coefficients

3. **Verification**: Recipients verify that:
   - `f(i)·G = Σ(C_j·i^j)` 
   - This proves the share is consistent with the committed polynomial **without revealing the secret**

**Security Properties:**
- **Hiding**: Commitments reveal nothing about the secret
- **Binding**: Cannot change the secret after committing
- **Verifiability**: Can detect if shares are inconsistent

### Schnorr Proofs for Signature Shares

During threshold signing, nodes can prove they computed their signature share correctly using **Schnorr proofs**:

```mermaid
sequenceDiagram
    participant Prover as Node i (Prover)
    participant Verifier as Other Nodes
    
    Note over Prover: Knows: d_i (private key share)
    Note over Prover: Public: Q_i = d_i·G
    Note over Prover: Computes: s_i = k^(-1)·(h + r·d_i)
    
    Prover->>Prover: Choose random r, compute R = r·G
    Prover->>Verifier: R (commitment)
    Verifier->>Prover: Challenge c = H(R || Q_i || context)
    Prover->>Prover: z = r + c·d_i
    Prover->>Verifier: Proof (c, z)
    
    Note over Verifier: Verify: z·G = R + c·Q_i
    Verifier->>Verifier: ✓ Prover knows d_i<br/>(without revealing it)
```

**Protocol Steps:**

1. **Commitment**: Prover chooses random `r`, computes `R = r·G`, sends `R`
2. **Challenge**: Verifier sends challenge `c = H(R || public_info || context)`
3. **Response**: Prover computes `z = r + c·d_i` and sends `(c, z)`
4. **Verification**: Verifier checks `z·G = R + c·Q_i`

This proves the prover knows `d_i` (their private key share) **without revealing it**.

### Why ZK Proofs Matter

**Without ZK Proofs (Honest-but-Curious):**
- Assumes nodes follow the protocol correctly
- Vulnerable to malicious nodes sending fake shares
- No way to detect cheating

**With ZK Proofs (Malicious Security):**
- Nodes can verify others are honest
- Malicious nodes are detected and rejected
- Protocol remains secure even with adversarial nodes

## Implementation Details

### Secret Sharing

Each node generates a random secret scalar `s_i` and creates a polynomial:

```
f_i(x) = s_i + a₁x + a₂x² + ... + aₜxᵗ
```

Shares are polynomial evaluations: `f_i(0), f_i(1), ..., f_i(n)`

### DKG Protocol

1. Each node generates random scalar `s_i` and shares it
2. Nodes compute local private key share: `d_i = Σⱼ f_j(i)`
3. Shared private key: `d = Σᵢ s_i` (never reconstructed)
4. Public key: `Q = d · G = (Σᵢ d_i) · G = Σᵢ (d_i · G)`

### Threshold Signing

1. **Nonce Generation**: Joint generation of random `k` via secret sharing
2. **Compute R**: `R = k · G`, extract `r = R.x mod n`
3. **Signature Shares**: Each node computes `s_i = k_i⁻¹ · (h + r · d_i)`
4. **Combine**: Final signature `s = Σᵢ s_i`

## Limitations

This is a **toy/educational implementation** with the following limitations:

- **Simplified ZK proofs**: The ZK proof implementation demonstrates concepts but uses simplified verification (full production would verify complete mathematical relationships)
- **Simplified nonce generation**: Nonces are reconstructed for simplicity (in production, would use more secure joint randomness)
- **Simulated network**: Uses channels, not real network communication
- **Educational focus**: Designed for learning, not production security

## Educational Notes

This implementation demonstrates:

- How secret sharing enables threshold cryptography
- Distributed key generation without a trusted dealer
- Threshold signature generation without key reconstruction
- Additive homomorphic properties of elliptic curves

## License

Educational project - feel free to use and modify for learning purposes.
