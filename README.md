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

5. **Network Simulator** (`cmd/mpc-demo/network/`)
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

- Go 1.19 or later

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd mpc-demo

# Install dependencies
go mod tidy
```

### Execute

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

- **Honest-but-curious security model** (no malicious security proofs)
- **Simplified nonce generation** (nonces are reconstructed for simplicity)
- **No zero-knowledge proofs** (would be needed for production)
- **Simulated network** (uses channels, not real network)

## Educational Notes

This implementation demonstrates:

- How secret sharing enables threshold cryptography
- Distributed key generation without a trusted dealer
- Threshold signature generation without key reconstruction
- Additive homomorphic properties of elliptic curves

## License

Educational project - feel free to use and modify for learning purposes.
