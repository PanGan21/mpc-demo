# Multi-Party Computation (MPC) Demo

A toy implementation of a Multi-Party Computation system in Go, focusing on architecture and using Go channels for communication between parties.

## Overview

This project demonstrates secure multi-party computation where multiple parties can collaboratively compute a function (in this case, sum) without revealing their individual inputs to each other. The implementation uses:

- **Shamir's Secret Sharing**: Cryptographic secret sharing scheme
- **Go Channels**: For inter-party communication
- **MPC Protocol**: Secure computation protocol that preserves privacy

## Architecture

### Components

1. **SecretSharing** (`secret_sharing.go`)

   - Implements Shamir's Secret Sharing (SSS)
   - Splits secrets into shares using polynomial interpolation over a finite field
   - Supports threshold-based reconstruction (k-out-of-n)

2. **Party** (`party.go`)

   - Represents a participant in the MPC protocol
   - Each party has:
     - A secret input value
     - Channels for receiving messages from other parties
     - Channels for communicating with the coordinator
   - Handles secret sharing and computation phases

3. **MPCProtocol** (`mpc.go`)

   - Orchestrates the multi-party computation
   - Manages the protocol phases:
     - **Secret Sharing Phase**: Each party shares its secret using SSS
     - **Computation Phase**: Parties compute on shares without revealing secrets
   - Coordinates communication between parties via channels

4. **Main** (`main.go`)
   - Demo program showcasing the MPC system
   - Computes the sum of multiple secrets without revealing individual values

### Communication Flow

```
Coordinator (MPCProtocol)
    │
    ├─── Party 0 ────────┐
    │    (Secret: 42)    │
    │                    │
    ├─── Party 1 ────────┤
    │    (Secret: 17)    ├───> Shares exchanged via channels
    │                    │
    ├─── Party 2 ────────┤
    │    (Secret: 89)    │
    │                    │
    └─── Party N         │
         (Secret: X)     │
                         │
                  Result: Sum computed securely
```

### Channel Architecture

Each party has:

- **CoordChannel**: Channel for coordinator communication
- **OutChannel**: Channel for broadcasting to other parties
- **InChannels**: Map of channels for receiving from specific parties

The coordinator uses these channels to:

1. Distribute shares during secret sharing phase
2. Trigger computation phase
3. Collect results

## How It Works

### 1. Secret Sharing Phase

For each party with secret `s`:

- Create a random polynomial `f(x) = s + a₁x + a₂x² + ... + aₖ₋₁xᵏ⁻¹`
- Evaluate at points x=1, 2, ..., n to get n shares
- Distribute share `f(i)` to party `i`

### 2. Computation Phase

- Each party receives shares of all other parties' secrets
- Parties compute locally on shares (additive homomorphism)
- Results are aggregated without revealing individual inputs

### 3. Result Reconstruction

- The final result (sum) can be computed from the shared values
- Individual secrets remain hidden

## Security Properties

1. **Privacy**: Individual secrets are never revealed - only shares are exchanged
2. **Threshold Security**: System is secure as long as fewer than `threshold` parties collude
3. **Correctness**: All parties compute the same result if they follow the protocol

## Running the Demo

```bash
# Install dependencies
go mod tidy

# Run the demo
go run .
```

Example output:

```
=== Multi-Party Computation Demo ===

Configuration:
  Number of parties: 5
  Threshold: 3
  Secrets:
    Party 0: 42
    Party 1: 17
    Party 2: 89
    Party 3: 123
    Party 4: 56

=== Starting MPC Protocol ===
=== Secret Sharing Phase ===
...
=== Computation Phase ===
...

=== Results ===
Computed sum (via MPC): 327
Expected sum:           327
✅ MPC computation successful!
```

## Project Structure

```
mpc-demo/
├── go.mod              # Go module definition
├── main.go             # Main demo program
├── secret_sharing.go   # Shamir's Secret Sharing implementation
├── party.go            # Party/node structure with channels
├── mpc.go              # MPC protocol orchestrator
└── README.md           # This file
```

## Future Enhancements

- [ ] Network-based communication (replace channels with TCP/gRPC)
- [ ] More complex computations (multiplication, comparison)
- [ ] Malicious security (instead of just honest-but-curious)
- [ ] Zero-knowledge proofs integration
- [ ] Better synchronization primitives
- [ ] Performance optimizations

## Educational Notes

This is a **toy implementation** for educational purposes. It demonstrates:

- Channel-based concurrency in Go
- Cryptographic secret sharing
- MPC protocol architecture

For production use, you would need:

- Network transport layer
- Authentication and encryption
- Malicious security guarantees
- Performance optimizations
- Formal security proofs

## License

This is a demo project for educational purposes.
