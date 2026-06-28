# crypto-lab-ot-gate

## What It Is

crypto-lab-ot-gate implements 1-of-2 Oblivious Transfer using the Simplest OT protocol (Chou-Orlandi 2015) over Curve25519. A sender holds two messages M0 and M1. A receiver selects one message using a choice bit b ∈ {0,1} and receives M_b, while the sender learns nothing about b and the receiver learns nothing about M_{1-b}. The protocol uses one round of Edwards25519 Diffie-Hellman exchange followed by AES-256-GCM encryption of both messages under keys derived from the shared secrets. Security reduces to the Decisional Diffie-Hellman (DDH) assumption on Curve25519. OT is complete for two-party computation — any function computable securely by two parties can be built from OT as the sole primitive.

## When to Use It

- Use OT as the base primitive when building MPC protocols that evaluate arbitrary boolean or arithmetic circuits — OT extension generates the required volume of OTs efficiently.
- Use OT-based private set intersection when two parties need to find common elements without revealing their full sets — deployed in ad measurement and contact discovery.
- Do not use base OT (without extension) when millions of OTs are required — the elliptic curve cost is prohibitive. Use IKNP OT extension instead.
- Do not use this protocol in post-quantum threat models — DDH on Curve25519 is broken by Shor's algorithm. Post-quantum OT from lattice assumptions exists but is not standardized.
- Do not use OT alone when the computation involves more than two parties — use full MPC frameworks like SPDZ or ABY.
- Do NOT use this code in production — it is a browser teaching demo; build on a vetted MPC/OT library for real systems.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ot-gate](https://systemslibrarian.github.io/crypto-lab-ot-gate/)**

Enter two messages as the sender and select your choice as the receiver. The demo executes the full Simplest OT protocol with real Edwards25519 Diffie-Hellman values and AES-256-GCM encryption. The privacy audit panels show exactly what each party sees, confirming that the sender cannot determine the receiver's choice and the receiver cannot decrypt the unchosen message.

## What Can Go Wrong

- **Malicious sender substituting A:** a malicious sender can send a specially crafted A (e.g., A = identity element) that allows them to learn the receiver's choice. The Simplest OT is secure against a semi-honest sender but requires additional checks for malicious security.
- **Malicious receiver sending invalid B:** a malicious receiver can send B values outside the curve's prime-order subgroup, potentially extracting information about both messages. Subgroup membership checks on B are required for malicious security.
- **Reusing the sender's scalar a:** the sender scalar a must be fresh for each OT session. Reusing a across sessions breaks the binding between A and the session, enabling key recovery.
- **Side-channel on choice encoding:** the receiver's B computation differs based on b — implementations must ensure the two code paths take equal time and access the same memory to prevent timing and cache-based choice leakage.
- **Missing post-quantum security:** Curve25519-based OT is broken by quantum computers. Lattice-based OT (e.g., from LWE) is an active research area without mature standardization.

## Real-World Usage

- **SCALE-MAMBA / SPDZ protocol:** uses OT extension (built on base OT) to generate Beaver multiplication triples in the offline phase, enabling general-purpose secure computation.
- **Google/Meta private set intersection:** deployed PSI protocols using OT extension for privacy-preserving ad measurement, allowing conversion attribution without sharing raw user identifiers.
- **IETF PRIO (RFC 9521):** uses a related secret-sharing and MPC approach for aggregate telemetry without revealing individual measurements.
- **EMP-toolkit:** open-source MPC research library with optimized IKNP OT extension, used in academic work on private machine learning and secure auctions.
- **OpenMined PySyft:** uses OT-based protocols for federated learning with cryptographic privacy guarantees beyond differential privacy alone.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ot-gate
cd crypto-lab-ot-gate
npm install
npm run dev
```

## Related Demos

- [crypto-lab-garbled-gate](https://systemslibrarian.github.io/crypto-lab-garbled-gate/) — garbled circuits, which use oblivious transfer to deliver input labels.
- [crypto-lab-silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) — Shamir-based MPC secure sum.
- [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) — threshold signatures.
- [crypto-lab-oblivious-shelf](https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/) — IT-PIR for library query privacy.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
