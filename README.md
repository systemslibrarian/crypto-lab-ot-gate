# crypto-lab-ot-gate

## What It Is

crypto-lab-ot-gate implements 1-of-2 Oblivious Transfer using the Simplest OT protocol (Chou-Orlandi 2015) over Curve25519. A sender holds two messages M0 and M1. A receiver selects one message using a choice bit b ∈ {0,1} and receives M_b, while the sender learns nothing about b and the receiver learns nothing about M_{1-b}. The protocol uses one round of Edwards25519 Diffie-Hellman exchange followed by AES-256-GCM encryption of both messages under keys derived from the shared secrets. The two halves of the security argument are not symmetric: the sender learns nothing about the choice bit *unconditionally* (with r uniform, B is a uniform curve point either way — Chou-Orlandi, Lemma 1), while the receiver's inability to derive the other key rests on the **computational** Diffie-Hellman (CDH) assumption on Curve25519, in the random oracle model. OT is complete for two-party computation — any function computable securely by two parties can be built from OT as the sole primitive.

## When to Use It

- Use OT as the base primitive when building MPC protocols that evaluate arbitrary boolean or arithmetic circuits — OT extension generates the required volume of OTs efficiently.
- Use OT-based private set intersection when two parties need to find common elements without revealing their full sets — deployed in ad measurement and contact discovery.
- Do not use base OT (without extension) when millions of OTs are required — the elliptic curve cost is prohibitive. Use IKNP OT extension instead.
- Do not use this protocol in post-quantum threat models — discrete log on Curve25519, and with it CDH, is broken by Shor's algorithm. Post-quantum OT from lattice assumptions exists but is not standardized.
- Do not use OT alone when the computation involves more than two parties — use full MPC frameworks like SPDZ or ABY.
- Do NOT use this code in production — it is a browser teaching demo; build on a vetted MPC/OT library for real systems.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ot-gate](https://systemslibrarian.github.io/crypto-lab-ot-gate/)**

Enter two messages as the sender and select your choice as the receiver. The demo executes the full Simplest OT protocol with real Edwards25519 Diffie-Hellman values and AES-256-GCM encryption. The privacy audit panels show exactly what each party sees, confirming that the sender cannot determine the receiver's choice and the receiver cannot decrypt the unchosen message.

Three teaching visuals sit on top of the real protocol (they never fake a value):

1. **Key-reconciliation panel** — after the receiver decrypts, the demo shows the two *independent* routes to the shared secret side by side: the receiver's `r·A` and the sender's `a·B` (or `a·(B−A)` when b=1). Both are computed from real curve math and shown landing on the *same* point `arG` (highlighted green), while the sender's other key lands elsewhere (red) — making the commutativity the whole protocol rests on visible instead of algebraic.
2. **Color-coded value chips** — the sender's `k₀`/`k₁` and the receiver's derived key carry matching green/red chips so "which key equals which" reads as a diagram rather than a wall of hex.
3. **Choice-hiding match** — the visualizer is a 10-round game with a running accuracy tally against the dashed 1-in-3 baseline, plus a "let the computer guess 1000×" button that runs 1000 real challenges and plots the measured ~33% hit rate. The inability to beat random is not a computational assumption here but a fact about the distribution — A + r·G with fresh uniform r *is* a uniform curve point — which is why choice hiding holds against an unbounded sender.

First-use micro-glosses (scalar, base point G, `a·P`, `H`, why B hides b) are inlined so a newcomer to elliptic-curve crypto has an on-ramp without cluttering the narrative for those who already know.

## What Can Go Wrong

- **Malicious sender substituting A:** a malicious sender can send a specially crafted A (e.g., a low-order point outside the prime-order subgroup) so that `B = rG + bA` carries a torsion component that depends only on `b` — revealing the receiver's choice. The Simplest OT is secure against a semi-honest sender but requires a subgroup/torsion check on A for malicious security. (Sending `A` = the identity is a different failure: it makes `k₀` and `k₁` collapse to the same value, handing the receiver *both* messages.)
- **Malicious receiver sending invalid B:** a malicious receiver can send B values outside the curve's prime-order subgroup, potentially extracting information about both messages. Subgroup membership checks on B are required for malicious security.
- **Simplified key derivation:** this demo derives keys as `H(a·B)` / `H(r·A)` — the shared point alone. The real protocol salts the hash with the transcript: Chou-Orlandi define `H : (G × G) × G → {0,1}^κ` and compute `k_j = H_(A,B)(a·B − j·aA)`, receiver side `k_R = H_(A,B)(r·A)`. That salt keeps the random oracle local to the session; without it a man-in-the-middle can relay A, forward `B' = A + B` to the sender, and shift the ciphertexts so the receiver decrypts the *wrong* message (paper, "Non-Malleability in Practice"). Treat the demo's KDF as a teaching simplification, not the scheme.
- **Reusing the receiver's scalar r:** the *sender's* key A = aG is meant to be reused — Chou-Orlandi run setup once and amortize A over all m transfers, which is exactly where the protocol's speed comes from (2 + 3m exponentiations for m OTs). What must be fresh per transfer is the receiver's scalar r: reuse it and two transfers produce the identical B and the identical key, linking the two choices and repeating key material. Reusing A safely also depends on the transcript-salted KDF above.
- **Side-channel on choice encoding:** the receiver's B computation differs based on b — implementations must ensure the two code paths take equal time and access the same memory to prevent timing and cache-based choice leakage.
- **Missing post-quantum security:** Curve25519-based OT is broken by quantum computers. Lattice-based OT (e.g., from LWE) is an active research area without mature standardization.

## Real-World Usage

- **SCALE-MAMBA / SPDZ protocol:** uses OT extension (built on base OT) to generate Beaver multiplication triples in the offline phase, enabling general-purpose secure computation.
- **Google/Meta private set intersection:** deployed PSI protocols using OT extension for privacy-preserving ad measurement, allowing conversion attribution without sharing raw user identifiers.
- **IRTF Prio3 / VDAF (`draft-irtf-cfrg-vdaf`, still an Internet-Draft, not an RFC):** uses a related secret-sharing and MPC approach for aggregate telemetry without revealing individual measurements.
- **EMP-toolkit:** open-source MPC research library with optimized IKNP OT extension, used in academic work on private machine learning and secure auctions.
- **OpenMined PySyft:** uses OT-based protocols for federated learning with cryptographic privacy guarantees beyond differential privacy alone.

## Testing

The OT correctness and privacy claims are verified headlessly, not just by the
in-app "correctness" button. `npm test` runs a Vitest suite (`src/ot.test.ts`)
against the real protocol code in `src/ot.ts`:

- **Correctness:** for both choice bits, the receiver recovers exactly M_b, over
  a fixed check and 25 random sessions.
- **Receiver privacy:** the receiver's key fails to decrypt M_{1-b} (AES-256-GCM
  authentication rejects), and the receiver key equals the *chosen* sender key
  but never the other.
- **Key-derivation identity:** H(r·A) = H(a·B) when b=0 and H(a·(B−A)) when b=1,
  recomputed independently from public transcript values plus the sender scalar.
- **Sender privacy structure:** B(b=0) and B(b=1) are both valid, distinct curve
  points and the sender's encryption never branches on b.
- **DDH visualizer:** produces three distinct valid curve points and an unbiased
  CSPRNG-selected index; the 1000× auto-simulation's random strategy is verified
  to land near the 1-in-3 baseline over real challenges (never a trivial 0 or 1).
- **Key reconciliation:** the receiver's `r·A` and the sender's `a·B` /
  `a·(B−A)` are asserted byte-identical (the point both parties reach), the
  reconciled key equals the receiver's actual protocol key, and the unchosen key
  differs — the same identity the teaching panel visualizes.

```bash
npm test          # Vitest unit/property tests (crypto correctness + privacy)
npm run test:a11y # Playwright + axe-core WCAG A/AA gate (both themes)
```

CI runs `npm test` on every push (it is a required gate, not `--if-present`), so
a regression that broke recovery of M_b or leaked M_{1-b} would fail the build.

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

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
