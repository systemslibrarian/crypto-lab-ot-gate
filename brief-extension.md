# Extension brief — `crypto-lab-ot-gate`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-ot-gate` at `e1b7f4a44301` and `audits/_MASTER-TEMPLATE.md` (catalog `20cb434d89e4`).
Template §5: "Extend, never restructure." Source of the gap: Boneh–Shoup v0.6 §23.7 "OT extension"
(book pp. 1087–1091).

**Branch note.** A remote branch `feat/andos-history` exists. At the time of writing its tree is
byte-identical to `main` (`git diff --stat origin/feat/andos-history main` is empty; it is the
pre-squash source of PR #23, which landed as `e1b7f4a44301`). Re-run that diff before building;
if it is still empty, ignore the branch; if it is not, stop and report what differs. Do not build
on it.

**Verdict: extension — Section D1 stops describing OT extension and runs it.**

## What the lab has now (at `e1b7f4a44301`)

- **Base OT engine:** `src/ot.ts` — Chou–Orlandi "Simplest OT" over the Edwards25519 group from
  `@noble/curves`, AES-256-GCM via WebCrypto. `senderInit()` (`src/ot.ts:151`),
  `receiverChoose()` (`:159`), `senderEncrypt()` (`:182`, derives `k0 = H(a·B)`,
  `k1 = H(a·(B−A))` with `sha256` from `@noble/hashes`), `runFullOT()` (`:226`). The file header
  (`:12–20`) documents a teaching simplification: the KDF hashes the shared point alone, without
  the Chou–Orlandi transcript salt, and Section B1 says so on the page.
- **Section D1 is prose plus a static table:** `src/main.ts:388` ("D1. OT Extension (IKNP 2003)").
  The table at `src/main.ts:402–403` asserts unmeasured figures ("~2 ms" per base OT, "~33
  minutes" for 1 M, "~0.001 ms", "~1 second"), and its first row is labelled **"Base OT
  (X25519)"** — but `src/ot.ts:7–10` states the lab does not use the X25519 ladder; its base OT is
  Edwards25519 point arithmetic. A2 (`src/main.ts:104`) and the A3 flavors table
  (`src/main.ts:125`) also name IKNP in prose.
- **Tests:** `src/ot.test.ts` (Vitest, `vitest.config.ts` includes `src/**/*.{test,spec}.ts`);
  `e2e/claims.spec.ts` exists (469 lines; Chou–Orlandi correctness, reconciliation, DDH game);
  `e2e/gate.ts`, `e2e/a11y.spec.ts`, `e2e/andos.spec.ts`. Playwright serves on port 4261 with
  `--strictPort` (`playwright.config.ts`).
- **Mutation tooling:** none found — no mutation script, ledger or `data-verdict` markers in the
  tree (searched `*.ts`, `*.mjs`, `*.json`, `*.md` for `mutat|ledger`). §4.1c mutations are
  therefore performed by hand and reported in the five-step form; see Tests.
- **README:** sections What It Is · All-or-nothing disclosure connection · When to Use It · Live
  Demo (with a numbered list of three teaching visuals, `README.md:34–36`) · What Can Go Wrong ·
  Real-World Usage · Testing · How to Run Locally · Related Demos. There is no section literally
  titled "Exhibits"; extend the numbered list under Live Demo rather than adding a new section.

## What to add

**The one headline mechanism:** 128 public-key OTs, run once, become tens of thousands of OTs
made from nothing but AES and SHA-256 — because the roles reverse: the extension *sender* plays
base-OT *receiver* with a random secret choice vector `r ∈ {0,1}^128`, and every later transfer
is a row of a matrix whose columns the two sides expand from the base-OT keys.

Implement the protocol exactly as Boneh–Shoup §23.7 presents it, with t = 2, ℓ = 2,
C = (0ⁿ, 1ⁿ), n = 128 (the book's own instantiation; it is IKNP's construction):

1. **Setup (128 base OTs, roles reversed).** The extension receiver holds key pairs
   `(k_{j,0}, k_{j,1})`, j = 1..128; the extension sender holds `(r_j, k_{j,r_j})` with `r_j`
   uniform. Produce each pair with the lab's own Chou–Orlandi arithmetic (`senderInit`,
   `receiverChoose`, and the same point formulas as `senderEncrypt`) — the extension receiver
   runs the base-OT *sender* side. Time it.
2. **Online phase (one message).** The receiver, with choice values `s_i ∈ {1,2}` for
   i = 1..N, computes `u_i = (F(k_{1,0},i),…,F(k_{n,0},i))`, `v_i` likewise from `k_{j,1}`, and
   sends `p_i = v_i ⊕ u_i ⊕ C[s_i]`. The sender computes
   `q_i = (F(k_{1,r_1},i),…,F(k_{n,r_n},i)) ⊕ (r ∧ p_i)` and
   `y_i = (H(i,1,q_i), H(i,2,q_i ⊕ r))`; the receiver outputs `ŷ_i = H(i, s_i, u_i)`. Use the
   book's per-coordinate hash `H_{i,a}(x) := H(i, a, x)` (its variant that lets n′ = 128).
3. **Chosen messages.** Because `s_i` are the receiver's own choices, the sender masks real
   messages: `c_{i,a} = m_{i,a} ⊕ y_i[a]` (truncated to the message length), and the receiver
   recovers `m_{i,s_i} = c_{i,s_i} ⊕ ŷ_i`. (Exercise 11.17 gives the derandomisation for a
   *random* choice; it is not needed here — say so in a code comment.)
4. **Verify every transfer.** For all N: recovered message equals `m_{i,s_i}`, and
   `c_{i,3−s_i} ⊕ ŷ_i ≠ m_{i,3−s_i}`. The verdict counts both, from the arrays, never assumed.

**Break-it-yourself (deliberately broken mode, never the default):** the book's own corrupt-
receiver attack (§23.7, eq. 23.23). For the first 128 transfers the malicious receiver sends
`p*_j = v_j ⊕ u_j ⊕ (C[1] ⊕ e_j)`; then `y_j[1] = H(j, 1, u_j ⊕ r_j·e_j)`. The book assumes the
receiver later learns `y_j[1]` "due to a later step in a larger protocol" — model that honestly
as **known plaintext in the first 128 slots** (the receiver knows `m_{j,1}`, so
`y_j[1] = c_{j,1} ⊕ m_{j,1}`), and label the assumption on the page. Comparing against
`H(j,1,u_j)` and `H(j,1,u_j ⊕ e_j)` reveals `r_j`; after 128 probes the receiver holds all of
`r` (assert it equals the sender's real `r`), and for every remaining transfer it computes
`q_i = u_i ⊕ (r ∧ C[s_i])` and both `y_i[1]`, `y_i[2]` — **both messages of every later OT**.

**Measured, not asserted:** live counters for base OTs (128, ms), extended OTs (N, ms),
bytes sent in the online message (N × 16 B), hash calls, and a *projection* of "N base OTs at
the measured per-base-OT rate" labelled as a projection computed from this run.

## Why it belongs here and not in a new lab

D1 already promises this exact mechanism in prose; the base OT it extends is this lab's
`src/ot.ts`; and Garbled Gate (`crypto-lab-garbled-gate` at `ed9d62ba47ef`, `src/main.ts:338`,
`:478`) and SPDZ Forge (`crypto-lab-spdz-forge` at `d5d8b60211fa`, `README.md:57`, `:80` —
MASCOT named, not built) both point at OT extension as the thing they do not run. It is the
missing half of this lab's own Section D, not a new concept.

## SECURITY / CORRECTNESS INVARIANTS

1. Real computation only: base OTs are the lab's Chou–Orlandi in Edwards25519; F is AES-128 in
   CTR mode via WebCrypto (`F(k, i)` := bit i of `AES-128-CTR_k(0^{⌈N/8⌉})`, key = first 16 bytes
   of the 32-byte base-OT key); H is SHA-256 from the existing `@noble/hashes` dependency, with
   an unambiguous encoding of `(i, a, x)` (fixed-width big-endian i, one byte a, 16-byte x).
   Justify noble over WebCrypto in a comment: `crypto.subtle.digest` is one awaited call per
   hash, and the online phase needs about 3N hashes.
2. Base-OT key derivation for the 128 setup OTs **salts the hash with the transcript and the
   index** — `H(A ‖ B ‖ j ‖ point)` — in the new module, per Chou–Orlandi's typed KDF. Do not
   change `senderEncrypt` or the unsalted teaching KDF the existing sections document.
3. The corrupt-receiver mode lives in its own module, is off by default, is visibly marked
   broken, and cannot run unless the learner turns it on; resetting returns to honest mode.
4. Every verdict is computed from the arrays the run produced: correct-count, wrong-count,
   recovered-`r` equality, both-messages-recovered count. No verdict string without its count.
5. The page's honesty line: both parties run in one tab and the page can see every secret; the
   protocol is semi-honest (honest-but-curious) as the book presents it.
6. N is bounded (offer 1,000 / 10,000 / 100,000; reject anything else) and the work is chunked
   (e.g. 4,096 transfers per slice with a yield to the event loop) so the page stays responsive;
   an in-progress run can be cancelled and leaves no stale verdict.

## ARCHITECTURE

- `src/ext/base.ts` — `setupBaseOTs(n = 128)` returns the receiver's `(k_{j,0},k_{j,1})`, the
  sender's `r` and `k_{j,r_j}`, and timing; built on `senderInit` / `receiverChoose` from
  `src/ot.ts` (import, do not copy) plus the salted KDF of invariant 2.
- `src/ext/prf.ts` — AES-128-CTR column expansion; `src/ext/transpose.ts` — 128×128 bit-block
  transpose from column-major to per-transfer 16-byte rows.
- `src/ext/iknp.ts` — `receiverMessage(...)`, `senderOutputs(...)`, `receiverOutputs(...)`,
  `maskMessages(...)`, `unmask(...)`, `verifyAll(...)`.
- `src/ext/corrupt-receiver.ts` — the eq. 23.23 probe, `recoverR(...)`,
  `decryptBoth(...)`. Imported only by the broken-mode handler.
- `src/ext/ext.test.ts` — Vitest, picked up by the existing `src/**/*.test.ts` include.
- UI in a new `src/ui-ext.ts` (or a function block in `src/main.ts` beside `sectionD()`), mounted
  inside D1. `// [extension] point` markers: (a) the code C (book: 1-out-of-t via codewords),
  (b) a consistency check for malicious security (KOS15 / SoftSpokenOT — prose only),
  (c) feeding extended OTs to a consumer (e.g. Garbled Gate's input wires).

## UI

Inside D1, below the existing prose (which stays):

1. "Step 1 — run the 128 base OTs." Button; shows count, elapsed ms, ms per OT, and a strip of
   the sender's secret `r` (128 cells, masked by default, revealable — label which side knows it).
2. "Step 2 — choose N." Radio 1,000 / 10,000 / 100,000; receiver choice bits random, with the
   first 16 shown and editable.
3. "Step 3 — extend." Shows a zoomed 16×16 window of the bit matrix: column j from `k_{j,0}`,
   the `k_{j,1}` column, the XOR column, the receiver's `C[s_i]` row, and the sender's `q_i` row
   lining up with `u_i` or `u_i ⊕ r` — the reversal made visible. Counters: online bytes, hash
   calls, elapsed ms.
4. "Step 4 — check all N." Correct count, wrong-message count, verdict.
5. Comparison readout replacing the static table: measured base-OT rate, measured extension
   time, projection of N base OTs at the measured rate (labelled "projection from this run").
6. Broken-mode toggle "Malicious receiver (book eq. 23.23)": the 128-cell `r` strip fills bit
   by bit as probes land; then the count of later transfers for which both messages are
   recovered.

Stacks below 640px; the matrix window scrolls inside a labelled region.

## VISUAL SEMANTICS

Honest run, all N correct: success (icon + text + colour). Any wrong count: failure naming the
count. Broken mode, `r` recovered and both messages opened: **ALARM**, even though every
receiver-side check is green — the verdict reads as success and failure at once (see §4.1d).
Never colour alone; the `r` strip uses fill pattern plus text, not hue.

## EDGE CASES

- N outside the offered set → refused by name, no run.
- Extend before setup → button disabled with the reason stated; never a silent no-op.
- Re-running setup retires the extension verdict and says so (retirement test).
- Toggling broken mode retires any honest verdict and vice versa.
- Cancelling mid-run → partial counters cleared, verdict "cancelled", no stale success.
- WebCrypto unavailable → fail closed with an error, no fallback cipher.

## Tests

- **Vitest (`src/ext/ext.test.ts`):** correctness for s_i ∈ {1,2} across random runs at
  N = 1,000 and one N = 100,000 run; `q_i` equals `u_i` or `u_i ⊕ r` per choice (algebraic
  identity from the book, checked bitwise); the transpose round-trips; the receiver's view
  (`p_i`) is identical in distribution for s_i = 1 vs 2 at toy size (enumerate over all `r` for
  n = 4, a test-only parameter); corrupt-receiver recovers exactly the sender's `r` and both
  messages for every i > 128.
- **KATs:** AES-128 known answers for the CTR expansion (NIST SP 800-38A F.5.1 CTR-AES128 —
  four blocks, so longer than one block; verify the appendix number in the PDF before citing).
  SHA-256: one vector longer than 64 bytes from NIST CSRC examples (verify source). There are no
  standard KATs for IKNP itself — say so in the README Testing section.
- **`e2e/claims.spec.ts` additions** (compare page-printed values; include an independent
  re-derivation): the printed correct-count equals the printed N; online bytes = N × 16; the
  projection equals measured per-base-OT ms × N (recomputed from the two printed numbers); in
  broken mode, the revealed `r` strip equals the sender's `r` the page prints in its
  "both parties" view; retirement on N change; no-op guard (re-selecting the same N keeps the
  verdict).
- **§4.1c mutations (one per rendered verdict), five steps each:** flip `p_i`'s `C[s_i]` term;
  drop `r ∧ p_i` from `q_i`; swap the hash index a; break the transpose; make
  `recoverR` invert one bit. Each must turn a named test red with the bundle hash moved.
- **§4.1d negative claim — "This OT extension is secure only against honest-but-curious
  parties: a receiver who deviates learns the sender's secret r, and with it both messages of
  every later transfer."** Evidence fixture: broken mode after the probe; every receiver-side
  check the page renders reports success (all N chosen messages correct) while the
  both-messages count is N − 128 and the verdict reads **"ALL N TRANSFERS CORRECT — AND THE
  SENDER'S SECRET r RECOVERED"**. Assert the three §4.1d points; deleting the claim text must
  fail assertion 3.

## README and card follow-up

- What It Is: add one sentence — the lab now also runs IKNP-style OT extension (Boneh–Shoup
  §23.7) on top of its Chou–Orlandi base OTs, semi-honest only.
- Live Demo numbered list: add item 4, "OT extension, run" — 128 base OTs to N extended OTs,
  measured, with the malicious-receiver break.
- Testing: list the new Vitest file and the absence of IKNP KATs.
- Fix the D1 table's "Base OT (X25519)" label everywhere it propagates (grep `X25519` in
  `src/main.ts`, `README.md`, `index.html`).
- Handoff (do not edit `../crypto-lab`): candidate chip `OT Extension` (implemented); the card
  copy may say "128 base OTs → N measured"; concept-coverage line for the MPC concept.

## Do not touch

The Chou–Orlandi engine and its unsalted teaching KDF (`src/ot.ts`), Sections A–C and E
behaviour, existing tests, the theme pin, header, footer, port 4261, and the deploy workflow.

## Sources

- Boneh, D., Shoup, V. *A Graduate Course in Applied Cryptography*, v0.6, Jan 2023, §23.7 and
  Remark 23.8 (AES cost), eq. 23.23 (corrupt receiver). https://toc.cryptobook.us/
- Ishai, Y., Kilian, J., Nissim, K., Petrank, E. "Extending Oblivious Transfers Efficiently."
  CRYPTO 2003, LNCS 2729, pp. 145–161. doi:10.1007/978-3-540-45146-4_9
- Chou, T., Orlandi, C. "The Simplest Protocol for Oblivious Transfer." IACR ePrint 2015/267
  (already cited by the lab).
- Keller, M., Orsini, E., Scholl, P. "Actively Secure OT Extension with Optimal Overhead."
  CRYPTO 2015. doi:10.1007/978-3-662-47989-6_35; ePrint 2015/546 (prose / seam only).
- Roy, L. "SoftSpokenOT: Quieter OT Extension from Small-Field Silent VOLE in the Minicrypt
  Model." CRYPTO 2022. doi:10.1007/978-3-031-15802-5_23; ePrint 2022/192 (the book's ref. [137];
  prose / seam only).
- NIST SP 800-38A (CTR test vectors) — `[verify the appendix section number in the PDF before
  citing]`.
