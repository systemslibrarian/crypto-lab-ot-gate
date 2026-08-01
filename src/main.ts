import './style.css';
import {
  senderInit,
  receiverChoose,
  senderEncrypt,
  receiverDecrypt,
  tryDecrypt,
  runFullOT,
  generateDDHPoints,
  simulateDDHGuesses,
  reconcileKeys,
  bytesToHex,
  bigintToHex,
  type SenderState,
} from './ot';

// ═══════════════════════════════════════════════════════════════════════
//  Utility
// ═══════════════════════════════════════════════════════════════════════

function $(sel: string): HTMLElement {
  return document.querySelector(sel)!;
}

function truncHex(hex: string, n = 24): string {
  return hex.length > n ? hex.slice(0, n) + '…' : hex;
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ═══════════════════════════════════════════════════════════════════════
//  Theme toggle
// ═══════════════════════════════════════════════════════════════════════

function setupThemeToggle(): void {
  const btn = $('#theme-toggle') as HTMLButtonElement;
  const update = (): void => {
    const theme = document.documentElement.getAttribute('data-theme');
    btn.textContent = theme === 'dark' ? '☀️' : '🌙';
    btn.setAttribute(
      'aria-label',
      theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
    );
  };
  btn.addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    update();
  });
  update();
}

// ═══════════════════════════════════════════════════════════════════════
//  HTML sections
// ═══════════════════════════════════════════════════════════════════════

function header(): string {
  return `
  <div class="container">
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">OT Gate</h1>
        <p class="cl-hero-sub">1-of-2 Oblivious Transfer · Simplest OT (Chou–Orlandi) · Curve25519</p>
        <p class="cl-hero-desc">Run the Chou–Orlandi OT protocol end to end — watch the sender and receiver exchange curve points so the receiver unlocks exactly one of two messages while neither side learns the other's secret.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">Oblivious transfer is complete for secure two-party computation: with it alone you can build private set intersection, secure auctions, and password checks that leak nothing. Get OT right and the whole MPC stack stands on solid ground.</p>
      </aside>
    </header>
  </div>
  <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Toggle theme" hidden aria-hidden="true"></button>`;
}

// ── Section A ────────────────────────────────────────────────────────

function sectionA(): string {
  return `
  <section id="section-a" class="section" aria-labelledby="heading-a">
    <div class="container">
      <h2 id="heading-a">A. What is Oblivious Transfer?</h2>

      <div class="subsection">
        <h3>A1. The Core Problem</h3>
        <p>A sender holds two messages: <strong>M<sub>0</sub></strong> and
           <strong>M<sub>1</sub></strong>. A receiver wants exactly one — say
           M<sub>b</sub> where b&nbsp;∈&nbsp;{0,&thinsp;1}. The constraints:</p>
        <ul>
          <li>The receiver obtains M<sub>b</sub></li>
          <li>The receiver learns <em>nothing</em> about M<sub>1−b</sub></li>
          <li>The sender learns <em>nothing</em> about b (which message was chosen)</li>
        </ul>
        <p>This seems impossible: if the receiver sends b to the sender, the sender
           learns the choice. If the sender sends both messages, the receiver gets
           both. OT solves this with cryptography.</p>

        <div class="ot-visual" role="img" aria-label="OT visual: Sender holds M0 and locked M1. Receiver with choice b=0 receives M0. M1 stays hidden.">
          <div class="ot-visual-sender">
            <div class="ot-visual-label" style="color:var(--sender-color)">Sender</div>
            <div class="ot-visual-msg unlocked">M<sub>0</sub></div>
            <div class="ot-visual-msg locked">🔒 M<sub>1</sub></div>
          </div>
          <div class="ot-visual-channel" aria-hidden="true">
            <div class="ot-visual-arrow">→</div>
            <div class="ot-visual-label" style="color:var(--channel-color)">Channel</div>
          </div>
          <div class="ot-visual-receiver">
            <div class="ot-visual-label" style="color:var(--receiver-text)">Receiver</div>
            <div class="ot-visual-choice">b = 0</div>
            <div class="ot-visual-msg unlocked">M<sub>0</sub> ✓</div>
            <div class="ot-visual-msg hidden-msg">🔒 Hidden</div>
          </div>
        </div>
      </div>

      <div class="subsection">
        <h3>A2. Why OT Is Foundational</h3>
        <p>OT is <strong>complete for two-party computation</strong>: any function
           that two parties can compute securely can be built using OT as the only
           primitive. This was proven by <strong>Kilian&nbsp;(1988)</strong>.</p>
        <p>The key insight: OT lets two parties compute a function of their private
           inputs without revealing those inputs. In practice OT is the bottleneck in
           MPC protocols — <strong>OT extension</strong> protocols (like IKNP&nbsp;2003)
           generate millions of OTs efficiently from a small number of base OTs.</p>
        <p><strong>Examples:</strong></p>
        <ul>
          <li><strong>Private set intersection</strong> — does my contact list overlap with yours?</li>
          <li><strong>Password authentication</strong> — verify a password without the server learning it</li>
          <li><strong>Secure auctions</strong> — determine the winning bid without revealing losing bids</li>
        </ul>
      </div>

      <div class="subsection">
        <h3>A3. Flavors of OT</h3>
        <div class="table-wrapper" tabindex="0" role="region" aria-label="Flavors of oblivious transfer (scrollable table)">
          <table>
            <thead>
              <tr><th scope="col">Variant</th><th scope="col">Description</th><th scope="col">Use Case</th></tr>
            </thead>
            <tbody>
              <tr><td>1‑of‑2 OT</td><td>Receiver gets 1 of 2 messages</td><td>Foundational primitive</td></tr>
              <tr><td>1‑of‑n OT</td><td>Receiver gets 1 of n messages</td><td>Oblivious RAM</td></tr>
              <tr><td>k‑of‑n OT</td><td>Receiver gets k of n messages</td><td>Generalized selection</td></tr>
              <tr><td>OT extension (IKNP)</td><td>Generate m OTs from k base OTs</td><td>Practical MPC at scale</td></tr>
              <tr><td>Random OT</td><td>Messages are random — receiver learns one</td><td>Preprocessing for MPC</td></tr>
            </tbody>
          </table>
        </div>
        <p class="note">This demo implements <strong>1‑of‑2&nbsp;OT</strong> using
           the <strong>Simplest OT protocol</strong> (Chou-Orlandi&nbsp;2015).</p>
      </div>
    </div>
  </section>`;
}

// ── Section B ────────────────────────────────────────────────────────

function sectionB(): string {
  return `
  <section id="section-b" class="section" aria-labelledby="heading-b">
    <div class="container">
      <h2 id="heading-b">B. The Simplest OT Protocol</h2>

      <div class="subsection">
        <h3>B1. Protocol Description</h3>
        <p>The Simplest OT uses <strong>Edwards25519</strong> (Curve25519 in twisted
           Edwards form). Every value below is a point on this curve or a big secret number.</p>

        <div class="term-key" role="note" aria-label="Terms used in this section">
          <p class="term-key-head">First, four terms this protocol leans on:</p>
          <ul class="term-list">
            <li>${gloss('scalar (a, r)', 'a big secret random number, ~253 bits. Kept private; never sent.')}</li>
            <li>${gloss('G — the base point', 'a fixed, public point on the curve that everyone agrees on.')}</li>
            <li>${gloss('a · P (scalar times point)', 'add point P to itself a times. Easy forward; reversing it (finding a from a·P) is the hard discrete-log problem.')}</li>
            <li>${gloss('H(…)', 'SHA-256 — hashes a curve point down to a 256-bit AES key.')}</li>
          </ul>
        </div>

        <div class="protocol-flow" role="img" aria-label="Protocol flow: Step 1 Sender generates scalar a and sends A=aG. Step 2 Receiver generates B based on choice bit b. Step 3 Sender derives keys k0 and k1, encrypts and sends E0 and E1. Step 4 Receiver derives key and decrypts chosen message.">
          <div class="flow-col flow-sender">
            <div class="flow-header" style="color:var(--sender-color)">Sender</div>
            <div class="flow-step">Generate scalar <em>a</em><br>Compute A&nbsp;=&nbsp;aG</div>
            <div class="flow-step">&nbsp;</div>
            <div class="flow-step">k<sub>0</sub>&nbsp;=&nbsp;H(a·B)<br>k<sub>1</sub>&nbsp;=&nbsp;H(a·(B−A))<br>Encrypt E<sub>0</sub>,&nbsp;E<sub>1</sub></div>
            <div class="flow-step">&nbsp;</div>
          </div>
          <div class="flow-col flow-channel">
            <div class="flow-header" style="color:var(--channel-color)">Channel</div>
            <div class="flow-step">A →</div>
            <div class="flow-step">← B</div>
            <div class="flow-step">(E<sub>0</sub>,&nbsp;E<sub>1</sub>) →</div>
            <div class="flow-step">&nbsp;</div>
          </div>
          <div class="flow-col flow-receiver">
            <div class="flow-header" style="color:var(--receiver-text)">Receiver</div>
            <div class="flow-step">&nbsp;</div>
            <div class="flow-step">Generate scalar <em>r</em><br>b=0: B&nbsp;=&nbsp;rG<br>b=1: B&nbsp;=&nbsp;A+rG</div>
            <div class="flow-step">&nbsp;</div>
            <div class="flow-step">k<sub>b</sub>&nbsp;=&nbsp;H(r·A)<br>Decrypt M<sub>b</sub></div>
          </div>
        </div>

        <p><strong>Why it works:</strong> the trick is that scalar multiplication
           <em>commutes</em> — a·(r·G) and r·(a·G) are the same point, so the two
           parties reach one shared secret by different routes.</p>
        <ul>
          <li><strong>If b=0:</strong> the receiver sends B&nbsp;=&nbsp;rG. The sender
              computes a·B&nbsp;=&nbsp;a·(rG)&nbsp;=&nbsp;<strong>arG</strong>. The receiver
              computes r·A&nbsp;=&nbsp;r·(aG)&nbsp;=&nbsp;<strong>arG</strong>. Same point →
              k<sub>0</sub>&nbsp;=&nbsp;H(arG) matches, so M<sub>0</sub> unlocks. ✅</li>
          <li><strong>If b=1</strong> (the tricky one): the receiver sends B&nbsp;=&nbsp;A+rG —
              it has A <em>folded in</em>. The sender first <em>peels A back off</em>:
              B−A&nbsp;=&nbsp;(A+rG)−A&nbsp;=&nbsp;rG, then multiplies by a to get
              a·(B−A)&nbsp;=&nbsp;<strong>arG</strong> — the very same shared point the
              receiver reaches via r·A. So k<sub>1</sub>&nbsp;=&nbsp;H(arG) matches and
              M<sub>1</sub> unlocks. ✅ The subtraction is what quietly selects
              <em>which</em> of the sender's two keys the receiver can reach.</li>
          <li><strong>Why the sender stays blind:</strong> B&nbsp;=&nbsp;rG (b=0) and
              B&nbsp;=&nbsp;A+rG (b=1) are ${gloss('computationally indistinguishable under DDH', 'DDH = Decisional Diffie-Hellman: given rG you cannot tell it apart from a random curve point, so the sender cannot read b off B.')}.
              Try to break that yourself in the DDH game below (Section&nbsp;C2).</li>
        </ul>
      </div>

      <div class="subsection">
        <h3>B2. Live OT Demo</h3>

        <!-- Live progress stepper (decorative for AT — narration handled by #sr-status) -->
        <ol class="ot-steps" aria-hidden="true">
          <li class="ot-step" data-step="1"><span class="ot-step-num">1</span> Sender setup</li>
          <li class="ot-step" data-step="2"><span class="ot-step-num">2</span> Receiver choice</li>
          <li class="ot-step" data-step="3"><span class="ot-step-num">3</span> Encrypt</li>
          <li class="ot-step" data-step="4"><span class="ot-step-num">4</span> Decrypt</li>
        </ol>

        <p id="demo-status" class="demo-status" aria-hidden="true">
          Press <strong>Initialize Sender</strong> to begin the protocol.
        </p>

        <p id="demo-error" class="demo-error" role="alert" hidden></p>

        <div class="ot-demo">
          <!-- Sender panel -->
          <div class="demo-sender">
            <div class="panel-label sender">Sender</div>

            <label for="m0-input">Message M<sub>0</sub></label>
            <textarea id="m0-input" rows="2" maxlength="2000" required>The treasure is buried under the oak tree</textarea>

            <label for="m1-input">Message M<sub>1</sub></label>
            <textarea id="m1-input" rows="2" maxlength="2000" required>Meet at the old lighthouse at midnight</textarea>

            <button id="btn-sender-init" class="btn btn-sender" type="button">Initialize Sender</button>

            <div id="sender-output"></div>
          </div>

          <!-- Channel -->
          <div class="demo-channel" id="demo-channel" role="group" aria-label="Protocol messages exchanged between sender and receiver"></div>

          <!-- Receiver panel -->
          <div class="demo-receiver">
            <div class="panel-label receiver">Receiver</div>

            <fieldset class="radio-group" aria-labelledby="choice-legend">
              <legend id="choice-legend" class="sr-only">Select which message to receive</legend>
              <div class="fake-legend" aria-hidden="true">Choice bit <em>b</em></div>
              <label for="choice-0"><input type="radio" id="choice-0" name="choice" value="0" checked> I want M<sub>0</sub></label>
              <label for="choice-1"><input type="radio" id="choice-1" name="choice" value="1"> I want M<sub>1</sub></label>
            </fieldset>

            <button id="btn-receiver-choose" class="btn btn-receiver" type="button" disabled>Make Selection</button>

            <div id="receiver-output"></div>
          </div>
        </div>

        <!-- Concise, screen-reader-only narration of each protocol step.
             Keeps AT users from having raw hex read out character by character. -->
        <div id="sr-status" class="sr-only" role="status" aria-live="polite"></div>

        <!-- Key reconciliation: the two independent routes to the shared point -->
        <div id="key-reconcile" class="key-reconcile" hidden></div>

        <!-- Privacy audit -->
        <div id="privacy-audit" hidden>
          <h3>Privacy Audit</h3>
          <div id="sender-sees" class="note" style="margin-bottom:0.75rem"></div>
          <div class="audit-grid">
            <div class="audit-box">
              <div class="audit-question">What the sender learned about the receiver's choice:</div>
              <div class="audit-answer">Nothing. B is computationally indistinguishable from a random point.</div>
            </div>
            <div class="audit-box">
              <div class="audit-question">What the receiver learned about the unchosen message:</div>
              <div class="audit-answer">Nothing. E<sub>1−b</sub> is encrypted under a key the receiver cannot compute.</div>
            </div>
          </div>
        </div>

      </div>
    </div>
  </section>`;
}

// ── Section C ────────────────────────────────────────────────────────

function sectionC(): string {
  return `
  <section id="section-c" class="section" aria-labelledby="heading-c">
    <div class="container">
      <h2 id="heading-c">C. OT Correctness &amp; Security</h2>

      <div class="subsection">
        <h3>C1. Correctness Check</h3>
        <p>Run the full OT protocol for both choices and verify that each produces
           the correct plaintext.</p>
        <button id="btn-correctness" class="btn" type="button">Verify Correctness</button>
        <div id="correctness-results" aria-live="polite"></div>
      </div>

      <div class="subsection">
        <h3>C2. DDH Hardness Visualizer</h3>
        <p>Three Ed25519 points are generated. Two are random (r·G) and one is of
           the form A&nbsp;+&nbsp;r·G (the b=1 case). Try to pick out the odd one.
           One guess feels like a gotcha — so play a <strong>10-round match</strong>
           and watch your accuracy. If you can't beat the dashed 1-in-3 line, that
           inability <em>is</em> the DDH assumption protecting the receiver's choice.</p>

        <!-- Running tally across the 10-round match -->
        <div class="ddh-scoreboard" role="group" aria-label="DDH match scoreboard">
          <div class="ddh-score-stat">
            <span class="ddh-score-num" id="ddh-round">0</span>
            <span class="ddh-score-cap">of 10 rounds</span>
          </div>
          <div class="ddh-score-stat">
            <span class="ddh-score-num" id="ddh-hits">0</span>
            <span class="ddh-score-cap">correct</span>
          </div>
          <div class="ddh-score-stat">
            <span class="ddh-score-num" id="ddh-acc">—</span>
            <span class="ddh-score-cap">your accuracy vs 33% baseline</span>
          </div>
        </div>
        <div class="ddh-bar" role="img" aria-hidden="true">
          <div class="ddh-bar-baseline"></div>
          <div class="ddh-bar-fill" id="ddh-bar-fill"></div>
        </div>

        <div class="ddh-controls">
          <button id="btn-ddh" class="btn" type="button">Deal a round</button>
          <button id="btn-ddh-auto" class="btn" type="button">Let the computer guess 1000×</button>
          <button id="btn-ddh-reset" class="btn" type="button" hidden>Reset match</button>
        </div>
        <div id="ddh-results"></div>
        <div id="ddh-auto" class="ddh-auto" aria-live="polite"></div>
      </div>

      <div class="subsection">
        <h3>C3. What Breaks if DDH Is Broken</h3>
        <p>If the Decisional Diffie-Hellman assumption is broken — for example by a
           quantum computer running Shor's algorithm — the sender could distinguish
           B&nbsp;=&nbsp;rG from B&nbsp;=&nbsp;A+rG by solving the discrete
           logarithm. OT protocols based on elliptic curves are
           <strong>not post-quantum secure</strong>.</p>
        <p class="warning-note">Post-quantum OT exists under lattice-based (LWE) or
           code-based assumptions, but it is not yet standardized and involves
           significantly larger parameters.</p>
      </div>
    </div>
  </section>`;
}

// ── Section D ────────────────────────────────────────────────────────

function sectionD(): string {
  return `
  <section id="section-d" class="section" aria-labelledby="heading-d">
    <div class="container">
      <h2 id="heading-d">D. OT in the MPC Ecosystem</h2>

      <div class="subsection">
        <h3>D1. OT Extension (IKNP 2003)</h3>
        <p>Base OT on elliptic curves requires ~2 ms per OT in the browser. MPC
           protocols for practical functions need millions of OTs. OT extension
           (Ishai, Kilian, Nissim, Petrank 2003) solves this: from k base OTs,
           generate m&nbsp;≫&nbsp;k random OTs using only symmetric operations
           (hash functions and XOR). The ratio is roughly 128 base OTs →
           millions of extended OTs.</p>

        <div class="table-wrapper" tabindex="0" role="region" aria-label="OT extension cost comparison (scrollable table)">
          <table>
            <thead>
              <tr><th scope="col">Method</th><th scope="col">OTs Needed</th><th scope="col">Time per OT</th><th scope="col">Total (1 M OTs)</th></tr>
            </thead>
            <tbody>
              <tr><td>Base OT (X25519)</td><td>1 M</td><td>~2 ms</td><td>~33 minutes</td></tr>
              <tr><td>OT Extension (IKNP)</td><td>128 base + 1 M ext.</td><td>~0.001 ms</td><td>~1 second</td></tr>
            </tbody>
          </table>
        </div>
        <p>This is why OT extension is used in every practical MPC system.</p>
      </div>

      <div class="subsection">
        <h3>D2. Real MPC Systems Using OT</h3>
        <ul>
          <li><strong>SCALE-MAMBA / SPDZ:</strong> uses OT extension for the offline
              phase that generates Beaver triples for arithmetic circuit evaluation.
              Used in academic MPC research and some financial applications.</li>
          <li><strong>EMP-toolkit (Wang et al.):</strong> open-source MPC library
              with optimized OT extension. Used in research on private set
              intersection and secure machine learning.</li>
          <li><strong>PSI (Private Set Intersection):</strong> Google and Meta have
              deployed PSI protocols using OT extension for ad measurement without
              sharing raw user data. The IETF PRIO protocol uses a related approach
              for aggregate telemetry.</li>
          <li><strong>Oblivious RAM (ORAM):</strong> uses OT as a building block for
              hiding access patterns to cloud storage. PathORAM and Circuit ORAM
              depend on OT or OT-adjacent primitives.</li>
        </ul>
      </div>

      <div class="subsection">
        <h3>D3. Connection to This Portfolio</h3>
        <div class="xref-map">
          <a class="xref-item" href="https://systemslibrarian.github.io/crypto-lab-silent-tally/" target="_blank" rel="noopener">
            <strong>silent-tally</strong>
            Shamir MPC — additive secret sharing, no OT needed for simple sums
          </a>
          <a class="xref-item" href="https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/" target="_blank" rel="noopener">
            <strong>oblivious-shelf</strong>
            IT-PIR — XOR secret sharing, conceptually related to OT
          </a>
          <a class="xref-item" href="https://systemslibrarian.github.io/crypto-lab-frost-threshold/" target="_blank" rel="noopener">
            <strong>frost-threshold</strong>
            FROST — threshold signing, different MPC paradigm
          </a>
          <div class="xref-item current">
            <strong>ot-gate (this demo)</strong>
            The primitive that makes general-purpose MPC possible
          </div>
        </div>
        <p>OT is the primitive that enables MPC to compute <em>arbitrary</em>
           functions, not just additions and threshold operations.</p>
      </div>
    </div>
  </section>`;
}

function footer(): string {
  return `
  <footer class="site-footer">
    <div class="container">
      <p>Related demos:
        <a href="https://systemslibrarian.github.io/crypto-lab-garbled-gate/" target="_blank" rel="noopener">crypto-lab-garbled-gate</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-silent-tally/" target="_blank" rel="noopener">crypto-lab-silent-tally</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-frost-threshold/" target="_blank" rel="noopener">crypto-lab-frost-threshold</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/" target="_blank" rel="noopener">crypto-lab-oblivious-shelf</a></p>
      <p>Part of the <a href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noopener">crypto-lab</a> portfolio</p>
    </div>
  </footer>`;
}

// ═══════════════════════════════════════════════════════════════════════
//  Demo interaction (Section B2)
// ═══════════════════════════════════════════════════════════════════════

let currentSender: SenderState | null = null;

// Push a short, human-readable sentence to the screen-reader status region.
// Hex values are visual reference only and are kept out of AT narration.
function announce(msg: string): void {
  $('#sr-status').textContent = msg;
}

// Update the visible status line AND the screen-reader live region together.
function narrate(msg: string, done = false): void {
  const status = $('#demo-status');
  status.textContent = msg;
  status.classList.toggle('complete', done);
  announce(msg);
}

// Drive the visual progress stepper. `active` is the in-flight step (0 = none),
// `done` marks every step up to and including that number as complete.
function setSteps(active: number, done: number): void {
  document.querySelectorAll<HTMLElement>('.ot-step').forEach((el) => {
    const n = Number(el.dataset.step);
    const isDone = n <= done;
    el.classList.toggle('done', isDone);
    el.classList.toggle('active', n === active);
    const num = el.querySelector('.ot-step-num');
    if (num) num.textContent = isDone ? '✓' : String(n);
  });
}

// Glow the panel whose turn it is, so the eye follows the protocol.
function highlightPanel(which: 'sender' | 'receiver' | null): void {
  document.querySelector('.demo-sender')?.classList.toggle('is-active', which === 'sender');
  document.querySelector('.demo-receiver')?.classList.toggle('is-active', which === 'receiver');
}

// Strip tags so an HTML label can be reused in a plain-text aria-label.
function plain(s: string): string {
  return s.replace(/<[^>]*>/g, '');
}

// A first-use micro-definition. Renders the term with a dotted underline and an
// inline aside gloss that is available to sighted users (title + visible ⓘ) and
// to screen readers (the gloss text is real DOM text, not color-only).
function gloss(term: string, def: string): string {
  return `<span class="gloss"><span class="gloss-term">${term}</span><span class="gloss-def"> — ${def}</span></span>`;
}

// A small colored token ("chip") that visually links a named value (A, B, k₀…)
// across panels. The name is real text (never color alone) so it stays
// accessible; the color is a redundant cue. `kind` maps to a CSS class.
function chip(name: string, kind: string): string {
  return `<span class="cl-chip cl-chip-${kind}">${name}</span>`;
}

// A labelled hex value with a copy button. `display` shows a shortened form
// while the full value is what actually gets copied.
function hexBlock(
  label: string,
  value: string,
  opts: { private?: boolean; display?: string } = {},
): string {
  const labelCls = opts.private ? 'hex-label private' : 'hex-label';
  const shown = opts.display ?? value;
  return `
    <div class="hex-block">
      <div class="hex-block-head">
        <span class="${labelCls}">${label}</span>
        <button class="copy-btn" type="button" data-copy="${value}" aria-label="Copy ${plain(label)} value">Copy</button>
      </div>
      <span class="hex-value" aria-hidden="true">${shown}</span>
    </div>`;
}

// One delegated handler for every copy button, current or future.
function setupCopyButtons(): void {
  $('#app').addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('.copy-btn');
    if (!btn) return;
    const value = btn.dataset.copy ?? '';
    void navigator.clipboard
      ?.writeText(value)
      .then(() => {
        const label = btn.getAttribute('aria-label') ?? 'Copy';
        btn.textContent = 'Copied!';
        btn.setAttribute('aria-label', 'Copied');
        btn.classList.add('copied');
        window.setTimeout(() => {
          btn.textContent = 'Copy';
          btn.setAttribute('aria-label', label);
          btn.classList.remove('copied');
        }, 1200);
      })
      .catch(() => {
        /* clipboard blocked (insecure context / permissions) — no-op */
      });
  });
}

// A short, glanceable hex fragment (first 10 chars) used inside chips/tokens so
// the learner can eyeball "same vs different" without a wall of hex.
function frag(hex: string): string {
  return hex.slice(0, 10) + '…';
}

// Render the "why the keys line up" reconciliation panel. Shows the two
// independent routes to the shared point arG (receiver via r·A, sender via a·B
// or a·(B−A)), highlights that they land on the SAME point in green, and shows
// the sender's OTHER key landing elsewhere (broken/red link). All values come
// from reconcileKeys(), which does the real curve math — nothing is faked.
function renderReconcile(rec: ReturnType<typeof reconcileKeys>): void {
  const panel = $('#key-reconcile');
  const matchCls = rec.sharedMatches ? 'match' : 'nomatch';
  const bStep =
    rec.b === 0
      ? 'B = rG, so a·B = a·(rG) = arG.'
      : 'B = A + rG. The sender peels A off first: B − A = rG, then a·(B − A) = arG.';

  panel.hidden = false;
  panel.innerHTML = `
    <h3>Why the two keys line up</h3>
    <p class="reconcile-intro">
      The receiver (with secret <em>r</em>) and the sender (with secret <em>a</em>)
      never share a scalar — yet both compute the <strong>same</strong> secret point.
      Watch the two routes meet. You chose <strong>b = ${rec.b}</strong>, so ${bStep}
    </p>
    <div class="reconcile-grid" role="img"
         aria-label="Receiver computes r times A and sender computes ${plain(rec.senderPointExpr)}; both reduce to the same point a r G, so the derived keys are identical.">
      <div class="reconcile-lane receiver-lane">
        <div class="reconcile-party">${chip('Receiver', 'receiver')} knows <em>r</em></div>
        <div class="reconcile-op">r · A</div>
        <div class="reconcile-frag" aria-hidden="true">${frag(rec.receiverPointHex)}</div>
      </div>
      <div class="reconcile-lane sender-lane">
        <div class="reconcile-party">${chip('Sender', 'sender')} knows <em>a</em></div>
        <div class="reconcile-op">${rec.senderPointExpr}</div>
        <div class="reconcile-frag" aria-hidden="true">${frag(rec.senderPointHex)}</div>
      </div>
      <div class="reconcile-meet ${matchCls}">
        <div class="reconcile-meet-arrow" aria-hidden="true">↘&nbsp;&nbsp;↙</div>
        <div class="reconcile-shared">
          <span class="reconcile-badge">${rec.sharedMatches ? '✓ same point' : '✗ mismatch'}</span>
          <span class="reconcile-shared-label">arG</span>
          <span class="reconcile-frag" aria-hidden="true">${frag(rec.sharedPointHex)}</span>
        </div>
      </div>
    </div>
    <div class="reconcile-keys">
      <div class="reconcile-key key-ok">
        ${chip('k' + (rec.b === 0 ? '₀' : '₁'), 'key-match')}
        H(arG) = <span class="reconcile-frag" aria-hidden="true">${frag(rec.chosenKeyHex)}</span>
        <span class="reconcile-note">— the working key. Receiver's k<sub>b</sub> equals this exactly.</span>
      </div>
      <div class="reconcile-key key-bad">
        ${chip('k' + (rec.b === 0 ? '₁' : '₀'), 'key-nomatch')}
        <span class="reconcile-frag" aria-hidden="true">${frag(rec.otherKeyHex)}</span>
        <span class="reconcile-note">— the sender's OTHER key. Lands on a different point, so the receiver can't reach it. That's what keeps M<sub>${rec.b === 0 ? 1 : 0}</sub> hidden.</span>
      </div>
    </div>`;

  announce(
    rec.sharedMatches
      ? `Key reconciliation: the receiver's r times A and the sender's ${plain(rec.senderPointExpr)} both reduce to the same point a r G, so their keys match. The sender's other key lands elsewhere.`
      : 'Key reconciliation mismatch — this should not happen.',
  );
}

function addChannelMsg(label: string, hex: string): void {
  const ch = $('#demo-channel');
  const div = document.createElement('div');
  div.className = 'channel-msg';
  // Payload hex is decorative for AT; the direction label carries the meaning.
  div.innerHTML = `<span class="direction">${label}</span><span class="payload" aria-hidden="true">${truncHex(hex, 48)}</span>`;
  ch.appendChild(div);
}

function showError(msg: string): void {
  const el = $('#demo-error');
  el.textContent = msg;
  el.hidden = false;
}

function clearError(): void {
  const el = $('#demo-error');
  el.textContent = '';
  el.hidden = true;
  for (const id of ['m0-input', 'm1-input']) {
    document.getElementById(id)?.removeAttribute('aria-invalid');
  }
}

// Validate both messages are present. On failure, flags the field, shows an
// alert, and returns the offending textarea so the caller can focus it.
function validateMessages(): {
  ok: boolean;
  m0: string;
  m1: string;
  focus?: HTMLTextAreaElement;
} {
  const m0El = document.getElementById('m0-input') as HTMLTextAreaElement;
  const m1El = document.getElementById('m1-input') as HTMLTextAreaElement;
  const m0 = m0El.value.trim();
  const m1 = m1El.value.trim();
  m0El.removeAttribute('aria-invalid');
  m1El.removeAttribute('aria-invalid');

  if (m0 === '') {
    m0El.setAttribute('aria-invalid', 'true');
    showError('Message M₀ can’t be empty — enter some text for the sender’s first message.');
    return { ok: false, m0, m1, focus: m0El };
  }
  if (m1 === '') {
    m1El.setAttribute('aria-invalid', 'true');
    showError('Message M₁ can’t be empty — enter some text for the sender’s second message.');
    return { ok: false, m0, m1, focus: m1El };
  }
  return { ok: true, m0, m1 };
}

// Common recovery path if any crypto/DOM step throws mid-protocol.
function handleDemoError(
  err: unknown,
  senderBtn: HTMLButtonElement,
  receiverBtn: HTMLButtonElement,
): void {
  console.error('OT demo error:', err);
  setSteps(0, 0);
  highlightPanel(null);
  showError('Something went wrong running the protocol in your browser. Press “Reset & Re-initialize” and try again.');
  narrate('The protocol hit an error and stopped. Press the reset button to start over.');
  senderBtn.textContent = 'Reset & Re-initialize';
  senderBtn.disabled = false;
  receiverBtn.disabled = true;
}

async function onSenderInit(): Promise<void> {
  const senderBtn = $('#btn-sender-init') as HTMLButtonElement;
  const receiverBtn = $('#btn-receiver-choose') as HTMLButtonElement;

  // Guard: both messages must be present before the sender can commit them.
  const valid = validateMessages();
  if (!valid.ok) {
    valid.focus?.focus();
    return;
  }
  clearError();

  // Disable buttons during async work to prevent race conditions
  senderBtn.disabled = true;
  receiverBtn.disabled = true;

  // Reset state
  currentSender = null;
  $('#demo-channel').innerHTML = '';
  $('#sender-output').innerHTML = '';
  $('#receiver-output').innerHTML = '';
  $('#privacy-audit').hidden = true;
  const kr = $('#key-reconcile');
  kr.hidden = true;
  kr.innerHTML = '';
  senderBtn.textContent = 'Initialize Sender';

  try {
    setSteps(1, 0);
    highlightPanel('sender');
    narrate('Step 1 — the sender is generating a private scalar a and the public point A = aG…');

    await delay(150);

    const sender = senderInit();
    currentSender = sender;

    // Display sender output
    $('#sender-output').innerHTML =
      hexBlock('a — sender private scalar (never transmitted)', bigintToHex(sender.a), {
        private: true,
      }) + hexBlock('A = aG (sent to receiver)', sender.AHex);

    await delay(100);
    addChannelMsg('A → Receiver', sender.AHex);

    setSteps(2, 1);
    highlightPanel('receiver');
    narrate('Sender ready. Now pick which message you want (b = 0 or b = 1) and press “Make Selection”.');

    // Re-enable buttons
    senderBtn.disabled = false;
    receiverBtn.disabled = false;
  } catch (err) {
    handleDemoError(err, senderBtn, receiverBtn);
  }
}

async function onReceiverChoose(): Promise<void> {
  if (!currentSender) return;

  const senderBtn = $('#btn-sender-init') as HTMLButtonElement;
  const receiverBtn = $('#btn-receiver-choose') as HTMLButtonElement;

  // Messages can be edited after init — re-validate before encrypting.
  const valid = validateMessages();
  if (!valid.ok) {
    valid.focus?.focus();
    return;
  }
  clearError();

  // Disable buttons during async work to prevent race conditions
  senderBtn.disabled = true;
  receiverBtn.disabled = true;

  const choiceEl = document.querySelector<HTMLInputElement>('input[name="choice"]:checked');
  const b = (choiceEl ? Number(choiceEl.value) : 0) as 0 | 1;

  try {
    // ── Step 2 — receiver computes B ─────────────────────────────────
    setSteps(2, 1);
    highlightPanel('receiver');
    narrate(`Step 2 — the receiver picks b = ${b}, generates scalar r, and computes B…`);

    const receiver = receiverChoose(currentSender.ABytes, b);
    // Display receiver output
    $('#receiver-output').innerHTML =
      hexBlock('r — receiver private scalar (never transmitted)', bigintToHex(receiver.r), {
        private: true,
      }) + hexBlock(`B (sent to sender) — choice b=${b}`, receiver.BHex);

    await delay(250);
    addChannelMsg('B → Sender', receiver.BHex);

    // ── Step 3 — sender encrypts both messages ───────────────────────
    setSteps(3, 2);
    highlightPanel('sender');
    narrate('Step 3 — the sender derives k₀ and k₁ and encrypts both messages…');
    await delay(350);

    const enc = await senderEncrypt(currentSender, receiver.BBytes, valid.m0, valid.m1);
    const e0Hex = bytesToHex(enc.e0.ciphertext);
    const e1Hex = bytesToHex(enc.e1.ciphertext);
    // Color-code the two keys by whether the receiver can reach them: the key
    // matching the receiver's choice b gets the green "match" chip (same color
    // used on the receiver's derived key below); the other gets the red chip.
    const k0Chip = b === 0 ? chip('k₀', 'key-match') : chip('k₀', 'key-nomatch');
    const k1Chip = b === 1 ? chip('k₁', 'key-match') : chip('k₁', 'key-nomatch');
    // Show sender keys and ciphertexts
    $('#sender-output').innerHTML +=
      hexBlock(`${k0Chip} k<sub>0</sub> = H(a·B)`, enc.k0Hex) +
      hexBlock(`${k1Chip} k<sub>1</sub> = H(a·(B−A))`, enc.k1Hex) +
      hexBlock('E<sub>0</sub> (encrypted M<sub>0</sub>)', e0Hex, { display: truncHex(e0Hex, 64) }) +
      hexBlock('E<sub>1</sub> (encrypted M<sub>1</sub>)', e1Hex, { display: truncHex(e1Hex, 64) });

    addChannelMsg('(E₀, E₁) → Receiver', truncHex(e0Hex, 20) + ' | ' + truncHex(e1Hex, 20));

    // ── Step 4 — receiver decrypts the chosen ciphertext ─────────────
    setSteps(4, 3);
    highlightPanel('receiver');
    narrate('Step 4 — the receiver derives k_b = H(r·A) and decrypts the chosen message…');
    await delay(350);

    const chosen = b === 0 ? enc.e0 : enc.e1;
    const unchosen = b === 0 ? enc.e1 : enc.e0;

    const decrypted = await receiverDecrypt(receiver.keyBytes, chosen);
    const otherResult = await tryDecrypt(receiver.keyBytes, unchosen);

    $('#receiver-output').innerHTML +=
      hexBlock(
        `${chip('k' + (b === 0 ? '₀' : '₁'), 'key-match')} k<sub>b</sub> = H(r·A) — matches the sender's k<sub>${b}</sub> (same green chip)`,
        receiver.keyHex,
      ) +
      `<div class="decrypted-msg">
        <span aria-hidden="true">✅ </span><strong>Decrypted M<sub>${b}</sub>:</strong> ${escapeHtml(decrypted)}
      </div>
      <div class="redacted-container" role="img" aria-label="Unchosen message — encrypted and hidden, receiver cannot decrypt">
        <div class="redacted-content" aria-hidden="true">${bytesToHex(unchosen.ciphertext)}</div>
        <div class="redacted-label"><span aria-hidden="true">🔒 </span>Hidden — receiver cannot decrypt</div>
      </div>
      ${otherResult !== null ? '<p style="color:var(--warning)">⚠ Unexpected: unchosen message was decryptable!</p>' : ''}`;

    // ── Done ─────────────────────────────────────────────────────────
    setSteps(0, 4);
    highlightPanel(null);
    narrate(
      `Done — the receiver read M${b} (“${decrypted}”). The other message stayed locked, ` +
        `and the sender never learned which one you chose.`,
      true,
    );

    // Key reconciliation — show the two independent routes meeting at arG.
    const rec = reconcileKeys(
      currentSender.a,
      receiver.r,
      currentSender.ABytes,
      receiver.BBytes,
      b,
    );
    renderReconcile(rec);

    // Privacy audit
    const audit = $('#privacy-audit');
    audit.hidden = false;
    $('#sender-sees').innerHTML =
      `Sender sees <code>B = ${truncHex(receiver.BHex, 32)}</code>. Cannot determine if b=0 or b=1.`;

    // Re-enable sender button for reset, keep receiver disabled until next init
    senderBtn.textContent = 'Reset & Re-initialize';
    senderBtn.disabled = false;
  } catch (err) {
    handleDemoError(err, senderBtn, receiverBtn);
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  Section C1 — Correctness check
// ═══════════════════════════════════════════════════════════════════════

function correctnessRow(
  b: 0 | 1,
  expected: string,
  decrypted: string,
  otherFailed: boolean,
): string {
  const decryptOk = decrypted === expected;
  const ok = decryptOk && otherFailed;
  return `
    <div class="result-row ${ok ? 'pass' : 'fail'}">
      <span class="result-icon" aria-hidden="true">${ok ? '✅' : '❌'}</span>
      <div>
        <div class="result-head"><strong>Choice b=${b}</strong> — receiver decrypted "<code>${escapeHtml(decrypted)}</code>"</div>
        <ul class="result-checks">
          <li class="${decryptOk ? 'ok' : 'bad'}">${decryptOk ? 'Chosen message M' + b + ' decrypted correctly' : 'Decryption did not match M' + b}</li>
          <li class="${otherFailed ? 'ok' : 'bad'}">${otherFailed ? 'Unchosen message could not be decrypted' : 'Unchosen message was unexpectedly decryptable'}</li>
        </ul>
      </div>
    </div>`;
}

async function onCorrectnessCheck(): Promise<void> {
  const btn = $('#btn-correctness') as HTMLButtonElement;
  const out = $('#correctness-results');
  btn.disabled = true;
  out.innerHTML =
    '<p class="check-status"><span class="spinner" aria-hidden="true"></span> Running the full protocol for b=0 and b=1…</p>';

  const m0 = 'Correctness test message ZERO';
  const m1 = 'Correctness test message ONE';

  try {
    const r0 = await runFullOT(m0, m1, 0);
    await delay(300);
    const r1 = await runFullOT(m0, m1, 1);

    const ok0 = r0.decrypted === m0 && r0.otherFailed;
    const ok1 = r1.decrypted === m1 && r1.otherFailed;
    const allOk = ok0 && ok1;

    out.innerHTML = `
      <div class="check-verdict ${allOk ? 'ok' : 'fail'}">
        <span class="result-icon" aria-hidden="true">${allOk ? '✅' : '❌'}</span>
        <span>${
          allOk
            ? 'All checks passed — each choice decrypts to the right message, and the other message stays locked.'
            : 'A check failed — see the details below.'
        }</span>
      </div>
      <div class="correctness-results">
        ${correctnessRow(0, m0, r0.decrypted, r0.otherFailed)}
        ${correctnessRow(1, m1, r1.decrypted, r1.otherFailed)}
      </div>`;
  } catch (err) {
    console.error('Correctness check error:', err);
    out.innerHTML = `
      <div class="check-verdict fail">
        <span class="result-icon" aria-hidden="true">❌</span>
        <span>The correctness check couldn’t run in your browser. Please try again.</span>
      </div>`;
  } finally {
    btn.disabled = false;
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  Section C2 — DDH visualizer
// ═══════════════════════════════════════════════════════════════════════

// DDH match state. A "match" is a run of up to 10 rounds; we track the running
// tally so the learner watches their accuracy converge on the 1-in-3 baseline.
const DDH_MATCH_LEN = 10;
let ddhAnswer: number | null = null; // A+r·G index of the CURRENT round, or null
let ddhRound = 0; // rounds played so far this match
let ddhHits = 0; // correct guesses so far this match

// Refresh the scoreboard + bar from the current tally.
function updateDDHScore(): void {
  $('#ddh-round').textContent = String(ddhRound);
  $('#ddh-hits').textContent = String(ddhHits);
  const accEl = $('#ddh-acc');
  const fill = $('#ddh-bar-fill');
  if (ddhRound === 0) {
    accEl.textContent = '—';
    fill.style.width = '0%';
    return;
  }
  const pct = (ddhHits / ddhRound) * 100;
  accEl.textContent = `${pct.toFixed(0)}%`;
  fill.style.width = `${Math.min(100, pct)}%`;
}

function resetDDHMatch(): void {
  ddhAnswer = null;
  ddhRound = 0;
  ddhHits = 0;
  updateDDHScore();
  $('#ddh-results').innerHTML = '';
  $('#ddh-auto').innerHTML = '';
  $('#btn-ddh').textContent = 'Deal a round';
  ($('#btn-ddh') as HTMLButtonElement).disabled = false;
  $('#btn-ddh-reset').hidden = true;
  announce('DDH match reset. Deal a round to start again.');
}

function onDDHGenerate(): void {
  if (ddhRound >= DDH_MATCH_LEN) return; // match already complete
  const out = $('#ddh-results');
  const { points, b1Index, AHex } = generateDDHPoints();
  ddhAnswer = b1Index;

  announce(
    `Round ${ddhRound + 1} of ${DDH_MATCH_LEN}. Three Curve25519 points: two are random r·G and one is A + r·G. ` +
      'Choose the point you think is A + r·G. Under the DDH assumption they are indistinguishable, so it is a one-in-three guess.',
  );

  $('#btn-ddh').textContent = `Round ${ddhRound + 1} of ${DDH_MATCH_LEN}`;
  ($('#btn-ddh') as HTMLButtonElement).disabled = true; // re-enabled after guess

  out.innerHTML = `
    ${hexBlock("A (sender's public point for this round)", AHex)}
    <p class="ddh-prompt">Round <strong>${ddhRound + 1}</strong>: which point is <strong>A + r·G</strong> (the b=1 case)? Take your best guess:</p>
    <div class="ddh-points" role="group" aria-label="Three candidate points — choose which one is A plus r·G">
      ${points
        .map(
          (p, i) => `
        <button class="ddh-point" type="button" data-index="${i}" aria-label="Guess that point ${i + 1} is A plus r·G">
          <span class="ddh-point-label">Point ${i + 1}</span>
          <span class="ddh-point-hex">${p}</span>
        </button>`,
        )
        .join('')}
    </div>
    <div id="ddh-feedback" class="ddh-feedback" role="status" aria-live="polite"></div>`;
}

function onDDHGuess(idx: number): void {
  if (ddhAnswer === null) return;
  const answer = ddhAnswer;
  ddhAnswer = null; // lock further guesses for this round
  const correct = idx === answer;

  ddhRound += 1;
  if (correct) ddhHits += 1;
  updateDDHScore();

  document.querySelectorAll<HTMLButtonElement>('.ddh-point').forEach((btn) => {
    const i = Number(btn.dataset.index);
    btn.disabled = true;
    btn.classList.add(i === answer ? 'is-b1' : 'is-random');
    if (i === idx && !correct) btn.classList.add('is-wrong');
    if (i === answer) {
      const label = btn.querySelector('.ddh-point-label');
      if (label) label.textContent = `Point ${i + 1} — A + r·G`;
    }
  });

  const matchDone = ddhRound >= DDH_MATCH_LEN;
  const pct = ((ddhHits / ddhRound) * 100).toFixed(0);

  const fb = $('#ddh-feedback');
  fb.className = 'ddh-feedback ' + (correct ? 'ok' : 'fail');
  const verdict = correct
    ? `<strong>Correct — Point ${answer + 1}</strong> was A + r·G.`
    : `<strong>Not quite — Point ${answer + 1}</strong> was A + r·G.`;
  const tally = matchDone
    ? ` Match over: <strong>${ddhHits}/${DDH_MATCH_LEN} = ${pct}%</strong>. Notice how it hugs the dashed 1-in-3 line — under DDH no strategy beats a blind guess, and that is exactly what hides the receiver's choice b from the sender.`
    : ` Running: <strong>${ddhHits}/${ddhRound} = ${pct}%</strong>. Deal the next round.`;
  fb.innerHTML = verdict + tally;

  if (matchDone) {
    $('#btn-ddh').textContent = 'Match complete';
    ($('#btn-ddh') as HTMLButtonElement).disabled = true;
  } else {
    $('#btn-ddh').textContent = 'Deal next round';
    ($('#btn-ddh') as HTMLButtonElement).disabled = false;
  }
  $('#btn-ddh-reset').hidden = false;

  announce(
    `${correct ? 'Correct' : 'Wrong'}. ${matchDone ? 'Match complete' : `Running score`}: ${ddhHits} of ${ddhRound}, ${pct} percent, versus a 33 percent baseline.`,
  );
}

// "Let the computer guess 1000×": run 1000 REAL DDH challenges and let a random
// strategy play each. The ~33% hit rate is measured, not hardcoded.
function onDDHAuto(): void {
  const btn = $('#btn-ddh-auto') as HTMLButtonElement;
  const out = $('#ddh-auto');
  btn.disabled = true;
  out.innerHTML =
    '<p class="check-status"><span class="spinner" aria-hidden="true"></span> Running 1000 real DDH challenges…</p>';

  // Defer so the spinner paints before the (fast but non-trivial) point math.
  window.setTimeout(() => {
    const N = 1000;
    const { hits, rate } = simulateDDHGuesses(N);
    const pct = (rate * 100).toFixed(1);
    out.innerHTML = `
      <div class="ddh-auto-result">
        <div class="ddh-auto-figure">
          <span class="ddh-auto-num">${pct}%</span>
          <span class="ddh-auto-cap">${hits} hits in ${N} real challenges</span>
        </div>
        <div class="ddh-auto-bar" role="img" aria-label="Computer hit rate ${pct} percent, essentially on the 33 percent baseline">
          <div class="ddh-auto-bar-baseline"></div>
          <div class="ddh-auto-bar-fill" style="width:${Math.min(100, rate * 100)}%"></div>
        </div>
        <p class="ddh-auto-note">Each of the ${N} rounds generated real Curve25519 points and the computer guessed at random. It lands near <strong>33.3%</strong> — the 1-in-3 baseline — because under DDH there is no signal to exploit. That empirical flatness is the security property, felt rather than asserted.</p>
      </div>`;
    announce(`Computer guessed ${hits} of ${N} correctly, about ${pct} percent — essentially the 33 percent baseline.`);
    btn.disabled = false;
  }, 30);
}

// ═══════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

// ═══════════════════════════════════════════════════════════════════════
//  Mount
// ═══════════════════════════════════════════════════════════════════════

function mount(): void {
  const app = $('#app');
  app.innerHTML =
    '<main>' + header() + sectionA() + sectionB() + sectionC() + sectionD() + '</main>' + footer();

  setupThemeToggle();
  setupCopyButtons();

  // B2 demo events
  $('#btn-sender-init').addEventListener('click', () => void onSenderInit());
  $('#btn-receiver-choose').addEventListener('click', () => void onReceiverChoose());

  // C1 correctness
  $('#btn-correctness').addEventListener('click', () => void onCorrectnessCheck());

  // C2 DDH
  updateDDHScore();
  $('#btn-ddh').addEventListener('click', onDDHGenerate);
  $('#btn-ddh-auto').addEventListener('click', onDDHAuto);
  $('#btn-ddh-reset').addEventListener('click', resetDDHMatch);
  $('#ddh-results').addEventListener('click', (e) => {
    const pt = (e.target as HTMLElement).closest<HTMLButtonElement>('.ddh-point');
    if (pt && !pt.disabled) onDDHGuess(Number(pt.dataset.index));
  });
}

mount();
