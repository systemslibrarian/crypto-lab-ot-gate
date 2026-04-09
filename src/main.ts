import './style.css';
import {
  senderInit,
  receiverChoose,
  senderEncrypt,
  receiverDecrypt,
  tryDecrypt,
  runFullOT,
  generateDDHPoints,
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
  <a href="#section-b" class="skip-link">Skip to interactive demo</a>
  <header class="site-header" role="banner">
    <div class="container header-inner">
      <div>
        <h1>🔐 OT Gate</h1>
        <p class="subtitle">Oblivious Transfer — the foundation of secure two-party computation</p>
      </div>
      <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Toggle theme"></button>
    </div>
  </header>`;
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
            <div class="ot-visual-label" style="color:var(--receiver-color)">Receiver</div>
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
        <div class="table-wrapper">
          <table>
            <thead>
              <tr><th>Variant</th><th>Description</th><th>Use Case</th></tr>
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
           Edwards form). Let G be the base point.</p>

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
            <div class="flow-header" style="color:var(--receiver-color)">Receiver</div>
            <div class="flow-step">&nbsp;</div>
            <div class="flow-step">Generate scalar <em>r</em><br>b=0: B&nbsp;=&nbsp;rG<br>b=1: B&nbsp;=&nbsp;A+rG</div>
            <div class="flow-step">&nbsp;</div>
            <div class="flow-step">k<sub>b</sub>&nbsp;=&nbsp;H(r·A)<br>Decrypt M<sub>b</sub></div>
          </div>
        </div>

        <p><strong>Why it works:</strong></p>
        <ul>
          <li>If b=0: B&nbsp;=&nbsp;rG, so a·B&nbsp;=&nbsp;arG&nbsp;=&nbsp;r·A →
              k<sub>0</sub>&nbsp;=&nbsp;H(r·A) ✅ receiver can decrypt M<sub>0</sub></li>
          <li>If b=1: B&nbsp;=&nbsp;A+rG, so a·(B−A)&nbsp;=&nbsp;arG&nbsp;=&nbsp;r·A →
              k<sub>1</sub>&nbsp;=&nbsp;H(r·A) ✅ receiver can decrypt M<sub>1</sub></li>
          <li>Sender cannot distinguish b=0 from b=1: B&nbsp;=&nbsp;rG vs B&nbsp;=&nbsp;A+rG
              are computationally indistinguishable under the DDH assumption</li>
        </ul>
      </div>

      <div class="subsection">
        <h3>B2. Live OT Demo</h3>

        <div class="ot-demo">
          <!-- Sender panel -->
          <div class="demo-sender">
            <div class="panel-label sender">Sender</div>

            <label for="m0-input">Message M<sub>0</sub></label>
            <textarea id="m0-input" rows="2">The treasure is buried under the oak tree</textarea>

            <label for="m1-input">Message M<sub>1</sub></label>
            <textarea id="m1-input" rows="2">Meet at the old lighthouse at midnight</textarea>

            <button id="btn-sender-init" class="btn btn-sender" type="button">Initialize Sender</button>

            <div id="sender-output" aria-live="polite"></div>
          </div>

          <!-- Channel -->
          <div class="demo-channel" id="demo-channel" aria-live="polite" aria-label="Protocol messages exchanged between sender and receiver"></div>

          <!-- Receiver panel -->
          <div class="demo-receiver">
            <div class="panel-label receiver">Receiver</div>

            <label>Choice bit <em>b</em></label>
            <fieldset class="radio-group">
              <legend class="sr-only">Select which message to receive</legend>
              <label for="choice-0"><input type="radio" id="choice-0" name="choice" value="0" checked> I want M<sub>0</sub></label>
              <label for="choice-1"><input type="radio" id="choice-1" name="choice" value="1"> I want M<sub>1</sub></label>
            </fieldset>

            <button id="btn-receiver-choose" class="btn btn-receiver" type="button" disabled>Make Selection</button>

            <div id="receiver-output" aria-live="polite"></div>
          </div>
        </div>

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
        <p>Below are three Ed25519 points. Two are random (r·G) and one is of the
           form A&nbsp;+&nbsp;r·G (the b=1 case). Can you tell which is which?</p>
        <button id="btn-ddh" class="btn" type="button">Generate Points</button>
        <div id="ddh-results" aria-live="polite"></div>
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

        <div class="table-wrapper">
          <table>
            <thead>
              <tr><th>Method</th><th>OTs Needed</th><th>Time per OT</th><th>Total (1 M OTs)</th></tr>
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
      <p>Part of the <a href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noopener">crypto-lab</a> portfolio</p>
    </div>
  </footer>`;
}

// ═══════════════════════════════════════════════════════════════════════
//  Demo interaction (Section B2)
// ═══════════════════════════════════════════════════════════════════════

let currentSender: SenderState | null = null;

function addChannelMsg(label: string, hex: string): void {
  const ch = $('#demo-channel');
  const div = document.createElement('div');
  div.className = 'channel-msg';
  div.innerHTML = `<span class="direction">${label}</span><span class="payload">${truncHex(hex, 48)}</span>`;
  ch.appendChild(div);
}

async function onSenderInit(): Promise<void> {
  // Reset state
  currentSender = null;
  $('#demo-channel').innerHTML = '';
  $('#sender-output').innerHTML = '';
  $('#receiver-output').innerHTML = '';
  $('#privacy-audit').hidden = true;

  const sender = senderInit();
  currentSender = sender;

  // Display sender output
  $('#sender-output').innerHTML = `
    <div class="hex-block">
      <span class="hex-label private">a — sender private scalar (never transmitted)</span>
      ${bigintToHex(sender.a)}
    </div>
    <div class="hex-block">
      <span class="hex-label">A = aG (sent to receiver)</span>
      ${sender.AHex}
    </div>`;

  await delay(100);
  addChannelMsg('A → Receiver', sender.AHex);

  // Enable receiver button
  ($('#btn-receiver-choose') as HTMLButtonElement).disabled = false;
}

async function onReceiverChoose(): Promise<void> {
  if (!currentSender) return;

  const choiceEl = document.querySelector<HTMLInputElement>('input[name="choice"]:checked');
  const b = (choiceEl ? Number(choiceEl.value) : 0) as 0 | 1;

  const receiver = receiverChoose(currentSender.ABytes, b);
  // Display receiver output
  $('#receiver-output').innerHTML = `
    <div class="hex-block">
      <span class="hex-label private">r — receiver private scalar (never transmitted)</span>
      ${bigintToHex(receiver.r)}
    </div>
    <div class="hex-block">
      <span class="hex-label">B (sent to sender) — choice b=${b}</span>
      ${receiver.BHex}
    </div>`;

  await delay(200);
  addChannelMsg('B → Sender', receiver.BHex);

  // Sender encrypts
  await delay(300);

  const m0 = (document.getElementById('m0-input') as HTMLTextAreaElement).value;
  const m1 = (document.getElementById('m1-input') as HTMLTextAreaElement).value;

  const enc = await senderEncrypt(currentSender, receiver.BBytes, m0, m1);
  // Show sender keys and ciphertexts
  $('#sender-output').innerHTML += `
    <div class="hex-block">
      <span class="hex-label">k<sub>0</sub> = H(a·B)</span>
      ${enc.k0Hex}
    </div>
    <div class="hex-block">
      <span class="hex-label">k<sub>1</sub> = H(a·(B−A))</span>
      ${enc.k1Hex}
    </div>
    <div class="hex-block">
      <span class="hex-label">E<sub>0</sub> (encrypted M<sub>0</sub>)</span>
      ${truncHex(bytesToHex(enc.e0.ciphertext), 64)}
    </div>
    <div class="hex-block">
      <span class="hex-label">E<sub>1</sub> (encrypted M<sub>1</sub>)</span>
      ${truncHex(bytesToHex(enc.e1.ciphertext), 64)}
    </div>`;

  addChannelMsg('(E₀, E₁) → Receiver', truncHex(bytesToHex(enc.e0.ciphertext), 20) + ' | ' + truncHex(bytesToHex(enc.e1.ciphertext), 20));

  // Receiver decrypts
  await delay(300);

  const chosen = b === 0 ? enc.e0 : enc.e1;
  const unchosen = b === 0 ? enc.e1 : enc.e0;

  const decrypted = await receiverDecrypt(receiver.keyBytes, chosen);
  const otherResult = await tryDecrypt(receiver.keyBytes, unchosen);

  $('#receiver-output').innerHTML += `
    <div class="hex-block">
      <span class="hex-label">k<sub>b</sub> = H(r·A) — receiver's derived key</span>
      ${receiver.keyHex}
    </div>
    <div class="decrypted-msg">
      ✅ <strong>Decrypted M<sub>${b}</sub>:</strong> ${escapeHtml(decrypted)}
    </div>
    <div class="redacted-container" role="img" aria-label="Unchosen message — encrypted and hidden, receiver cannot decrypt">
      <div class="redacted-content" aria-hidden="true">${bytesToHex(unchosen.ciphertext)}</div>
      <div class="redacted-label">🔒 Hidden — receiver cannot decrypt</div>
    </div>
    ${otherResult !== null ? '<p style="color:var(--warning)">⚠ Unexpected: unchosen message was decryptable!</p>' : ''}`;

  // Privacy audit
  const audit = $('#privacy-audit');
  audit.hidden = false;
  $('#sender-sees').innerHTML =
    `Sender sees <code>B = ${truncHex(receiver.BHex, 32)}</code>. Cannot determine if b=0 or b=1.`;

  // Disable buttons to indicate completion
  ($('#btn-sender-init') as HTMLButtonElement).textContent = 'Reset & Re-initialize';
  ($('#btn-receiver-choose') as HTMLButtonElement).disabled = true;
}

// ═══════════════════════════════════════════════════════════════════════
//  Section C1 — Correctness check
// ═══════════════════════════════════════════════════════════════════════

async function onCorrectnessCheck(): Promise<void> {
  const btn = $('#btn-correctness') as HTMLButtonElement;
  const out = $('#correctness-results');
  btn.disabled = true;
  out.innerHTML = '<span class="spinner"></span> Running protocol for both choices…';

  const m0 = 'Correctness test message ZERO';
  const m1 = 'Correctness test message ONE';

  const r0 = await runFullOT(m0, m1, 0);
  const r1 = await runFullOT(m0, m1, 1);

  const ok0 = r0.decrypted === m0 && r0.otherFailed;
  const ok1 = r1.decrypted === m1 && r1.otherFailed;

  out.innerHTML = `
    <div class="correctness-results">
      <div class="result-row">
        <span class="result-icon">${ok0 ? '✅' : '❌'}</span>
        <span><strong>b=0:</strong> receiver decrypted
          "<code>${escapeHtml(r0.decrypted)}</code>"
          ${r0.otherFailed ? '— unchosen message undecryptable ✓' : '— ⚠ unchosen was decryptable!'}</span>
      </div>
      <div class="result-row">
        <span class="result-icon">${ok1 ? '✅' : '❌'}</span>
        <span><strong>b=1:</strong> receiver decrypted
          "<code>${escapeHtml(r1.decrypted)}</code>"
          ${r1.otherFailed ? '— unchosen message undecryptable ✓' : '— ⚠ unchosen was decryptable!'}</span>
      </div>
    </div>`;

  btn.disabled = false;
}

// ═══════════════════════════════════════════════════════════════════════
//  Section C2 — DDH visualizer
// ═══════════════════════════════════════════════════════════════════════

function onDDHGenerate(): void {
  const out = $('#ddh-results');
  const { points, b1Index, AHex } = generateDDHPoints();

  out.innerHTML = `
    <div class="hex-block" style="margin-bottom:1rem">
      <span class="hex-label">A (sender's public point for this example)</span>
      ${AHex}
    </div>
    <div class="ddh-points">
      ${points
        .map(
          (p, i) => `
        <div class="ddh-point">
          <div class="ddh-point-label">Point ${i + 1}</div>
          <div class="ddh-point-hex">${p}</div>
        </div>`,
        )
        .join('')}
    </div>
    <p class="note">Under the Decisional Diffie-Hellman (DDH) assumption on
       Curve25519, these three points are computationally indistinguishable. The
       sender sees only B — a single point — and cannot determine whether it
       equals rG (b=0) or A+rG (b=1).</p>
    <details style="margin-top:0.75rem">
      <summary style="cursor:pointer;color:var(--text-muted);font-size:0.9rem">
        Reveal which point is the b=1 case
      </summary>
      <p style="margin-top:0.5rem">Point <strong>${b1Index + 1}</strong> is A + r·G
         (the b=1 case). The other two are random r·G points.</p>
    </details>`;
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
    header() + '<main>' + sectionA() + sectionB() + sectionC() + sectionD() + '</main>' + footer();

  setupThemeToggle();

  // B2 demo events
  $('#btn-sender-init').addEventListener('click', () => void onSenderInit());
  $('#btn-receiver-choose').addEventListener('click', () => void onReceiverChoose());

  // C1 correctness
  $('#btn-correctness').addEventListener('click', () => void onCorrectnessCheck());

  // C2 DDH
  $('#btn-ddh').addEventListener('click', onDDHGenerate);
}

mount();
