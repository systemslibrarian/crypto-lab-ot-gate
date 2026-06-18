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
        <h1><span aria-hidden="true">🔐 </span>OT Gate</h1>
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
           the form A&nbsp;+&nbsp;r·G (the b=1 case). Try to pick out the odd one —
           if you can't beat a 1-in-3 guess, that's the DDH assumption protecting
           the receiver's choice.</p>
        <button id="btn-ddh" class="btn" type="button">Generate Points</button>
        <div id="ddh-results"></div>
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
    // Show sender keys and ciphertexts
    $('#sender-output').innerHTML +=
      hexBlock('k<sub>0</sub> = H(a·B)', enc.k0Hex) +
      hexBlock('k<sub>1</sub> = H(a·(B−A))', enc.k1Hex) +
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
      hexBlock("k<sub>b</sub> = H(r·A) — receiver's derived key", receiver.keyHex) +
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

// Index of the A+r·G point in the currently displayed DDH challenge, or null
// once the user has already guessed / before any points exist.
let ddhAnswer: number | null = null;

function onDDHGenerate(): void {
  const out = $('#ddh-results');
  const { points, b1Index, AHex } = generateDDHPoints();
  ddhAnswer = b1Index;

  announce(
    'Generated three Curve25519 points. Two are random r·G and one is A + r·G. ' +
      'Choose the point you think is A + r·G. Under the DDH assumption they are indistinguishable, so it is a one-in-three guess.',
  );

  $('#btn-ddh').textContent = 'Generate New Points';

  out.innerHTML = `
    ${hexBlock("A (sender's public point for this example)", AHex)}
    <p class="ddh-prompt">Which point is <strong>A + r·G</strong> (the b=1 case)? Take your best guess:</p>
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

  const fb = $('#ddh-feedback');
  fb.className = 'ddh-feedback ' + (correct ? 'ok' : 'fail');
  fb.innerHTML = correct
    ? `<strong>Correct — Point ${answer + 1}</strong> was A + r·G. But you had no real way to know: under DDH the three points are computationally indistinguishable, so you'd be right only about 1 time in 3. That indistinguishability is exactly what stops the sender from learning the receiver's choice b.`
    : `<strong>Not quite — Point ${answer + 1}</strong> was A + r·G. Don't worry: under DDH the points are computationally indistinguishable, so no strategy beats a 1-in-3 guess. That's precisely why the sender can't tell B = rG (b=0) from B = A + rG (b=1).`;
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
  setupCopyButtons();

  // B2 demo events
  $('#btn-sender-init').addEventListener('click', () => void onSenderInit());
  $('#btn-receiver-choose').addEventListener('click', () => void onReceiverChoose());

  // C1 correctness
  $('#btn-correctness').addEventListener('click', () => void onCorrectnessCheck());

  // C2 DDH
  $('#btn-ddh').addEventListener('click', onDDHGenerate);
  $('#ddh-results').addEventListener('click', (e) => {
    const pt = (e.target as HTMLElement).closest<HTMLButtonElement>('.ddh-point');
    if (pt && !pt.disabled) onDDHGuess(Number(pt.dataset.index));
  });
}

mount();
