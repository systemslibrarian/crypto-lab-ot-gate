import { isBaseSetupCompromised, markBaseSetupCompromised, setupBaseOTs, type BaseOTSetup } from './ext/base';
import {
  assessCorruptAttack,
  makeCorruptReceiverState,
} from './ext/corrupt-receiver';
import {
  createMessagePairs,
  maskMessages,
  randomChoices,
  receiverMessage,
  receiverOutputs,
  senderOutputs,
  verifyAll,
  type MaskedMessages,
  type MessagePairs,
  type ReceiverMessageState,
  type SenderOutputState,
} from './ext/iknp';
import { rowAt } from './ext/transpose';

interface PendingRun {
  receiver: ReceiverMessageState;
  sender: SenderOutputState;
  messages: MessagePairs;
  ciphertexts: MaskedMessages;
  receiverMasks: Uint8Array;
  elapsedMs: number;
  broken: boolean;
}

const number = new Intl.NumberFormat('en-US');
let baseSetup: BaseOTSetup | null = null;
let transferCount: 1_000 | 10_000 | 100_000 = 1_000;
let choices: Uint8Array<ArrayBufferLike> = new Uint8Array(1_000);
let brokenMode = false;
let pending: PendingRun | null = null;
let controller: AbortController | null = null;
let generation = 0;
let revealSenderR = false;

function el<T extends HTMLElement>(selector: string): T {
  return document.querySelector<T>(selector)!;
}

function status(message: string): void {
  el('#ext-status').textContent = message;
}

function setError(message: string): void {
  const error = el('#ext-error');
  error.textContent = message;
  error.hidden = message === '';
}

function bitInRow(row: Uint8Array, column: number): number {
  return (row[column >>> 3] >>> (7 - (column & 7))) & 1;
}

function renderChoiceButtons(): void {
  const target = el('#ext-choice-preview');
  target.innerHTML = Array.from({ length: 16 }, (_, i) => {
    const choice = choices[i] || 1;
    return `<button class="ext-choice-bit" type="button" data-index="${i}" aria-pressed="${choice === 2}" ${baseSetup && !brokenMode ? '' : 'disabled'}><span class="ext-choice-index">${i + 1}</span><span class="ext-choice-value">${choice}</span></button>`;
  }).join('');
}

function renderBitStrip(
  target: HTMLElement,
  bits: Uint8Array,
  reveal: boolean,
  label: string,
): void {
  target.dataset.bits = Array.from(bits).join('');
  target.setAttribute('aria-label', reveal ? `${label}: ${target.dataset.bits}` : `${label}: masked`);
  target.innerHTML = Array.from(bits, (bit, index) =>
    `<span class="ext-secret-bit ${reveal ? `bit-${bit}` : 'masked'}" aria-hidden="true" title="bit ${index + 1}">${reveal ? bit : '•'}</span>`,
  ).join('');
}

function renderProbeProgress(bits: Uint8Array, completed: number): void {
  const target = el('#ext-recovered-r');
  target.setAttribute('aria-label', `${completed} of 128 sender-secret bits recovered`);
  target.innerHTML = Array.from({ length: 128 }, (_, index) => {
    if (index >= completed) {
      return `<span class="ext-secret-bit masked" aria-hidden="true" title="bit ${index + 1}">•</span>`;
    }
    const bit = bits[index];
    return `<span class="ext-secret-bit bit-${bit}" aria-hidden="true" title="bit ${index + 1}">${bit}</span>`;
  }).join('');
}

function renderSenderSecret(): void {
  if (!baseSetup) return;
  renderBitStrip(
    el('#ext-sender-r'),
    baseSetup.senderChoiceBits,
    revealSenderR,
    "Extension sender's 128-bit secret r",
  );
  const button = el<HTMLButtonElement>('#ext-reveal-r');
  button.textContent = revealSenderR ? 'Mask r' : 'Reveal r';
  button.setAttribute('aria-pressed', String(revealSenderR));
}

function clearVerdicts(): void {
  for (const selector of [
    '#ext-verdict',
    '#ext-wrong-verdict',
    '#ext-r-verdict',
    '#ext-both-verdict',
  ]) {
    const target = el(selector);
    target.hidden = true;
    target.textContent = '';
    target.className = 'ext-verdict';
  }
  const recovered = el('#ext-recovered-wrap');
  recovered.hidden = true;
  el('#ext-recovered-r').innerHTML = '';
  el('#ext-run-output').removeAttribute('data-n');
  el('#ext-correct-count').textContent = '—';
  el('#ext-wrong-count').textContent = '—';
  el('#ext-both-count').textContent = '—';
}

function clearOnlineResult(): void {
  clearVerdicts();
  el('#ext-online-count').textContent = '—';
  el('#ext-online-ms').textContent = '—';
  el('#ext-online-bytes').textContent = '—';
  el('#ext-hash-calls').textContent = '—';
  el('#ext-index-range').textContent = '—';
  el('#ext-index-range').removeAttribute('data-first-index');
  el('#ext-matrix').innerHTML = '<p class="ext-placeholder">Run the extension to draw the first 16 rows and columns.</p>';
  el('#ext-comparison').hidden = true;
  el<HTMLButtonElement>('#ext-check').disabled = true;
}

function retireResult(message: string): void {
  controller?.abort();
  controller = null;
  generation += 1;
  pending = null;
  clearOnlineResult();
  status(message);
}

function setRunning(running: boolean): void {
  const compromised = baseSetup !== null && isBaseSetupCompromised(baseSetup);
  el<HTMLButtonElement>('#ext-base').disabled = running;
  el<HTMLButtonElement>('#ext-extend').disabled = running || !baseSetup || compromised;
  el('#ext-extend-reason').textContent = !baseSetup
    ? 'Run step 1 first; extension cannot proceed without the 128 base correlations.'
    : compromised
      ? 'The malicious receiver used this setup. Run step 1 for fresh base OTs before another extension.'
      : 'Ready: each run uses fresh AES stream positions and hash indices; cancelled ranges are never reused.';
  el<HTMLButtonElement>('#ext-check').disabled = running || !pending;
  el<HTMLButtonElement>('#ext-reveal-r').disabled = running || !baseSetup;
  el<HTMLInputElement>('#ext-malicious').disabled = running;
  document.querySelectorAll<HTMLInputElement>('input[name="ext-count"]').forEach((radio) => {
    radio.disabled = running;
  });
  document.querySelectorAll<HTMLButtonElement>('.ext-choice-bit').forEach((button) => {
    button.disabled = running || !baseSetup || brokenMode;
  });
  el<HTMLButtonElement>('#ext-cancel').hidden = !running;
}

function discardBaseSetup(): void {
  baseSetup = null;
  revealSenderR = false;
  for (const selector of ['#ext-base-count', '#ext-base-ms', '#ext-base-per']) el(selector).textContent = '—';
  el('#ext-sender-r').innerHTML = '';
  el('#ext-sender-r').removeAttribute('data-bits');
  el('#ext-sender-r').setAttribute('aria-label', 'Sender secret r not generated');
  el('#ext-reveal-r').textContent = 'Reveal r';
  el('#ext-reveal-r').setAttribute('aria-pressed', 'false');
}

function cancelRun(): void {
  controller?.abort();
  controller = null;
  generation += 1;
  pending = null;
  clearOnlineResult();
  setRunning(false);
  status('Cancelled — partial counters cleared; no stale success remains.');
}

function renderMatrix(receiver: ReceiverMessageState, sender: SenderOutputState, receiverMasks: Uint8Array): void {
  const heads = Array.from({ length: 16 }, (_, j) => `<th scope="col">j${j + 1}</th>`).join('');
  const rows = Array.from({ length: 16 }, (_, i) => {
    const u = rowAt(receiver.uRows, i);
    const v = rowAt(receiver.vRows, i);
    const p = rowAt(receiver.pRows, i);
    const q = rowAt(sender.qRows, i);
    const c = receiver.choices[i] === 2 ? 1 : 0;
    const cells = Array.from({ length: 16 }, (_, j) => {
      const values = `${bitInRow(u, j)}${bitInRow(v, j)}${bitInRow(p, j)}${c}${bitInRow(q, j)}`;
      return `<td><span class="ext-matrix-cell c-${c}" role="img" aria-label="transfer ${receiver.firstIndex + i}, column ${j + 1}: u ${values[0]}, v ${values[1]}, p ${values[2]}, C ${values[3]}, q ${values[4]}">${values}</span></td>`;
    }).join('');
    return `<tr><th scope="row">i${receiver.firstIndex + i}<small>s=${receiver.choices[i]}</small></th>${cells}</tr>`;
  }).join('');
  const hex = (bytes: Uint8Array): string => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  const chosenPad = receiver.choices[0] === 1 ? sender.y1 : sender.y2;
  el('#ext-matrix').innerHTML = `
    <p class="ext-matrix-key"><strong>Each cell:</strong> u · v · p · C[s] · q. ${brokenMode ? 'These probe rows deliberately deviate: q differs from u in coordinate j when sender bit r_j is 1.' : 'For s=1, q lines up with u; for s=2, q lines up with u xor r.'}</p>
    <div class="ext-matrix-scroll" tabindex="0" role="region" aria-label="First 16 by 16 OT extension matrix window, scrollable">
      <table class="ext-matrix-table"><thead><tr><th scope="col">row</th>${heads}</tr></thead><tbody>${rows}</tbody></table>
    </div>
    ${brokenMode ? '' : `<details class="ext-hash-work"><summary>Inspect the first transfer's hash</summary>
      <p>SHA-256(uint32 big-endian index ‖ one-byte choice ‖ 16-byte u row). The index advances across runs.</p>
      <p>Index: <code id="ext-hash-index">${receiver.firstIndex}</code> · Choice: <code id="ext-hash-choice">${receiver.choices[0]}</code></p>
      <p>u: <code id="ext-hash-u">${hex(rowAt(receiver.uRows, 0))}</code></p>
      <p>Receiver pad: <code id="ext-hash-receiver">${hex(receiverMasks.subarray(0, 32))}</code></p>
      <p>Sender's selected pad: <code id="ext-hash-sender">${hex(chosenPad.subarray(0, 32))}</code></p>
    </details>`}`;
}

function renderMetrics(run: PendingRun): void {
  if (!baseSetup) return;
  const perBasePrinted = Number((baseSetup.elapsedMs / baseSetup.n).toFixed(6));
  const projection = perBasePrinted * transferCount;
  el('#ext-online-count').textContent = number.format(transferCount);
  el('#ext-online-ms').textContent = run.elapsedMs.toFixed(3);
  el('#ext-online-bytes').textContent = number.format(transferCount * 16);
  el('#ext-hash-calls').textContent = number.format(transferCount * 3);
  el('#ext-index-range').textContent = `${number.format(run.receiver.firstIndex)}–${number.format(run.receiver.firstIndex + run.receiver.count - 1)}`;
  el('#ext-index-range').dataset.firstIndex = String(run.receiver.firstIndex);
  el('#ext-measured-base-rate').textContent = perBasePrinted.toFixed(6);
  el('#ext-measured-extension').textContent = run.elapsedMs.toFixed(3);
  const projectionEl = el('#ext-projection');
  projectionEl.textContent = projection.toFixed(3);
  projectionEl.dataset.value = projection.toFixed(3);
  projectionEl.dataset.perBaseMs = perBasePrinted.toFixed(6);
  projectionEl.dataset.n = String(transferCount);
  el('#ext-comparison').hidden = false;
}

async function runBaseSetup(): Promise<void> {
  if (!globalThis.crypto?.subtle) {
    setError('WebCrypto is unavailable. Base setup failed closed; there is no fallback cipher.');
    return;
  }
  const replacedSetup = baseSetup !== null;
  if (replacedSetup) retireResult('Previous extension verdict retired: a fresh base setup was requested.');
  discardBaseSetup();
  setError('');
  const token = ++generation;
  setRunning(true);
  status('Running 128 real Chou–Orlandi base OTs with reversed roles…');
  try {
    const next = await setupBaseOTs();
    if (token !== generation) return;
    baseSetup = next;
    revealSenderR = false;
    choices = randomChoices(transferCount);
    if (brokenMode) choices.fill(1, 0, 128);
    renderChoiceButtons();
    renderSenderSecret();
    el('#ext-base-count').textContent = String(next.n);
    el('#ext-base-ms').textContent = next.elapsedMs.toFixed(3);
    el('#ext-base-per').textContent = (next.elapsedMs / next.n).toFixed(6);
    el<HTMLButtonElement>('#ext-base').textContent = 'Run 128 base OTs again';
    status(
      replacedSetup
        ? 'Step 1 complete — the previous extension verdict was retired and 128 fresh base-OT correlations are ready.'
        : 'Step 1 complete — 128 transcript-salted base-OT correlations are ready.',
    );
  } catch (error) {
    if (token !== generation) return;
    setError(error instanceof Error ? error.message : 'Base OT setup failed.');
    status('Base setup stopped without producing keys.');
  } finally {
    if (token === generation) setRunning(false);
  }
}

async function runExtension(): Promise<void> {
  if (!baseSetup) return;
  const setup = baseSetup;
  const broken = brokenMode;
  retireResult('Starting a fresh extension run…');
  setError('');
  const token = ++generation;
  controller = new AbortController();
  const signal = controller.signal;
  setRunning(true);
  const started = performance.now();
  try {
    const runChoices = choices.slice();
    if (broken) runChoices.fill(1, 0, 128);
    const progress = (update: { phase: string; completed: number; total: number }) => {
      if (token === generation) {
        status(`Step 3 — ${update.phase}: ${number.format(update.completed)} / ${number.format(update.total)}`);
      }
    };
    const honestReceiver = await receiverMessage(setup, runChoices, { signal, onProgress: progress });
    if (token !== generation) return;
    const receiver = broken ? makeCorruptReceiverState(honestReceiver) : honestReceiver;
    if (broken) markBaseSetupCompromised(setup);
    const sender = await senderOutputs(setup, receiver, { signal, onProgress: progress });
    const messages = createMessagePairs(transferCount);
    const ciphertexts = maskMessages(messages, sender);
    const receiverMasks = await receiverOutputs(receiver, { signal, onProgress: progress });
    if (token !== generation) return;
    pending = {
      receiver,
      sender,
      messages,
      ciphertexts,
      receiverMasks,
      elapsedMs: performance.now() - started,
      broken,
    };
    renderMatrix(receiver, sender, receiverMasks);
    renderMetrics(pending);
    status(`Step 3 complete — ${number.format(transferCount)} real extended transfers are ready to check.`);
  } catch (error) {
    if (token !== generation) return;
    pending = null;
    clearOnlineResult();
    if (error instanceof DOMException && error.name === 'AbortError') {
      status('Cancelled — partial counters cleared; no stale success remains.');
    } else {
      setError(error instanceof Error ? error.message : 'OT extension failed.');
      status('Extension stopped without a verdict.');
    }
  } finally {
    if (token === generation) {
      controller = null;
      setRunning(false);
    }
  }
}

function showVerdict(selector: string, text: string, kind: 'success' | 'failure' | 'alarm'): void {
  const target = el(selector);
  target.hidden = false;
  target.textContent = text;
  target.className = `ext-verdict ${kind}`;
}

async function checkRun(): Promise<void> {
  if (!pending || !baseSetup) return;
  const run = pending;
  const token = ++generation;
  controller = new AbortController();
  setRunning(true);
  status(`Step 4 — checking all ${number.format(run.receiver.count)} computed transfers…`);
  try {
    el('#ext-run-output').dataset.n = String(run.receiver.count);
    if (!run.broken) {
      const result = await verifyAll(
        run.receiver,
        run.messages,
        run.ciphertexts,
        run.receiverMasks,
        { signal: controller.signal },
      );
      if (token !== generation) return;
      el('#ext-correct-count').textContent = number.format(result.correctCount);
      el('#ext-wrong-count').textContent = number.format(result.wrongMessageRejectedCount);
      showVerdict(
        '#ext-verdict',
        result.allCorrect
          ? `✓ ALL ${number.format(result.count)} CHOSEN MESSAGES RECOVERED`
          : `✗ ${number.format(result.count - result.correctCount)} CHOSEN MESSAGES FAILED`,
        result.allCorrect ? 'success' : 'failure',
      );
      showVerdict(
        '#ext-wrong-verdict',
        result.wrongMessageRejectedCount === result.count
          ? `✓ ${number.format(result.wrongMessageRejectedCount)} / ${number.format(result.count)} WRONG-MESSAGE CHECKS REJECTED`
          : `✗ ${number.format(result.count - result.wrongMessageRejectedCount)} WRONG MESSAGES OPENED`,
        result.wrongMessageRejectedCount === result.count ? 'success' : 'failure',
      );
      status('Step 4 complete — every verdict was counted from the produced arrays.');
    } else {
      el('#ext-recovered-wrap').hidden = false;
      renderProbeProgress(new Uint8Array(128), 0);
      const attack = await assessCorruptAttack(
        baseSetup,
        run.receiver,
        run.sender,
        run.ciphertexts,
        run.messages,
        {
          signal: controller.signal,
          onProbe: (bits, completed) => {
            if (token === generation) renderProbeProgress(bits, completed);
          },
        },
      );
      if (token !== generation) return;
      el('#ext-correct-count').textContent = number.format(attack.chosenCorrectCount);
      el('#ext-wrong-count').textContent = 'not claimed';
      el('#ext-both-count').textContent = number.format(attack.bothMessagesRecoveredCount);
      showVerdict(
        '#ext-verdict',
        attack.chosenCorrectCount === run.receiver.count && attack.recoveredExactly
          ? "ALL N TRANSFERS CORRECT — AND THE SENDER'S SECRET r RECOVERED"
          : `✗ ${number.format(attack.chosenCorrectCount)} / ${number.format(run.receiver.count)} CHOSEN MESSAGES CORRECT; SENDER SECRET ${attack.recoveredExactly ? 'RECOVERED' : 'NOT RECOVERED'}`,
        attack.chosenCorrectCount === run.receiver.count && attack.recoveredExactly ? 'alarm' : 'failure',
      );
      if (attack.chosenCorrectCount === run.receiver.count && attack.recoveredExactly) {
        el('#ext-verdict').className = 'ext-verdict success alarm';
      }
      showVerdict(
        '#ext-r-verdict',
        attack.recoveredExactly
          ? '⚠ ALARM: 128 / 128 sender-secret bits recovered exactly'
          : '✗ Attack did not recover the sender secret exactly',
        attack.recoveredExactly ? 'alarm' : 'failure',
      );
      const expectedBoth = run.receiver.count - 128;
      showVerdict(
        '#ext-both-verdict',
        attack.bothMessagesRecoveredCount === expectedBoth
          ? `⚠ ALARM: BOTH MESSAGES OPENED FOR ${number.format(expectedBoth)} / ${number.format(expectedBoth)} LATER TRANSFERS`
          : `✗ BOTH-MESSAGE RECOVERY MISSED ${number.format(expectedBoth - attack.bothMessagesRecoveredCount)} TRANSFERS`,
        attack.bothMessagesRecoveredCount === expectedBoth ? 'alarm' : 'failure',
      );
      renderBitStrip(
        el('#ext-recovered-r'),
        attack.recovered.bits,
        true,
        "Corrupt receiver's recovered sender secret r",
      );
      status('Step 4 complete — green chosen-message checks coexist with a red confidentiality alarm.');
    }
  } catch (error) {
    if (token !== generation) return;
    clearVerdicts();
    if (error instanceof DOMException && error.name === 'AbortError') {
      cancelRun();
      return;
    }
    setError(error instanceof Error ? error.message : 'Verification failed.');
    status('Verification stopped without a verdict.');
  } finally {
    if (token === generation) {
      controller = null;
      setRunning(false);
    }
  }
}

export function extensionPanel(): string {
  // [extension] point (a): replace C=(0^n,1^n) with a wider code for 1-out-of-t.
  // [extension] point (b): add a KOS15/SoftSpokenOT consistency check here.
  // [extension] point (c): hand the extended pads to a consumer such as
  // Garbled Gate's input-wire delivery instead of the teaching messages below.
  return `
    <div id="ot-extension" class="ext-lab" role="region" aria-labelledby="ext-heading">
      <div class="ext-lead">
        <h4 id="ext-heading">Run the extension: 128 curve OTs → N symmetric-key OTs</h4>
        <p>Do the expensive public-key work once. Then expand two AES columns per base key, turn columns into transfer rows, and hash each row into the two pads. The roles reverse: the extension <strong>sender</strong> holds the base-OT choices <em>r</em>, while the extension <strong>receiver</strong> holds both keys.</p>
        <p class="note">Both parties run in this one browser tab, so the page can see every secret. This is the book's semi-honest (honest-but-curious) construction, not a production boundary.</p>
      </div>

      <section class="ext-step" aria-labelledby="ext-step-1">
        <h5 id="ext-step-1"><span>1</span> Run the 128 base OTs</h5>
        <button id="ext-base" class="btn" type="button">Run 128 base OTs</button>
        <dl class="ext-counters">
          <div><dt>Base OTs</dt><dd id="ext-base-count">—</dd></div>
          <div><dt>Measured time (ms)</dt><dd id="ext-base-ms">—</dd></div>
          <div><dt>Measured ms / OT</dt><dd id="ext-base-per">—</dd></div>
        </dl>
        <div class="ext-secret-wrap">
          <div class="ext-secret-head"><strong>Sender knows r (128 base-OT choices)</strong><button id="ext-reveal-r" class="btn btn-small" type="button" aria-pressed="false" disabled>Reveal r</button></div>
          <div id="ext-sender-r" class="ext-secret-strip" role="img" aria-label="Sender secret r not generated"></div>
        </div>
      </section>

      <section class="ext-step" aria-labelledby="ext-step-2">
        <h5 id="ext-step-2"><span>2</span> Choose N and the receiver's first choices</h5>
        <fieldset class="ext-counts"><legend>Extended transfers</legend>
          <label><input type="radio" name="ext-count" value="1000" checked> 1,000</label>
          <label><input type="radio" name="ext-count" value="10000"> 10,000</label>
          <label><input type="radio" name="ext-count" value="100000"> 100,000</label>
        </fieldset>
        <p>First 16 receiver choices (press a cell to switch 1 ↔ 2). In malicious mode these are probe slots fixed at 1.</p>
        <div id="ext-choice-preview" class="ext-choice-preview" tabindex="0" role="group" aria-label="First 16 receiver choices"></div>
      </section>

      <section class="ext-step" aria-labelledby="ext-step-3">
        <h5 id="ext-step-3"><span>3</span> Extend with AES-128-CTR and SHA-256</h5>
        <div class="ext-actions"><button id="ext-extend" class="btn" type="button" disabled>Extend</button><button id="ext-cancel" class="btn btn-danger" type="button" hidden>Cancel run</button></div>
        <p id="ext-extend-reason" class="note">Run step 1 first; extension cannot proceed without the 128 base correlations.</p>
        <dl class="ext-counters">
          <div><dt>Extended OTs</dt><dd id="ext-online-count">—</dd></div>
          <div><dt>Measured online time (ms)</dt><dd id="ext-online-ms">—</dd></div>
          <div><dt>Online message bytes</dt><dd id="ext-online-bytes">—</dd></div>
          <div><dt>Protocol hash calls</dt><dd id="ext-hash-calls">—</dd></div>
          <div><dt>Fresh transfer indices</dt><dd id="ext-index-range">—</dd></div>
        </dl>
        <div id="ext-matrix" class="ext-matrix"><p class="ext-placeholder">Run the extension to draw the first 16 rows and columns.</p></div>
      </section>

      <section class="ext-step" aria-labelledby="ext-step-4">
        <h5 id="ext-step-4"><span>4</span> Check every transfer</h5>
        <button id="ext-check" class="btn" type="button" disabled>Check all N</button>
        <div id="ext-run-output" class="ext-run-output" aria-live="polite">
          <p>Chosen messages correct: <strong id="ext-correct-count">—</strong></p>
          <p>Wrong-message checks rejected: <strong id="ext-wrong-count">—</strong></p>
          <div id="ext-verdict" class="ext-verdict" data-verdict="chosen-correct" hidden></div>
          <div id="ext-wrong-verdict" class="ext-verdict" data-verdict="wrong-rejected" hidden></div>
        </div>
      </section>

      <section id="ext-comparison" class="ext-comparison" aria-labelledby="ext-compare-heading" hidden>
        <h5 id="ext-compare-heading">Measured comparison from this run</h5>
        <div class="table-wrapper" tabindex="0" role="region" aria-label="Measured OT extension comparison, scrollable table"><table><thead><tr><th scope="col">Measurement</th><th scope="col">Result (ms)</th></tr></thead><tbody>
          <tr><td>Measured base-OT rate</td><td><span id="ext-measured-base-rate">—</span> per OT</td></tr>
          <tr><td>Measured extension time</td><td id="ext-measured-extension">—</td></tr>
          <tr><td>Projection from this run: N base OTs</td><td><span id="ext-projection" data-verdict="projection">—</span></td></tr>
        </tbody></table></div>
      </section>

      <section class="ext-break" aria-labelledby="ext-break-heading">
        <h5 id="ext-break-heading">Break it yourself</h5>
        <label class="ext-switch"><input id="ext-malicious" type="checkbox"> <strong>Malicious receiver (book eq. 23.23)</strong> — deliberately broken, off by default</label>
        <div id="ext-malicious-copy" hidden>
          <p class="warning-note">Known-plaintext assumption: in the first 128 slots, a later step in a larger protocol reveals each first pad because the receiver already knows message 1. One probe then reveals one bit of r.</p>
          <p id="ext-negative-claim" class="ext-negative-claim">This OT extension is secure only against honest-but-curious parties: a receiver who deviates learns the sender's secret r, and with it both messages of every later transfer.</p>
        </div>
        <div id="ext-recovered-wrap" class="ext-secret-wrap ext-alarm-wrap" hidden>
          <strong>Corrupt receiver recovered r</strong>
          <div id="ext-recovered-r" class="ext-secret-strip" role="img" aria-label="Recovered sender secret not available"></div>
        </div>
        <p>Later transfers with both messages opened: <strong id="ext-both-count">—</strong></p>
        <div id="ext-r-verdict" class="ext-verdict" data-verdict="r-recovered" hidden></div>
        <div id="ext-both-verdict" class="ext-verdict" data-verdict="both-opened" hidden></div>
      </section>

      <p id="ext-status" class="ext-status" role="status">Ready to run step 1.</p>
      <p id="ext-error" class="ext-error" role="alert" hidden></p>
      <p class="ext-seams"><code>// [extension] point</code> Swap C for a wider code to teach 1-out-of-t; add a KOS15 or SoftSpokenOT consistency check for malicious security; feed these extended OTs into Garbled Gate input wires.</p>
    </div>`;
}

export function setupExtension(): void {
  if (!globalThis.crypto?.getRandomValues) {
    choices = new Uint8Array(transferCount).fill(1);
    renderChoiceButtons();
    setError('WebCrypto is unavailable. The extension is disabled and has no fallback cipher.');
    el<HTMLButtonElement>('#ext-base').disabled = true;
    return;
  }
  choices = randomChoices(transferCount);
  renderChoiceButtons();

  el('#ext-base').addEventListener('click', () => void runBaseSetup());
  el('#ext-extend').addEventListener('click', () => void runExtension());
  el('#ext-check').addEventListener('click', () => void checkRun());
  el('#ext-cancel').addEventListener('click', cancelRun);
  el('#ext-reveal-r').addEventListener('click', () => {
    revealSenderR = !revealSenderR;
    renderSenderSecret();
  });

  el('#ext-choice-preview').addEventListener('click', (event) => {
    const button = (event.target as HTMLElement).closest<HTMLButtonElement>('.ext-choice-bit');
    if (!button || !baseSetup || brokenMode) return;
    const index = Number(button.dataset.index);
    choices[index] = choices[index] === 1 ? 2 : 1;
    retireResult(`Previous verdict retired: receiver choice ${index + 1} changed.`);
    renderChoiceButtons();
    setRunning(false);
  });

  document.querySelectorAll<HTMLInputElement>('input[name="ext-count"]').forEach((radio) => {
    radio.addEventListener('change', () => {
      const next = Number(radio.value) as 1_000 | 10_000 | 100_000;
      if (next === transferCount) return;
      transferCount = next;
      choices = randomChoices(transferCount);
      if (brokenMode) choices.fill(1, 0, 128);
      retireResult(`Previous verdict retired: N changed to ${number.format(transferCount)}.`);
      renderChoiceButtons();
      setRunning(false);
    });
  });

  el<HTMLInputElement>('#ext-malicious').addEventListener('change', (event) => {
    brokenMode = (event.currentTarget as HTMLInputElement).checked;
    choices = randomChoices(transferCount);
    if (brokenMode) choices.fill(1, 0, 128);
    if (!brokenMode) discardBaseSetup();
    el('#ext-malicious-copy').hidden = !brokenMode;
    retireResult(
      brokenMode
        ? 'Honest verdict retired. Deliberately broken receiver mode is armed; press Extend to run it.'
        : 'Broken-mode verdict retired. Honest receiver mode restored; run step 1 for a fresh base setup.',
    );
    renderChoiceButtons();
    setRunning(false);
  });
}
