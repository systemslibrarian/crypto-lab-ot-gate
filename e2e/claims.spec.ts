import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate for the claims this page makes on screen.
 *
 * The a11y suite drives the same controls but only asks axe whether the result
 * is reachable. This suite asks whether it is true. Every hex value compared
 * here is the FULL value the page put in a copy button's `data-copy`, not the
 * truncated display string, and every comparison is between two things the page
 * itself produced — the receiver's derived key against the sender's, the
 * redacted ciphertext against the one the sender sent, the DDH scoreboard
 * against the round-by-round outcomes it was built from.
 */

const M0 = 'The treasure is buried under the oak tree';
const M1 = 'Meet at the old lighthouse at midnight';

// ---------------------------------------------------------------- guards

function guardPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(`console.error: ${msg.text()}`);
  });
  return errors;
}

test.beforeEach(async ({ page }) => {
  (test.info() as unknown as { _pageErrors: string[] })._pageErrors = guardPageErrors(page);
});

test.afterEach(async () => {
  const errors = (test.info() as unknown as { _pageErrors?: string[] })._pageErrors ?? [];
  expect(errors, 'page must raise no uncaught exceptions or console errors').toEqual([]);
});

// ---------------------------------------------------------------- helpers

/** The full (untruncated) value behind the copy button of a labelled hex block. */
async function hexByLabel(scope: Locator, label: RegExp): Promise<string> {
  const blocks = await scope.locator('.hex-block').all();
  const seen: string[] = [];
  for (const block of blocks) {
    const text = ((await block.locator('.hex-label').textContent()) ?? '').replace(/\s+/g, ' ');
    seen.push(text);
    if (label.test(text)) {
      const value = await block.locator('.copy-btn').getAttribute('data-copy');
      expect(value, `no data-copy on the block labelled ${text}`).toBeTruthy();
      expect(value!, `${text} is not lowercase hex`).toMatch(/^[0-9a-f]+$/);
      return value!;
    }
  }
  throw new Error(`no hex block matching ${label} — saw: ${JSON.stringify(seen)}`);
}

/** The 10-character fragment form the reconciliation panel prints. */
function frag(hex: string): string {
  return hex.slice(0, 10) + '…';
}

async function runProtocol(page: Page, b: 0 | 1): Promise<void> {
  await page.locator('#btn-sender-init').click();
  await expect(page.locator('#btn-receiver-choose')).toBeEnabled({ timeout: 15_000 });
  await page.locator(`#choice-${b}`).check();
  await page.locator('#btn-receiver-choose').click();
  await expect(page.locator('#privacy-audit')).toBeVisible({ timeout: 15_000 });
  await expect(page.locator('#btn-sender-init')).toHaveText('Reset & Re-initialize');
}

// ---------------------------------------------------------------- live demo

for (const b of [0, 1] as const) {
  test(`b=${b}: the receiver's key is the sender's k${b} and unlocks exactly M${b}`, async ({
    page,
  }) => {
    await page.goto('.');
    const sender = page.locator('#sender-output');
    const receiver = page.locator('#receiver-output');

    await runProtocol(page, b);

    const k0 = await hexByLabel(sender, /k0 = H\(a·B\)/);
    const k1 = await hexByLabel(sender, /k1 = H\(a·\(B−A\)\)/);
    const kb = await hexByLabel(receiver, /kb = H\(r·A\)/);

    // The whole protocol in two lines: the receiver derived, from its own r
    // alone, exactly one of the sender's two keys — the one it chose.
    expect(k0, 'the sender must derive two distinct keys').not.toBe(k1);
    expect(kb, `H(r·A) must equal the sender's k${b}`).toBe(b === 0 ? k0 : k1);
    expect(kb, `H(r·A) must not equal the sender's k${1 - b}`).not.toBe(b === 0 ? k1 : k0);
    expect(kb).toHaveLength(64);

    // The plaintext the page reports is the message the sender actually holds.
    await expect(receiver.locator('.decrypted-msg')).toContainText(
      `Decrypted M${b}: ${b === 0 ? M0 : M1}`,
    );
    // ...and the message it did not choose appears nowhere on the receiver side.
    expect(await receiver.innerText()).not.toContain(b === 0 ? M1 : M0);

    // The redacted blob is byte-for-byte the ciphertext the sender sent for the
    // unchosen message — it is hidden, not merely omitted.
    const eOther = await hexByLabel(sender, b === 0 ? /E1 \(encrypted M1\)/ : /E0 \(encrypted M0\)/);
    expect(
      ((await receiver.locator('.redacted-content').textContent()) ?? '').trim(),
      'the hidden blob must be the unchosen ciphertext',
    ).toBe(eOther);
    await expect(receiver.locator('.redacted-label')).toContainText(
      'Hidden — receiver cannot decrypt',
    );

    // The failure verdict the page reserves for a broken protocol must be absent.
    expect(await receiver.innerText()).not.toContain('Unexpected: unchosen message was decryptable');

    // Progress state: all four steps complete, none in flight.
    await expect(page.locator('.ot-step.done')).toHaveCount(4);
    await expect(page.locator('.ot-step.active')).toHaveCount(0);
    await expect(page.locator('#demo-status')).toHaveClass(/complete/);
    await expect(page.locator('#demo-status')).toContainText(`the receiver read M${b}`);
    // The last thing narrated is the reconciliation, and it must report a match.
    await expect(page.locator('#sr-status')).toContainText(
      'both reduce to the same point a r G, so their keys match',
    );
    await expect(page.locator('#sr-status')).not.toContainText('mismatch');
  });
}

test('the two independent routes to the shared point land on the same point', async ({ page }) => {
  await page.goto('.');
  await runProtocol(page, 1);

  const panel = page.locator('#key-reconcile');
  await expect(panel).toBeVisible();

  // b=1 must take the subtraction route, and the panel must say so.
  await expect(panel.locator('.sender-lane .reconcile-op')).toHaveText('a · (B − A)');
  await expect(panel.locator('.receiver-lane .reconcile-op')).toHaveText('r · A');
  await expect(panel.locator('.reconcile-intro')).toContainText('B = A + rG');
  await expect(panel.locator('.reconcile-intro')).toContainText('b = 1');

  const receiverFrag = (
    (await panel.locator('.receiver-lane .reconcile-frag').textContent()) ?? ''
  ).trim();
  const senderFrag = ((await panel.locator('.sender-lane .reconcile-frag').textContent()) ?? '').trim();
  const sharedFrag = (
    (await panel.locator('.reconcile-shared .reconcile-frag').textContent()) ?? ''
  ).trim();

  expect(receiverFrag, "r·A and a·(B−A) must be the same point").toBe(senderFrag);
  expect(sharedFrag, 'the shared point must be the point both routes reached').toBe(senderFrag);
  await expect(panel.locator('.reconcile-meet')).toHaveClass(/match/);
  await expect(panel.locator('.reconcile-meet')).not.toHaveClass(/nomatch/);
  await expect(panel.locator('.reconcile-badge')).toHaveText('✓ same point');

  // The working key shown here is H of that point, and it is the receiver's key.
  const kb = await hexByLabel(page.locator('#receiver-output'), /kb = H\(r·A\)/);
  const k0 = await hexByLabel(page.locator('#sender-output'), /k0 = H\(a·B\)/);
  await expect(panel.locator('.key-ok .reconcile-frag')).toHaveText(frag(kb));
  // ...and the other key, the one the receiver can never reach, is the other one.
  await expect(panel.locator('.key-bad .reconcile-frag')).toHaveText(frag(k0));
  expect(frag(kb)).not.toBe(frag(k0));
  await expect(panel.locator('.key-ok')).toContainText("Receiver's k");
  await expect(panel.locator('.key-bad')).toContainText("the sender's OTHER key");
});

test('nothing labelled "never transmitted" reaches the other side', async ({ page }) => {
  await page.goto('.');
  await runProtocol(page, 0);

  const a = await hexByLabel(page.locator('#sender-output'), /sender private scalar/);
  const r = await hexByLabel(page.locator('#receiver-output'), /receiver private scalar/);
  const A = await hexByLabel(page.locator('#sender-output'), /A = aG \(sent to receiver\)/);
  const B = await hexByLabel(page.locator('#receiver-output'), /B \(sent to sender\)/);

  expect(a).not.toBe(r);
  expect(A).not.toBe(B);

  // Everything that crossed the channel, plus everything each side rendered.
  const channel = await page.locator('#demo-channel').innerHTML();
  const senderSide = await page.locator('#sender-output').innerHTML();
  const receiverSide = await page.locator('#receiver-output').innerHTML();

  expect(channel, "the sender's scalar a must never cross the channel").not.toContain(a);
  expect(channel, "the receiver's scalar r must never cross the channel").not.toContain(r);
  expect(receiverSide, "the receiver must never be shown the sender's a").not.toContain(a);
  expect(senderSide, "the sender must never be shown the receiver's r").not.toContain(r);

  // Exactly three messages cross, in protocol order, carrying the right values.
  const msgs = page.locator('#demo-channel .channel-msg');
  await expect(msgs).toHaveCount(3);
  await expect(msgs.nth(0).locator('.direction')).toHaveText('A → Receiver');
  await expect(msgs.nth(1).locator('.direction')).toHaveText('B → Sender');
  await expect(msgs.nth(2).locator('.direction')).toHaveText('(E₀, E₁) → Receiver');
  expect(A.startsWith(((await msgs.nth(0).locator('.payload').textContent()) ?? '').replace('…', ''))).toBe(
    true,
  );
  expect(B.startsWith(((await msgs.nth(1).locator('.payload').textContent()) ?? '').replace('…', ''))).toBe(
    true,
  );

  // The privacy audit quotes the B the sender was actually handed.
  const sees = ((await page.locator('#sender-sees').textContent()) ?? '').replace(/\s+/g, ' ');
  const quoted = /B = ([0-9a-f]+)…?/.exec(sees);
  expect(quoted, `no B quoted in the audit: ${sees}`).not.toBeNull();
  expect(B.startsWith(quoted![1])).toBe(true);
});

test('the privacy audit does not downgrade the choice-hiding claim the page makes elsewhere', async ({
  page,
}) => {
  // B1, C2 and C3 all say the choice bit is hidden *unconditionally* — r is
  // uniform, so rG and A+rG are identically distributed. The audit box must not
  // contradict that by calling it merely computational.
  await page.goto('.');
  await runProtocol(page, 0);

  const audit = await page.locator('#privacy-audit').innerText();
  expect(audit).toContain("What the sender learned about the receiver's choice:");
  expect(audit, 'choice hiding is unconditional, not computational').not.toMatch(
    /computationally indistinguishable/i,
  );
  expect(audit).toMatch(/perfectly indistinguishable|identical distributions|unconditional/i);

  // The asymmetry must survive: the receiver's side IS the computational half.
  expect(audit).toMatch(/CDH|computational Diffie-Hellman/i);

  // And the page's other statements of it are still there to agree with.
  await expect(page.locator('#section-b')).toContainText('perfectly indistinguishable');
  await expect(page.locator('#section-c')).toContainText('hidden from the sender unconditionally');
});

test('an empty message is refused by name and no protocol runs', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#btn-receiver-choose')).toBeDisabled();
  await expect(page.locator('#demo-error')).toBeHidden();

  await page.locator('#m0-input').fill('   ');
  await page.locator('#btn-sender-init').click();
  await expect(page.locator('#demo-error')).toBeVisible();
  await expect(page.locator('#demo-error')).toContainText('Message M₀ can’t be empty');
  await expect(page.locator('#m0-input')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#m1-input')).not.toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#demo-channel .channel-msg')).toHaveCount(0);
  await expect(page.locator('#sender-output')).toBeEmpty();
  await expect(page.locator('#btn-receiver-choose')).toBeDisabled();

  await page.locator('#m0-input').fill(M0);
  await page.locator('#m1-input').fill('');
  await page.locator('#btn-sender-init').click();
  await expect(page.locator('#demo-error')).toContainText('Message M₁ can’t be empty');
  await expect(page.locator('#m1-input')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#m0-input')).not.toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#demo-channel .channel-msg')).toHaveCount(0);

  // Fixing it clears the error and lets the protocol run.
  await page.locator('#m1-input').fill(M1);
  await page.locator('#btn-sender-init').click();
  await expect(page.locator('#demo-error')).toBeHidden();
  await expect(page.locator('#btn-receiver-choose')).toBeEnabled({ timeout: 15_000 });
});

test('emptying a message after setup blocks encryption instead of encrypting nothing', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#btn-sender-init').click();
  await expect(page.locator('#btn-receiver-choose')).toBeEnabled({ timeout: 15_000 });

  await page.locator('#m1-input').fill('');
  await page.locator('#choice-1').check();
  await page.locator('#btn-receiver-choose').click();

  await expect(page.locator('#demo-error')).toContainText('Message M₁ can’t be empty');
  await expect(page.locator('#m1-input')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#receiver-output')).toBeEmpty();
  await expect(page.locator('#privacy-audit')).toBeHidden();
  await expect(page.locator('#key-reconcile')).toBeHidden();
  // Only A crossed; nothing was encrypted.
  await expect(page.locator('#demo-channel .channel-msg')).toHaveCount(1);
});

test('re-initializing clears the finished run rather than leaving it on screen', async ({
  page,
}) => {
  await page.goto('.');
  await runProtocol(page, 0);
  const firstA = await hexByLabel(page.locator('#sender-output'), /A = aG/);
  await expect(page.locator('#receiver-output .decrypted-msg')).toBeVisible();

  await page.locator('#btn-sender-init').click();
  await expect(page.locator('#btn-receiver-choose')).toBeEnabled({ timeout: 15_000 });

  // No trace of the completed transfer may survive the reset.
  await expect(page.locator('#receiver-output')).toBeEmpty();
  await expect(page.locator('#privacy-audit')).toBeHidden();
  await expect(page.locator('#key-reconcile')).toBeHidden();
  await expect(page.locator('#demo-channel .channel-msg')).toHaveCount(1);
  await expect(page.locator('#btn-sender-init')).toHaveText('Initialize Sender');

  // A fresh session must use a fresh A.
  const secondA = await hexByLabel(page.locator('#sender-output'), /A = aG/);
  expect(secondA, 'each session must publish a fresh A = aG').not.toBe(firstA);

  // And the second run must still be correct.
  await page.locator('#choice-1').check();
  await page.locator('#btn-receiver-choose').click();
  await expect(page.locator('#privacy-audit')).toBeVisible({ timeout: 15_000 });
  await expect(page.locator('#receiver-output .decrypted-msg')).toContainText(
    `Decrypted M1: ${M1}`,
  );
});

// ---------------------------------------------------------------- C1

test('the correctness check reports the run it actually performed', async ({ page }) => {
  await page.goto('.');
  await page.locator('#btn-correctness').click();
  await expect(page.locator('#correctness-results .check-verdict')).toBeVisible({
    timeout: 30_000,
  });

  const out = page.locator('#correctness-results');
  await expect(out.locator('.check-verdict')).toHaveClass(/ok/);
  await expect(out.locator('.check-verdict')).not.toHaveClass(/fail/);
  await expect(out.locator('.check-verdict')).toContainText('All checks passed');

  // One row per choice bit, each passing both of its two sub-checks.
  await expect(out.locator('.result-row')).toHaveCount(2);
  await expect(out.locator('.result-row.pass')).toHaveCount(2);
  await expect(out.locator('.result-row.fail')).toHaveCount(0);
  await expect(out.locator('.result-checks li')).toHaveCount(4);
  await expect(out.locator('.result-checks li.ok')).toHaveCount(4);
  await expect(out.locator('.result-checks li.bad')).toHaveCount(0);

  // The plaintext each row reports must be the message for that choice bit.
  await expect(out.locator('.result-row').nth(0)).toContainText('Choice b=0');
  await expect(out.locator('.result-row').nth(0)).toContainText(
    'decrypted "Correctness test message ZERO"',
  );
  await expect(out.locator('.result-row').nth(1)).toContainText('Choice b=1');
  await expect(out.locator('.result-row').nth(1)).toContainText(
    'decrypted "Correctness test message ONE"',
  );

  const text = await out.innerText();
  expect(text).not.toContain('Decryption did not match');
  expect(text).not.toContain('unexpectedly decryptable');
  await expect(page.locator('#btn-correctness')).toBeEnabled();
});

// ---------------------------------------------------------------- C2

test('the choice-hiding match scoreboard is the sum of its own rounds', async ({ page }) => {
  test.slow();
  await page.goto('.');

  await expect(page.locator('#ddh-round')).toHaveText('0');
  await expect(page.locator('#ddh-hits')).toHaveText('0');
  await expect(page.locator('#ddh-acc')).toHaveText('—');
  await expect(page.locator('#btn-ddh-reset')).toBeHidden();

  let hits = 0;
  for (let round = 1; round <= 10; round++) {
    await page.locator('#btn-ddh').click();
    await expect(page.locator('#ddh-results .ddh-point')).toHaveCount(3);
    // Nothing is revealed before the guess.
    await expect(page.locator('#ddh-results .ddh-point.is-b1')).toHaveCount(0);
    await expect(page.locator('#btn-ddh')).toBeDisabled();
    await expect(page.locator('.ddh-prompt')).toContainText(`Round ${round}`);

    await page.locator('#ddh-results .ddh-point').first().click();

    // Exactly one of the three was A+r·G, and every button is now locked.
    await expect(page.locator('#ddh-results .ddh-point.is-b1')).toHaveCount(1);
    await expect(page.locator('#ddh-results .ddh-point.is-random')).toHaveCount(2);
    await expect(page.locator('#ddh-results .ddh-point[disabled]')).toHaveCount(3);

    const feedback = page.locator('#ddh-feedback');
    const text = ((await feedback.textContent()) ?? '').replace(/\s+/g, ' ');
    const correct = text.startsWith('Correct —');
    if (correct) hits++;

    // The verdict, its styling and the revealed answer must all agree.
    await expect(feedback).toHaveClass(correct ? /\bok\b/ : /\bfail\b/);
    const answerLabel = ((await page
      .locator('#ddh-results .ddh-point.is-b1 .ddh-point-label')
      .textContent()) ?? '').trim();
    const answerNum = Number(/Point (\d+) — A \+ r·G/.exec(answerLabel)![1]);
    expect(text).toContain(`Point ${answerNum}`);
    expect(
      correct,
      'a correct call must be the one where the guessed point was the answer',
    ).toBe(answerNum === 1);
    await expect(page.locator('#ddh-results .ddh-point.is-wrong')).toHaveCount(correct ? 0 : 1);

    // The running tally is the count of rounds and hits so far, and the
    // accuracy is those two divided.
    await expect(page.locator('#ddh-round')).toHaveText(String(round));
    await expect(page.locator('#ddh-hits')).toHaveText(String(hits));
    const pct = ((hits / round) * 100).toFixed(0);
    await expect(page.locator('#ddh-acc')).toHaveText(`${pct}%`);
    expect(text).toContain(`${hits}/${round === 10 ? 10 : round} = ${pct}%`);

    // The bar is the same number drawn.
    // The browser re-serialises the inline width to 6 significant digits, so
    // compare the number rather than the string.
    const width = await page
      .locator('#ddh-bar-fill')
      .evaluate((el) => (el as HTMLElement).style.width);
    expect(width).toMatch(/%$/);
    expect(Number(width.replace('%', '')), 'the bar must draw the accuracy shown').toBeCloseTo(
      Math.min(100, (hits / round) * 100),
      3,
    );

    await expect(page.locator('#btn-ddh-reset')).toBeVisible();
  }

  // Ten rounds is the whole match; the deal button closes.
  await expect(page.locator('#btn-ddh')).toHaveText('Match complete');
  await expect(page.locator('#btn-ddh')).toBeDisabled();
  await expect(page.locator('#ddh-feedback')).toContainText(`Match over: ${hits}/10`);

  // Reset must return the scoreboard to zero, not just hide the last round.
  await page.locator('#btn-ddh-reset').click();
  await expect(page.locator('#ddh-round')).toHaveText('0');
  await expect(page.locator('#ddh-hits')).toHaveText('0');
  await expect(page.locator('#ddh-acc')).toHaveText('—');
  await expect(page.locator('#ddh-results')).toBeEmpty();
  await expect(page.locator('#btn-ddh')).toHaveText('Deal a round');
  await expect(page.locator('#btn-ddh')).toBeEnabled();
});

test('the 1000-round simulation reports the rate its own hit count implies', async ({ page }) => {
  test.slow();
  await page.goto('.');
  await page.locator('#btn-ddh-auto').click();
  await expect(page.locator('#ddh-auto .ddh-auto-result')).toBeVisible({ timeout: 60_000 });

  const cap = ((await page.locator('.ddh-auto-cap').textContent()) ?? '').replace(/\s+/g, ' ');
  const m = /(\d+) hits in (\d+) real challenges/.exec(cap);
  expect(m, `unparseable caption: ${cap}`).not.toBeNull();
  const hits = Number(m![1]);
  const rounds = Number(m![2]);
  expect(rounds).toBe(1000);

  const shown = ((await page.locator('.ddh-auto-num').textContent()) ?? '').trim();
  expect(shown, 'the headline rate must be the hit count over the rounds').toBe(
    `${((hits / rounds) * 100).toFixed(1)}%`,
  );

  // A blind guess at 1 of 3 has σ ≈ 14.9 over 1000 rounds; ±90 is six sigma.
  // Outside that band the point generation is not producing a uniform placement.
  expect(hits, 'the measured hit rate must sit on the 1-in-3 baseline').toBeGreaterThan(243);
  expect(hits).toBeLessThan(423);

  // The bar drawn is the rate reported.
  const width = await page
    .locator('.ddh-auto-bar-fill')
    .evaluate((el) => (el as HTMLElement).style.width);
  expect(width).toMatch(/%$/);
  expect(Number(width.replace('%', '')), 'the bar must draw the rate reported').toBeCloseTo(
    Math.min(100, (hits / rounds) * 100),
    3,
  );

  await expect(page.locator('#btn-ddh-auto')).toBeEnabled();
  await expect(page.locator('#sr-status')).toContainText(`guessed ${hits} of ${rounds} correctly`);
});
