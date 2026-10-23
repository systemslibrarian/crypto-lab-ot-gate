import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertNormalExit, validateNamedRun } from './mutation-report.mjs';

const mutations = [
  {
    id: 'flip-p-codeword',
    verdict: 'chosen-message correctness',
    file: 'src/ext/iknp.ts',
    from: 'p[b] = u[b] ^ v[b] ^ (choice === 2 ? 0xff : 0x00);',
    to: 'p[b] = u[b] ^ v[b] ^ (choice === 1 ? 0xff : 0x00);',
    test: 'OT extension printed correctness is derived from every produced transfer',
  },
  {
    id: 'drop-r-and-p',
    verdict: 'sender q identity',
    file: 'src/ext/iknp.ts',
    from: 'q[b] = selected[b] ^ (setup.senderChoiceBytes[b] & p[b]);',
    to: 'q[b] = selected[b] ^ (p[b] & 0);',
    test: 'sender q row uses r AND p, preserving the book identity',
  },
  {
    id: 'swap-hash-branch',
    verdict: 'wrong-message rejection',
    file: 'src/ext/iknp.ts',
    from: 'y2.set(hashRow(receiver.firstIndex + i, 2, qXorR), i * 32);',
    to: 'y2.set(hashRow(receiver.firstIndex + i, 1, qXorR), i * 32);',
    test: 'hash branch domain separation keeps both receiver choices correct',
  },
  {
    id: 'reverse-u-transpose',
    verdict: '128-coordinate alignment',
    file: 'src/ext/iknp.ts',
    from: 'const uRows = await transposeColumnsChunked(zeroColumns, ownedChoices.length, {',
    to: 'const uRows = await transposeColumnsChunked([...zeroColumns].reverse(), ownedChoices.length, {',
    test: 'rendered transpose keeps all 128 base coordinates aligned',
  },
  {
    id: 'invert-recovered-r',
    verdict: 'corrupt-receiver alarm',
    file: 'src/ext/corrupt-receiver.ts',
    from: 'recovered[j] = matchedOne ? 1 : 0;',
    to: 'recovered[j] = matchedOne ? 0 : 1;',
    test: 'corrupt receiver fixture keeps chosen checks green while recovering r and both later messages',
  },
  {
    id: 'repeat-aes-stream',
    verdict: 'fresh PRF positions across runs',
    file: 'src/ext/prf.ts',
    from: 'setUint32(12, (firstIndex - 1) / 128, false)',
    to: 'setUint32(12, 0, false)',
    test: 'repeated extension runs use new PRF positions under the same base setup',
  },
  {
    id: 'restart-hash-index',
    verdict: 'independent global-index hash calculation',
    file: 'src/ext/iknp.ts',
    from: 'writeIndex(encoded, index);',
    to: 'writeIndex(encoded, 1);',
    test: 'the repeated-run hash is independently derived from its displayed global index and row',
  },
  {
    id: 'misdisplay-probe-choices',
    verdict: 'displayed choices match fixed probes',
    file: 'src/ui-ext.ts',
    from: "brokenMode = (event.currentTarget as HTMLInputElement).checked;\n    choices = randomChoices(transferCount);\n    if (brokenMode) choices.fill(1, 0, 128);",
    to: "brokenMode = (event.currentTarget as HTMLInputElement).checked;\n    choices = randomChoices(transferCount);\n    if (brokenMode) choices.fill(2, 0, 128);",
    test: 'malicious probe choices are fixed and match the rows the page computes',
  },
  {
    id: 'retain-compromised-setup',
    verdict: 'discard base secrets after the attack',
    file: 'src/ui-ext.ts',
    from: 'if (!brokenMode) discardBaseSetup();',
    to: 'if (!brokenMode && false) discardBaseSetup();',
    test: 'returning from malicious mode discards the compromised base setup before an honest run',
  },
  {
    id: 'delete-negative-claim',
    verdict: 'visible malicious-security limitation',
    file: 'src/ui-ext.ts',
    from: "This OT extension is secure only against honest-but-curious parties: a receiver who deviates learns the sender's secret r, and with it both messages of every later transfer.",
    to: '',
    test: 'corrupt receiver fixture keeps chosen checks green while recovering r and both later messages',
  },
];

function run(file, args) {
  const result = spawnSync(file, args, {
    cwd: process.cwd(),
    env: { ...process.env, CI: '1', NO_COLOR: '1', FORCE_COLOR: '0' },
    encoding: 'utf8',
    stdio: 'pipe',
    timeout: 180_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  assertNormalExit(result, `${file} ${args.join(' ')}`);
  return result;
}

function filesUnder(path) {
  return readdirSync(path)
    .flatMap((name) => {
      const full = join(path, name);
      return statSync(full).isDirectory() ? filesUnder(full) : [full];
    })
    .sort();
}

function bundleHash() {
  const hash = createHash('sha256');
  for (const file of filesUnder('dist').filter((path) => path.endsWith('.js'))) {
    hash.update(file);
    hash.update(readFileSync(file));
  }
  return hash.digest('hex');
}

function build() {
  const result = run('npm', ['run', 'build']);
  if (result.status !== 0) throw new Error(`build failed; this is not a mutation kill\n${result.stdout}\n${result.stderr}`);
  return bundleHash();
}

function namedTest(name, expectSuccess) {
  const result = run(
    'npx',
    [
      'playwright',
      'test',
      'e2e/claims.spec.ts',
      '--grep',
      // --grep includes the project/file prefix; the JSON validator below
      // still requires the exact spec.title and exactly one result.
      `${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`,
      '--retries=0',
      '--workers=1',
      '--reporter=json',
    ],
  );
  try {
    validateNamedRun(result, name, expectSuccess);
  } catch (error) {
    throw new Error(`${error.message}\n${result.stdout}\n${result.stderr}`);
  }
}

const initialStatus = execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' });
if (initialStatus !== '') {
  throw new Error('mutation run requires a clean committed worktree');
}

for (const mutation of mutations) {
  const original = readFileSync(mutation.file, 'utf8');
  if (original.split(mutation.from).length !== 2) {
    throw new Error(`${mutation.id}: mutation target must occur exactly once`);
  }
  process.stdout.write(`\nMUTATION ${mutation.id} — ${mutation.verdict}\n`);
  const baselineHash = build();
  namedTest(mutation.test, true);
  process.stdout.write(`1 baseline passes — ${mutation.test}\n`);
  try {
    writeFileSync(mutation.file, original.replace(mutation.from, mutation.to));
    const diff = execFileSync('git', ['diff', '--', mutation.file], { encoding: 'utf8' });
    if (diff.trim() === '') throw new Error(`${mutation.id}: source diff was empty`);
    process.stdout.write(`2 source diff NON-EMPTY — ${mutation.file}\n`);

    const mutantHash = build();
    if (mutantHash === baselineHash) throw new Error(`${mutation.id}: bundle hash did not move`);
    process.stdout.write(`3 bundle hash MOVED — ${baselineHash.slice(0, 12)} -> ${mutantHash.slice(0, 12)}\n`);

    namedTest(mutation.test, false);
    process.stdout.write(`4 named test RED (--retries=0) — ${mutation.test}\n`);
  } finally {
    writeFileSync(mutation.file, original);
    const restoredHash = build();
    if (restoredHash !== baselineHash) throw new Error(`${mutation.id}: restored bundle differs from baseline`);
    namedTest(mutation.test, true);
    if (execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }) !== '') {
      throw new Error(`${mutation.id}: restore did not return to the committed tree`);
    }
    process.stdout.write(`5 restored, original bundle hash and GREEN — ${mutation.test}\n`);
  }
}

process.stdout.write(`\nSUMMARY ${mutations.length} of ${mutations.length} mutations killed\n`);
