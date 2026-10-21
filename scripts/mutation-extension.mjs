import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

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
    to: 'q[b] = selected[b];',
    test: 'sender q row uses r AND p, preserving the book identity',
  },
  {
    id: 'swap-hash-branch',
    verdict: 'wrong-message rejection',
    file: 'src/ext/iknp.ts',
    from: 'y2.set(hashRow(i + 1, 2, qXorR), i * 32);',
    to: 'y2.set(hashRow(i + 1, 1, qXorR), i * 32);',
    test: 'hash branch domain separation keeps both receiver choices correct',
  },
  {
    id: 'reverse-u-transpose',
    verdict: '128-coordinate alignment',
    file: 'src/ext/iknp.ts',
    from: 'const uRows = await transposeColumnsChunked(zeroColumns, choices.length, {',
    to: 'const uRows = await transposeColumnsChunked([...zeroColumns].reverse(), choices.length, {',
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
];

function command(file, args, expectSuccess = true) {
  const result = spawnSync(file, args, {
    cwd: process.cwd(),
    env: { ...process.env, CI: '1' },
    encoding: 'utf8',
    stdio: 'pipe',
  });
  const succeeded = result.status === 0;
  if (succeeded !== expectSuccess) {
    const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim();
    throw new Error(`${file} ${args.join(' ')} ${expectSuccess ? 'failed' : 'unexpectedly passed'}\n${output}`);
  }
  return `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
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
  for (const file of filesUnder('dist')) {
    hash.update(file);
    hash.update(readFileSync(file));
  }
  return hash.digest('hex');
}

function build() {
  command('npm', ['run', 'build']);
  return bundleHash();
}

function namedTest(name, expectSuccess) {
  return command(
    'npx',
    [
      'playwright',
      'test',
      'e2e/claims.spec.ts',
      '--grep',
      name,
      '--retries=0',
      '--workers=1',
    ],
    expectSuccess,
  );
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
  try {
    const baselineHash = build();
    namedTest(mutation.test, true);
    process.stdout.write(`1 baseline passes — ${mutation.test}\n`);

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
  }
  build();
  namedTest(mutation.test, true);
  if (execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }) !== '') {
    throw new Error(`${mutation.id}: restore did not return to the committed tree`);
  }
  process.stdout.write(`5 restored and GREEN — ${mutation.test}\n`);
}

process.stdout.write(`\nSUMMARY ${mutations.length} of ${mutations.length} mutations killed\n`);
