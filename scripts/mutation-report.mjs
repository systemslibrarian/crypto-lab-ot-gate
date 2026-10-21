/** Only an assertion in the exact owning test can kill a source mutation. */
export function assertNormalExit(result, label) {
  if (result.error || result.signal || !Number.isInteger(result.status)) {
    throw new Error(`${label}: process did not exit normally (${result.error?.message ?? result.signal ?? 'no exit status'})`);
  }
}

export function validateNamedRun(result, owner, shouldPass) {
  assertNormalExit(result, owner);
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    throw new Error(`${owner}: missing or invalid Playwright JSON report`);
  }
  if (!Array.isArray(report.errors) || report.errors.length) {
    throw new Error(`${owner}: runner errors cannot count as a mutation kill`);
  }
  const specs = [];
  function visit(suite) {
    specs.push(...(suite.specs ?? []));
    for (const child of suite.suites ?? []) visit(child);
  }
  for (const suite of report.suites ?? []) visit(suite);
  // Playwright's JSON locations are relative to testDir (e2e/).
  if (specs.length !== 1 || specs[0].title !== owner || specs[0].file !== 'claims.spec.ts') {
    throw new Error(`${owner}: expected exactly the named owning test`);
  }
  const tests = specs[0].tests ?? [];
  if (tests.length !== 1 || tests[0].expectedStatus !== 'passed' || tests[0].results?.length !== 1) {
    throw new Error(`${owner}: skipped, expected-failure, repeated, or retried tests are invalid`);
  }
  const observed = tests[0].results[0];
  const expectedStatus = shouldPass ? 'passed' : 'failed';
  if (observed.status !== expectedStatus || observed.retry !== 0 || result.status !== (shouldPass ? 0 : 1)) {
    throw new Error(`${owner}: expected ${expectedStatus}, observed ${observed.status}, exit ${result.status}`);
  }
  const errors = observed.errors ?? (observed.error ? [observed.error] : []);
  if (shouldPass) {
    if (errors.length) throw new Error(`${owner}: passing test reported errors`);
    return;
  }
  if (errors.length !== 1) throw new Error(`${owner}: expected exactly one owning assertion failure`);
  const failure = [observed.error?.message, observed.error?.stack, errors[0].message, errors[0].stack].filter(Boolean).join('\n');
  if (!/expect\(|AssertionError/.test(failure) || !/claims\.spec\.ts:\d+:\d+/.test(failure) ||
      /No tests found|browserType\.launch|browser has been closed|Target (?:page|browser|context).*closed|net::ERR_|Test timeout of|page\.goto:|locator\.(?:click|check|uncheck):|waiting for.*web server|at (?:setupExtensionBase|extendAndCheck|runProtocol)\b|page must raise no uncaught exceptions/i.test(failure)) {
    throw new Error(`${owner}: infrastructure, setup, runtime, or non-assertion failure cannot count as a mutation kill`);
  }
}
