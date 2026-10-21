import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateNamedRun } from './mutation-report.mjs';

const owner = 'rendered chosen-message count';
function fixture(passing = false) {
  return {
    status: passing ? 0 : 1, signal: null,
    stdout: JSON.stringify({
      errors: [], suites: [{ suites: [{ specs: [{ title: owner, file: 'claims.spec.ts', tests: [{
        expectedStatus: 'passed', results: [{ status: passing ? 'passed' : 'failed', retry: 0,
          errors: passing ? [] : [{ message: 'Error: expect(received).toBe(expected)\nExpected: 1000\nReceived: 0', stack: 'at /repo/e2e/claims.spec.ts:510:20' }],
        }],
      }] }] }] }],
    }),
  };
}
function editReport(change) {
  const result = fixture();
  const report = JSON.parse(result.stdout);
  change(report, report.suites[0].suites[0].specs[0]);
  result.stdout = JSON.stringify(report);
  return result;
}

test('accepts a single ordinary assertion failure and its restored green run', () => {
  validateNamedRun(fixture(), owner, false);
  validateNamedRun(fixture(true), owner, true);
  const result = editReport((r, s) => {
    const observed = s.tests[0].results[0];
    observed.error = observed.errors[0];
    observed.errors = [{ message: 'formatted assertion details' }];
  });
  validateNamedRun(result, owner, false);
});
test('rejects missing tests and malformed reports', () => {
  assert.throws(() => validateNamedRun({ ...fixture(), stdout: 'No tests found' }, owner, false));
  assert.throws(() => validateNamedRun(editReport((r) => { r.suites = []; }), owner, false));
});
test('rejects signals, spawn errors, timeouts and inconsistent exits', () => {
  for (const patch of [{ status: null, signal: 'SIGTERM' }, { error: new Error('ETIMEDOUT') }, { status: 2 }, { status: 0 }]) {
    assert.throws(() => validateNamedRun({ ...fixture(), ...patch }, owner, false));
  }
  assert.throws(() => validateNamedRun(editReport((r, s) => { s.tests[0].results[0].status = 'timedOut'; }), owner, false));
});
test('rejects infrastructure and setup errors even inside a selected test', () => {
  for (const message of ['browserType.launch: Target page, context or browser has been closed',
    'Error: expect(received).toBe(expected) at setupExtensionBase (/repo/e2e/claims.spec.ts:480:3)',
    'Test timeout of 30000ms exceeded', 'locator.click: Timeout 30000ms exceeded',
    'Error: expect(errors).toEqual([]): page must raise no uncaught exceptions', 'net::ERR_CONNECTION_REFUSED']) {
    const result = editReport((r, s) => { s.tests[0].results[0].errors[0].message = message; });
    assert.throws(() => validateNamedRun(result, owner, false));
  }
});
test('rejects a different owner, multiple tests, retry, skip and expected failure', () => {
  for (const change of [
    (r, s) => { s.title = 'another test'; },
    (r, s) => { s.file = 'e2e/other.spec.ts'; },
    (r, s) => { s.tests.push(structuredClone(s.tests[0])); },
    (r, s) => { s.tests[0].results.push(structuredClone(s.tests[0].results[0])); },
    (r, s) => { s.tests[0].results[0].retry = 1; },
    (r, s) => { s.tests[0].results[0].status = 'skipped'; },
    (r, s) => { s.tests[0].expectedStatus = 'failed'; },
    (r, s) => { r.errors.push({ message: 'web server failed' }); },
  ]) assert.throws(() => validateNamedRun(editReport(change), owner, false));
});
test('rejects an unexpected green mutant and an assertion in a restored run', () => {
  assert.throws(() => validateNamedRun(fixture(true), owner, false));
  assert.throws(() => validateNamedRun(fixture(), owner, true));
});
