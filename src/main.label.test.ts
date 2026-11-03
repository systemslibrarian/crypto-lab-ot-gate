import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

/**
 * `hexBlock` used to build its button's `aria-label` by stripping tags out of
 * the HTML label with `s.replace(/<[^>]*>/g, '')`. A single-pass tag strip is
 * an incomplete sanitizer whatever it is fed (CodeQL
 * `js/incomplete-multi-character-sanitization`), so the function is gone and a
 * marked-up label now has to bring its own plain text.
 *
 * Nothing in the type system can require that, so it is required here: every
 * `hexBlock(` call whose LABEL contains markup must also pass `ariaLabel`.
 * Restore a marked-up label without one and this reddens.
 */
function hexBlockCalls(source: string): string[] {
  const calls: string[] = [];
  for (let at = source.indexOf('hexBlock('); at !== -1; at = source.indexOf('hexBlock(', at + 1)) {
    // A declaration is not a call.
    if (/function\s+$/.test(source.slice(Math.max(0, at - 10), at))) continue;
    let depth = 0;
    for (let i = at + 'hexBlock'.length; i < source.length; i += 1) {
      if (source[i] === '(') depth += 1;
      else if (source[i] === ')') {
        depth -= 1;
        if (depth === 0) {
          calls.push(source.slice(at, i + 1));
          break;
        }
      }
    }
  }
  return calls;
}

/** The first argument, up to the comma that is not nested in any bracket. */
function labelArgument(call: string): string {
  const body = call.slice(call.indexOf('(') + 1);
  let depth = 0;
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if ('([{'.includes(ch)) depth += 1;
    else if (')]}'.includes(ch)) depth -= 1;
    else if (ch === ',' && depth === 0) return body.slice(0, i);
  }
  return body;
}

const source = readFileSync(fileURLToPath(new URL('./main.ts', import.meta.url)), 'utf8');

describe('hex block labels carry their own plain text', () => {
  it('finds every hexBlock call site', () => {
    // A scan that found nothing would pass the rule below over nothing.
    expect(hexBlockCalls(source).length).toBeGreaterThanOrEqual(8);
  });

  it('never asks a marked-up label to be turned into plain text at run time', () => {
    const unlabelled = hexBlockCalls(source).filter(
      (call) => labelArgument(call).includes('<') && !call.includes('ariaLabel:'),
    );
    expect(unlabelled, `these hexBlock labels carry markup and no ariaLabel:\n${unlabelled.join('\n')}`).toEqual([]);
  });

  it('catches a marked-up label that brings no plain text', () => {
    // The positive control: the rule above is only worth having if it fails.
    const offender = "hexBlock('E<sub>0</sub> (encrypted M<sub>0</sub>)', e0Hex, { display: d })";
    const calls = hexBlockCalls(offender);
    expect(calls).toHaveLength(1);
    expect(labelArgument(calls[0]).includes('<')).toBe(true);
    expect(calls[0].includes('ariaLabel:')).toBe(false);
  });

  it('no longer carries a tag-stripping sanitizer', () => {
    expect(source).not.toContain('replace(/<[^>]*>/g');
  });
});
