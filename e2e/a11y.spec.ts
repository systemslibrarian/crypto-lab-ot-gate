import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The OT protocol is walked in order, both receiver choices exercised, and the
 * DDH game played, with every resulting rendering scanned in both themes at
 * desktop and phone width. See `gate.ts` for why nothing is injected into the
 * page, why each scan asserts its content first, and why `violations` is not
 * the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(600_000);
    await boot(page, theme);
    await driveAllStates(page, theme, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(600_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`, theme);
    expectBaselineNotStale();
  });
}
