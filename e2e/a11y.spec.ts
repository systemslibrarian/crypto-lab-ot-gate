import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on cryptographic correctness;
 * this gates them on accessibility the same way. Drives the Section B live OT
 * demo, the correctness check, and the DDH game so the dynamically injected
 * output regions are present, then scans the full page in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Kill transitions/animations/opacity fades: a mid-fade element produces
// phantom contrast failures that do not reflect the settled UI.
const NEUTRALIZE_MOTION = `
  *, *::before, *::after {
    transition: none !important;
    animation: none !important;
    opacity: 1 !important;
  }
`;

async function revealEverything(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Open any native <details> (this page has none today, but keep the gate
    // future-proof against added collapsibles).
    for (const d of document.querySelectorAll('details')) {
      (d as HTMLDetailsElement).open = true;
    }
    // Reveal any class-toggled / [hidden] panels so their contents are scanned.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
  });
  await page.addStyleTag({ content: NEUTRALIZE_MOTION });
}

// Drive the full Section B protocol so the injected sender/receiver output,
// channel messages, and the privacy-audit region all render, plus the
// Section C correctness check and DDH game.
async function runDemo(page: Page): Promise<void> {
  await page.locator('#btn-sender-init').click();
  const chooseBtn = page.locator('#btn-receiver-choose');
  await expect(chooseBtn).toBeEnabled();
  await chooseBtn.click();
  // The privacy-audit region un-hides once the receiver decrypts.
  await expect(page.locator('#privacy-audit')).toBeVisible();

  await page.locator('#btn-correctness').click();
  await expect(page.locator('#correctness-results .check-verdict')).toBeVisible();

  await page.locator('#btn-ddh').click();
  await expect(page.locator('#ddh-results .ddh-point').first()).toBeVisible();
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await runDemo(page);
  await revealEverything(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runDemo(page);
  await revealEverything(page);
  await scan(page);
});
