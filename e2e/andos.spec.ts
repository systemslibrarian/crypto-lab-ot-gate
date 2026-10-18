import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
test('ANDOS bridge runs actual OT for both choices in separate sessions',async({page})=>{
 await page.setViewportSize({width:390,height:850});await page.goto('./#andos');
 await page.locator('#andos-zero').click();await expect(page.locator('#andos-result')).toContainText('North archive: fictional access phrase CEDAR-17');await expect(page.locator('#andos-result')).toContainText('authentication rejected');
 await expect(page.locator('#andos-one')).toBeDisabled();await page.locator('#andos-reset').click();await page.locator('#andos-one').click();
 await expect(page.locator('#andos-result')).toContainText('South archive: fictional access phrase AMBER-42');await expect(page.locator('#andos-result')).toContainText('authentication rejected');
 await expect(page.locator('#andos-transcript')).toContainText('senderPublicPoint');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 expect((await new AxeBuilder({page}).include('#andos').withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa']).analyze()).violations).toEqual([]);
});
