// The header dropdowns (public/js/menus.js): Docs and Rules open their panels on hover with a
// mouse, when held a moment with a finger (a tap follows the link, at any width), and with
// ArrowDown from the keyboard. A closed panel stays out of the tab order.
import { test, expect } from "@playwright/test";

const DOCS = "nav.main a[data-menu='docs']";
const RULES = "nav.main a[data-menu='rules']";

// A finger held on an element for `ms`, through the browser's own touch input.
async function hold(page, selector, ms = 600) {
  const box = await page.locator(selector).boundingBox();
  const point = { x: box.x + box.width / 2, y: box.y + box.height / 2 };
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [point] });
  await page.waitForTimeout(ms);
  await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  await cdp.detach();
}

test.describe("mouse", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("hovering opens a panel, the other item switches it, leaving both closes it", async ({ page }) => {
    await page.goto("/coverage/");
    await page.hover(DOCS);
    await expect(page.locator("#menu-docs")).toBeVisible();
    await expect(page.locator(DOCS)).toHaveAttribute("aria-expanded", "true");

    await page.hover(RULES);
    await expect(page.locator("#menu-rules")).toBeVisible();
    await expect(page.locator("#menu-docs")).toBeHidden();
    await expect(page.locator(DOCS)).toHaveAttribute("aria-expanded", "false");

    await page.hover("#menu-rules .menu-all");
    await page.waitForTimeout(400);
    await expect(page.locator("#menu-rules")).toBeVisible();

    await page.mouse.move(4, 790);
    await expect(page.locator("#menu-rules")).toBeHidden();
    await expect(page.locator(RULES)).toHaveAttribute("aria-expanded", "false");
  });

  test("a click on the item still follows its link", async ({ page }) => {
    await page.goto("/coverage/");
    await page.click(DOCS);
    await page.waitForURL("**/docs/");
  });
});

for (const width of [1280, 820, 390]) {
  test(`${width}px touch: a tap follows the link, holding the item opens its panel`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width, height: 800 }, hasTouch: true, isMobile: width < 900 });
    const page = await context.newPage();
    await page.goto("/coverage/");
    await page.evaluate(() => {
      window.longPressMenus = [];
      document.addEventListener("contextmenu", (e) => window.longPressMenus.push(e.defaultPrevented));
    });

    await hold(page, DOCS);
    await expect(page.locator("#menu-docs")).toBeVisible();
    await expect(page.locator(DOCS)).toHaveAttribute("aria-expanded", "true");
    await page.waitForTimeout(300);
    expect(new URL(page.url()).pathname, "the hold does not follow the link").toBe("/coverage/");
    expect(await page.evaluate(() => window.longPressMenus.every(Boolean)), "no long-press menu").toBe(true);
    const box = await page.locator("[data-menus]").boundingBox();
    expect(box.x, "the panel starts on screen").toBeGreaterThanOrEqual(0);
    expect(box.x + box.width, "the panel ends on screen").toBeLessThanOrEqual(width);

    // holding the other item switches panels
    await hold(page, RULES);
    await expect(page.locator("#menu-rules")).toBeVisible();
    await expect(page.locator("#menu-docs")).toBeHidden();

    // a tap elsewhere closes it
    await page.locator("footer.site .foot-note").tap();
    await expect(page.locator("#menu-rules")).toBeHidden();

    // the panel's links work (on a fresh page: the tap above scrolled the visual viewport away,
    // which throws later synthetic touches off target)
    await page.goto("/coverage/");
    await hold(page, DOCS);
    await page.locator("#menu-docs a[href$='/docs/cli/']").tap();
    await page.waitForURL("**/docs/cli/");

    // and a tap follows the item's link
    await page.tap(RULES);
    await page.waitForURL("**/rules/");
    await context.close();
  });
}

test("keyboard: ArrowDown opens the panel at its first link, Escape closes it", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/coverage/");
  await page.focus(DOCS);
  await page.keyboard.press("ArrowDown");
  await expect(page.locator("#menu-docs a").first()).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.locator("#menu-docs")).toBeHidden();
  await expect(page.locator(DOCS)).toBeFocused();
  // closed, the panel is out of the tab order
  await page.keyboard.press("Tab");
  await expect(page.locator(RULES)).toBeFocused();
});
