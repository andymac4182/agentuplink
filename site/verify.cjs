// Browser verification for the static site. Run from this directory:
//   node verify.cjs
// Needs Playwright (or playwright-core) resolvable by Node and a local Chrome.
// The local server sends the same response headers as vercel.json, including
// the Content-Security-Policy, so a CSP violation fails the run.
const assert = require('node:assert/strict');
const http = require('node:http');
const os = require('node:os');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = (() => { try { return require('playwright'); } catch { return require('playwright-core'); } })();

const TOKENS = { light: 'rgb(245, 246, 245)', dark: 'rgb(20, 25, 22)' };
const DOCS = ['', 'downloads', 'join', 'setup', 'architecture', 'mcp', 'acp', 'cua', 'filesystems', 'support'];
const shots = process.env.SITE_SHOTS || os.tmpdir();

(async () => {
  const root = __dirname;
  const headers = JSON.parse(await fs.readFile(path.join(root, 'vercel.json'), 'utf8')).headers[0].headers;
  const server = http.createServer(async (req, res) => {
    const route = new URL(req.url, 'http://localhost').pathname;
    const files = { '/': 'index.html', '/style.css': 'style.css', '/hero.jpg': 'hero.jpg', '/theme.css': 'theme.css', '/theme.js': 'theme.js', '/brand-lab': 'brand-lab.html', '/brand-lab.css': 'brand-lab.css', '/brand-lab.js': 'brand-lab.js', '/logo-board.png': 'logo-board.png' };
    files['/docs.css'] = 'docs.css';
    files['/releases.js'] = 'releases.js';
    files['/architecture.css'] = 'architecture.css';
    files['/architecture.js'] = 'architecture.js';
    const doc = route.match(/^\/docs(?:\/(index|downloads|join|setup|architecture|mcp|acp|cua|filesystems|support))?\/?$/);
    if (doc) files[route] = `docs/${doc[1] || 'index'}.html`;
    if (!files[route]) { res.writeHead(404).end(); return; }
    for (const { key, value } of headers) res.setHeader(key, value);
    res.setHeader('Content-Type', route.endsWith('.css') ? 'text/css' : route.endsWith('.js') ? 'text/javascript' : route.endsWith('.jpg') ? 'image/jpeg' : route.endsWith('.png') ? 'image/png' : 'text/html');
    res.end(await fs.readFile(path.join(root, files[route])));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = process.env.SITE_URL || `http://127.0.0.1:${server.address().port}`;
  const url = route => new URL(route, base).href;
  let browser;

  // A page whose console errors, CSP violations, script errors and failed
  // responses are all collected, so each check can assert there were none.
  async function open(options) {
    const context = await browser.newContext(options);
    // The release lookup is the site's only cross-origin request; keep local runs hermetic.
    if (!process.env.SITE_URL) await context.route('https://api.github.com/**', route => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
    const page = await context.newPage();
    const failures = [];
    page.on('pageerror', error => failures.push(`pageerror: ${error.message}`));
    page.on('console', message => { if (message.type() === 'error') failures.push(`console: ${message.text()}`); });
    page.on('response', response => { if (response.status() >= 400) failures.push(`${response.status()} ${response.url()}`); });
    return { context, page, failures };
  }
  const background = page => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const fits = page => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);

  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });

    // 1. Existing site walk: home, brand lab, every docs page, manual theme control.
    for (const [width, height] of [[1440, 1000], [1920, 1080], [768, 1024], [390, 844], [320, 740]]) {
      const { context, page, failures } = await open({ viewport: { width, height } });
      await page.goto(base, { waitUntil: 'networkidle' });
      assert.equal(await page.locator('h1').innerText(), 'Agent Uplink');
      for (const theme of ['dark', 'light']) {
        await page.getByLabel('Colour theme').selectOption(theme);
        assert.equal(await page.locator('html').getAttribute('data-theme'), theme);
        assert.equal(await background(page), TOKENS[theme]);
        await page.reload();
        assert.equal(await page.locator('html').getAttribute('data-theme'), theme);
      }
      await page.getByLabel('Colour theme').selectOption('system');
      await page.emulateMedia({ colorScheme: 'dark' });
      await page.waitForFunction(() => document.documentElement.dataset.theme === 'dark');
      assert(await fits(page), `home overflows at ${width}`);
      assert(await page.evaluate(() => [...document.querySelectorAll('a[href^="#"]')].every(a => a.hash === '' || a.hash === '#' || document.getElementById(a.hash.slice(1)))));
      assert(await page.evaluate(async () => { const image = new Image(); image.src = '/hero.jpg'; await image.decode(); return image.naturalWidth > 1000; }));
      assert.equal(await page.locator('.site-nav a[href="/docs/architecture"]').count(), 1);
      assert.equal(await page.locator('.teaser a[href="/docs/architecture"]').count(), 1);
      await page.screenshot({ path: path.join(shots, `agentuplink-dark-${width}.png`), fullPage: true });
      await page.emulateMedia({ colorScheme: 'light' });
      await page.waitForFunction(() => document.documentElement.dataset.theme === 'light');
      await page.screenshot({ path: path.join(shots, `agentuplink-${width}.png`), fullPage: true });
      await page.emulateMedia({ colorScheme: 'dark' });
      await page.locator('.button').click();
      await page.waitForURL('**/docs/setup');
      await page.goto(url('/brand-lab'), { waitUntil: 'networkidle' });
      assert.equal(await page.locator('.option').count(), 20);
      assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
      assert(await fits(page), `brand lab overflows at ${width}`);
      await page.screenshot({ path: path.join(shots, `agentuplink-brand-dark-${width}.png`), fullPage: true });
      await page.getByLabel('Colour theme').selectOption('light');
      assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
      for (const slug of DOCS) {
        const response = await page.goto(url(`/docs/${slug}`), { waitUntil: 'networkidle' });
        assert.equal(response.status(), 200);
        assert.equal(await page.locator('h1').count(), 1);
        assert.equal(await page.locator('[aria-current="page"]').count(), 1);
        assert(await fits(page), `/docs/${slug} overflows at ${width}`);
        for (const mode of ['dark', 'light']) {
          await page.getByLabel('Colour theme').selectOption(mode);
          assert.equal(await page.locator('html').getAttribute('data-theme'), mode);
          assert.equal(await background(page), TOKENS[mode]);
        }
        const links = await page.locator('a[href^="/"]').evaluateAll(elements => [...new Set(elements.map(a => a.href))]);
        for (const link of links) assert.equal((await page.request.get(link)).status(), 200, link);
        if (slug === 'setup') await page.screenshot({ path: path.join(shots, `agentuplink-docs-${width}.png`), fullPage: true });
      }
      assert.deepEqual(failures, []);
      console.log(`PASS ${width}x${height}: homepage, brand lab, 10 docs pages, links, themes, images, layout, console, CSP`);
      await context.close();
    }

    // 2. Automatic theme: no stored preference, with and without JavaScript.
    for (const javaScriptEnabled of [true, false]) {
      for (const route of ['/', '/docs/', '/docs/architecture', '/brand-lab']) {
        const { context, page, failures } = await open({ viewport: { width: 1280, height: 900 }, colorScheme: 'light', javaScriptEnabled });
        await page.goto(url(route), { waitUntil: 'networkidle' });
        assert.equal(await background(page), TOKENS.light, `${route} light`);
        await page.emulateMedia({ colorScheme: 'dark' });
        await page.waitForFunction(expected => getComputedStyle(document.body).backgroundColor === expected, TOKENS.dark).catch(() => {});
        assert.equal(await background(page), TOKENS.dark, `${route} dark`);
        assert.equal(await page.locator('html').getAttribute('data-theme'), javaScriptEnabled ? 'dark' : null);
        if (javaScriptEnabled) assert.equal(await page.getByLabel('Colour theme').inputValue(), 'system');
        else assert.equal(await page.getByLabel('Colour theme').count(), 0);
        assert.deepEqual(failures, []);
        await context.close();
      }
      console.log(`PASS automatic theme, JavaScript ${javaScriptEnabled ? 'on' : 'off'}: light and dark follow the emulated OS on 4 pages`);
    }

    // 3. Architecture explainer.
    for (const [width, height] of [[1440, 1000], [768, 1024], [390, 844], [320, 740]]) {
      for (const colorScheme of ['light', 'dark']) {
        const { context, page, failures } = await open({ viewport: { width, height }, colorScheme });
        await page.goto(url('/docs/architecture'), { waitUntil: 'networkidle' });
        const diagram = page.locator('.ax-svg:visible');
        assert.equal(await diagram.count(), 1, 'exactly one diagram layout is shown');
        const node = id => diagram.locator(`[data-node="${id}"]`);
        const count = () => page.locator('.ax-count').innerText();
        const caption = () => page.locator('.ax-caption').innerText();

        // Scenes
        const tabs = page.getByRole('tab');
        assert.equal(await tabs.count(), 3);
        for (const [index, id] of ['cluster', 'daemon', 'agent'].entries()) {
          await tabs.nth(index).click();
          assert.equal(await tabs.nth(index).getAttribute('aria-selected'), 'true');
          assert.equal(await page.locator('.ax-scene:visible').getAttribute('data-scene'), id);
          assert(page.url().includes(`scene=${id}`));
          assert(await fits(page), `architecture ${id} overflows at ${width}`);
        }

        // Every step of every scene: the accent stroke marks exactly the parts
        // involved in the step, and the diagram does not move between steps.
        const accentReport = () => diagram.evaluate(svg => {
          const probe = document.createElement('span');
          probe.style.color = 'var(--dg-active)';
          svg.parentNode.append(probe);
          const accent = getComputedStyle(probe).color;
          probe.remove();
          const parts = [...svg.querySelectorAll('[data-node], [data-link]:not(.is-off)')];
          const id = part => part.dataset.node || part.dataset.link;
          const stroke = part => getComputedStyle(part.querySelector('rect, .ax-link-line')).stroke;
          return {
            accent: parts.filter(part => stroke(part) === accent).map(id).sort(),
            active: parts.filter(part => part.classList.contains('is-active')).map(id).sort(),
            top: Math.round(svg.getBoundingClientRect().top + scrollY),
            captionAbove: document.querySelector('.ax-caption').getBoundingClientRect().bottom <= svg.getBoundingClientRect().top,
          };
        });
        for (const index of [0, 1, 2]) {
          await tabs.nth(index).click();
          const tops = new Set();
          let checked = 0;
          for (const seq of ['main', 'alt']) {
            const buttons = page.locator(`.ax-scene:visible [data-seq="${seq}"] li:not([hidden]) .ax-step-btn`);
            for (let i = 0; i < await buttons.count(); i++) {
              await buttons.nth(i).click();
              const report = await accentReport();
              assert(report.active.length > 0, 'a step highlights something');
              assert.deepEqual(report.accent, report.active, `accent stroke differs from the active set at scene ${index + 1} ${seq} step ${i + 1}`);
              assert(report.captionAbove, 'caption sits above the diagram');
              tops.add(report.top);
              checked++;
            }
          }
          assert(checked >= 9);
          assert.equal(tops.size, 1, `diagram moved between steps of scene ${index + 1} at ${width}: ${[...tops]}`);
        }

        // Stepping: buttons, arrow keys, the step list, and the live caption.
        await tabs.nth(0).click();
        assert.equal(await count(), 'Step 1 of 9');
        const first = await caption();
        await page.getByRole('button', { name: 'Next', exact: true }).click();
        assert.equal(await count(), 'Step 2 of 9');
        assert.notEqual(await caption(), first);
        assert(page.url().includes('step=2'));
        assert.equal(await node('redis').getAttribute('class').then(value => value.includes('is-active')), true);
        await page.keyboard.press('ArrowRight');
        assert.equal(await count(), 'Step 3 of 9');
        await page.keyboard.press('ArrowLeft');
        assert.equal(await count(), 'Step 2 of 9');
        await page.locator('.ax-scene:visible [data-seq="main"] .ax-step-btn').nth(5).click();
        assert.equal(await count(), 'Step 6 of 9');
        assert.equal(await page.locator('.ax-step-btn[aria-current="step"]').count(), 1);
        assert.equal(await page.locator('.ax-caption').getAttribute('aria-live'), 'polite');
        const play = page.getByRole('button', { name: 'Play', exact: true });
        await play.click();
        assert.equal(await page.getByRole('button', { name: 'Pause', exact: true }).getAttribute('aria-pressed'), 'true');
        await page.getByRole('button', { name: 'Pause', exact: true }).click();

        // Scene 1: choose the entry and owner relays, then stop the owner.
        await page.getByLabel('Request enters at').selectOption('c');
        await page.getByLabel('Device is owned by').selectOption('a');
        assert.equal(await node('relay-c').locator('[data-role-line="1"]').textContent(), 'entry');
        assert.equal(await node('relay-a').locator('[data-role-line="1"]').textContent(), 'owner');
        assert(page.url().includes('in=c') && page.url().includes('own=a'));
        assert.equal(await diagram.locator('[data-link="data-a"]:not(.is-off)').count(), 1);
        assert.equal(await diagram.locator('[data-link="data-b"]:not(.is-off)').count(), 0);
        await page.getByLabel('Request enters at').selectOption('a');
        assert.equal(await node('relay-a').locator('[data-role-line="2"]').textContent(), 'owner');
        assert.equal(await count(), 'Step 6 of 9');
        await page.getByRole('button', { name: 'Stop the owning relay' }).click();
        assert((await node('relay-a').getAttribute('class')).includes('is-down'));
        assert.equal(await count(), 'Step 1 of 7');
        for (let i = 0; i < 4; i++) await page.keyboard.press('ArrowRight');
        assert((await node('relay-b').getAttribute('class')).includes('is-owner'), 'another relay becomes owner');
        await page.keyboard.press('ArrowRight');
        assert((await node('relay-a').getAttribute('class')).includes('is-stale'));
        await page.getByRole('button', { name: 'Restore the cluster' }).click();
        assert.equal(await count(), 'Step 1 of 9');

        // Scene 2: rotation goes two sockets, three, then two again.
        await tabs.nth(1).click();
        assert.equal(await page.getByLabel('Request enters at').isVisible(), false, 'relay choice is hidden outside the routing scenes');
        const sockets = () => diagram.locator('.ax-k-ctl:not(.is-off), .ax-k-data:not(.is-off), .ax-k-cand:not(.is-off)').count();
        await page.locator('.ax-scene:visible [data-seq="main"] .ax-step-btn').nth(4).click();
        assert.equal(await sockets(), 2);
        await page.getByRole('button', { name: 'Rotate now' }).click();
        assert.equal(await sockets(), 3);
        await page.locator('.ax-scene:visible [data-seq="alt"] .ax-step-btn').last().click();
        assert.equal(await sockets(), 2);
        assert(page.url().includes('seq=alt'));

        // Detail panel by keyboard: focus opens, Escape closes, Enter toggles.
        const panel = page.locator('.ax-panel');
        await node('redis').focus();
        await panel.waitFor({ state: 'visible' });
        assert((await panel.innerText()).includes('single authoritative store'));
        assert.equal(await node('redis').getAttribute('aria-expanded'), 'true');
        await page.keyboard.press('Escape');
        await panel.waitFor({ state: 'hidden' });
        assert.equal(await node('redis').getAttribute('aria-expanded'), 'false');
        await page.keyboard.press('Enter');
        await panel.waitFor({ state: 'visible' });
        await page.keyboard.press('Space');
        await panel.waitFor({ state: 'hidden' });
        const link = diagram.locator('[data-link="peer-a-b"]');
        await link.focus();
        assert((await panel.innerText()).includes('Private peer link'));
        await page.getByRole('button', { name: 'Close details' }).click();
        await panel.waitFor({ state: 'hidden' });
        assert.equal(await diagram.locator('[data-part]:not([tabindex="0"])').count(), 0, 'every part is focusable');
        assert.equal(await diagram.locator('[data-part]:not([aria-label])').count(), 0, 'every part is labelled');

        // Real text no smaller than 12 CSS pixels once the diagram is scaled.
        const smallest = await diagram.evaluate(svg => {
          const scale = svg.getBoundingClientRect().width / svg.viewBox.baseVal.width;
          return Math.min(...[...svg.querySelectorAll('text')].map(text => Number.parseFloat(getComputedStyle(text).fontSize) * scale));
        });
        assert(smallest >= 12, `diagram text is ${smallest.toFixed(1)}px at ${width}`);
        assert(await fits(page), `architecture overflows at ${width}`);
        await page.screenshot({ path: path.join(shots, `agentuplink-architecture-${colorScheme}-${width}.png`), fullPage: true });

        // Deep link to a scene and step.
        await page.goto(url('/docs/architecture#scene=agent&step=3'), { waitUntil: 'networkidle' });
        await page.reload({ waitUntil: 'networkidle' });
        assert.equal(await tabs.nth(2).getAttribute('aria-selected'), 'true');
        assert.equal(await count(), 'Step 3 of 9');
        assert((await caption()).includes('Route to the owner'));
        assert((await diagram.locator('[data-link="peer-a-b"]').getAttribute('class')).includes('is-active'));
        assert.equal(await diagram.locator('.ax-packet').count(), 1);
        await page.evaluate(() => { location.hash = 'scene=daemon&seq=alt&step=2'; });
        await page.waitForFunction(() => document.querySelector('.ax-count').textContent === 'Step 2 of 6');
        assert.deepEqual(failures, []);
        await context.close();
      }
      console.log(`PASS architecture ${width}x${height}: scenes, stepping, relay choice, failure, rotation, panel keyboard, text size, hash, light and dark`);
    }

    // 4. Reduced motion: highlights without moving packets.
    {
      const { context, page, failures } = await open({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
      await page.goto(url('/docs/architecture#scene=agent&step=3'), { waitUntil: 'networkidle' });
      assert((await page.locator('.ax-svg:visible [data-link="peer-a-b"]').getAttribute('class')).includes('is-active'));
      assert.equal(await page.locator('.ax-packet').count(), 0);
      assert.deepEqual(failures, []);
      await context.close();
      console.log('PASS reduced motion: highlighted end state, no packets');
    }

    // 5. No JavaScript: static diagram and every step of every scene as plain lists.
    for (const width of [1440, 390, 320]) {
      const { context, page, failures } = await open({ viewport: { width, height: 900 }, javaScriptEnabled: false });
      await page.goto(url('/docs/architecture'), { waitUntil: 'networkidle' });
      assert.equal(await page.locator('.ax-svg:visible').count(), 1);
      assert.equal(await page.locator('.ax-tabs, .ax-transport, .ax-panel, [role="tab"]').count(), 0);
      assert.equal(await page.locator('.ax-scene:visible').count(), 3);
      assert.equal(await page.locator('ol.ax-steps:visible').count(), 5);
      const steps = await page.locator('ol.ax-steps > li').count();
      assert.equal(steps, 40);
      assert.equal(await page.locator('ol.ax-steps > li:visible .ax-step-text:visible').count(), steps);
      assert.equal(await page.locator('.ax-parts [data-part-info]').count(), 15);
      assert.equal(await page.locator('.ax-svg:visible [data-link]:not(.is-off)').count(), 14);
      assert(await fits(page), `no-JS architecture overflows at ${width}`);
      assert.deepEqual(failures, []);
      if (width === 1440) await page.screenshot({ path: path.join(shots, 'agentuplink-architecture-nojs.png'), fullPage: true });
      await context.close();
    }
    console.log('PASS no JavaScript: static diagram, 3 scenes, 40 steps and 15 part descriptions visible as plain content');
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
