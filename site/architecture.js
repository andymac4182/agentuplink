// Engine for the interactive explainer on /docs/architecture.
// It holds no content. Scenes, steps and part descriptions are generated into
// the page by build-architecture.cjs as ordinary lists; this script reads them
// and adds tabs, a stepper, packets and a detail panel. Without it the page
// keeps the static diagram and the full lists.
(() => {
  const root = document.querySelector('[data-ax]');
  if (!root) return;
  const RELAYS = ['a', 'b', 'c'];
  const PLAY_MS = 4500;
  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)');
  // Packets need offset-path on SVG; without it, or with reduced motion, a step
  // shows only its highlighted end state.
  const canTravel = () => !reduceMotion.matches && CSS.supports('offset-path', 'path("M0 0")');
  const el = (tag, props = {}, ...children) => {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children);
    return node;
  };
  const all = selector => [...root.querySelectorAll(selector)];
  const name = id => `Relay ${id.toUpperCase()}`;

  const scenes = all('[data-scene]').map(section => {
    const list = seq => {
      const ol = section.querySelector(`[data-seq="${seq}"]`);
      return ol ? [...ol.children] : null;
    };
    const altHeading = section.querySelector('[data-alt-label]');
    return {
      id: section.dataset.scene, section, tab: section.dataset.tab, ingress: section.dataset.ingress === '1',
      steps: { main: list('main'), alt: list('alt') },
      altLabel: altHeading && altHeading.dataset.altLabel, altBack: altHeading && altHeading.dataset.altBack,
    };
  });
  const state = { scene: scenes[0].id, seq: 'main', step: 1, in: 'a', own: 'b', playing: false };
  let timer = null;
  let selected = null;

  // ---- Controls -----------------------------------------------------------
  root.classList.add('ax-js');
  const stage = root.querySelector('.ax-stage');
  const figure = root.querySelector('.ax-figure');
  const tabs = el('div', { className: 'ax-tabs' });
  tabs.setAttribute('role', 'tablist');
  tabs.setAttribute('aria-label', 'Architecture scenes');
  for (const scene of scenes) {
    const tab = el('button', { type: 'button', className: 'ax-tab', id: `ax-tab-${scene.id}`, textContent: scene.tab });
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-controls', scene.section.id);
    tab.addEventListener('click', () => go({ scene: scene.id, seq: 'main', step: 1 }));
    scene.tabButton = tab;
    scene.section.setAttribute('role', 'tabpanel');
    scene.section.setAttribute('aria-labelledby', tab.id);
    tabs.append(tab);
  }
  tabs.addEventListener('keydown', event => {
    const index = scenes.findIndex(scene => scene.id === state.scene);
    const move = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
    if (!move) return;
    event.preventDefault();
    const next = scenes[(index + move + scenes.length) % scenes.length];
    go({ scene: next.id, seq: 'main', step: 1 });
    next.tabButton.focus();
  });

  const relaySelect = (label, key) => {
    const select = el('select');
    for (const id of RELAYS) select.append(el('option', { value: id, textContent: name(id) }));
    select.addEventListener('change', () => go({ [key]: select.value, step: Math.min(state.step, visibleSteps({ ...state, [key]: select.value }).length) }));
    return { select, field: el('label', { className: 'field' }, label, select) };
  };
  const enters = relaySelect('Request enters at', 'in');
  const owned = relaySelect('Device is owned by', 'own');
  const altButton = el('button', { type: 'button', className: 'ax-btn ax-btn-alt' });
  altButton.addEventListener('click', () => go({ seq: state.seq === 'alt' ? 'main' : 'alt', step: 1 }));
  const controls = el('div', { className: 'ax-controls' }, enters.field, owned.field, altButton);

  const prev = el('button', { type: 'button', className: 'ax-btn', textContent: 'Previous' });
  const play = el('button', { type: 'button', className: 'ax-btn', textContent: 'Play' });
  const next = el('button', { type: 'button', className: 'ax-btn', textContent: 'Next' });
  const count = el('p', { className: 'ax-count' });
  prev.addEventListener('click', () => { stop(); step(-1); });
  next.addEventListener('click', () => { stop(); step(1); });
  play.addEventListener('click', () => (state.playing ? stop() : start()));
  const transport = el('div', { className: 'ax-transport' }, prev, play, next, count);
  transport.setAttribute('role', 'group');
  transport.setAttribute('aria-label', 'Step through the scene');

  const captionTitle = el('strong');
  const captionText = el('p');
  const caption = el('div', { className: 'ax-caption' }, captionTitle, captionText);
  caption.setAttribute('role', 'status');
  caption.setAttribute('aria-live', 'polite');

  const panelBody = el('div');
  const panelClose = el('button', { type: 'button', className: 'ax-btn ax-panel-close', textContent: 'Close' });
  panelClose.setAttribute('aria-label', 'Close details');
  panelClose.addEventListener('click', () => closePanel(true));
  const panel = el('aside', { className: 'ax-panel', id: 'ax-panel', hidden: true }, panelClose, panelBody);
  panel.setAttribute('aria-label', 'Details of the selected part');
  panel.setAttribute('aria-live', 'polite');

  // Controls and the live caption sit above the diagram so both stay in view together.
  stage.prepend(tabs, controls, transport, caption);
  figure.append(panel);

  // Step lists become buttons; the caption carries the text of the current one.
  for (const scene of scenes) {
    for (const seq of ['main', 'alt']) {
      for (const item of scene.steps[seq] || []) {
        const title = item.querySelector('.ax-step-title');
        const button = el('button', { type: 'button', className: 'ax-step-btn', textContent: title.textContent.replace(/\.$/, '') });
        button.addEventListener('click', () => {
          stop();
          go({ scene: scene.id, seq, step: visibleSteps({ ...state, scene: scene.id, seq }).indexOf(item) + 1 });
        });
        title.replaceWith(button);
        item.button = button;
      }
    }
  }

  // Diagram parts become buttons that open the detail panel.
  for (const svg of all('.ax-svg')) svg.setAttribute('role', 'group');
  for (const part of all('.ax-svg [data-part]')) {
    part.setAttribute('tabindex', '0');
    part.setAttribute('role', 'button');
    part.setAttribute('aria-controls', 'ax-panel');
    part.setAttribute('aria-expanded', 'false');
    part.setAttribute('aria-label', `${part.dataset.name}. Show details`);
    part.addEventListener('click', () => openPanel(part));
    part.addEventListener('focus', () => openPanel(part));
    part.addEventListener('keydown', event => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      if (selected === part) closePanel(false); else openPanel(part);
    });
  }

  function openPanel(part) {
    const info = root.querySelector(`[data-part-info="${part.dataset.part}"]`);
    if (!info) return;
    if (selected) { selected.classList.remove('is-selected'); selected.setAttribute('aria-expanded', 'false'); }
    selected = part;
    part.classList.add('is-selected');
    part.setAttribute('aria-expanded', 'true');
    panelBody.replaceChildren(...[...info.children].map(child => child.cloneNode(true)));
    panel.hidden = false;
    // The panel sticks to the bottom of the viewport; keep the chosen part clear of it.
    const partBox = part.getBoundingClientRect();
    const panelBox = panel.getBoundingClientRect();
    const overlap = partBox.bottom - panelBox.top;
    if (overlap > 0 && partBox.top < panelBox.bottom) scrollBy({ top: overlap + 16, behavior: reduceMotion.matches ? 'auto' : 'smooth' });
  }
  function closePanel(refocus) {
    if (!selected) return;
    const part = selected;
    selected = null;
    part.classList.remove('is-selected');
    part.setAttribute('aria-expanded', 'false');
    panel.hidden = true;
    if (refocus) part.focus({ preventScroll: true });
    if (refocus) closePanel(false); // focusing reopens the panel; close it again
  }

  root.addEventListener('keydown', event => {
    if (event.key === 'Escape' && selected) { event.preventDefault(); closePanel(panel.contains(document.activeElement)); return; }
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
    if (event.target.closest('select, [role="tab"], summary')) return;
    event.preventDefault();
    stop();
    step(event.key === 'ArrowRight' ? 1 : -1);
  });

  // ---- State --------------------------------------------------------------
  const sceneOf = s => scenes.find(scene => scene.id === s.scene);
  function visibleSteps(s) {
    const forward = s.in !== s.own;
    return (sceneOf(s).steps[s.seq] || []).filter(item => !item.dataset.when || (item.dataset.when === 'forward') === forward);
  }
  function go(change) {
    Object.assign(state, change);
    if (!sceneOf(state).steps[state.seq]) state.seq = 'main';
    state.step = Math.max(1, Math.min(state.step, visibleSteps(state).length));
    if (change.scene || change.seq) stop();
    render();
    writeHash();
  }
  function step(delta) {
    const total = visibleSteps(state).length;
    const target = state.step + delta;
    if (target < 1 || target > total) { stop(); return; }
    go({ step: target });
  }
  function start() {
    if (state.step >= visibleSteps(state).length) go({ step: 1 });
    state.playing = true;
    timer = setInterval(() => step(1), PLAY_MS);
    renderTransport();
  }
  function stop() {
    if (!state.playing) return;
    state.playing = false;
    clearInterval(timer);
    renderTransport();
  }

  // ---- Rendering ----------------------------------------------------------
  function resolver() {
    const values = { in: state.in, own: state.own, new: RELAYS.find(id => id !== state.own) };
    const sub = text => (text || '').replace(/\$(in|own|new)/g, (_, key) => values[key]);
    const list = text => sub(text).split(' ').filter(Boolean);
    const link = token => {
      let reverse = token.endsWith('<');
      let id = reverse ? token.slice(0, -1) : token;
      if (id.startsWith('peer:')) {
        const [, from, to] = id.split(':');
        if (from === to) return null;
        if (from > to) reverse = !reverse;
        id = `peer-${[from, to].sort().join('-')}`;
      }
      return { id, reverse };
    };
    return { values, sub, list, link };
  }

  function render() {
    const scene = sceneOf(state);
    const steps = visibleSteps(state);
    const item = steps[state.step - 1];
    const data = item.dataset;
    const { values, sub, list, link } = resolver();

    for (const other of scenes) {
      const current = other === scene;
      other.section.hidden = !current;
      other.tabButton.setAttribute('aria-selected', String(current));
      other.tabButton.tabIndex = current ? 0 : -1;
      for (const seq of ['main', 'alt']) {
        for (const li of other.steps[seq] || []) {
          li.hidden = current && Boolean(li.dataset.when) && !visibleSteps({ ...state, seq }).includes(li);
          if (li === item) li.button.setAttribute('aria-current', 'step'); else li.button.removeAttribute('aria-current');
        }
      }
    }
    for (const span of all('[data-var]')) span.textContent = name(values[span.dataset.var]);

    enters.field.hidden = owned.field.hidden = !scene.ingress;
    enters.select.value = state.in;
    owned.select.value = state.own;
    altButton.hidden = !scene.steps.alt;
    altButton.textContent = state.seq === 'alt' ? scene.altBack : scene.altLabel;

    // Cluster state for this step.
    const owner = data.owner === 'none' ? null : sub(data.owner || '$own');
    const down = sub(data.down);
    const stale = sub(data.stale);
    const at = sub(data.at) || owner;
    const sockets = 'sockets' in data ? list(data.sockets) : ['ctl', 'data'];
    for (const id of RELAYS) {
      const entry = scene.ingress && id === state.in && id !== down;
      const roles = id === down ? ['stopped'] : id === stale ? ['stale owner', 'refused'] : [entry && 'entry', id === owner && 'owner'].filter(Boolean);
      for (const node of all(`[data-node="relay-${id}"]`)) {
        node.classList.toggle('is-owner', id === owner);
        node.classList.toggle('is-down', id === down);
        node.classList.toggle('is-stale', id === stale);
        node.querySelector('[data-role-line="1"]').textContent = roles[0] || '';
        node.querySelector('[data-role-line="2"]').textContent = roles[1] || '';
        node.setAttribute('aria-label', `${name(id)}${roles.length ? `, ${roles.join(', ')}` : ''}. Show details`);
      }
      for (const kind of ['ctl', 'data', 'cand']) {
        for (const socket of all(`[data-link="${kind}-${id}"]`)) {
          socket.classList.toggle('is-off', !(id === at && sockets.includes(kind)));
          socket.classList.toggle('is-promoted', kind === 'cand' && data.promoted === '1');
        }
      }
    }
    for (const node of all('[data-node="device"]')) node.classList.toggle('is-offline', sockets.length === 0);

    // Highlights and packets.
    const flow = list(data.flow).map(link).filter(Boolean);
    const activeLinks = new Set([...flow.map(hop => hop.id), ...list(data.links)]);
    const activeNodes = new Set(list(data.nodes));
    for (const node of all('[data-node]')) {
      node.classList.toggle('is-active', activeNodes.has(node.dataset.node));
      node.classList.toggle('is-dim', !activeNodes.has(node.dataset.node));
    }
    for (const line of all('[data-link]')) {
      line.classList.toggle('is-active', activeLinks.has(line.dataset.link));
      line.classList.toggle('is-dim', !activeLinks.has(line.dataset.link));
    }
    for (const svg of all('.ax-svg')) {
      const layer = svg.querySelector('.ax-packets');
      layer.replaceChildren();
      if (!canTravel()) continue;
      flow.forEach((hop, index) => {
        const path = svg.querySelector(`[data-link="${hop.id}"] .ax-link-line`);
        if (!path) return;
        const packet = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        packet.setAttribute('r', svg.dataset.packet);
        packet.setAttribute('class', `ax-packet${hop.reverse ? ' is-reverse' : ''}`);
        packet.style.offsetPath = `path("${path.getAttribute('d')}")`;
        packet.style.animationDelay = `${index * 0.9}s`;
        layer.append(packet);
      });
    }

    captionTitle.textContent = `${state.step}. ${item.button.textContent}`;
    captionText.replaceChildren(...[...item.querySelector('.ax-step-text').childNodes].map(node => node.cloneNode(true)));
    count.textContent = `Step ${state.step} of ${steps.length}`;
    prev.disabled = state.step === 1;
    next.disabled = state.step === steps.length;
    renderTransport();
  }
  function renderTransport() {
    play.textContent = state.playing ? 'Pause' : 'Play';
    play.setAttribute('aria-pressed', String(state.playing));
  }

  // ---- URL hash -----------------------------------------------------------
  function writeHash() {
    const params = new URLSearchParams({ scene: state.scene });
    if (state.seq === 'alt') params.set('seq', 'alt');
    params.set('step', String(state.step));
    if (sceneOf(state).ingress && (state.in !== 'a' || state.own !== 'b')) { params.set('in', state.in); params.set('own', state.own); }
    history.replaceState(null, '', `#${params}`);
  }
  function readHash() {
    const params = new URLSearchParams(location.hash.slice(1));
    if (!scenes.some(scene => scene.id === params.get('scene'))) return false;
    state.scene = params.get('scene');
    state.seq = params.get('seq') === 'alt' && sceneOf(state).steps.alt ? 'alt' : 'main';
    if (RELAYS.includes(params.get('in'))) state.in = params.get('in');
    if (RELAYS.includes(params.get('own'))) state.own = params.get('own');
    state.step = Math.max(1, Math.min(Number.parseInt(params.get('step'), 10) || 1, visibleSteps(state).length));
    return true;
  }
  addEventListener('hashchange', () => { if (readHash()) { stop(); render(); } });
  reduceMotion.addEventListener('change', render);
  readHash();
  render();
})();
