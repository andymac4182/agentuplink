// Optional manual override for the colour theme. The automatic light/dark
// behaviour is pure CSS (see theme.css) and works without this file; this
// script only resolves a stored System / Light / Dark preference, mirrors the
// result on <html data-theme>, and adds the control to the header.
(() => {
  const media = matchMedia('(prefers-color-scheme: dark)');
  const colors = { light: '#f5f6f5', dark: '#141916' };
  let preference = 'system';
  try { preference = localStorage.getItem('agentuplink-theme') || 'system'; } catch {}
  if (!['system', 'light', 'dark'].includes(preference)) preference = 'system';
  function apply() {
    const theme = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
    document.documentElement.dataset.theme = theme;
    for (const meta of document.querySelectorAll('meta[name="theme-color"]')) meta.content = colors[theme];
  }
  apply();
  media.addEventListener('change', apply);
  document.addEventListener('DOMContentLoaded', () => {
    apply();
    const label = document.createElement('label');
    label.className = 'theme-control';
    label.textContent = 'Theme';
    const select = document.createElement('select');
    select.setAttribute('aria-label', 'Colour theme');
    for (const value of ['system', 'light', 'dark']) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = value[0].toUpperCase() + value.slice(1);
      select.append(option);
    }
    select.value = preference;
    select.addEventListener('change', () => {
      preference = select.value;
      try { localStorage.setItem('agentuplink-theme', preference); } catch {}
      apply();
    });
    label.append(select);
    document.querySelector('header').append(label);
  });
})();
