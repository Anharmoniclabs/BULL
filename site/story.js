/* Story-first page. Third-party Python and the optional model connector load
   only after an explicit request. No policy decisions are fabricated here. */
const byId = (id) => document.getElementById(id);

async function showBuildEvidence() {
  try {
    const response = await fetch('./data/verification.json', { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    byId('build-sha').textContent = data.commit?.slice(0, 12) || 'Unknown';
    byId('pytest-status').textContent = data.pytest_summary || 'Not reported';
    byId('redteam-status').textContent = data.redteam_summary || 'Not reported';
    byId('formal-status').textContent = data.gates?.tla_model_check === true ? 'Passed modeled checks' : 'Not verified';
    byId('built-at').textContent = data.built_at || 'Not reported';
    byId('source-hashes').textContent = JSON.stringify(data.source_hashes || {}, null, 2);
  } catch (error) {
    for (const id of ['build-sha', 'pytest-status', 'redteam-status', 'formal-status', 'built-at']) {
      byId(id).textContent = 'Build evidence unavailable';
    }
    byId('source-hashes').textContent = error instanceof Error ? error.message : String(error);
  }
}

byId('load-demo').addEventListener('click', async () => {
  const button = byId('load-demo');
  button.disabled = true;
  button.textContent = 'Loading…';
  byId('runtime-state').textContent = 'Loading the demo…';
  byId('runtime-detail').textContent = 'Downloading the browser Python runtime from jsDelivr.';
  const banner = byId('runtime-banner');
  const observer = new MutationObserver(() => {
    if (banner.classList.contains('ready') || banner.classList.contains('error')) {
      button.textContent = banner.classList.contains('ready') ? 'Demo ready' : 'Reload to retry';
      observer.disconnect();
    }
  });
  observer.observe(banner, { attributes: true, attributeFilter: ['class'] });
  try {
    await new Promise((resolve, reject) => {
      const script = document.createElement('script');
      const timeout = setTimeout(() => reject(new Error('Demo download timed out. Reload to retry.')), 60000);
      script.src = 'https://cdn.jsdelivr.net/pyodide/v314.0.7/full/pyodide.js';
      script.onload = () => { clearTimeout(timeout); resolve(); };
      script.onerror = () => { clearTimeout(timeout); script.remove(); reject(new Error('Demo download failed. Reload to retry.')); };
      document.head.append(script);
    });
    await import('./app.js');
    await import('./model-connector.js');
  } catch (error) {
    observer.disconnect();
    banner.classList.add('error');
    byId('runtime-state').textContent = 'Demo unavailable';
    byId('runtime-detail').textContent = error instanceof Error ? error.message : String(error);
    byId('browser-status').textContent = 'Not available';
    button.textContent = 'Reload to retry';
    byId('evaluate-button').disabled = true;
    byId('reset-button').disabled = true;
  }
});
showBuildEvidence();
