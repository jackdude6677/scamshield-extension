// Content script for ScamShield extension
// Listens for verdict messages and injects a warning overlay.

// Export an init function for testing / manual invocation.
function init() {
  if (typeof chrome === 'undefined' || !chrome.runtime) {
    // Not in Chrome extension context; expose for Node require.
    return;
  }
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'verdict') {
      showWarning(message);
    }
    // No async response needed.
    return false;
  });
}

function showWarning({ verdict, details }) {
  // Remove existing overlay if any.
  const existing = document.getElementById('scamshield-warning');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'scamshield-warning';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.style.position = 'fixed';
  overlay.style.top = '0';
  overlay.style.left = '0';
  overlay.style.width = '100%';
  overlay.style.height = '100%';
  overlay.style.backgroundColor = 'rgba(0,0,0,0.85)';
  overlay.style.color = '#fff';
  overlay.style.display = 'flex';
  overlay.style.flexDirection = 'column';
  overlay.style.justifyContent = 'center';
  overlay.style.alignItems = 'center';
  overlay.style.zIndex = '2147483647';
  overlay.style.fontSize = '1.5rem';
  overlay.style.textAlign = 'center';
  overlay.style.padding = '1rem';

  const title = document.createElement('h1');
  title.textContent = 'Warning: Potential Scam Detected';
  title.style.fontSize = '2rem';
  title.style.marginBottom = '0.5rem';
  overlay.appendChild(title);

  const msg = document.createElement('p');
  msg.textContent = `Verdict: ${verdict}`;
  overlay.appendChild(msg);

  if (details) {
    const det = document.createElement('p');
    det.textContent = details;
    overlay.appendChild(det);
  }

  const btnContainer = document.createElement('div');
  btnContainer.style.marginTop = '1rem';
  btnContainer.style.display = 'flex';
  btnContainer.style.gap = '1rem';

  const backBtn = document.createElement('button');
  backBtn.textContent = 'Go Back';
  backBtn.style.padding = '0.5rem 1rem';
  backBtn.style.fontSize = '1rem';
  backBtn.onclick = () => {
    window.history.back();
  };

  const whyBtn = document.createElement('button');
  whyBtn.textContent = 'Why?';
  whyBtn.style.padding = '0.5rem 1rem';
  whyBtn.style.fontSize = '1rem';
  whyBtn.onclick = () => {
    alert(details || 'No additional information.');
  };

  const continueBtn = document.createElement('button');
  continueBtn.textContent = 'Continue Anyway';
  continueBtn.style.padding = '0.5rem 1rem';
  continueBtn.style.fontSize = '1rem';
  continueBtn.onclick = () => {
    overlay.remove();
  };

  btnContainer.appendChild(backBtn);
  btnContainer.appendChild(whyBtn);
  btnContainer.appendChild(continueBtn);
  overlay.appendChild(btnContainer);

  document.body.appendChild(overlay);
}

// Auto‑init when script runs in extension context.
if (typeof chrome !== 'undefined' && chrome.runtime) {
  init();
}

module.exports = { init, showWarning };
