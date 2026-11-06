// background.js
// Listens for messages from content scripts and forwards URL checks to the backend proxy.

chrome.runtime.onInstalled.addListener(() => {
  console.log('ScamShield background service worker installed');
});

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'checkUrl' && request.url) {
    // Forward to backend server (assumed running on localhost:8000)
    fetch('http://localhost:8000/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: request.url })
    })
      .then(res => res.json())
      .then(data => sendResponse({ result: data }))
      .catch(err => sendResponse({ error: err.message }));
    // Return true to indicate async response
    return true;
  }
  // Unknown message
  return false;
});
