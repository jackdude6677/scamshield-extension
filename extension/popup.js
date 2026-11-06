document.addEventListener('DOMContentLoaded', function() {
  const input = document.getElementById('input');
  const btn = document.getElementById('analyzeBtn');
  const resultDiv = document.getElementById('result');

  btn.addEventListener('click', function() {
    const text = input.value.trim();
    if (!text) {
      resultDiv.textContent = 'Please enter a message or link.';
      return;
    }
    // Simple heuristic: if contains "http" treat as URL, else plain text.
    const isUrl = /^https?:\/\//i.test(text);
    const payload = isUrl ? {url: text} : {text: text};
    fetch('http://localhost:5000/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    })
      .then(res => res.json())
      .then(data => {
        resultDiv.textContent = data.risk || 'No risk info';
      })
      .catch(err => {
        resultDiv.textContent = 'Error contacting server';
      });
  });

  // Keyboard accessibility: Enter on textarea triggers analysis
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      btn.click();
    }
  });
});
