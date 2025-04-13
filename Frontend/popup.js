document.addEventListener("DOMContentLoaded", function () {
  const resultDiv = document.getElementById("result");
  const loadingDiv = document.getElementById("loading");
  const historyDiv = document.getElementById("history");

  // Show loading state
  loadingDiv.style.display = "block";

  // Get current status from background script
  chrome.runtime.sendMessage({ action: "getCurrentStatus" }, (response) => {
    loadingDiv.style.display = "none";
    
    if (response?.error) {
      resultDiv.innerHTML = `
        <div class="error">
          ❌ Error checking URL<br>
          <small>${response.error}</small>
        </div>
      `;
      return;
    }

    const verdict = response.isPhishing ? "❌ Phishing" : "✅ Safe";
    const verdictClass = response.isPhishing ? "phishing" : "safe";

    resultDiv.innerHTML = `
      <div class="${verdictClass}">
        <strong>${verdict}</strong><br>
        <small>${response.url}</small>
      </div>
    `;
  });

  // Load scan history
  function loadHistory() {
    chrome.runtime.sendMessage({ action: "getHistory" }, (history) => {
      historyDiv.innerHTML = "";
      history.forEach((entry) => {
        const el = document.createElement("div");
        el.className = `history-entry ${entry.isPhishing ? 'phishing' : 'safe'}`;
        el.innerHTML = `
          <div>
            <strong>${entry.isPhishing ? '❌ Phishing' : '✅ Safe'}</strong>
            <a href="https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(entry.url)}" 
               target="_blank" 
               class="report-link">Report</a>
          </div>
          <div class="url">${entry.url}</div>
          <div class="time">Scanned at: ${entry.timestamp}</div>
        `;
        historyDiv.appendChild(el);
      });
    });
  }

  // Initial history load
  loadHistory();

  // Refresh history every 5 seconds
  setInterval(loadHistory, 5000);
});
