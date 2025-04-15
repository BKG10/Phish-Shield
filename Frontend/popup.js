/**
// =================================================================
// PhishShield Browser Extension - Popup Script
// This script handles the extension's popup UI, displaying the current URL's
// phishing status and scan history.
// =================================================================

// Wait for the DOM to be fully loaded before initializing
document.addEventListener("DOMContentLoaded", function () {
  // Get references to key UI elements
  const resultDiv = document.getElementById("result");
  const loadingDiv = document.getElementById("loading");
  const historyDiv = document.getElementById("history");

  // Show loading indicator while we fetch the current URL's status
  loadingDiv.style.display = "block";

  // Request the current URL's phishing status from the background script
  chrome.runtime.sendMessage({ action: "getCurrentStatus" }, (response) => {
    // Hide loading indicator
    loadingDiv.style.display = "none";
    
    // Handle error cases
    if (response?.error) {
      resultDiv.innerHTML = `
        <div class="error">
          ❌ Error checking URL<br>
          <small>${response.error}</small>
        </div>
      `;
      return;
    }

    // Determine the verdict text and CSS class based on phishing status
    const verdict = response.isPhishing ? "❌ Phishing" : "✅ Safe";
    const verdictClass = response.isPhishing ? "phishing" : "safe";

    // Display the verdict and URL
    resultDiv.innerHTML = `
      <div class="${verdictClass}">
        <strong>${verdict}</strong><br>
        <small>${response.url}</small>
      </div>
    `;
  });

  /**
   * Load and display the scan history from local storage
   * Each history entry shows the URL, verdict, timestamp, and a report button
   */
  function loadHistory() {
    chrome.runtime.sendMessage({ action: "getHistory" }, (history) => {
      // Clear existing history display
      historyDiv.innerHTML = "";

      // Create and append history entries
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

  // Load history when popup opens
  loadHistory();

  // Refresh history periodically to catch updates
  setInterval(loadHistory, 5000);
});
*/
