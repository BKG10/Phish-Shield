// =================================================================
// PhishShield Browser Extension - Background Script
// This script runs in the background and handles URL scanning, user notifications,
// and communication between the extension's components.
// =================================================================

// Global state management
const tabStates = new Map(); // Tracks each tab's state: { tabId: { domain: string, previousUrl: string } }
const MAX_HISTORY_ITEMS = 10; // Maximum number of scan history items to keep in storage

/**
 * Extract the domain name from a URL
 * @param {string} url - The URL to process
 * @returns {string} The domain name or the original URL if parsing fails
 */
function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return url;
  }
}

/**
 * Save a scan result to the browser's local storage
 * Maintains a history of the last MAX_HISTORY_ITEMS scans
 * @param {Object} result - The scan result containing url and phishing status
 */
function storeScanHistory(result) {
  chrome.storage.local.get(["scanHistory"], (res) => {
    const history = res.scanHistory || [];
    // Add new scan result at the beginning
    history.unshift({
      url: result.url,
      isPhishing: result.isPhishing,
      timestamp: new Date().toLocaleString(),
      reported: false
    });
    
    // Keep only the most recent items
    if (history.length > MAX_HISTORY_ITEMS) {
      history.pop();
    }
    
    // Update storage
    chrome.storage.local.set({ scanHistory: history });
  });
}

/**
 * Inject a popup notification into the webpage
 * Shows different popups for phishing warnings, safe sites, and same-page navigations
 * @param {number} tabId - The ID of the current tab
 * @param {string} url - The URL being checked
 * @param {boolean} isPhishing - Whether the URL was detected as phishing
 * @param {boolean} isSamePage - Whether this is a same-page navigation
 */
function injectPopup(tabId, url, isPhishing, isSamePage = false) {
  const hostname = new URL(url).hostname;
  
  if (isPhishing) {
    // Create warning popup for phishing sites
    const popupHTML = `
      <div id="phishing-warning-popup" style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: #ff4444;
        color: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        z-index: 999999;
        max-width: 400px;
        font-family: Arial, sans-serif;
      ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
          <div style="display: flex; align-items: center;">
            <span style="font-size: 24px; margin-right: 10px;">⚠️</span>
            <h3 style="margin: 0;">PHISHING WARNING!</h3>
          </div>
          <button id="close-popup-btn" style="
            background: none;
            border: none;
            color: white;
            font-size: 20px;
            cursor: pointer;
            padding: 0 5px;
          ">×</button>
        </div>
        <p style="margin: 10px 0;">The website "${hostname}" has been detected as a potential phishing site.</p>
        <div style="display: flex; gap: 10px; margin-top: 15px;">
          <button id="close-tab-btn" style="
            background: white;
            color: #ff4444;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
          ">Close Tab</button>
          <button id="report-btn" style="
            background: white;
            color: #ff4444;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
          ">Report</button>
        </div>
      </div>
    `;

    // Inject the warning popup and set up event handlers
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: (html) => {
        // Remove any existing popups
        const existingPopup = document.getElementById('phishing-warning-popup');
        if (existingPopup) existingPopup.remove();

        // Add new popup
        const popup = document.createElement('div');
        popup.innerHTML = html;
        document.body.appendChild(popup);

        // Set up button click handlers
        document.getElementById('close-popup-btn').addEventListener('click', () => {
          popup.remove();
        });

        document.getElementById('close-tab-btn').addEventListener('click', () => {
          window.close();
        });

        document.getElementById('report-btn').addEventListener('click', () => {
          window.open('https://safebrowsing.google.com/safebrowsing/report_phish/?url=' + encodeURIComponent(window.location.href), '_blank');
        });
      },
      args: [popupHTML]
    });
  } else if (isSamePage) {
    // Create indicator for same-page navigation
    const samePageHTML = `
      <div id="same-page-indicator" style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: #2196F3;
        color: white;
        padding: 8px 12px;
        border-radius: 4px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        z-index: 999999;
        font-family: Arial, sans-serif;
        display: flex;
        align-items: center;
        gap: 5px;
        animation: fadeOut 5s forwards;
      ">
        <span style="font-size: 16px;">🔄</span>
        <span style="font-size: 14px;">Same Website</span>
        <button id="close-samepage-btn" style="
          background: none;
          border: none;
          color: white;
          font-size: 16px;
          cursor: pointer;
          margin-left: 5px;
          padding: 0 5px;
        ">×</button>
      </div>
      <style>
        @keyframes fadeOut {
          0% { opacity: 1; }
          80% { opacity: 1; }
          100% { opacity: 0; }
        }
      </style>
    `;

    // Inject the same-page indicator and set up auto-removal
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: (html) => {
        // Remove any existing indicators
        const existingPopup = document.getElementById('phishing-warning-popup');
        const existingTick = document.getElementById('safe-url-indicator');
        const existingSamePage = document.getElementById('same-page-indicator');
        if (existingPopup) existingPopup.remove();
        if (existingTick) existingTick.remove();
        if (existingSamePage) existingSamePage.remove();

        // Add new indicator
        const indicator = document.createElement('div');
        indicator.innerHTML = html;
        document.body.appendChild(indicator);

        // Set up close button handler
        document.getElementById('close-samepage-btn').addEventListener('click', () => {
          indicator.remove();
        });

        // Auto-remove after animation completes
        setTimeout(() => {
          indicator.remove();
        }, 5000);
      },
      args: [samePageHTML]
    });
  } else {
    // Create indicator for safe URLs
    const tickHTML = `
      <div id="safe-url-indicator" style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4CAF50;
        color: white;
        padding: 8px 12px;
        border-radius: 4px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        z-index: 999999;
        font-family: Arial, sans-serif;
        display: flex;
        align-items: center;
        gap: 5px;
        animation: fadeOut 5s forwards;
      ">
        <span style="font-size: 16px;">✓</span>
        <span style="font-size: 14px;">Safe</span>
        <button id="report-safe-btn" style="
          background: none;
          border: none;
          color: white;
          font-size: 14px;
          cursor: pointer;
          margin-left: 5px;
          padding: 0 5px;
          text-decoration: underline;
        ">Report</button>
        <button id="close-tick-btn" style="
          background: none;
          border: none;
          color: white;
          font-size: 16px;
          cursor: pointer;
          margin-left: 5px;
          padding: 0 5px;
        ">×</button>
      </div>
      <style>
        @keyframes fadeOut {
          0% { opacity: 1; }
          80% { opacity: 1; }
          100% { opacity: 0; }
        }
      </style>
    `;

    // Inject the safe indicator and set up event handlers
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: (html) => {
        // Remove any existing indicators
        const existingPopup = document.getElementById('phishing-warning-popup');
        const existingTick = document.getElementById('safe-url-indicator');
        const existingSamePage = document.getElementById('same-page-indicator');
        if (existingPopup) existingPopup.remove();
        if (existingTick) existingTick.remove();
        if (existingSamePage) existingSamePage.remove();

        // Add new indicator
        const indicator = document.createElement('div');
        indicator.innerHTML = html;
        document.body.appendChild(indicator);

        // Set up button handlers
        document.getElementById('close-tick-btn').addEventListener('click', () => {
          indicator.remove();
        });

        document.getElementById('report-safe-btn').addEventListener('click', () => {
          window.open('https://safebrowsing.google.com/safebrowsing/report_phish/?url=' + encodeURIComponent(window.location.href), '_blank');
        });

        // Auto-remove after animation completes
        setTimeout(() => {
          indicator.remove();
        }, 5000);
      },
      args: [tickHTML]
    });
  }
}

/**
 * Check if a URL is potentially a phishing site
 * Makes an API call to the backend service for analysis
 * @param {string} url - The URL to check
 * @param {number} tabId - The ID of the current tab
 * @param {boolean} isReload - Whether this is a page reload
 */
async function checkForPhishing(url, tabId, isReload = false) {
  try {
    // Skip checking if URL is empty or about:blank
    if (!url || url === 'about:blank') {
      return;
    }

    // Get current domain and check if it's the same as previous
    const currentDomain = getDomain(url);
    const tabState = tabStates.get(tabId);
    
    if (tabState && currentDomain === tabState.domain && !isReload) {
      // Same domain, show same-page indicator
      injectPopup(tabId, url, false, true);
      return;
    }

    // Update tab state
    tabStates.set(tabId, {
      domain: currentDomain,
      previousUrl: url
    });

    // Call backend API for phishing check
    const response = await fetch('http://localhost:8000/predict_url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error('API request failed');
    }

    const result = await response.json();

    if (result.error) {
      console.error('Error checking URL:', result.error);
      return;
    }

    // Store result in history
    storeScanHistory({
      url: url,
      isPhishing: result.prediction === 0
    });

    // Show appropriate popup
    injectPopup(tabId, url, result.prediction === 0);

  } catch (error) {
    console.error('Error in checkForPhishing:', error);
  }
}

/**
 * Debounce function to limit the rate of API calls
 * @param {Function} func - The function to debounce
 * @param {number} wait - The debounce delay in milliseconds
 * @returns {Function} The debounced function
 */
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Set up event listeners for URL changes
const debouncedCheck = debounce(checkForPhishing, 1000);

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    debouncedCheck(tab.url, tabId);
  }
});

// Listen for tab activation
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);
  if (tab.url) {
    debouncedCheck(tab.url, tab.id);
  }
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getCurrentStatus") {
    // Return current tab's status
    chrome.tabs.query({active: true, currentWindow: true}, async (tabs) => {
      if (tabs[0]) {
        try {
          const response = await fetch('http://localhost:8000/predict_url', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: tabs[0].url })
          });
          
          if (!response.ok) {
            throw new Error('API request failed');
          }

          const result = await response.json();
          
          if (result.error) {
            sendResponse({ error: result.error });
          } else {
            sendResponse({
              url: tabs[0].url,
              isPhishing: result.prediction === 0
            });
          }
        } catch (error) {
          sendResponse({ error: error.message });
        }
      }
    });
    return true; // Keep the message channel open for async response
  }
  
  if (request.action === "getHistory") {
    // Return scan history
    chrome.storage.local.get(["scanHistory"], (result) => {
      sendResponse(result.scanHistory || []);
    });
    return true; // Keep the message channel open for async response
  }
});

// Clean up tab states every 30 minutes
setInterval(() => {
  tabStates.clear();
}, 30 * 60 * 1000);

// Log when the extension starts
console.log("Phishing Detector background script started"); 