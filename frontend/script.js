// Main initialization function that runs when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', () => {
    // DOM element references for URL checking functionality
    const urlInput = document.getElementById('urlInput');
    const checkButton = document.getElementById('checkButton');
    const resultContainer = document.getElementById('resultContainer');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const errorContainer = document.getElementById('errorContainer');
    const statusIcon = document.getElementById('statusIcon');
    const resultTitle = document.getElementById('resultTitle');
    const resultDescription = document.getElementById('resultDescription');
    const scanTime = document.getElementById('scanTime');
    const reportButton = document.getElementById('reportButton');
    const historyContainer = document.getElementById('historyContainer');
    const historyList = document.getElementById('historyList');
    const clearHistoryButton = document.getElementById('clearHistory');
    const announcementBanner = document.getElementById('announcementBanner');
    const closeBannerButton = document.getElementById('closeBanner');
    const faqItems = document.querySelectorAll('.faq-item');
    const statsNumbers = document.querySelectorAll('.stat-number');

    // Statistics display elements
    const totalScansElement = document.getElementById('totalScans');
    const safeUrlsElement = document.getElementById('safeUrls');
    const phishingUrlsElement = document.getElementById('phishingUrls');

    // Screenshot and sharing functionality elements
    const shareResult = document.getElementById('shareResult');
    const screenshotOverlay = document.getElementById('screenshotOverlay');
    const closeScreenshot = document.getElementById('closeScreenshot');
    const downloadScreenshot = document.getElementById('downloadScreenshot');
    const shareScreenshot = document.getElementById('shareScreenshot');
    const resultScreenshot = document.getElementById('resultScreenshot');

    // API endpoints configuration
    const API_BASE_URL = 'https://backend-website-6rsa.onrender.com';
    const PREDICT_URL = `${API_BASE_URL}/predict_url`;
    const HISTORY_URL = `${API_BASE_URL}/history`;

    // Constants for application configuration
    const PHISHING_REPORT_URL = 'https://safebrowsing.google.com/safebrowsing/report_phish/';
    const LOCAL_STORAGE_KEYS = {
        ANNOUNCEMENT_CLOSED: 'phishShield_announcement_closed',
        STATS_VIEWED: 'phishShield_stats_viewed'
    };

    // Initialize Animate On Scroll library
    AOS.init({
        duration: 800,
        easing: 'ease-in-out',
        once: true
    });

    // Initialize particles.js for background animation
    particlesJS('particles-js', {
        particles: {
            number: { value: 80, density: { enable: true, value_area: 800 } },
            color: { value: '#4a6bff' },
            shape: { type: 'circle' },
            opacity: { value: 0.5, random: false },
            size: { value: 3, random: true },
            line_linked: { enable: true, distance: 150, color: '#4a6bff', opacity: 0.4, width: 1 },
            move: { enable: true, speed: 6, direction: 'none', random: false, straight: false, out_mode: 'out', bounce: false }
        },
        interactivity: {
            detect_on: 'canvas',
            events: {
                onhover: { enable: true, mode: 'grab' },
                onclick: { enable: true, mode: 'push' },
                resize: true
            }
        },
        retina_detect: true
    });

    // Statistics tracking object
    let statistics = {
        totalScans: 0,
        safeUrls: 0,
        phishingUrls: 0
    };

    // Session-specific history array
    let sessionHistory = [];

    // Event listeners for user interactions
    checkButton.addEventListener('click', checkUrl);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            checkUrl();
        }
    });

    reportButton.addEventListener('click', reportUrl);
    clearHistoryButton.addEventListener('click', clearHistory);
    closeBannerButton?.addEventListener('click', closeAnnouncement);

    // Initialize the page state
    initializePage();

    /**
     * Initializes the page state and loads initial data
     * @async
     */
    async function initializePage() {
        try {
            // Hide any loading indicators or errors on startup
            hideLoading();
            hideError();
            hideResult();
            
            // Load initial data in the background
            await Promise.all([
                loadHistory(),
                updateStatistics(),
                checkAnnouncementBanner()
            ]);
        } catch (error) {
            console.error('Error initializing page:', error);
        }
    }

    /**
     * Checks a URL for phishing using the API
     * @async
     */
    async function checkUrl() {
        const url = urlInput.value.trim();
        if (!url) {
            showError('Please enter a URL to check');
            return;
        }

        if (!isValidUrl(url)) {
            showError('Please enter a valid URL');
            return;
        }

        try {
            // Disable input and button while checking
            urlInput.disabled = true;
            checkButton.disabled = true;
            checkButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking...';
            
            // Show loading indicator
            showLoading();
            hideError();
            hideResult();

            const startTime = performance.now();
            
            // Make API request to check URL
            const response = await fetch(PREDICT_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Failed to check URL');
            }

            const data = await response.json();
            const endTime = performance.now();
            
            // Hide loading and display results
            hideLoading();
            displayResult(data, endTime - startTime);
            
            // Update history and statistics
            addToSessionHistory(url, data.isPhishing);
            await Promise.all([
                updateStatistics(data.isPhishing),
                loadHistory()
            ]);

        } catch (error) {
            hideLoading();
            showError(error.message || 'An error occurred while checking the URL');
            console.error('Error:', error);
        } finally {
            // Re-enable input and button
            urlInput.disabled = false;
            checkButton.disabled = false;
            checkButton.innerHTML = '<i class="fas fa-shield-alt"></i> Check URL';
        }
    }

    /**
     * Adds a URL check to the session history
     * @param {string} url - The URL that was checked
     * @param {boolean} isPhishing - Whether the URL was identified as phishing
     */
    function addToSessionHistory(url, isPhishing) {
        const timestamp = new Date().toISOString();
        const historyItem = {
            url,
            isPhishing,
            timestamp
        };
        
        // Add to beginning of array to show newest first
        sessionHistory.unshift(historyItem);
        
        // Keep only last 10 items
        if (sessionHistory.length > 10) {
            sessionHistory = sessionHistory.slice(0, 10);
        }
        
        // Update display
        displayHistory(sessionHistory);
    }

    /**
     * Loads and displays the scan history
     * @async
     */
    async function loadHistory() {
        try {
            displayHistory(sessionHistory);
        } catch (error) {
            console.error('Error loading history:', error);
        }
    }

    /**
     * Displays the scan history in the UI
     * @param {Array} history - Array of history items to display
     */
    function displayHistory(history) {
        if (history.length === 0) {
            historyContainer.classList.add('hidden');
            return;
        }

        historyList.innerHTML = '';
        history.forEach(item => {
            const historyItem = document.createElement('div');
            historyItem.className = 'history-item';
            historyItem.innerHTML = `
                <div class="url">${truncateUrl(item.url)}</div>
                <div class="status ${item.isPhishing ? 'phishing' : 'safe'}">
                    ${item.isPhishing ? 'Phishing' : 'Safe'}
                </div>
                <div class="time">${formatTime(item.timestamp)}</div>
            `;
            historyList.appendChild(historyItem);
        });

        historyContainer.classList.remove('hidden');
    }

    /**
     * Displays the URL check result
     * @param {Object} data - The result data from the API
     * @param {number} processingTime - Time taken to process the request
     */
    function displayResult(data, processingTime) {
        resultContainer.classList.remove('hidden');
        
        if (data.isPhishing) {
            statusIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
            statusIcon.style.color = 'var(--danger-color)';
            resultTitle.textContent = 'Phishing URL Detected!';
            resultDescription.textContent = 'This URL has been identified as a potential phishing attempt. Please exercise caution.';
        } else {
            statusIcon.innerHTML = '<i class="fas fa-shield-alt"></i>';
            statusIcon.style.color = 'var(--success-color)';
            resultTitle.textContent = 'Safe URL';
            resultDescription.textContent = 'This URL appears to be safe. However, always remain vigilant when browsing.';
        }

        scanTime.textContent = `Scan completed in ${(processingTime / 1000).toFixed(2)}s`;
    }

    /**
     * Shows the loading indicator
     */
    function showLoading() {
        loadingIndicator.classList.remove('hidden');
        loadingIndicator.innerHTML = `
            <div class="spinner"></div>
            <p>Analyzing URL...</p>
        `;
    }

    /**
     * Hides the loading indicator
     */
    function hideLoading() {
        loadingIndicator.classList.add('hidden');
        loadingIndicator.innerHTML = '';
    }

    /**
     * Shows the result container
     */
    function showResult() {
        resultContainer.classList.remove('hidden');
    }

    /**
     * Hides the result container
     */
    function hideResult() {
        resultContainer.classList.add('hidden');
    }

    /**
     * Shows an error message
     * @param {string} message - The error message to display
     * @param {string} type - The type of message ('error' or 'success')
     */
    function showError(message, type = 'error') {
        errorContainer.classList.remove('hidden');
        const errorMessage = document.querySelector('.error-message');
        errorMessage.textContent = message;
        
        // Update error message styling based on type
        if (type === 'success') {
            errorMessage.style.color = 'var(--success-color)';
            errorMessage.style.borderColor = 'var(--success-color)';
            errorMessage.style.backgroundColor = 'rgba(16, 185, 129, 0.1)';
        } else {
            errorMessage.style.color = 'var(--danger-color)';
            errorMessage.style.borderColor = 'var(--danger-color)';
            errorMessage.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
        }
        
        // Auto-hide success messages after 3 seconds
        if (type === 'success') {
            setTimeout(() => {
                hideError();
            }, 3000);
        }
    }

    /**
     * Hides the error message
     */
    function hideError() {
        errorContainer.classList.add('hidden');
    }

    /**
     * Updates the statistics display
     * @param {boolean} isPhishing - Whether the last check was a phishing URL
     */
    function updateStatistics(isPhishing) {
        statistics.totalScans++;
        if (isPhishing) {
            statistics.phishingUrls++;
        } else {
            statistics.safeUrls++;
        }
        
        totalScansElement.textContent = statistics.totalScans;
        safeUrlsElement.textContent = statistics.safeUrls;
        phishingUrlsElement.textContent = statistics.phishingUrls;
    }

    /**
     * Opens the Google Safe Browsing report page for the current URL
     */
    function reportUrl() {
        const url = urlInput.value.trim();
        if (url) {
            window.open(`https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`, '_blank');
        }
    }

    /**
     * Clears the scan history
     * @async
     */
    async function clearHistory() {
        try {
            sessionHistory = [];
            historyList.innerHTML = '';
            historyContainer.classList.add('hidden');
            showError('History cleared successfully', 'success');
        } catch (error) {
            console.error('Error clearing history:', error);
            showError('Failed to clear history');
        }
    }

    /**
     * Validates if a string is a valid URL
     * @param {string} string - The string to validate
     * @returns {boolean} - Whether the string is a valid URL
     */
    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    /**
     * Truncates a URL for display purposes
     * @param {string} url - The URL to truncate
     * @returns {string} - The truncated URL
     */
    function truncateUrl(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname + (urlObj.pathname.length > 1 ? urlObj.pathname : '');
        } catch (_) {
            return url;
        }
    }

    /**
     * Formats a timestamp for display
     * @param {string} timestamp - The timestamp to format
     * @returns {string} - The formatted time string
     */
    function formatTime(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    }

    /**
     * Closes the announcement banner and stores the state
     */
    function closeAnnouncement() {
        announcementBanner?.classList.add('hidden');
        localStorage.setItem(LOCAL_STORAGE_KEYS.ANNOUNCEMENT_CLOSED, 'true');
    }

    /**
     * Checks if the announcement banner should be shown
     */
    function checkAnnouncementBanner() {
        const isClosed = localStorage.getItem(LOCAL_STORAGE_KEYS.ANNOUNCEMENT_CLOSED);
        if (isClosed && announcementBanner) {
            announcementBanner.classList.add('hidden');
        }
    }

    /**
     * Initializes the statistics animation
     */
    function initializeStats() {
        const hasViewed = localStorage.getItem(LOCAL_STORAGE_KEYS.STATS_VIEWED);
        if (!hasViewed) {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        animateStats();
                        localStorage.setItem(LOCAL_STORAGE_KEYS.STATS_VIEWED, 'true');
                        observer.disconnect();
                    }
                });
            });

            statsNumbers.forEach(stat => observer.observe(stat));
        }
    }

    /**
     * Animates the statistics numbers
     */
    function animateStats() {
        statsNumbers.forEach(stat => {
            const target = parseInt(stat.getAttribute('data-target'));
            const duration = 2000;
            const step = target / (duration / 16);
            let current = 0;

            const updateNumber = () => {
                current += step;
                if (current < target) {
                    stat.textContent = Math.floor(current);
                    requestAnimationFrame(updateNumber);
                } else {
                    stat.textContent = target;
                }
            };

            updateNumber();
        });
    }

    // Initialize FAQ functionality
    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        const answer = item.querySelector('.faq-answer');
        
        question.addEventListener('click', () => {
            // Close other open FAQs
            faqItems.forEach(otherItem => {
                if (otherItem !== item && otherItem.classList.contains('active')) {
                    otherItem.classList.remove('active');
                    otherItem.querySelector('.faq-answer').style.maxHeight = '0px';
                }
            });
            
            // Toggle current FAQ
            item.classList.toggle('active');
            if (item.classList.contains('active')) {
                answer.style.maxHeight = answer.scrollHeight + 'px';
            } else {
                answer.style.maxHeight = '0px';
            }
        });
    });

    /**
     * Takes a screenshot of the result card
     * @async
     * @returns {string|null} - The screenshot data URL or null if failed
     */
    async function takeScreenshot() {
        try {
            const resultCard = document.querySelector('.result-card');
            const canvas = await html2canvas(resultCard, {
                scale: 1,
                backgroundColor: '#ffffff',
                logging: false,
                useCORS: true,
                allowTaint: true,
                imageTimeout: 0,
                removeContainer: true
            });
            return canvas.toDataURL('image/png', 1.0);
        } catch (error) {
            console.error('Error taking screenshot:', error);
            return null;
        }
    }

    // Share result button click handler
    shareResult.addEventListener('click', async () => {
        showLoading();
        const screenshotData = await takeScreenshot();
        hideLoading();
        
        if (screenshotData) {
            resultScreenshot.src = screenshotData;
            screenshotOverlay.style.display = 'flex';
        } else {
            showError('Failed to generate screenshot');
        }
    });

    // Close screenshot overlay
    closeScreenshot.addEventListener('click', () => {
        screenshotOverlay.style.display = 'none';
    });

    // Download screenshot
    downloadScreenshot.addEventListener('click', () => {
        const link = document.createElement('a');
        link.download = 'phishshield-result.png';
        link.href = resultScreenshot.src;
        link.click();
    });

    // Share screenshot using Web Share API
    shareScreenshot.addEventListener('click', async () => {
        try {
            const blob = await fetch(resultScreenshot.src).then(r => r.blob());
            const file = new File([blob], 'phishshield-result.png', { type: 'image/png' });
            
            if (navigator.share) {
                await navigator.share({
                    title: 'PhishShield Scan Result',
                    text: 'Check out this URL scan result from PhishShield!',
                    files: [file]
                });
            } else {
                // Fallback for browsers that don't support Web Share API
                const shareUrl = URL.createObjectURL(blob);
                const newWindow = window.open();
                newWindow.document.write(`
                    <html>
                        <body style="margin:0">
                            <img src="${shareUrl}" style="max-width:100%">
                            <div style="position:fixed;bottom:20px;right:20px">
                                <a download="phishshield-result.png" href="${shareUrl}">
                                    Download Image
                                </a>
                            </div>
                        </body>
                    </html>
                `);
            }
        } catch (error) {
            console.error('Error sharing screenshot:', error);
            showError('Failed to share screenshot');
        }
    });

    // Close screenshot overlay when clicking outside
    screenshotOverlay.addEventListener('click', (e) => {
        if (e.target === screenshotOverlay) {
            screenshotOverlay.style.display = 'none';
        }
    });

    // Add html2canvas script to the document
    const html2canvasScript = document.createElement('script');
    html2canvasScript.src = 'https://html2canvas.hertzen.com/dist/html2canvas.min.js';
    document.head.appendChild(html2canvasScript);

    // Testimonials rotation functionality
    const testimonials = document.querySelectorAll('.testimonial-card');
    let currentTestimonial = 0;

    /**
     * Rotates through testimonials on mobile devices
     */
    function rotateTestimonials() {
        testimonials.forEach((testimonial, index) => {
            if (window.innerWidth < 768) {  // Only rotate on mobile
                testimonial.style.display = index === currentTestimonial ? 'block' : 'none';
            } else {
                testimonial.style.display = 'block';
            }
        });
        currentTestimonial = (currentTestimonial + 1) % testimonials.length;
    }

    // Initialize testimonials rotation on mobile
    if (window.innerWidth < 768) {
        rotateTestimonials();
        setInterval(rotateTestimonials, 5000);  // Rotate every 5 seconds on mobile
    }

    // Blog card hover effects
    const blogCards = document.querySelectorAll('.blog-card');
    blogCards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.querySelector('.read-more').style.gap = '0.8rem';
        });
        
        card.addEventListener('mouseleave', () => {
            card.querySelector('.read-more').style.gap = '0.5rem';
        });
    });

    // Smooth scroll for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}); 
