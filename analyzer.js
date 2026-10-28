// Grab the elements from the HTML
const urlInput = document.querySelector('.url-input');
const analyzeBtn = document.querySelector('.analyze-btn');


const searchContainer = document.querySelector('.search-bar-container');
const resultDiv = document.createElement('div');
resultDiv.id = 'analysis-results';
resultDiv.style.display = 'none'; 
resultDiv.style.marginTop = '30px';
resultDiv.style.textAlign = 'left';
resultDiv.style.maxWidth = '600px';
resultDiv.style.margin = '30px auto';
resultDiv.style.color = '#fff';
searchContainer.parentNode.insertBefore(resultDiv, searchContainer.nextSibling);

// The Core Analyzer Rules

function analyzeUrl(url) {
    let score = 0;
    let breakdown = [];
    
    // Rule 10: Empty or Invalid URL (5 Points) - We check this first to prevent errors
    let urlObj;
    try {
        // Adding http:// temporarily just to parse if the user forgot it, 
        // but for strict validation, we want them to enter a full URL.
        urlObj = new URL(url);
        score += 5;
        breakdown.push('✔ Valid URL format.');
    } catch (e) {
        return { error: 'Please enter a valid URL (e.g., https://example.com).' };
    }

    // Rule 1: HTTPS Check (20 Points)
    if (url.startsWith('https://')) {
        score += 20;
        breakdown.push('✔ HTTPS is enabled (data is encrypted).');
    } else {
        breakdown.push('❌ Missing HTTPS (data may not be secure).');
    }

    // Rule 2: URL Length Check (10 Points)
    if (url.length <= 75) {
        score += 10;
        breakdown.push('✔ URL length is normal.');
    } else {
        breakdown.push('❌ URL is longer than recommended (often used to hide suspicious paths).');
    }

    // Rule 3: IP Address Detection (15 Points)
    // Regex matches standard IPv4 formats
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
    if (!ipRegex.test(urlObj.hostname)) {
        score += 15;
        breakdown.push('✔ No IP address detected in the domain.');
    } else {
        breakdown.push('❌ Uses an IP address instead of a domain name.');
    }

    // Rule 4: '@' Symbol Detection (10 Points)
    if (!url.includes('@')) {
        score += 10;
        breakdown.push('✔ No "@" symbol found (good).');
    } else {
        breakdown.push('❌ Contains an "@" symbol (often used to mask the real destination).');
    }

    // Rule 5: Double Slash Check (After Domain) (5 Points)
    // Strip the protocol (http:// or https://) then check for extra slashes
    const pathAndQuery = url.replace(/^https?:\/\//, '');
    if (!pathAndQuery.includes('//')) {
        score += 5;
        breakdown.push('✔ No suspicious double slashes found.');
    } else {
        breakdown.push('❌ Extra "//" found after the protocol (may indicate a hidden redirect).');
    }

    // Rule 6: Hyphen Count Check (5 Points)
    // Count hyphens specifically in the hostname (domain)
    const hyphenCount = (urlObj.hostname.match(/-/g) || []).length;
    if (hyphenCount <= 2) {
        score += 5;
        breakdown.push('✔ Domain hyphen count is safe.');
    } else {
        breakdown.push('❌ Too many hyphens in the domain name (common in phishing).');
    }

    // Rule 7: Suspicious Keyword Check (15 Points)
    const suspiciousKeywords = [
        'login', 'verify', 'secure', 'bank', 'account', 'update', 
        'password', 'confirm', 'signin', 'wallet', 'gift', 'free', 
        'bonus', 'winner', 'prize'
    ];
    const lowerUrl = url.toLowerCase();
    const foundKeywords = suspiciousKeywords.filter(keyword => lowerUrl.includes(keyword));
    
    if (foundKeywords.length === 0) {
        score += 15;
        breakdown.push('✔ No suspicious keywords found.');
    } else {
        breakdown.push(`❌ Suspicious keywords found: "${foundKeywords.join(', ')}".`);
    }

    // Rule 8: Domain Extension Check (10 Points)
    const trustedExtensions = ['.com', '.org', '.net', '.edu', '.gov', '.in', '.co.in', '.io'];
    const domainParts = urlObj.hostname.split('.');
    let tld = '';
    
    if (domainParts.length > 1) {
        // Grabbing the last part of the domain as the TLD
        tld = '.' + domainParts[domainParts.length - 1]; 
        // Check for co.in specifically
        if (urlObj.hostname.endsWith('.co.in')) tld = '.co.in'; 
    }

    if (trustedExtensions.includes(tld)) {
        score += 10;
        breakdown.push(`✔ Uses a trusted domain extension (${tld}).`);
    } else {
        breakdown.push(`❌ Unusual or untrusted domain extension (${tld}) - needs caution.`);
    }

    // Rule 9: Excessive Special Characters (5 Points)
    // Look for %, &, =, ?, $, !
    const specialChars = (url.match(/[%&=?$!]/g) || []).length;
    if (specialChars <= 3) {
        score += 5;
        breakdown.push('✔ Normal amount of special characters.');
    } else {
        breakdown.push('❌ Excessive special characters detected.');
    }

    return { error: null, score: score, breakdown: breakdown };
}

// Determine Risk Level & Output

function getRiskDetails(score) {
    if (score >= 90) return { status: '🟢 Safe', level: 'Low Risk', recommendations: 'Continue browsing, but always verify the website before entering sensitive information. Keep your browser and antivirus updated.' };
    if (score >= 70) return { status: '🟡 Mostly Safe', level: 'Moderate Risk', recommendations: 'Double-check the domain spelling. Avoid downloading files from unknown pages.' };
    if (score >= 40) return { status: '🟠 Suspicious', level: 'High Risk', recommendations: 'Verify the website through an official source before proceeding. Do not share passwords or payment information.' };
    return { status: '🔴 Unsafe', level: 'Very High Risk', recommendations: 'Do not open the website if possible. Never enter personal or banking details. Report or block the link if it came from an unknown sender.' };
}

//  Event Listener 

analyzeBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    
    if (!url) {
        alert("Please enter a URL to analyze.");
        return;
    }

    // Run the analysis
    const result = analyzeUrl(url);

    // Handle invalid format before showing score
    if (result.error) {
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = `<h3 style="color: #ff4c4c;">${result.error}</h3>`;
        return;
    }

    // Get final risk details
    const risk = getRiskDetails(result.score);

    // Build the UI
    let htmlContent = `
        <div style="background: #1a2035; padding: 20px; border-radius: 8px; border: 1px solid #2d3748;">
            <h2 style="margin-top: 0;">Score: ${result.score}/100</h2>
            <h3>Status: ${risk.status} (${risk.level})</h3>
            
            <hr style="border-color: #2d3748; margin: 20px 0;">
            
            <h4>Why This Result?</h4>
            <ul style="list-style: none; padding: 0; line-height: 1.6;">
                ${result.breakdown.map(item => `<li>${item}</li>`).join('')}
            </ul>

            <hr style="border-color: #2d3748; margin: 20px 0;">

            <h4>Recommendations</h4>
            <p>${risk.recommendations}</p>
        </div>
    `;

    resultDiv.innerHTML = htmlContent;
    resultDiv.style.display = 'block';
});







analyzeBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    
    if (!url) {
        alert("Please enter a URL to analyze.");
        return;
    }

    // Run the analysis
    const result = analyzeUrl(url);

    if (result.error) {
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = `<h3 style="color: #ef4444; text-align: center;">${result.error}</h3>`;
        return;
    }

    const risk = getRiskDetails(result.score);
    
    // Determine the color class for the pill
    let pillClass = 'status-danger';
    if (result.score >= 90) pillClass = 'status-safe';
    else if (result.score >= 70) pillClass = 'status-warning';

    // Parse URL components for the breakdown section
    let parsedUrl;
    try { parsedUrl = new URL(url); } catch(e) { parsedUrl = { protocol: 'N/A', hostname: 'N/A', pathname: 'N/A', search: 'N/A' }; }

    // Map the breakdown array into styled list items
    const formattedChecks = result.breakdown.map(item => {
        if (item.startsWith('✔')) return `<li class="check-pass">${item}</li>`;
        if (item.startsWith('❌')) return `<li class="check-fail">${item}</li>`;
        return `<li>${item}</li>`;
    }).join('');

    // Clean up the status text to remove the emoji for the big pill
    const cleanStatus = risk.status.replace(/[🟢🟡🟠🔴]/g, '').trim();

    // Build the new UI matching your reference image
    const htmlContent = `
        <div class="report-container">
            
            <!-- Top Score Section -->
            <div class="report-card score-section">
                <div class="score-circle" style="--score: ${result.score}%;">
                    <span>${result.score}%</span>
                </div>
                <div class="status-details">
                    <div class="status-pill ${pillClass}">${cleanStatus}</div>
                    <p class="risk-level">${risk.level}</p>
                </div>
            </div>

            <!-- Middle Grid Section -->
            <div class="grid-section">
                <!-- Security Checks -->
                <div class="report-card">
                    <h3>Security Checks</h3>
                    <ul class="check-list">
                        ${formattedChecks}
                    </ul>
                </div>

                <!-- URL Breakdown -->
                <div class="report-card">
                    <h3>URL Breakdown</h3>
                    <div class="breakdown-row">
                        <strong>Protocol:</strong> <span>${parsedUrl.protocol.replace(':', '') || 'None'}</span>
                    </div>
                    <div class="breakdown-row">
                        <strong>Domain:</strong> <span>${parsedUrl.hostname || 'None'}</span>
                    </div>
                    <div class="breakdown-row">
                        <strong>Path:</strong> <span>${parsedUrl.pathname === '/' ? 'None' : parsedUrl.pathname}</span>
                    </div>
                    <div class="breakdown-row">
                        <strong>Query Params:</strong> <span>${parsedUrl.search || 'None'}</span>
                    </div>
                </div>
            </div>

            <!-- Bottom Recommendations Section -->
            <div class="report-card">
                <h3>Recommendations & Explanation</h3>
                <p style="color: #cbd5e1; line-height: 1.6; margin: 0;">${risk.recommendations}</p>
            </div>

        </div>
    `;

    resultDiv.innerHTML = htmlContent;
    resultDiv.style.display = 'block';
});



