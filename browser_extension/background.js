/**
 * Manifest V3 Service Worker — AI Email Forensics URL Guard
 * Ported from ai-threat-detection-security-ops SuspiciousURLDetector
 * (Group B consolidation), with the cache-sync bug fixed and the
 * config-driven API base.
 *
 * Strategy:
 * 1. Fast pre-check (pattern matching) → instant tab close if suspicious
 * 2. Background deep scan (backend /check-url) → runs after tab close
 * 3. Syncs recent ThreatLog entries from the email platform so URLs
 *    flagged by email forensics are blocked on click instantly
 */

importScripts("config.js");

// Cached domain reputation (prevents repeated scanning)
const domainCache = new Map();
const CACHE_TTL = 3600000; // 1 hour
const CACHE_MAX_ENTRIES = 1000;
const ACTIVITY_DEBOUNCE_MS = 100;
let lastActivity = { tabId: null, url: null, when: 0 };
let cacheSynced = false;

// Instantly suspicious patterns (0.1ms detection)
const INSTANT_BLOCK_PATTERNS = [
    // Common phishing/malware indicators
    /phishing|malware|ransomware|trojan/i,
    // IP addresses (often malicious)
    /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    // Suspicious TLDs
    /\.(ru|cn|work|xyz|top|download|review|trade|pw)$/i,
    // Port indicators (suspicious non-standard ports)
    /:([5-9]\d{3,})/,
    // Double-dash obfuscation
    /--/,
    // Excessive subdomains (often phishing)
    /^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\./i,
];

/**
 * Heuristic fast check: common phishing cues in path/host
 */
function isHeuristicallySuspicious(url) {
    try {
        const u = new URL(url);
        const host = u.hostname.toLowerCase();
        const path = (u.pathname + u.search).toLowerCase();
        const keywords = [/login/, /verify/, /update/, /secure/, /account/, /payment/, /wallet/];
        const tlds = [/\.app$/, /\.click$/, /\.link$/, /\.cfd$/, /\.zip$/];
        const manyLabels = (host.split('.').length >= 4);
        const keywordHit = keywords.some(k => k.test(path));
        const tldHit = tlds.some(t => t.test(host));
        return (manyLabels && keywordHit) || (keywordHit && tldHit);
    } catch {
        return false;
    }
}

/**
 * Quick reputation check from cache: "Malicious", "Suspicious", "Phishing", "Safe" or null
 */
function getCachedReputation(domain) {
    const cached = domainCache.get(domain);
    if (!cached) return null;
    if (Date.now() - cached.timestamp > CACHE_TTL) {
        domainCache.delete(domain);
        return null;
    }
    return cached.status;
}

function setCachedReputation(domain, status) {
    const entry = { status, timestamp: Date.now() };
    domainCache.set(domain, entry);
    persistCacheEntry(domain, entry);
    pruneCache();
}

function pruneCache() {
    try {
        if (domainCache.size <= CACHE_MAX_ENTRIES) return;
        const entries = Array.from(domainCache.entries());
        entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
        const toRemove = entries.slice(0, entries.length - CACHE_MAX_ENTRIES);
        for (const [k] of toRemove) domainCache.delete(k);
    } catch (e) {
        // ignore
    }
}

function persistCacheEntry(domain, entry) {
    if (!chrome.storage || !chrome.storage.local) return;
    try {
        chrome.storage.local.get(['domainCache'], (result) => {
            const stored = result.domainCache || {};
            stored[domain] = entry;
            const keys = Object.keys(stored);
            if (keys.length > CACHE_MAX_ENTRIES) {
                keys.sort((a, b) => stored[a].timestamp - stored[b].timestamp);
                const keep = keys.slice(keys.length - CACHE_MAX_ENTRIES);
                const newStored = {};
                for (const k of keep) newStored[k] = stored[k];
                chrome.storage.local.set({ domainCache: newStored });
            } else {
                chrome.storage.local.set({ domainCache: stored });
            }
        });
    } catch (e) {
        // ignore storage errors
    }
}

function loadCacheFromStorage() {
    if (!chrome.storage || !chrome.storage.local) return;
    try {
        chrome.storage.local.get(['domainCache'], (result) => {
            const stored = result.domainCache || {};
            const now = Date.now();
            for (const [domain, entry] of Object.entries(stored)) {
                if (now - entry.timestamp <= CACHE_TTL) {
                    domainCache.set(domain, entry);
                }
            }
            pruneCache();
        });
    } catch (e) {
        // ignore
    }
}

/**
 * Sync recent ThreatLog entries from the email platform into the extension
 * cache. This is what makes "URL found in a scanned email" instantly blocked
 * on click, before any deep scan completes.
 */
async function syncRecentThreatsFromServer(limit = 100) {
    try {
        const base = await getApiBase();
        const resp = await fetch(base + "/api/recent_threats?limit=" + encodeURIComponent(limit), { cache: 'no-store' });
        if (!resp.ok) return;
        const data = await resp.json();
        if (!data || !Array.isArray(data.results)) return;
        for (const entry of data.results) {
            try {
                const domain = extractDomain(entry.url || "");
                if (!domain) continue;
                const raw = entry.status || "Unknown";
                const normalized = (typeof raw === 'string') ?
                    (raw.charAt(0).toUpperCase() + raw.slice(1)) : String(raw);
                const BLOCKING = new Set(["Malicious", "Phishing", "Suspicious"]);
                setCachedReputation(domain, normalized);
                if (BLOCKING.has(normalized)) {
                    // remember the blocking verdict even after TTL-style expiry logic
                    setCachedReputation(domain, normalized);
                }
            } catch (e) {
                // ignore per-entry errors
            }
        }
        cacheSynced = true;
    } catch (e) {
        // backend offline — extension keeps working with patterns only
    }
}

/**
 * Extract domain/IP from URL
 */
function extractDomain(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return "";
    }
}

/**
 * Check if a hostname is localhost/private (safe, never scanned)
 */
function isLocalhost(hostname) {
    if (!hostname) return false;
    return (
        hostname === "localhost" ||
        hostname === "127.0.0.1" ||
        hostname === "0.0.0.0" ||
        hostname === "::1" ||
        hostname === "[::1]" ||
        hostname.startsWith("127.") ||
        hostname.startsWith("192.168.") ||
        hostname.startsWith("10.") ||
        hostname.startsWith("172.16.") ||
        hostname.startsWith("172.31.")
    );
}

/**
 * Pre-check: Fast pattern-based detection (instant decision)
 */
function isInstantlySuspicious(url) {
    return INSTANT_BLOCK_PATTERNS.some(pattern => pattern.test(url)) || isHeuristicallySuspicious(url);
}

/**
 * Deep scan: send to the email-forensics backend for VT/GSB/RDAP verification.
 * Runs async without waiting (tab may already be closed).
 */
async function deepScanInBackground(url, tabId) {
    const domain = extractDomain(url);
    const cached = getCachedReputation(domain);
    if (cached === "Safe") {
        return;
    }

    try {
        const base = await getApiBase();
        const response = await fetch(base + "/check-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });
        if (!response.ok) {
            console.warn(`Backend returned ${response.status}`);
            return;
        }
        const data = await response.json();
        if (!data || !data.status) return;

        setCachedReputation(domain, data.status);

        const closeableStatuses = ["Malicious", "Phishing", "Suspicious"];
        if (closeableStatuses.includes(data.status)) {
            console.log(`🚨 Deep scan blocked (${data.status}): ${url}`);
            try { chrome.tabs.remove(tabId); } catch (e) { /* tab may be gone */ }
        }
    } catch (err) {
        console.error(`Background scan error for ${url}:`, err);
    }
}

/**
 * Main listener: monitors all tab updates
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (!["loading", "complete"].includes(changeInfo.status) || !tab.url) {
        return;
    }

    const url = tab.url;
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        return;
    }

    const hostname = extractDomain(url);
    if (isLocalhost(hostname)) {
        return;
    }

    const cached = getCachedReputation(hostname);
    if (isInstantlySuspicious(url) || ["Malicious", "Phishing", "Suspicious"].includes(cached)) {
        console.log(`🚨 Instant block (pattern/cached): ${url}`);
        try { chrome.tabs.remove(tabId); } catch (e) { /* ignore */ }
        deepScanInBackground(url, tabId);
        return;
    }

    deepScanInBackground(url, tabId);
});

/**
 * Early navigation: catch navigations earlier than tab update
 */
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
    chrome.webNavigation.onBeforeNavigate.addListener((details) => {
        try {
            if (details.frameId !== 0) return;
            const url = details.url;
            if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;

            const hostname = extractDomain(url);
            if (isLocalhost(hostname)) return;

            const cached = getCachedReputation(hostname);
            if (isInstantlySuspicious(url) || ["Malicious", "Phishing", "Suspicious"].includes(cached)) {
                console.log(`🚨 Early nav block (onBeforeNavigate): ${url}`);
                try { chrome.tabs.remove(details.tabId); } catch (e) { /* ignore */ }
                deepScanInBackground(url, details.tabId);
            }
        } catch (e) {
            // ignore
        }
    });
}

/**
 * Tab switch detection: fire-and-forget activity log + fast cached decisions
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (!tab || !tab.url) return;
        const url = tab.url;
        if (!url.startsWith("http://") && !url.startsWith("https://")) return;

        const now = Date.now();
        if (lastActivity.tabId === activeInfo.tabId && lastActivity.url === url && (now - lastActivity.when) < ACTIVITY_DEBOUNCE_MS) {
            return;
        }
        lastActivity = { tabId: activeInfo.tabId, url, when: now };

        const hostname = extractDomain(url);
        if (isLocalhost(hostname)) return;

        const base = await getApiBase();
        fetch(base + "/api/tab-activity", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, title: tab.title || "", action: "switch" })
        }).catch(() => {});

        const cached = getCachedReputation(hostname);
        if (["Malicious", "Phishing"].includes(cached)) {
            try { chrome.tabs.remove(activeInfo.tabId); } catch (e) { /* ignore */ }
            return;
        }
        if (isInstantlySuspicious(url)) {
            try { chrome.tabs.remove(activeInfo.tabId); } catch (e) { /* ignore */ }
            deepScanInBackground(url, activeInfo.tabId);
            return;
        }
        deepScanInBackground(url, activeInfo.tabId);
    } catch (e) {
        // ignore
    }
});

/**
 * Startup: load persisted cache and sync email-flagged URLs from the
 * platform (fixed: runs once at worker start, not nested in a listener).
 */
loadCacheFromStorage();
syncRecentThreatsFromServer(100);
// Periodic re-sync so fresh email-scan verdicts propagate within seconds
setInterval(syncRecentThreatsFromServer, 60000);
