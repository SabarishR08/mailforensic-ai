// Runtime configuration for the AI Email Forensics URL Guard extension.
// Change API_BASE here (or set chrome.storage.local.apiBase) if the
// platform is not running on http://localhost:5000 (e.g. a Render deploy).
const DEFAULTS = {
  API_BASE: "http://localhost:5000",
};

// Resolve the effective API base. chrome.storage.local.apiBase wins over
// the default so deployments can be repointed without editing code.
async function getApiBase() {
  try {
    if (chrome.storage && chrome.storage.local) {
      const stored = await chrome.storage.local.get(["apiBase"]);
      if (stored && stored.apiBase) return stored.apiBase.replace(/\/+$/, "");
    }
  } catch (e) {
    // fall through to default
  }
  return DEFAULTS.API_BASE;
}
