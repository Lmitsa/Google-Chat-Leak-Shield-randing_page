let debounceTimer = null;
let lastAnalyzedText = "";
let pendingAnalysis = null; // Globally tracks the active AI request
let activeWarningToastId = null;
let lastAnalysisResult = null; // Caches the last AI analysis result: { text, result }
let lastBgApiCallTime = 0; // Tracks the timestamp of the last background API call to prevent rate limit exhaustion
let recentLeaks = []; // Local cache of confirmed sensitive leakage substrings

let customRegexes = [];

try {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    // Load custom regexes from storage
    chrome.storage.local.get(['custom_regexes'], (result) => {
      if (result.custom_regexes) {
        updateCustomRegexes(result.custom_regexes);
      }
    });

    // Listen for updates to custom regexes in real-time
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'local' && changes.custom_regexes) {
        updateCustomRegexes(changes.custom_regexes.newValue || []);
      }
    });
  }
} catch (e) {
  console.warn("[LeakShield] Storage access failed, extension context may be invalidated:", e);
}

function updateCustomRegexes(regexStrings) {
  customRegexes = [];
  regexStrings.forEach(str => {
    try {
      customRegexes.push(new RegExp(str, 'i')); // Default to case-insensitive matching
    } catch (e) {
      console.error("[LeakShield] Invalid custom regex:", str, e);
    }
  });
  console.log(`[LeakShield] Loaded ${customRegexes.length} custom regex rules.`);
}