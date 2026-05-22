// Safe extension message sending helper to prevent "Context Invalidated" or "chrome.runtime undefined" crashes
function safeSendMessage(message, callback) {
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          console.warn("[LeakShield] Runtime error during message send:", chrome.runtime.lastError.message);
          callback({ success: false, error: chrome.runtime.lastError.message });
          return;
        }
        callback(response);
      });
    } catch (e) {
      console.error("[LeakShield] Failed to send message to background worker:", e);
      callback({ success: false, error: "Extension context invalidated. Please refresh the page." });
    }
  } else {
    console.error("[LeakShield] Extension context is disconnected. chrome.runtime is undefined.");
    callback({ success: false, error: "Extension context disconnected. Please refresh the page." });
  }
}

// Helper to determine if a matched button is the actual Send button (and not a dropdown options menu)
function isRealSendButton(el) {
  if (!el) return false;

  // Exclude elements that look like dropdown/menu/options trigger
  const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
  const dataTooltip = (el.getAttribute('data-tooltip') || '').toLowerCase();
  const hasPopup = el.getAttribute('aria-haspopup');

  if (hasPopup && hasPopup !== 'false') return false;
  if (el.hasAttribute('aria-expanded')) return false;

  const excludeKeywords = ['option', '옵션', '설정', 'menu', '메뉴', '하위', 'dropdown', '드롭다운'];
  for (const keyword of excludeKeywords) {
    if (ariaLabel.includes(keyword) || dataTooltip.includes(keyword)) {
      return false;
    }
  }
  return true;
}

function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, function (m) { return map[m]; });
}