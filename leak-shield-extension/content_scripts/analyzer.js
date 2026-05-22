function checkLocalLeakCache(text) {
  for (const leak of recentLeaks) {
    if (text.includes(leak)) {
      return {
        isLeak: true,
        riskLevel: "CRITICAL",
        category: "Credential",
        reason: "이전 단계에서 이미 보안 유출로 판명된 민감 정보(자격 증명 등)가 여전히 포함되어 있습니다.",
        leakSnippet: leak
      };
    }
  }
  return null;
}

// 1차: Local Regex check (returns true if ANY matches)
function checkRegexPreFilter(text) {
  // 1. Check confirmed rules
  for (const [key, regex] of Object.entries(CONFIRMED_REGEXES)) {
    if (regex.test(text)) {
      console.log(`[LeakShield] Confirmed rule matched: [${key}]`);
      return true;
    }
  }

  // 2. Check suspicious rules
  for (const [key, regex] of Object.entries(SUSPICIOUS_REGEXES)) {
    if (regex.test(text)) {
      console.log(`[LeakShield] Suspicious rule matched: [${key}]`);
      return true;
    }
  }

  // 3. Check user-defined custom rules
  for (let i = 0; i < customRegexes.length; i++) {
    if (customRegexes[i].test(text)) {
      console.log(`[LeakShield] Custom rule matched: [${customRegexes[i].source}]`);
      return true;
    }
  }

  return false;
}

// 1.5차: Local Confirmed Leak Direct Engine (Instantly hard block, Zero API requests)
function checkConfirmedLeak(text) {
  for (const [key, regex] of Object.entries(CONFIRMED_REGEXES)) {
    const match = text.match(regex);
    if (match) {
      const categoryName = key.toUpperCase().replace('_', ' ');
      return {
        isLeak: true,
        riskLevel: "CRITICAL",
        category: categoryName,
        reason: `명백한 기밀 자격 증명/데이터(${categoryName}) 노출 양식이 포착되어 전송이 즉시 원천 차단되었습니다.`,
        leakSnippet: match[0]
      };
    }
  }
  return null;
}

// Debounced Background Local-only analysis (Zero API requests during typing)
function runDebouncedAnalysis(text, inputEl) {
  lastAnalyzedText = text;

  // Run Regex Pre-Filter
  const isSuspicious = checkRegexPreFilter(text);
  if (!isSuspicious) {
    // If it's no longer suspicious, dismiss any active warning toast
    if (activeWarningToastId) {
      dismissToast(activeWarningToastId);
      activeWarningToastId = null;
    }
    // Also clear cached result
    lastAnalysisResult = null;
    return;
  }

  // Check Local Leak Cache (Instant match!)
  const cachedLeak = checkLocalLeakCache(text);
  if (cachedLeak) {
    console.log("[LeakShield] Local Leak Cache hit! Displaying cached warning:", cachedLeak.leakSnippet);
    lastAnalysisResult = { text: text, result: cachedLeak };
    if (activeWarningToastId) {
      dismissToast(activeWarningToastId);
    }
    activeWarningToastId = showToast({
      title: "유출 위험 실시간 차단 감지!",
      message: `입력창에 이미 보안 유출로 확인된 [${cachedLeak.category}] 정보가 입력되어 있습니다. 전송 시 전송이 완벽 차단됩니다.`,
      riskLevel: "CRITICAL",
      category: cachedLeak.category,
      snippet: cachedLeak.leakSnippet,
      duration: 0 // Persistent until closed
    });
    return;
  }

  // General Regex hit - warn user locally that sending will trigger final AI evaluation
  console.log("[LeakShield] Local regex hit. Quietly displaying localized warning without API call.");
  // 실시간 진단 함수에서 이미 띄웠으므로, activeWarningToastId가 없는 경우에만 보험용으로 띄워줍니다.
  if (!activeWarningToastId && !document.querySelector('.leakshield-toast')) {
    let detectedCategory = "민감 정보";
    let detectedSnippet = text.substring(0, 100);
    for (const [key, regex] of Object.entries(BUILTIN_REGEXES)) {
      const match = text.match(regex);
      if (match) {
        detectedCategory = key.toUpperCase().replace('_', ' ');
        detectedSnippet = match[0];
        break;
      }
    }

    activeWarningToastId = showToast({
      title: "민감 정보 입력 감지 (로컬 보안 엔진)",
      message: `입력창에 [${detectedCategory}] 양식이 포착되었습니다.<br>전송(Enter)을 누르시면 안전을 위해 <strong>Gemini AI 최종 정밀 보안 검사</strong>를 진행합니다.<br>(급격한 우회 전송이 필요하다면 <strong>Ctrl + Enter</strong>를 누르세요.)`,
      riskLevel: "WARNING",
      category: detectedCategory,
      snippet: detectedSnippet,
      duration: 0 // Persistent until closed
    });
  }
}