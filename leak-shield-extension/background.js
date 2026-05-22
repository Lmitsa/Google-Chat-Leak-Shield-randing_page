// Google Chat Real-Time Leak Detector - Background Service Worker

// Cyber-Security Sheriff System Instruction
const SYSTEM_INSTRUCTION = `You are an expert enterprise cyber-security sheriff. Your job is to analyze the following message typed in an internal corporate messenger and check for potential sensitive data leaks.

You must enforce an EXTREMELY strict policy. The following items MUST ALWAYS be flagged as a leak ("isLeak": true):
1. Any Korean Business Registration Number (사업자등록번호, format: xxx-xx-xxxxx) -> Category: "PII" or "Other", Risk Level: "WARNING". Reason: "사업자등록번호 노출 위험"
2. Any Private or Internal IP Address (e.g., 192.168.x.x, 10.x.x.x, 172.16.x.x-172.31.x.x) -> Category: "Database" or "Other", Risk Level: "WARNING" or "CRITICAL" depending on context. Reason: "내부 서버 IP 주소 노출 위험"
3. Credentials (AWS Keys, Google Cloud API Keys, GitHub Access Tokens, JWT Tokens, SSH/TLS Private Keys, API secrets) -> Category: "Credential", Risk Level: "CRITICAL"
4. Source Code (Proprietary code snippets, database configurations, business logic algorithms) -> Category: "Source Code", Risk Level: "WARNING"
5. Database connection strings, credentials, hosts, endpoints -> Category: "Database", Risk Level: "CRITICAL"
6. Personally Identifiable Information (PII) like Korean Resident Registration Numbers, Phone Numbers, Email addresses, Driver's License Numbers, Passport Numbers -> Category: "PII", Risk Level: "CRITICAL" or "WARNING"
7. Financial Data (Credit Card numbers, Bank Account numbers) -> Category: "Financial", Risk Level: "CRITICAL"

Provide your evaluation strictly in JSON format matching this schema:
{
  "isLeak": boolean,
  "riskLevel": "CRITICAL" | "WARNING" | "INFO",
  "category": "Credential" | "Source Code" | "Database" | "PII" | "Financial" | "Other",
  "reason": "Short user-friendly explanation in Korean why this is a leak (e.g. '사업자등록번호 노출 위험', '내부 서버 IP 노출 위험', 'GitHub Token 유출 의심')",
  "leakSnippet": "The specific leaked string or code fragment"
}
Ensure response contains valid JSON ONLY, without markdown fences like \`\`\`json.`;

// Monitor incoming messages from Content Script and Options Page
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'analyze_text') {
    handleTextAnalysis(message.text)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep the message channel open for asynchronous response
  }

  if (message.action === 'test_api_key') {
    testApiKey(message.apiKey)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep the message channel open for asynchronous response
  }

  if (message.action === 'log_leak') {
    handleLogLeak(message.leak)
      .then(() => sendResponse({ success: true }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep the message channel open for asynchronous response
  }
});

// Perform Secure LLM Analysis using Gemini API
async function executeGeminiRequest(model, apiKey, text, retries = 2, delay = 1000) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

  const payload = {
    contents: [
      {
        role: 'user',
        parts: [
          { text: text }
        ]
      }
    ],
    systemInstruction: {
      parts: [
        { text: SYSTEM_INSTRUCTION }
      ]
    },
    generationConfig: {
      responseMimeType: 'application/json',
      maxOutputTokens: 200
    }
  };

  for (let i = 0; i <= retries; i++) {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `HTTP error ${response.status}`;
        throw new Error(errorMessage);
      }

      const responseData = await response.json();
      const rawText = responseData.candidates?.[0]?.content?.parts?.[0]?.text;

      if (!rawText) {
        throw new Error('Returned an empty or invalid structure.');
      }

      return JSON.parse(rawText.trim());
    } catch (error) {
      const errorMsg = error.message || "";
      const isTransient = errorMsg.includes("high demand") || errorMsg.includes("overloaded") || errorMsg.includes("503") || errorMsg.includes("Unavailable") || errorMsg.includes("ResourceExhausted") || errorMsg.includes("429") || errorMsg.includes("quota") || errorMsg.includes("limit");

      if (isTransient && i < retries) {
        console.warn(`[LeakShield] Transient API error on ${model} (attempt ${i + 1}/${retries + 1}): ${errorMsg}. Retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        delay *= 2; // Exponential backoff
        continue;
      }
      throw new Error(`Gemini API Error (${model}): ${errorMsg}`);
    }
  }
}

// Perform Secure LLM Analysis using Gemini API with automatic fallback
async function handleTextAnalysis(text) {
  // 1. Retrieve the secure API Key from chrome.storage.local
  const storage = await chrome.storage.local.get(['gemini_api_key', 'stats']);
  const apiKey = storage.gemini_api_key;

  if (!apiKey) {
    throw new Error('Gemini API key is not configured. Please set it in the Extension Options page.');
  }

  let parsedResult;
  let modelUsed = 'gemini-2.5-flash';

  try {
    parsedResult = await executeGeminiRequest(modelUsed, apiKey, text);
  } catch (error) {
    const errorMsg = error.message || "";
    const isOverloaded = errorMsg.includes("high demand") || errorMsg.includes("overloaded") || errorMsg.includes("503") || errorMsg.includes("Unavailable") || errorMsg.includes("ResourceExhausted") || errorMsg.includes("quota") || errorMsg.includes("limit");

    if (isOverloaded) {
      console.warn(`[LeakShield] Primary model ${modelUsed} overloaded. Attempting fallback to gemini-1.5-flash...`);
      try {
        modelUsed = 'gemini-1.5-flash';
        parsedResult = await executeGeminiRequest(modelUsed, apiKey, text);
        console.log(`[LeakShield] Fallback to ${modelUsed} successful.`);
      } catch (fallbackError) {
        console.error("[LeakShield] Fallback model also failed:", fallbackError);
        throw error; // throw the original error if fallback also fails
      }
    } else {
      throw error;
    }
  }

  // 3. Normalize if AI returned an array of objects (due to multiple matches in a single prompt)
  if (Array.isArray(parsedResult)) {
    console.log("[LeakShield] AI returned an array of evaluations. Normalizing...");
    const leaks = parsedResult.filter(item => item && item.isLeak);
    if (leaks.length > 0) {
      const hasCritical = leaks.some(item => item.riskLevel === 'CRITICAL');
      const riskLevel = hasCritical ? 'CRITICAL' : 'WARNING';

      const categories = [...new Set(leaks.map(item => item.category).filter(Boolean))];
      const category = categories.length > 0 ? categories.join(', ') : 'Other';

      const reasons = [...new Set(leaks.map(item => item.reason).filter(Boolean))];
      const reason = reasons.length > 0 ? reasons.join(' / ') : '민감 정보 유출 위험 감지';

      const snippets = [...new Set(leaks.map(item => item.leakSnippet).filter(Boolean))];
      const leakSnippet = snippets.length > 0 ? snippets.join(', ') : '';

      parsedResult = {
        isLeak: true,
        riskLevel: riskLevel,
        category: category,
        reason: reason,
        leakSnippet: leakSnippet
      };
    } else {
      parsedResult = {
        isLeak: false,
        riskLevel: 'INFO',
        category: 'System',
        reason: '안전함',
        leakSnippet: ''
      };
    }
  }

  // 4. Update Statistics on Leaks
  let stats = storage.stats || { scanned: 0, regexBlocked: 0, llmFlagged: 0, savedLeaks: 0 };
  stats.scanned = (stats.scanned || 0) + 1;
  stats.regexBlocked = (stats.regexBlocked || 0) + 1;

  if (parsedResult.isLeak) {
    stats.llmFlagged = (stats.llmFlagged || 0) + 1;

    // Save to historical leak logs
    const historyData = await chrome.storage.local.get(['leak_logs']);
    let leakLogs = historyData.leak_logs || [];

    const newLog = {
      id: 'leak_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
      timestamp: new Date().toISOString(),
      snippet: parsedResult.leakSnippet || text.substring(0, 100),
      category: parsedResult.category || 'Other',
      riskLevel: parsedResult.riskLevel || 'WARNING',
      reason: parsedResult.reason || '잠재적인 보안 유출 위험이 감지되었습니다.',
      fullText: text
    };

    // Keep max 50 logs for storage space optimization
    leakLogs.unshift(newLog);
    if (leakLogs.length > 50) {
      leakLogs.pop();
    }

    await chrome.storage.local.set({
      leak_logs: leakLogs,
      stats: stats
    });
  } else {
    await chrome.storage.local.set({ stats: stats });
  }

  return parsedResult;
}

// Diagnostics helper to test key connectivity and validity with fallback support
async function testApiKey(apiKey) {
  if (!apiKey) {
    throw new Error('API Key is empty.');
  }

  try {
    return await executeTestRequest('gemini-2.5-flash', apiKey);
  } catch (error) {
    const errorMsg = error.message || "";
    const isOverloaded = errorMsg.includes("high demand") || errorMsg.includes("overloaded") || errorMsg.includes("503") || errorMsg.includes("Unavailable") || errorMsg.includes("ResourceExhausted") || errorMsg.includes("quota") || errorMsg.includes("limit");

    if (isOverloaded) {
      try {
        console.warn("[LeakShield] Testing connection fallback to gemini-1.5-flash...");
        return await executeTestRequest('gemini-1.5-flash', apiKey);
      } catch (fallbackError) {
        throw error;
      }
    }
    throw error;
  }
}

async function executeTestRequest(model, apiKey) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

  const payload = {
    contents: [
      {
        role: 'user',
        parts: [
          { text: 'Ping' }
        ]
      }
    ],
    generationConfig: {
      maxOutputTokens: 5
    }
  };

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    const errorMessage = errorData.error?.message || `HTTP error ${response.status}`;
    throw new Error(errorMessage);
  }

  return { status: 'connected', model: model };
}

// Log locally confirmed leak blocks directly
async function handleLogLeak(leakData) {
  const storage = await chrome.storage.local.get(['stats', 'leak_logs']);
  let stats = storage.stats || { scanned: 0, regexBlocked: 0, llmFlagged: 0, savedLeaks: 0 };
  stats.scanned = (stats.scanned || 0) + 1;
  stats.regexBlocked = (stats.regexBlocked || 0) + 1;

  let leakLogs = storage.leak_logs || [];

  // Check if we already logged this exact snippet within the last 5 seconds to avoid duplicates
  const now = Date.now();
  const isDuplicate = leakLogs.some(log => {
    const logTime = new Date(log.timestamp).getTime();
    return log.snippet === leakData.snippet && (now - logTime < 5000);
  });

  if (isDuplicate) {
    return;
  }

  const newLog = {
    id: 'leak_' + now + '_' + Math.random().toString(36).substr(2, 5),
    timestamp: new Date().toISOString(),
    snippet: leakData.snippet || '',
    category: leakData.category || 'Other',
    riskLevel: leakData.riskLevel || 'CRITICAL',
    reason: leakData.reason || '보안 유출 위험이 감지되었습니다.',
    fullText: leakData.fullText || ''
  };

  leakLogs.unshift(newLog);
  if (leakLogs.length > 50) {
    leakLogs.pop();
  }

  await chrome.storage.local.set({
    leak_logs: leakLogs,
    stats: stats
  });
}
