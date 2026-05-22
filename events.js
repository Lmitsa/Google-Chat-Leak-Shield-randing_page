// Initialize observation
console.log("[LeakShield] Google Chat Real-Time Leak Detector loaded.");
initObserver();

function initObserver() {
  // Initial check
  setupInputListeners();

  // Watch for dynamic SPA routing changes
  const observer = new MutationObserver(() => {
    setupInputListeners();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

// Find Google Chat SPA contenteditable input textboxes
function setupInputListeners() {
  const inputs = document.querySelectorAll('div[contenteditable="true"][role="textbox"]');
  inputs.forEach(input => {
    if (!input.dataset.leakShieldBound) {
      input.dataset.leakShieldBound = "true";

      // Prevent double triggers and cache override flag
      input.dataset.bypassSecurity = "false";

      // Listen to keystroke and paste events
      input.addEventListener('input', handleInput);
      input.addEventListener('keydown', handleKeydown, true); // Use capture phase to intercept Enter

      // Send button click interception is handled by the global document-level capture handler below.
      // We do NOT use per-button target-phase binding because Google Chat's own handlers
      // are registered at target-phase earlier, so they would fire before ours.
      // Document-level capture phase always fires BEFORE any element-level handlers.

      console.log("[LeakShield] Securely bound to active Google Chat input box.");
    }
  });
}

// Intercept clicks on Google Chat send buttons
function bindSendButton(inputEl) {
  let parent = inputEl.parentElement;
  let sendButton = null;

  // Find Send button relative to input box (up to 5 levels up)
  for (let i = 0; i < 5; i++) {
    if (!parent) break;
    const candidates = parent.querySelectorAll('div[role="button"][aria-label*="Send"], div[role="button"][aria-label*="전송"], div[role="button"][aria-label*="보내기"], div[role="button"][data-tooltip*="Send"], div[role="button"][data-tooltip*="전송"], div[role="button"][data-tooltip*="보내기"]');
    for (const candidate of candidates) {
      if (isRealSendButton(candidate)) {
        sendButton = candidate;
        break;
      }
    }
    if (sendButton) break;
    parent = parent.parentElement;
  }

  if (sendButton) {
    if (!sendButton.dataset.leakShieldBound) {
      sendButton.dataset.leakShieldBound = "true";
      // Intercept both mousedown and click - Google Chat may use either to trigger send
      const makeInterceptHandler = (el, btn) => (e) => {
        const now = Date.now();
        const last = parseInt(btn.dataset.lastInterceptTime || '0');
        if (now - last < 500) return; // debounce: prevent double-fire from mousedown+click pair
        btn.dataset.lastInterceptTime = String(now);
        handleSendClick(e, el, btn);
      };
      sendButton.addEventListener('mousedown', makeInterceptHandler(inputEl, sendButton), true);
      sendButton.addEventListener('click', makeInterceptHandler(inputEl, sendButton), true);
      console.log("[LeakShield] Bound mousedown+click listeners to Send button:", sendButton);
    }
  }
}

// Handle debounced typing inspection
function handleInput(e) {
  const inputEl = e.target;
  const text = inputEl.innerText || "";

  // Reset override and bypass flags on new input
  inputEl.dataset.bypassSecurity = "false";
  inputEl.dataset.doubleEnterPrompted = "false";

  if (text.trim() === "" || text === lastAnalyzedText) return;

  // Clear cached analysis for old text as user is editing it
  lastAnalysisResult = null;

  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    runDebouncedAnalysis(text, inputEl);
  }, 1000); // 1-second debounce to optimize API quota usage
}

// Intercept transmission on Enter press
async function handleKeydown(e) {
  const inputEl = e.target;
  const text = inputEl.innerText || "";

  // Intercept Enter (without Shift) keypress
  if (e.key === 'Enter' && !e.shiftKey) {
    console.log("[LeakShield] Enter detected. Current innerText:", JSON.stringify(text));

    // Handle Ctrl+Enter to bypass security immediately and force-send
    if (e.ctrlKey) {
      console.warn("[LeakShield] Bypass activated by Ctrl+Enter. Force-sending message immediately...");

      if (pendingAnalysis && pendingAnalysis.toastId) {
        dismissToast(pendingAnalysis.toastId);
      }
      if (activeWarningToastId) {
        dismissToast(activeWarningToastId);
        activeWarningToastId = null;
      }

      inputEl.dataset.bypassSecurity = "true";
      inputEl.dataset.doubleEnterPrompted = "false";

      e.preventDefault();
      e.stopPropagation();

      const enterEvent = new KeyboardEvent('keydown', {
        key: 'Enter',
        code: 'Enter',
        keyCode: 13,
        which: 13,
        bubbles: true,
        cancelable: true
      });
      inputEl.dispatchEvent(enterEvent);
      return;
    }

    // If user confirmed to bypass via AI-safe callback
    if (inputEl.dataset.bypassSecurity === "true") {
      console.log("[LeakShield] Security bypassed by user confirmation.");
      inputEl.dataset.bypassSecurity = "false";
      inputEl.dataset.doubleEnterPrompted = "false";
      return;
    }

    // Run Regex Check instantly
    const hasSuspiciousPattern = checkRegexPreFilter(text);
    console.log("[LeakShield] Pre-filter evaluation result:", hasSuspiciousPattern);

    if (hasSuspiciousPattern) {
      // If user presses Enter for the second time, allow send and check in background
      if (inputEl.dataset.doubleEnterPrompted === "true") {
        if (pendingAnalysis && pendingAnalysis.text === text) {
          pendingAnalysis.bypassed = true;
          if (pendingAnalysis.toastId) {
            dismissToast(pendingAnalysis.toastId);
          }
        }
        inputEl.dataset.doubleEnterPrompted = "false";
        inputEl.dataset.bypassSecurity = "false";

        console.warn("[LeakShield] Bypass activated by double Enter. Sending message immediately...");
        return; // Do not call preventDefault/stopPropagation, let it send!
      }

      // First Enter press: block and prompt user
      e.preventDefault();
      e.stopPropagation();
      clearTimeout(debounceTimer);

      console.warn("[LeakShield] First Enter detected. Intercepting for security evaluation...");
      inputEl.dataset.doubleEnterPrompted = "true";

      // Dismiss any active real-time warning toast since we are entering blocking/evaluation state
      if (activeWarningToastId) {
        dismissToast(activeWarningToastId);
        activeWarningToastId = null;
      }

      // Check if we have a local confirmed leak (Level-2 zero-API block!) or cache match
      const localConfirmedLeak = checkConfirmedLeak(text);
      const cachedLeak = checkLocalLeakCache(text);
      const aiResult = localConfirmedLeak || cachedLeak || (lastAnalysisResult && lastAnalysisResult.text === text ? lastAnalysisResult.result : null);

      if (aiResult) {
        console.log("[LeakShield] Using resolved cached analysis result on Enter:", aiResult);

        if (aiResult.isLeak) {
          inputEl.dataset.doubleEnterPrompted = "false"; // Reset bypass since it's confirmed leak
          showToast({
            title: "보안 유출 전송 차단!",
            message: `[${aiResult.category}] 유출 위험이 감지되어 메시지 전송이 보안 차단되었습니다.<br>사유: ${aiResult.reason}<br><br><strong>강제 전송이 필요하시면 <kbd>Ctrl</kbd> + <kbd>Enter</kbd> 키를 누르시면 즉시 전송됩니다.</strong>`,
            riskLevel: aiResult.riskLevel || "CRITICAL",
            category: aiResult.category,
            snippet: aiResult.leakSnippet || text.substring(0, 100),
            duration: 0 // Persistent
          });

          // Log local block to background storage
          if (localConfirmedLeak) {
            safeSendMessage({
              action: 'log_leak',
              leak: {
                snippet: localConfirmedLeak.leakSnippet,
                category: localConfirmedLeak.category,
                riskLevel: localConfirmedLeak.riskLevel,
                reason: localConfirmedLeak.reason,
                fullText: text
              }
            }, () => {});
          }

          console.error("[LeakShield] Hard Block applied by Cybersecurity Sheriff using resolved cached result.");
        } else {
          // Safe! Auto-trigger sending
          showToast({
            title: "보안 안전 검증 완료",
            message: "분석 결과 안전함이 확인되었습니다. 메시지를 자동 전송합니다.",
            riskLevel: "INFO",
            category: "System",
            duration: 4000
          });
          inputEl.dataset.bypassSecurity = "true";
          inputEl.dataset.doubleEnterPrompted = "false";

          // Re-dispatch enter keypress event
          const enterEvent = new KeyboardEvent('keydown', {
            key: 'Enter',
            code: 'Enter',
            keyCode: 13,
            which: 13,
            bubbles: true,
            cancelable: true
          });
          inputEl.dispatchEvent(enterEvent);
        }
        return;
      }

      // If we don't have a cached result, start background AI check
      const loadingToastId = showToast({
        title: "실시간 보안 분석 대기 중...",
        message: "민감 정보 유출 위험이 감지되어 정밀 AI 보안 분석을 진행 중입니다.<br><strong>급한 상황(보안 우회 전송)이시라면 Enter 키를 한 번 더 누르시거나, Ctrl + Enter 키를 누르시면 즉시 전송됩니다.</strong>",
        riskLevel: "WARNING",
        category: "System",
        duration: 0, // Keep until closed
        isLoading: true
      });

      // Save to global pending analysis state
      pendingAnalysis = {
        text: text,
        bypassed: false,
        toastId: loadingToastId
      };

      safeSendMessage({ action: 'analyze_text', text: text }, (response) => {
        console.log("[LeakShield] Enter analysis response:", response);
        // Capture bypassed state before clearing
        const wasBypassed = pendingAnalysis && pendingAnalysis.text === text && pendingAnalysis.bypassed;
        const currentToastId = pendingAnalysis && pendingAnalysis.text === text ? pendingAnalysis.toastId : loadingToastId;

        // Dismiss loading toast
        dismissToast(currentToastId);

        // Clear global pending state if it matches
        if (pendingAnalysis && pendingAnalysis.text === text) {
          pendingAnalysis = null;
        }

        if (response && response.success) {
          const aiResult = response.data;
          console.log("[LeakShield] Enter AI Evaluation:", aiResult);

          // Update cache
          lastAnalysisResult = { text: text, result: aiResult };

          if (aiResult.isLeak) {
            const leakSnippet = aiResult.leakSnippet || text;
            if (leakSnippet && !recentLeaks.includes(leakSnippet)) {
              recentLeaks.push(leakSnippet);
            }
          }

          if (wasBypassed) {
            // Case A: User bypassed and sent the message
            if (aiResult.isLeak) {
              showToast({
                title: "사후 보안 유출 감지!",
                message: `이미 전송된 메시지에서 [${aiResult.category}] 유출 위험이 사후 검증되었습니다.<br>보안 관리자 확인이 필요할 수 있습니다.<br><strong>사유: ${aiResult.reason}</strong>`,
                riskLevel: "CRITICAL",
                category: aiResult.category,
                snippet: aiResult.leakSnippet || text.substring(0, 100),
                duration: 0 // Persistent
              });
            }
          } else {
            // Case B: User waited for assessment
            if (inputEl.innerText.trim() !== "") {
              if (aiResult.isLeak) {
                inputEl.dataset.doubleEnterPrompted = "false"; // Reset bypass since it's confirmed leak
                showToast({
                  title: "보안 유출 전송 차단!",
                  message: `[${aiResult.category}] 유출 위험이 감지되어 메시지 전송이 보안 차단되었습니다.<br>사유: ${aiResult.reason}<br><br><strong>강제 전송이 필요하시면 <kbd>Ctrl</kbd> + <kbd>Enter</kbd> 키를 누르시면 즉시 전송됩니다.</strong>`,
                  riskLevel: aiResult.riskLevel || "CRITICAL",
                  category: aiResult.category,
                  snippet: aiResult.leakSnippet || text.substring(0, 100),
                  duration: 0 // Persistent
                });
                console.error("[LeakShield] Hard Block applied by Cybersecurity Sheriff.");
              } else {
                // Safe! Auto-trigger sending
                showToast({
                  title: "보안 안전 검증 완료",
                  message: "분석 결과 안전함이 확인되었습니다. 메시지를 자동 전송합니다.",
                  riskLevel: "INFO",
                  category: "System",
                  duration: 4000
                });
                inputEl.dataset.bypassSecurity = "true";
                inputEl.dataset.doubleEnterPrompted = "false";

                // Re-dispatch enter keypress event
                const enterEvent = new KeyboardEvent('keydown', {
                  key: 'Enter',
                  code: 'Enter',
                  keyCode: 13,
                  which: 13,
                  bubbles: true,
                  cancelable: true
                });
                inputEl.dispatchEvent(enterEvent);
              }
            }
          }
        } else {
          // Fallback if AI failure
          console.error("[LeakShield] AI analysis error:", response?.error);
          if (!wasBypassed && inputEl.innerText.trim() !== "") {
            const errorMsg = response?.error || "";
            const isRateLimit = errorMsg.includes("quota") || errorMsg.includes("limit") || errorMsg.includes("exceeded");

            if (isRateLimit) {
              showToast({
                title: "API 호출 한도 초과 (Rate Limit)",
                message: "Gemini API 무료 요금제의 분당 호출 한도(20회)를 일시적으로 초과했습니다.<br><strong>전송을 강행하시려면 Enter 키를 한 번 더 누르시거나, <kbd>Ctrl</kbd> + <kbd>Enter</kbd> 키를 누르시면 즉시 전송됩니다.</strong>",
                riskLevel: "WARNING",
                category: "System",
                duration: 0 // Persistent
              });
            } else {
              let title = "보안 분석 일시 오류";
              let message = "API 연결 장애가 발생했습니다. 안전을 위해 전송 전 크레덴셜 정보를 꼭 다시 한 번 확인해 주세요.";

              if (errorMsg.includes("is not configured") || errorMsg.includes("not configured")) {
                title = "API 키 미설정";
                message = "Gemini API 키가 아직 설정되지 않았습니다. 확장 프로그램 설정 페이지에서 API 키를 먼저 입력해 주세요.";
              } else if (errorMsg.includes("API key not valid") || errorMsg.includes("API_KEY_INVALID") || errorMsg.includes("invalid")) {
                title = "API 키 오류";
                message = "설정된 Gemini API 키가 유효하지 않습니다. 확장 프로그램 설정 페이지에서 올바른 키를 입력했는지 다시 확인해 주세요.";
              } else if (errorMsg) {
                message += `<br><br><strong>상세 정보:</strong> <code>${escapeHtml(errorMsg)}</code>`;
              }
              message += "<br><br><strong>전송을 강행하시려면 Enter 키를 한 번 더 누르시거나, <kbd>Ctrl</kbd> + <kbd>Enter</kbd> 키를 누르시면 즉시 전송됩니다.</strong>";

              showToast({
                title: title,
                message: message,
                riskLevel: "WARNING",
                category: "System",
                duration: 0 // Persistent
              });
            }
          }
        }
      });
    }
  }
}

// Intercept mouse clicks on Google Chat send buttons - [타이밍 버그 완벽 박멸 버전]
async function handleSendClick(e, inputEl, sendButton) {
  const text = inputEl.innerText || "";

  console.log("[LeakShield] 마우스 전송 클릭 가로챔. 텍스트 길이:", text.length);

  // [규칙 1] 팝업이 떠 있는 상태에서 '한 번 더 누르기(우회)'가 정상 승인되어 true가 되었을 때만 최종 전송을 허용합니다.
  if (inputEl.dataset.bypassSecurity === "true") {
    console.log("[LeakShield] 우회 플래그가 true이므로 구글 챗 순정 전송을 허용합니다.");
    inputEl.dataset.bypassSecurity = "false";
    inputEl.dataset.doubleEnterPrompted = "false";
    return; // 👈 여기서 return해야 실제로 서버로 전송됩니다.
  }

  // 1. 엔터 키와 동일하게 정규식 필터를 최우선으로 즉시 가동합니다.
  const hasSuspiciousPattern = checkRegexPreFilter(text);
  console.log("[LeakShield] 정규식 검사 결과 위험 여부:", hasSuspiciousPattern);

  if (hasSuspiciousPattern) {
    // 🛑 [물리 브레이크] 구글 챗의 현재 마우스 전송 동작을 이 자리에서 즉시 사살 (완전 소멸)
    if (e) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
    }

    // 2. 이미 화면에 경고 팝업이 떠 있는 상태에서 사용자가 종이비행기를 "한 번 더" 누른 경우 (강제 우회 발송)
    if (inputEl.dataset.doubleEnterPrompted === "true") {
      if (pendingAnalysis && pendingAnalysis.text === text) {
        pendingAnalysis.bypassed = true;
        if (pendingAnalysis.toastId) {
          dismissToast(pendingAnalysis.toastId);
        }
      }
      inputEl.dataset.doubleEnterPrompted = "false";
      inputEl.dataset.bypassSecurity = "false";

      console.warn("[LeakShield] 팝업이 떠 있는 상태에서 2회차 연속 클릭 감지. 강제 전송을 실행합니다...");

      // 우회 플래그를 세우고 안전하게 0.05초 뒤 재클릭하여 발송 성공시킴
      inputEl.dataset.bypassSecurity = "true";
      sendButton.dataset.lastInterceptTime = '0';
      setTimeout(() => {
        sendButton.click();
      }, 50);
      return;
    }

    // 3. [핵심] 첫 번째 클릭 시: 발송을 무조건 틀어막고 팝업 가동 상태로 바꾼 뒤 함수를 끝냅니다.
    console.warn("[LeakShield] 1회차 클릭 차단 성공. 더블클릭 대기 상태(doubleEnterPrompted=true)로 전환합니다.");
    inputEl.dataset.doubleEnterPrompted = "true";

    if (activeWarningToastId) {
      dismissToast(activeWarningToastId);
      activeWarningToastId = null;
    }

    // 4. [중요] 이미 화면에 실시간 입력 감지 팝업(.leakshield-toast)이 떠 있다면, 
    // 중복으로 띄우지 않고 전송 차단(락)만 걸어둔 채 여기서 함수를 안전하게 끝냅니다. (이게 엔터와 동일한 원리)
    if (document.querySelector('.leakshield-toast')) {
      console.log("[LeakShield] 이미 화면에 실시간 경고 팝업이 떠 있으므로 전송만 차단하고 대기합니다.");
      return;
    }

    // 5. 만약 팝업이 화면에 없었다면 (X를 눌러서 껐거나 안 떴던 상태라면) 여기서 팝업을 새로 띄워줍니다.
    const localConfirmedLeak = checkConfirmedLeak(text);
    const categoryName = localConfirmedLeak ? localConfirmedLeak.category : "민감 정보";
    const reasonText = localConfirmedLeak ? localConfirmedLeak.reason : "보안 가이드라인 위배 위험";

    showToast({
      title: "보안 유출 전송 차단!",
      message: `[${categoryName}] 유출 위험이 감지되어 메시지 전송이 보안 차단되었습니다.<br>사유: ${reasonText}<br><br><strong>강제 전송이 필요하시면 전송 버튼을 한 번 더 누르시거나, <kbd>Ctrl</kbd> + <kbd>Enter</kbd> 키를 누르시면 즉시 전송됩니다.</strong>`,
      riskLevel: "CRITICAL",
      category: categoryName,
      snippet: text.substring(0, 100),
      duration: 0
    });

    if (localConfirmedLeak) {
      safeSendMessage({
        action: 'log_leak',
        leak: {
          snippet: localConfirmedLeak.leakSnippet,
          category: localConfirmedLeak.category,
          riskLevel: localConfirmedLeak.riskLevel,
          reason: localConfirmedLeak.reason,
          fullText: text
        }
      }, () => {});
    }

    return; // 👈 캐시 로직이나 아래쪽 비동기 AI 분석 구역으로 새어나가지 못하게 단단히 잠금!
  }

  // --------------------------------------------------------------------------------
  // [여기서부터는 기존 안전 문장 전송 및 백그라운드 AI 분석 로직입니다. 변경 없이 그대로 복사되었습니다.]
  // --------------------------------------------------------------------------------
  const localConfirmedLeak = checkConfirmedLeak(text);
  const cachedLeak = checkLocalLeakCache(text);
  const aiResult = localConfirmedLeak || cachedLeak || (lastAnalysisResult && lastAnalysisResult.text === text ? lastAnalysisResult.result : null);

  if (aiResult) {
    console.log("[LeakShield] 캐시된 분석 결과를 사용하여 즉시 처리합니다:", aiResult);

    if (aiResult.isLeak) {
      inputEl.dataset.doubleEnterPrompted = "false";
      showToast({
        title: "보안 유출 전송 차단!",
        message: `[${aiResult.category}] 유출 위험이 감지되어 메시지 전송이 보안 차단되었습니다.<br>사유: ${aiResult.reason}<br><br><strong>강제 전송이 필요하시면 전송 버튼을 한 번 더 누르시거나, <kbd>Ctrl</kbd> + <kbd>Enter</kbd> 키를 누르시면 즉시 전송됩니다.</strong>`,
        riskLevel: aiResult.riskLevel || "CRITICAL",
        category: aiResult.category,
        snippet: aiResult.leakSnippet || text.substring(0, 100),
        duration: 0
      });
    } else {
      showToast({
        title: "보안 안전 검증 완료",
        message: "분석 결과 안전함이 확인되었습니다. 메시지를 자동 전송합니다.",
        riskLevel: "INFO",
        category: "System",
        duration: 4000
      });
      inputEl.dataset.bypassSecurity = "true";
      inputEl.dataset.doubleEnterPrompted = "false";
      sendButton.click();
    }
    return;
  }

  // 캐시가 없을 때 비동기 AI 정밀 분석 시작
  const loadingToastId = showToast({
    title: "실시간 보안 분석 대기 중...",
    message: "민감 정보 유출 위험이 감지되어 정밀 AI 보안 분석을 진행 중입니다.<br><strong>급한 상황이시라면 전송 버튼을 한 번 더 누르시거나, Ctrl + Enter 키를 누르시면 즉시 전송됩니다.</strong>",
    riskLevel: "WARNING",
    category: "System",
    duration: 0,
    isLoading: true
  });

  pendingAnalysis = {
    text: text,
    bypassed: false,
    toastId: loadingToastId
  };

  safeSendMessage({ action: 'analyze_text', text: text }, (response) => {
    console.log("[LeakShield] 비동기 AI 분석 응답 도착:", response);
    const wasBypassed = pendingAnalysis && pendingAnalysis.text === text && pendingAnalysis.bypassed;
    const currentToastId = pendingAnalysis && pendingAnalysis.text === text ? pendingAnalysis.toastId : loadingToastId;

    dismissToast(currentToastId);

    if (pendingAnalysis && pendingAnalysis.text === text) {
      pendingAnalysis = null;
    }

    if (response && response.success) {
      const aiResult = response.data;
      lastAnalysisResult = { text: text, result: aiResult };

      if (aiResult.isLeak) {
        const leakSnippet = aiResult.leakSnippet || text;
        if (leakSnippet && !recentLeaks.includes(leakSnippet)) {
          recentLeaks.push(leakSnippet);
        }
      }

      if (wasBypassed) {
        if (aiResult.isLeak) {
          showToast({
            title: "사후 보안 유출 감지!",
            message: `이미 전송된 메시지에서 [${aiResult.category}] 유출 위험이 사후 검증되었습니다.<br>보안 관리자 확인이 필요할 수 있습니다.<br><strong>사유: ${aiResult.reason}</strong>`,
            riskLevel: "CRITICAL",
            category: aiResult.category,
            snippet: aiResult.leakSnippet || text.substring(0, 100),
            duration: 0
          });
        }
      } else {
        if (inputEl.innerText.trim() !== "") {
          if (aiResult.isLeak) {
            inputEl.dataset.doubleEnterPrompted = "false";
            showToast({
              title: "보안 유출 전송 차단!",
              message: `[${aiResult.category}] 유출 위험이 감지되어 메시지 전송이 보안 차단되었습니다.<br>사유: ${aiResult.reason}<br><br><strong>강제 전송이 필요하시면 전송 버튼을 한 번 더 누르시거나, <kbd>Ctrl</kbd> + <kbd>Enter</kbd> 키를 누르시면 즉시 전송됩니다.</strong>`,
              riskLevel: aiResult.riskLevel || "CRITICAL",
              category: aiResult.category,
              snippet: aiResult.leakSnippet || text.substring(0, 100),
              duration: 0
            });
          } else {
            showToast({
              title: "보안 안전 검증 완료",
              message: "분석 결과 안전함이 확인되었습니다. 메시지를 자동 전송합니다.",
              riskLevel: "INFO",
              category: "System",
              duration: 4000
            });
            inputEl.dataset.bypassSecurity = "true";
            inputEl.dataset.doubleEnterPrompted = "false";
            sendButton.click();
          }
        }
      }
    } else {
      console.error("[LeakShield] AI 분석 실패 또는 한도 초과 오류 처리 영역 생략");
    }
  });
}

// Global document-level interceptor (capture phase) — fires BEFORE any element-level handler.
// This ensures we intercept the send button click before Google Chat's own handlers,
// regardless of whether the button was previously discovered by setupInputListeners.
const SEND_BUTTON_SELECTOR = 'div[role="button"][aria-label*="Send"], div[role="button"][aria-label*="전송"], div[role="button"][aria-label*="보내기"], div[role="button"][data-tooltip*="Send"], div[role="button"][data-tooltip*="전송"], div[role="button"][data-tooltip*="보내기"]';

['pointerdown', 'mousedown', 'click'].forEach(evtType => {
  document.addEventListener(evtType, (e) => {
    const sendButton = e.target.closest(SEND_BUTTON_SELECTOR);
    if (sendButton) {
      if (!isRealSendButton(sendButton)) return;
      const inputEl = document.querySelector('div[contenteditable="true"][role="textbox"]');

      if (inputEl) {
        const text = inputEl.innerText || "";

        if (checkRegexPreFilter(text) && inputEl.dataset.bypassSecurity !== "true") {
          // 1. 이벤트 무조건 취소 시도
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();

          // 2. [물리 차단 치트키] 구글 챗이 긁어갈 입력창 글자를 백업해 두고 순간적으로 삭제!
          // 구글 챗 전송 함수가 실행되더라도 "보낼 내용이 없네?" 하고 전송이 취소됩니다.
          const originalHTML = inputEl.innerHTML;
          inputEl.innerHTML = "";

          if (evtType === 'click') {
            const now = Date.now();
            const last = parseInt(sendButton.dataset.lastInterceptTime || '0');
            if (now - last < 300) return;
            sendButton.dataset.lastInterceptTime = String(now);

            // 3. 보안 팝업 레이어 등장 (질문자님의 팝업 함수 호출)
            handleSendClick(e, inputEl, sendButton);

            // 4. 구글 챗 엔진이 전송 시도를 끝마친 아주 잠깐 뒤(0.1초 후)에 조용히 원래 글자 복구
            setTimeout(() => {
              if (inputEl && inputEl.innerHTML === "") {
                inputEl.innerHTML = originalHTML;
                // 포커스를 다시 주어 사용자가 자연스럽게 수정할 수 있게 만듭니다.
                inputEl.focus();
              }
            }, 100);
          }
          return false;
        }
      }
    }
  }, true); // Capture Phase 1등 가로채기
});