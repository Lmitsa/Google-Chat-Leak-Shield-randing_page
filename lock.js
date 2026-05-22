/****************************************************************************
 * LeakShield - 선제적 UI 잠금 시스템 (Proactive UI Lock Engine)
 * [진입 즉시 무조건 선잠금 버전 - 파일 최하단 덮어쓰기]
 ****************************************************************************/
(() => {
  const SEND_BUTTON_SELECTOR = '[role="button"][aria-label*="Send"], [role="button"][aria-label*="전송"], [role="button"][aria-label*="보내기"], [role="button"][data-tooltip*="Send"], [role="button"][data-tooltip*="전송"], [role="button"][data-tooltip*="보내기"], button[aria-label*="Send"], button[aria-label*="전송"], button[aria-label*="보내기"]';
  const LOCK_SHIELD_ID = 'leakshield-proactive-button-lock';

  function getRealSendButton() {
    const candidates = document.querySelectorAll(SEND_BUTTON_SELECTOR);
    for (const candidate of candidates) {
      if (isRealSendButton(candidate)) {
        return candidate;
      }
    }
    return null;
  }

  function 제어_물리잠금벽(잠글까) {
    const sendButton = getRealSendButton();
    if (!sendButton) return;

    let lockShield = document.getElementById(LOCK_SHIELD_ID);

    if (잠글까) {
      const rect = sendButton.getBoundingClientRect();
      // rect의 크기가 0이 아닐 때만 물리 잠금벽을 씌움
      if (rect.width === 0 || rect.height === 0) {
        if (lockShield) {
          lockShield.style.display = 'none';
        }
        return;
      }

      if (!lockShield) {
        lockShield = document.createElement('div');
        lockShield.id = LOCK_SHIELD_ID;
        lockShield.className = 'leakshield-proactive-lock-wall';

        // inline style로 물리적 팝업 잠금(Overlay) 속성 설정
        lockShield.style.position = 'fixed';
        lockShield.style.zIndex = '2147483647';
        lockShield.style.cursor = 'not-allowed';
        lockShield.style.backgroundColor = 'rgba(239, 68, 68, 0.2)'; // 빨간 오버레이를 통해 시각적으로 팝업(가림) 인지 유도
        lockShield.style.border = '2.5px solid #ef4444';
        lockShield.style.borderRadius = '50%';
        lockShield.style.boxShadow = '0 0 10px rgba(239, 68, 68, 0.6)';

        lockShield.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();

          console.warn("[LeakShield] 잠금벽 전면 충돌! 위험 문장 수정을 유도하거나 빈 입력 상태입니다.");

          const inputEl = document.querySelector('div[contenteditable="true"][role="textbox"]');
          if (inputEl && sendButton) {
            // 텍스트가 있을 때만 기존 팝업 함수를 트리거합니다.
            if ((inputEl.innerText || "").trim().length > 0) {
              handleSendClick(e, inputEl, sendButton);
            }
          }
        }, true);

        document.body.appendChild(lockShield);
      }

      lockShield.style.top = `${rect.top}px`;
      lockShield.style.left = `${rect.left}px`;
      lockShield.style.width = `${rect.width}px`;
      lockShield.style.height = `${rect.height}px`;
      lockShield.style.display = 'block';
    } else {
      if (lockShield) {
        lockShield.style.display = 'none';
      }
    }
  }

  function 실시간_텍스트_보안진단() {
    const inputEl = document.querySelector('div[contenteditable="true"][role="textbox"]');
    const sendButton = getRealSendButton();

    // 전송 버튼 자체가 없다면 잠금벽 제어를 할 수 없으므로 해제 처리
    if (!sendButton) {
      제어_물리잠금벽(false);
      return;
    }

    // 1. 채팅 페이지에 들어왔으나 아직 입력창 요소를 찾지 못한 경우 (진입 초기), 무조건 전송을 잠급니다.
    if (!inputEl) {
      제어_물리잠금벽(true);
      if (activeWarningToastId) {
        dismissToast(activeWarningToastId);
        activeWarningToastId = null;
      }
      return;
    }

    const text = (inputEl.innerText || "").trim();

    // 2. 강제 우회 상태가 활성화되어 있다면 즉시 잠금을 해제하여 전송 길을 열어줍니다.
    if (inputEl.dataset.bypassSecurity === "true") {
      제어_물리잠금벽(false);
      return;
    }

    // 3. 입력창이 완전히 비어있다면, 차단막은 켜고 경고창은 지웁니다.
    if (text === "") {
      제어_물리잠금벽(true);
      if (activeWarningToastId) {
        dismissToast(activeWarningToastId);
        activeWarningToastId = null;
      }
      return;
    }

    // 4. 정규식 필터에 걸리는 위험 문장이라면 "무조건 잠금" 및 "즉시 경고 Toast 노출"
    if (checkRegexPreFilter(text)) {
      제어_물리잠금벽(true);  // 🚨 위험 시 빨간 막 가동!

      // 아직 경고 팝업이 없는 상태라면 즉시 띄웁니다.
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
          duration: 0 // 사용자가 고치거나 강제우회 전송할 때까지 유지
        });
      }
    } else {
      // 5. 무언가 입력되었고, 정규식 검사 결과 안전함이 100% 확정되었을 때만 빨간 막을 치우고, 경고창도 지웁니다.
      제어_물리잠금벽(false); // ✨ 잠금 해제 (순정 버튼 노출)

      if (activeWarningToastId) {
        dismissToast(activeWarningToastId);
        activeWarningToastId = null;
      }
    }
  }

  // 사용자의 실시간 액션 감지
  document.addEventListener('input', 실시간_텍스트_보안진단);
  document.addEventListener('keyup', 실시간_텍스트_보안진단);
  document.addEventListener('mousemove', 실시간_텍스트_보안진단, true);

  window.addEventListener('resize', () => {
    const lockShield = document.getElementById(LOCK_SHIELD_ID);
    if (lockShield && lockShield.style.display === 'block') {
      제어_물리잠금벽(true);
    }
  });

  // 중요: 구글 챗 방에 진입하자마자 입력창이 빈 상태일 때 버튼을 바로 낚아채기 위해 
  // 인터벌 주기를 0.2초(200ms)로 더 촘촘하게 당겨서 선제 공격을 날립니다.
  setInterval(실시간_텍스트_보안진단, 200);
})();