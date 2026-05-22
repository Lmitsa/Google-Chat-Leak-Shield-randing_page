// Simulator Script - Client Side Protection Simulation Engine
const inputArea = document.getElementById('simulator-input');
const sendBtn = document.getElementById('simulator-send-btn');
const chatStream = document.getElementById('chat-stream');
const shieldStatus = document.getElementById('shield-status');
const toastContainer = document.getElementById('simulator-toast-container');
const presetBtns = document.querySelectorAll('.preset-btn');

// Leak Regex definitions matching content.js strictly
const LEAK_PATTERNS = [
  {
    name: 'AWS Access Key ID',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: '공개된 AWS 자격증명은 악의적 인프라 도용 및 자원 소모의 위험성이 있습니다.'
  },
  {
    name: 'Google Gemini API Key',
    regex: /\bAIza[0-9A-Za-z-_]{35}\b/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: 'Google Cloud 및 Gemini API Key가 포착되었습니다. 불법 API 악용 요금 청구 위협이 존재합니다.'
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /\bghp_[0-9a-zA-Z]{36}\b|\bgithub_pat_[0-9a-zA-Z_]{82}\b/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: 'GitHub 개인 액세스 토큰이 노출되었습니다. 소스 코드 유출 및 악의적 레포 변조 위험이 큽니다.'
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/[T|B][A-Z0-9]{8}\/[B][A-Z0-9]{8}\/[A-Za-z0-9]{24}/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: 'Slack 수신 웹훅 주소가 노출되었습니다. 외부 악의적 메시지 스팸 전송에 도용될 수 있습니다.'
  },
  {
    name: 'Slack API Token',
    regex: /\bxox[bpar]-[0-9]{11,13}-[a-zA-Z0-9]{24}/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: 'Slack API 인증 토큰(Bot, User 등)이 감지되었습니다. 사내 메신저 권한 탈취 사고로 이어질 수 있습니다.'
  },
  {
    name: 'Discord Bot Token',
    regex: /\b[A-Za-z0-9\-_]{24,28}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,38}\b/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: '디스코드 봇 토큰이 포착되었습니다. 봇 권한을 통한 채널 및 서버 변조 공격에 사용될 수 있습니다.'
  },
  {
    name: 'Discord Webhook URL',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,21}\/[A-Za-z0-9\-_]{68,76}/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: '디스코드 웹훅 주소가 포착되었습니다. 외부에서의 권한 없는 무단 알림 발송에 노출됩니다.'
  },
  {
    name: 'Stripe API Key',
    regex: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24}\b/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: 'Stripe 결제 API 키가 유출되었습니다. 무단 결제 처리 및 재무 정보 접근 위협이 심각합니다.'
  },
  {
    name: 'JWT Session Token',
    regex: /\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b/,
    severity: 'warning',
    badge: 'WARNING',
    description: 'JSON Web Token(JWT) 세션 정보가 감지되었습니다. 사용자 세션 하이재킹 및 무단 인증 우회가 발생할 수 있습니다.'
  },
  {
    name: 'Private Key Block',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: '프라이빗 키 블록은 원격 서버 원격 셸 접속 권한 또는 데이터 암호화 해독 권한을 부여하는 최상위 등급 기밀 정보입니다.'
  },
  {
    name: 'Database URI Credential',
    regex: /(?:mongodb(?:\+srv)?|mysql|postgresql|redis|sqlite|mssql|oracle):\/\/[%a-zA-Z0-9_\-\.\~+]+:[^@\s]+@[a-zA-Z0-9_\-\.\~%:]+/i,
    severity: 'critical',
    badge: 'CRITICAL',
    description: '데이터베이스 유저 패스워드 및 커넥션 주소가 평문 노출되었습니다. 즉각 차단해야 합니다.'
  },
  {
    name: 'Korean Resident Registration Number',
    regex: /\b\d{6}\s*-\s*[1-490]\d{6}\b/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: '주민등록번호(RRN)는 타 법률에 의거 수집 및 전송이 원천 금지되는 최상위 등급의 민감 개인정보입니다.'
  },
  {
    name: 'Korean Business Registration Number',
    regex: /\b\d{3}-\d{2}-\d{5}\b/,
    severity: 'warning',
    badge: 'WARNING',
    description: '사업자등록번호 양식이 노출되었습니다. 기업의 민감 비즈니스 파트너 식별자 누출 위험이 있습니다.'
  },
  {
    name: 'Credit Card Number',
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b/,
    severity: 'critical',
    badge: 'CRITICAL',
    description: '카드 결제 자격 증명 번호가 감지되었습니다. 금융 부정 결제 및 결제 사기 피해로 연계될 수 있습니다.'
  }
];

// Local Scan state memory
let typingTimer = null;
let recentLeaks = [];

// Dynamically adjust textarea heights
inputArea.addEventListener('input', function () {
  this.style.height = 'auto';
  this.style.height = (this.scrollHeight - 8) + 'px';

  if (this.value.trim().length > 0) {
    sendBtn.classList.add('active');
  } else {
    sendBtn.classList.remove('active');
  }

  // Mimic Content JS Typing delay
  shieldStatus.innerHTML = '<span class="leak-shield-spinner" style="display:inline-block;vertical-align:middle;margin-right:8px;"></span>AI & Regex Scanning...';
  shieldStatus.classList.add('scanning');

  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => {
    analyzeText(this.value);
    shieldStatus.innerHTML = '<svg style="width:12px;height:12px;fill:currentColor" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 15l-4-4 1.41-1.41L10 13.17l5.59-5.59L17 9l-7 7z"/></svg> Leak Shield Active';
    shieldStatus.classList.remove('scanning');
  }, 500);
});

// Preset button clicks helper
presetBtns.forEach(btn => {
  btn.addEventListener('click', function () {
    const text = this.getAttribute('data-text');
    inputArea.value = text;
    inputArea.dispatchEvent(new Event('input'));
    inputArea.focus();
  });
});

// Send Message Simulator
sendBtn.addEventListener('click', sendMessage);
inputArea.addEventListener('keydown', function (e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

function sendMessage() {
  const text = inputArea.value.trim();
  if (!text) return;

  // Scan one last time before sending
  const foundLeaks = analyzeText(text);

  // Emulate Chat Bubble appending
  const newMsg = document.createElement('div');
  newMsg.className = 'message-row';
  newMsg.innerHTML = `
    <div class="msg-avatar" style="background:#424242">평</div>
    <div class="msg-content">
      <div class="msg-sender">평가자 (Evaluator)</div>
      <div class="msg-text">${escapeHtml(text)}</div>
    </div>
  `;
  chatStream.appendChild(newMsg);
  chatStream.scrollTop = chatStream.scrollHeight;

  // Clear input
  inputArea.value = '';
  inputArea.style.height = '24px';
  sendBtn.classList.remove('active');
}

// Local Scanner Execution
function analyzeText(text) {
  if (!text) return [];

  const leaksDetected = [];

  LEAK_PATTERNS.forEach(pattern => {
    const match = text.match(pattern.regex);
    if (match) {
      const matchedString = match[0];

      // Skip if already toasted just recently to avoid noise
      if (!recentLeaks.includes(matchedString)) {
        recentLeaks.push(matchedString);
        triggerSimulatorToast(pattern, matchedString);
        leaksDetected.push(matchedString);
      }
    }
  });

  return leaksDetected;
}

// Simulated Premium Toast Trigger
function triggerSimulatorToast(pattern, matchedSnippet) {
  const toastId = 'toast-' + Math.random().toString(36).substr(2, 9);

  const toast = document.createElement('div');
  toast.id = toastId;
  toast.className = `leak-shield-toast leak-shield-toast-${pattern.severity}`;

  const badgeClass = pattern.severity === 'critical' ? 'bg-red' : 'bg-amber';

  toast.innerHTML = `
    <div class="leak-shield-toast-header">
      <div class="leak-shield-toast-icon">
        <svg style="width:20px;height:20px;fill:${pattern.severity === 'critical' ? '#ef4444' : '#f59e0b'}" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
      </div>
      <div class="leak-shield-toast-title-area">
        <span class="leak-shield-toast-title">민감 정보 유출 정황 포착</span>
        <span class="leak-shield-toast-badge ${badgeClass}">${pattern.badge}</span>
      </div>
      <button class="leak-shield-toast-close" onclick="dismissSimulatorToast('${toastId}')">&times;</button>
    </div>
    <div class="leak-shield-toast-body">
      <p class="leak-shield-toast-text">${pattern.description}</p>
      <div class="leak-shield-toast-snippet">
        <code>${escapeHtml(matchedSnippet)}</code>
      </div>
    </div>
  `;

  toastContainer.appendChild(toast);

  // Force Reflow & Show
  setTimeout(() => {
    toast.classList.add('visible');
  }, 50);
}

// Manual Close Trigger (Evaluator must click X)
window.dismissSimulatorToast = function (id) {
  const toast = document.getElementById(id);
  if (toast) {
    toast.classList.remove('visible');
    toast.classList.add('dismissed');
    setTimeout(() => {
      toast.remove();
    }, 400);
  }
};

// Helper functions
function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
