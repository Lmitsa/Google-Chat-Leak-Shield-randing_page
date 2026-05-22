// Google Chat Real-Time Leak Detector - Content Script

// Built-in Regex Firewall - Confirmed Leaks (100% Local Hard Block, Skip API completely)
const CONFIRMED_REGEXES = {
  aws_key: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
  google_api: /\bAIza[0-9A-Za-z-_]{35}\b/,
  github_token: /\bghp_[0-9a-zA-Z]{36}\b|\bgithub_pat_[0-9a-zA-Z_]{82}\b/,
  slack_webhook: /https:\/\/hooks\.slack\.com\/services\/[T|B][A-Z0-9]{8}\/[B][A-Z0-9]{8}\/[A-Za-z0-9]{24}/,
  slack_token: /\bxox[bpar]-[0-9]{11,13}-[a-zA-Z0-9]{24}/,
  discord_token: /\b[A-Za-z0-9\-_]{24,28}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,38}\b/,
  discord_webhook: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,21}\/[A-Za-z0-9\-_]{68,76}/,
  stripe_key: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24}\b/,
  jwt_token: /\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b/,
  private_key: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----/,
  db_connection: /(?:mongodb(?:\+srv)?|mysql|postgresql|redis|sqlite|mssql|oracle):\/\/[%a-zA-Z0-9_\-\.\~+]+:[^@\s]+@[a-zA-Z0-9_\-\.\~%:]+/i,
  korean_rrn: /\b\d{6}\s*-\s*[1-490]\d{6}\b/,
  korean_brn: /\b\d{3}-\d{2}-\d{5}\b/,
  credit_card: /\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b/,
  openai_key: /\bsk-(?:proj-)?[a-zA-Z0-9-_]{40,120}\b/,
  anthropic_key: /\bsk-ant-[a-zA-Z0-9-_]{40,100}\b/,
  gcp_service_account: /"type"\s*:\s*"service_account"/i,
  azure_connection: /(?:DefaultEndpointsProtocol=https|AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]+)/
};

// Built-in Regex Firewall - Suspicious Leaks (AI-assisted verification required during sending)
const SUSPICIOUS_REGEXES = {
  generic_secret: /(?:key|token|secret|password|passwd|auth|credential|private_key|api_key|client_secret|db_password)\s*[:=]\s*["'][a-zA-Z0-9_\-\.\~\+\/]{16,}["']/i,
  source_code: /(?:import\s+[\s\S]+?\s+from|const\s+\w+\s*=\s*require|function\s+\w+\s*\(|def\s+\w+\s*\(|public\s+class\s+\w+|struct\s+\w+|#include\s+<\w+>)/,
  pii: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  passport_number: /\b[A-Z]\d{8}\b|\b[A-Z\d]\d[A-Z\d]\d\d{5}\b/i,
  driver_license: /\b\d{2}-\d{2}-\d{6}-\d{2}\b/,
  ip_address: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
  korean_bank: /\b\d{3,6}-\d{2,6}-\d{3,6}(?:-\d{1,3})?\b/
};
const BUILTIN_REGEXES = { ...CONFIRMED_REGEXES, ...SUSPICIOUS_REGEXES };

const RECOMMENDATIONS = {
  // Cloud & API Keys
  AWS_KEY: "💡 <strong>해결법:</strong> AWS IAM Role을 활용하여 하드코딩을 제거하고, 노출된 키는 AWS 콘솔에서 즉시 <strong>폐기(Deactivate) 및 재생성</strong>하세요.",
  GOOGLE_API: "💡 <strong>해결법:</strong> Google Cloud 콘솔의 'API 및 서비스'에서 해당 API 키의 <strong>접근 제한(IP/HTTP/API 제한)</strong>을 설정하거나 즉시 재발급하세요.",
  GITHUB_TOKEN: "💡 <strong>해결법:</strong> GitHub 개인 액세스 토큰(PAT)이 노출된 경우 GitHub 설정에서 즉시 <strong>토큰을 삭제(Revoke)</strong>하고 새로 발급받으세요.",
  STRIPE_KEY: "💡 <strong>해결법:</strong> Stripe 대시보드의 API Keys 메뉴에서 노출된 키를 즉시 <strong>롤오버(Roll key)</strong>하여 폐기하고 재발급하세요.",
  OPENAI_KEY: "💡 <strong>해결법:</strong> OpenAI API 키가 유출된 경우 OpenAI 플랫폼의 API Keys 메뉴에서 즉시 해당 키를 <strong>삭제(Revoke)</strong>하세요.",
  ANTHROPIC_KEY: "💡 <strong>해결법:</strong> Anthropic 콘솔의 API Keys 메뉴에서 노출된 키를 즉시 <strong>비활성화(Delete)</strong>하고 재발급하세요.",

  // Webhooks & Messengers
  SLACK_WEBHOOK: "💡 <strong>해결법:</strong> Slack Webhook URL은 무단 알림 발송에 도용될 수 있으므로, Slack 앱 관리자 설정에서 해당 <strong>웹훅을 비활성화/삭제</strong>하세요.",
  SLACK_TOKEN: "💡 <strong>해결법:</strong> Slack API 토큰이 노출된 경우 해당 앱/봇의 토큰을 즉시 <strong>재생성(Regenerate)</strong>하여 이전 토큰을 무효화하세요.",
  DISCORD_TOKEN: "💡 <strong>해결법:</strong> Discord 봇 토큰이 감지되었습니다. Discord Developer Portal에서 봇의 <strong>토큰을 즉시 재설정(Reset Token)</strong>하여 탈취를 방지하세요.",
  DISCORD_WEBHOOK: "💡 <strong>해결법:</strong> Discord 서버 설정의 웹훅(Integrations) 메뉴에서 노출된 <strong>웹훅 주소를 삭제</strong>하고 새로 생성하세요.",

  // Credentials & Systems
  JWT_TOKEN: "💡 <strong>해결법:</strong> JWT 세션 정보는 사용자 로그인 상태를 도용당할 수 있습니다. 세션 만료 시간을 짧게 설정하고 노출 즉시 로그아웃(세션 폐기) 처리를 권장합니다.",
  PRIVATE_KEY: "💡 <strong>해결법:</strong> 프라이빗 키(개인 키)는 암호화 해독 및 서버 직접 접속의 최상위 자산입니다. 노출된 키는 절대 다시 사용하지 마시고, 서버의 <strong>authorized_keys에서 즉시 삭제 및 키페어를 재생성</strong>하세요.",
  DB_CONNECTION: "💡 <strong>해결법:</strong> 데이터베이스 비밀번호가 평문으로 포함되어 있습니다. 즉시 데이터베이스의 <strong>해당 계정 비밀번호를 변경</strong>하고, 공유 시에는 비밀번호 관리도구(Vault)를 이용하세요.",
  GCP_SERVICE_ACCOUNT: "💡 <strong>해결법:</strong> GCP 서비스 계정 키 파일의 유출이 의심됩니다. Google Cloud 콘솔의 'IAM 및 관리자 > 서비스 계정'에서 해당 키를 즉시 <strong>삭제 및 폐기</strong>하세요.",
  AZURE_CONNECTION: "💡 <strong>해결법:</strong> Azure 연결 정보 유출 시 데이터 탈취 위험이 있습니다. Azure 포털에서 해당 스토리지 계정 또는 데이터베이스의 <strong>접속 키(Access Key)를 즉시 재생성(Rotate)</strong>하세요.",

  // Personal Info
  KOREAN_RRN: "💡 <strong>해결법:</strong> 주민등록번호는 법적으로 수집/공유가 금지됩니다. 반드시 뒷자리 7자리를 마스킹 처리(예: 950520-*******)한 후 전송하세요.",
  KOREAN_BRN: "💡 <strong>해결법:</strong> 사내 업무 목적 외 무단 공유는 자제하시고, 필요 시 사업자등록번호의 뒷자리 부분을 마스킹하여 전송하세요.",
  CREDIT_CARD: "💡 <strong>해결법:</strong> 신용카드 번호 유출 시 부정 결제 피해를 입을 수 있습니다. 반드시 중간 8자리를 마스킹(예: 1234-****-****-5678)하여 공유하세요.",
  PASSPORT_NUMBER: "💡 <strong>해결법:</strong> 여권번호 유출 방지를 위해 식별 번호 중 뒷자리 4~5자리를 마스킹 처리하여 안전하게 발송하세요.",
  DRIVER_LICENSE: "💡 <strong>해결법:</strong> 운전면허 번호 유출 방지를 위해 지역 코드를 제외한 일련번호 뒷부분을 마스킹하여 전송하세요.",
  KOREAN_BANK: "💡 <strong>해결법:</strong> 계좌번호 유출 방지를 위해 가급적 계좌번호의 중간 부분을 마스킹 처리(예: 110-***-123456)한 뒤 예금주명과 함께 발송하세요.",

  // Heuristics
  GENERIC_SECRET: "💡 <strong>해결법:</strong> 소스 코드나 텍스트 파일 내 자격 증명이 노출되었습니다. 소스 코드 배정 방식 대신 환경변수(`.env`)를 활용하여 비밀정보를 격리하세요.",
  SOURCE_CODE: "💡 <strong>해결법:</strong> 사내 소스 코드는 지적 자산 및 잠재적 취약점 누출 경로입니다. 공유가 필수적이라면 핵심 로직만 간추리고 기밀 키워드가 제거되었는지 다시 점검하세요.",
  PII: "💡 <strong>해결법:</strong> 이메일 등 개인 식별 정보가 감지되었습니다. 불필요한 개인 정보 공유는 피하시고, 식별 불가능하도록 부분 마스킹 처리를 권장합니다.",
  IP_ADDRESS: "💡 <strong>해결법:</strong> 내부망/서버 IP 주소 노출은 해킹 공격의 표적이 될 수 있습니다. 공유 시 가급적 일부 대역을 마스킹(예: 192.168.*.*)하여 사용하세요.",

  // General Categories (Fallback from Gemini AI)
  CREDENTIAL: "💡 <strong>해결법:</strong> 기밀 자격 증명이 노출되었습니다. 해당 키/토큰을 즉시 비활성화하거나 재생성하시고, 코드 하드코딩 대신 환경변수나 시큐어 볼트(Vault) 서비스를 사용해 주세요.",
  SYSTEM: "💡 <strong>해결법:</strong> 서버 정보 및 내부 시스템 아키텍처 노출 위험이 있습니다. 중요 식별자나 IP 대역을 마스킹하고, 권한이 있는 담당자에게만 보안 채널로 공유해 주세요."
};