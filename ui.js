// Toast Manager
function getOrCreateToastContainer() {
  let container = document.getElementById('leak-shield-toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'leak-shield-toast-container';
    document.body.appendChild(container);
  }
  return container;
}

function showToast({ title, message, riskLevel, category, snippet, duration = 8000, isLoading = false }) {
  const container = getOrCreateToastContainer();
  const id = 'toast_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5);

  const toast = document.createElement('div');
  toast.className = `leak-shield-toast leak-shield-toast-${riskLevel.toLowerCase()}`;
  toast.id = id;

  // Premium glow and border animations
  let borderGlow = '';
  if (riskLevel === 'CRITICAL') borderGlow = 'box-shadow: 0 0 15px rgba(239, 68, 68, 0.4);';
  else if (riskLevel === 'WARNING') borderGlow = 'box-shadow: 0 0 15px rgba(245, 158, 11, 0.3);';
  else borderGlow = 'box-shadow: 0 0 15px rgba(59, 130, 246, 0.2);';

  toast.setAttribute('style', borderGlow);

  let iconHtml = '';
  if (isLoading) {
    iconHtml = `<div class="leak-shield-spinner"></div>`;
  } else {
    const iconColor = riskLevel === 'CRITICAL' ? '#ef4444' : (riskLevel === 'WARNING' ? '#f59e0b' : '#3b82f6');
    iconHtml = `
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    `;
  }

  const badgeColor = riskLevel === 'CRITICAL' ? 'bg-red' : (riskLevel === 'WARNING' ? 'bg-amber' : 'bg-blue');

  // Look up recommendation advice based on the category
  let recommendationHtml = '';
  if (category) {
    const key = category.toUpperCase().trim().replace(/ /g, '_');
    if (RECOMMENDATIONS[key]) {
      recommendationHtml = `
        <div class="leak-shield-toast-recommendation">
          ${RECOMMENDATIONS[key]}
        </div>
      `;
    }
  }

  toast.innerHTML = `
    <div class="leak-shield-toast-header">
      <div class="leak-shield-toast-icon">${iconHtml}</div>
      <div class="leak-shield-toast-title-area">
        <span class="leak-shield-toast-title">${title}</span>
        <span class="leak-shield-toast-badge ${badgeColor}">${category}</span>
      </div>
      <button class="leak-shield-toast-close">&times;</button>
    </div>
    <div class="leak-shield-toast-body">
      <p class="leak-shield-toast-text">${message.replace(/\n/g, '<br>')}</p>
      ${recommendationHtml}
      ${snippet ? `
        <div class="leak-shield-toast-snippet">
          <code>${escapeHtml(snippet)}</code>
        </div>
      ` : ''}
    </div>
  `;

  // Append toast
  container.appendChild(toast);

  // Smooth slide-in
  setTimeout(() => {
    toast.classList.add('visible');
  }, 50);

  // Close Event
  toast.querySelector('.leak-shield-toast-close').addEventListener('click', () => {
    dismissToast(id);
  });

  // Auto-dismiss setup
  if (duration > 0) {
    setTimeout(() => {
      dismissToast(id);
    }, duration);
  }

  return id;
}

function dismissToast(id) {
  const toast = document.getElementById(id);
  if (toast) {
    toast.classList.remove('visible');
    toast.classList.add('dismissed');
    setTimeout(() => {
      toast.remove();
    }, 400); // Wait for transition out
  }
}