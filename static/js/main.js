/* ── Barangay Management System — Main JavaScript ──────────────── */

// ── Dark Mode ────────────────────────────────────
function toggleTheme() {
  const html = document.documentElement;
  const theme = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
}

function initTheme() {
  const saved = localStorage.getItem('theme');
  if (saved === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
}
initTheme();

// ── Confirm Dialog ────────────────────────────────────
function showConfirm(message, callback, options = {}) {
  const { title = 'Confirm Action', confirmText = 'Yes, proceed', cancelText = 'Cancel', variant = 'danger' } = options;
  let overlay = document.getElementById('confirmOverlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'confirmOverlay';
    overlay.className = 'confirm-overlay';
    overlay.innerHTML = `
      <div class="confirm-dialog">
        <div class="confirm-header">
          <div class="confirm-icon ${variant}">
            <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </div>
          <div class="confirm-title" id="confirmTitle">${title}</div>
          <div class="confirm-message" id="confirmMessage">${message}</div>
        </div>
        <div class="confirm-actions">
          <button class="btn btn-outline" id="confirmCancel">${cancelText}</button>
          <button class="btn btn-${variant}" id="confirmOk">${confirmText}</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) closeConfirm();
    });
  } else {
    document.getElementById('confirmTitle').textContent = title;
    document.getElementById('confirmMessage').textContent = message;
    document.getElementById('confirmOk').className = `btn btn-${variant}`;
    document.getElementById('confirmOk').textContent = confirmText;
    document.getElementById('confirmCancel').textContent = cancelText;
    const icon = overlay.querySelector('.confirm-icon');
    icon.className = `confirm-icon ${variant}`;
  }

  overlay.classList.add('show');

  document.getElementById('confirmOk').onclick = function() {
    closeConfirm();
    if (typeof callback === 'function') callback();
  };
  document.getElementById('confirmCancel').onclick = closeConfirm;
}

function closeConfirm() {
  const overlay = document.getElementById('confirmOverlay');
  if (overlay) overlay.classList.remove('show');
}

// ── Password Strength Meter ──────────────────────────────
function initPasswordStrength(inputId, meterId, textId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const meter = document.getElementById(meterId);
  const text = document.getElementById(textId);

  input.addEventListener('input', function() {
    const val = this.value;
    let score = 0;
    if (val.length >= 8) score++;
    if (val.length >= 12) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[a-z]/.test(val)) score++;
    if (/\d/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;

    if (!meter || !text) return;
    const bars = meter.querySelectorAll('.strength-bar');
    let level = score <= 2 ? 'weak' : score <= 4 ? 'medium' : 'strong';
    let label = score <= 2 ? 'Weak' : score <= 4 ? 'Medium' : 'Strong';

    bars.forEach((bar, i) => {
      bar.className = 'strength-bar';
      if (i < Math.min(score, 6)) bar.classList.add('active', level);
    });
    text.textContent = label;
    text.className = 'strength-text ' + level;
  });
}

// ── Inline Form Validation ─────────────────────────────────
function showFieldError(inputId, message) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const group = input.closest('.form-group');
  if (!group) return;
  let err = group.querySelector('.field-error');
  if (!err) {
    err = document.createElement('div');
    err.className = 'field-error';
    group.appendChild(err);
  }
  err.textContent = message;
  err.classList.add('show');
  group.classList.add('has-error');
}

function clearFieldError(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const group = input.closest('.form-group');
  if (!group) return;
  group.classList.remove('has-error');
  const err = group.querySelector('.field-error');
  if (err) err.classList.remove('show');
}

function clearAllErrors(formId) {
  const form = document.getElementById(formId);
  if (!form) return;
  form.querySelectorAll('.form-group').forEach(g => {
    g.classList.remove('has-error');
    const err = g.querySelector('.field-error');
    if (err) err.classList.remove('show');
  });
}

// ── Pagination ────────────────────────────────────
function renderPagination(containerId, currentPage, totalPages, onPage) {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (totalPages <= 1) { container.innerHTML = ''; return; }

  let html = '';
  html += `<button class="page-btn" data-page="${currentPage - 1}" ${currentPage <= 1 ? 'disabled' : ''}>&lsaquo;</button>`;

  let start = Math.max(1, currentPage - 2);
  let end = Math.min(totalPages, currentPage + 2);
  if (start > 1) html += `<button class="page-btn" data-page="1">1</button>`;
  if (start > 2) html += `<span class="page-info">...</span>`;

  for (let i = start; i <= end; i++) {
    html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
  }

  if (end < totalPages - 1) html += `<span class="page-info">...</span>`;
  if (end < totalPages) html += `<button class="page-btn" data-page="${totalPages}">${totalPages}</button>`;

  html += `<button class="page-btn" data-page="${currentPage + 1}" ${currentPage >= totalPages ? 'disabled' : ''}>&rsaquo;</button>`;

  container.innerHTML = html;
  container.querySelectorAll('.page-btn:not(:disabled)').forEach(btn => {
    btn.addEventListener('click', function() {
      const page = parseInt(this.dataset.page);
      if (page && page !== currentPage) onPage(page);
    });
  });
}

// ── Skeleton Helpers ──────────────────────────────────────
function showSkeleton(containerId, rows = 5, columns = 4) {
  const container = document.getElementById(containerId);
  if (!container) return;
  let html = '';
  for (let i = 0; i < rows; i++) {
    html += '<div class="skeleton-row">';
    for (let j = 0; j < columns; j++) {
      html += `<div class="skeleton skeleton-text" style="width:${30 + Math.random() * 40}%"></div>`;
    }
    html += '</div>';
  }
  container.innerHTML = html;
}

// ── Toast Notifications ─────────────────────────────
function showToast(message, type = 'success') {
  const container = document.querySelector('.toast-container');
  if (!container) {
    const div = document.createElement('div');
    div.className = 'toast-container';
    document.body.appendChild(div);
  }
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span>${message}</span>
    <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
  `;
  document.querySelector('.toast-container').appendChild(toast);
  setTimeout(() => {
    if (toast.parentElement) toast.remove();
  }, 4000);
}

// ── Modal Helpers ───────────────────────────────────
function openModal(id) {
  document.getElementById(id).classList.add('show');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('show');
}

// Close modal on backdrop click
document.addEventListener('click', function(e) {
  if (e.target.classList.contains('modal-overlay')) {
    e.target.classList.remove('show');
  }
});

// ── Formatting Helpers ──────────────────────────────
function formatDate(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-PH', { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatDateTime(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-PH', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

function computeAge(birthdate) {
  if (!birthdate) return 0;
  const bd = new Date(birthdate);
  const today = new Date();
  let age = today.getFullYear() - bd.getFullYear();
  const m = today.getMonth() - bd.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < bd.getDate())) age--;
  return age;
}

function statusBadge(status) {
  const map = {
    'Pending': 'badge-pending',
    'Processing': 'badge-processing',
    'Ready': 'badge-ready',
    'Released': 'badge-released',
    'Rejected': 'badge-rejected',
    'Filed': 'badge-filed',
    'Under Investigation': 'badge-investigation',
    'Resolved': 'badge-resolved',
    'Dismissed': 'badge-dismissed'
  };
  const cls = map[status] || 'badge-pending';
  return `<span class="badge ${cls}">${status}</span>`;
}

// ── CSRF Token ──────────────────────────────────────
let _csrfToken = null;

function getCsrfToken() {
  if (_csrfToken) return _csrfToken;
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute('content') : null;
}

async function _loadCsrf() {
  try {
    const res = await fetch('/api/session', { headers: { 'Accept': 'application/json' } });
    const data = await res.json();
    if (data.csrf_token) _csrfToken = data.csrf_token;
  } catch (e) { /* ignore */ }
}

// ── API Helper ──────────────────────────────────────
async function api(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const defaultHeaders = { 'Content-Type': 'application/json' };
  if (method !== 'GET' && method !== 'HEAD') {
    const token = getCsrfToken();
    if (token) defaultHeaders['X-CSRF-Token'] = token;
  }
  const config = {
    headers: { ...defaultHeaders, ...options.headers },
    ...options
  };
  if (config.body && typeof config.body === 'object') {
    config.body = JSON.stringify(config.body);
  }
  const res = await fetch(url, config);
  if (res.status === 401) {
    window.location.href = '/login';
    return null;
  }
  if (res.status === 429) {
    const data = await res.json().catch(() => ({ error: 'Too many requests' }));
    showToast(data.error || 'Too many attempts. Please try again later.', 'error');
    return null;
  }
  if (res.status === 403) {
    showToast('Access denied', 'error');
    return null;
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok && data.error) {
    showToast(data.error, 'error');
    return null;
  }
  if (data.csrf_token) _csrfToken = data.csrf_token;
  return data;
}

// ── Sidebar Toggle (Mobile) ─────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  const hamburger = document.getElementById('hamburger');
  const sidebar = document.querySelector('.sidebar');
  const backdrop = document.querySelector('.sidebar-backdrop');
  if (hamburger && sidebar) {
    hamburger.addEventListener('click', function() {
      const isOpen = sidebar.classList.contains('open');
      sidebar.classList.toggle('open');
      if (backdrop) backdrop.classList.toggle('show');
      hamburger.style.display = isOpen ? 'flex' : 'none';
    });
    if (backdrop) {
      backdrop.addEventListener('click', function() {
        sidebar.classList.remove('open');
        backdrop.classList.remove('show');
        if (hamburger) hamburger.style.display = 'flex';
      });
    }
  }

  const hamburgerRes = document.getElementById('hamburgerResident');
  const sidebarRes = document.querySelector('.resident-sidebar');
  const backdropRes = document.querySelector('.sidebar-backdrop');
  if (hamburgerRes && sidebarRes) {
    hamburgerRes.addEventListener('click', function() {
      const isOpen = sidebarRes.classList.contains('open');
      sidebarRes.classList.toggle('open');
      if (backdropRes) backdropRes.classList.toggle('show');
      hamburgerRes.style.display = isOpen ? 'flex' : 'none';
    });
    if (backdropRes) {
      backdropRes.addEventListener('click', function() {
        sidebarRes.classList.remove('open');
        backdropRes.classList.remove('show');
        if (hamburgerRes) hamburgerRes.style.display = 'flex';
      });
    }
  }

  // Auto-logout idle timer (30 min)
  let idleTimer;
  function resetIdle() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      api('/api/logout', { method: 'POST' }).then(() => {
        window.location.href = '/login';
      });
    }, 30 * 60 * 1000);
  }
  ['mousemove', 'keydown', 'click', 'scroll'].forEach(evt => {
    document.addEventListener(evt, resetIdle);
  });
  resetIdle();

  // Logout buttons
  document.querySelectorAll('.logout-btn').forEach(btn => {
    btn.addEventListener('click', async function(e) {
      e.preventDefault();
      await api('/api/logout', { method: 'POST' });
      window.location.href = '/login';
    });
  });
});
