/* ── Barangay Management System — Main JavaScript ──────────────── */

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
      sidebar.classList.toggle('open');
      if (backdrop) backdrop.classList.toggle('show');
    });
    if (backdrop) {
      backdrop.addEventListener('click', function() {
        sidebar.classList.remove('open');
        backdrop.classList.remove('show');
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
