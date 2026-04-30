/**
 * core.js — Theme, modals, toasts, utilities shared across all pages
 */

// ============================================================
// Theme — applied immediately to prevent flash of wrong theme
// ============================================================

(function initTheme() {
  const stored = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', stored);
})();

// ============================================================
// Sidebar — applied immediately to prevent flash of collapsed state
// ============================================================

(function initSidebar() {
  if (localStorage.getItem('sidebarCollapsed') === 'true') {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.add('collapsed');
    // Keep html class in sync (set in <head> but repeat here for completeness)
    document.documentElement.classList.add('sb-collapsed');
  }
})();

document.addEventListener('DOMContentLoaded', function () {
  // Theme toggle
  document.querySelectorAll('#themeToggle').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
    });
  });

  // Sidebar toggle (desktop collapse)
  const sidebarToggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', function () {
      sidebar.classList.toggle('collapsed');
      const isCollapsed = sidebar.classList.contains('collapsed');
      document.documentElement.classList.toggle('sb-collapsed', isCollapsed);
      localStorage.setItem('sidebarCollapsed', isCollapsed);
    });
    // Note: collapsed state is applied before paint by the IIFE above + head script
  }

  // Sidebar sub-menu toggle — entire nav row click
  document.querySelectorAll('.nav-item-has-sub').forEach(function (navItem) {
    navItem.addEventListener('click', function (e) {
      e.preventDefault();
      var sub = this.nextElementSibling;
      if (sub && sub.classList.contains('nav-sub')) {
        var isOpen = sub.classList.toggle('open');
        var chevron = this.querySelector('.nav-chevron');
        if (chevron) chevron.classList.toggle('rotated', isOpen);
      }
    });
  });

  // Mobile sidebar toggle
  const mobileToggle = document.getElementById('mobileToggle');
  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener('click', function () {
      sidebar.classList.toggle('mobile-open');
    });
    document.addEventListener('click', function (e) {
      if (sidebar.classList.contains('mobile-open') &&
          !sidebar.contains(e.target) &&
          e.target !== mobileToggle) {
        sidebar.classList.remove('mobile-open');
      }
    });
  }

  // Global modal close
  setupModal('globalModal', 'globalModalClose');
  setupModal('confirmModal', 'confirmClose');

  // Tab switching
  document.querySelectorAll('.tab-bar').forEach(function (bar) {
    bar.querySelectorAll('[data-tab]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        const target = this.dataset.tab;
        bar.querySelectorAll('[data-tab]').forEach(function (t) { t.classList.remove('active'); });
        this.classList.add('active');
        // Show/hide panels
        const panelContainer = bar.closest('.page-content') || document;
        panelContainer.querySelectorAll('.tab-panel').forEach(function (panel) {
          panel.style.display = panel.id === 'tab-' + target ? 'block' : 'none';
        });
      });
    });
  });
});

// ============================================================
// Toast notifications
// ============================================================

function showToast(message, type, duration) {
  type = type || 'info';
  duration = duration || 4000;
  const container = document.getElementById('toastContainer') || _createToastContainer();
  const toast = document.createElement('div');
  toast.className = 'toast toast-' + type;
  toast.style.setProperty('--toast-duration', (duration - 200) + 'ms');

  const icons = {
    success: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
    error:   '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    warning: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info:    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  };

  toast.innerHTML = (icons[type] || '') + '<span>' + escapeHtml(message) + '</span>';
  container.appendChild(toast);
  setTimeout(function () { toast.remove(); }, duration);
}

function _createToastContainer() {
  const container = document.createElement('div');
  container.id = 'toastContainer';
  container.className = 'toast-container';
  document.body.appendChild(container);
  return container;
}

// ============================================================
// Modal utilities
// ============================================================

function setupModal(overlayId, closeId) {
  const overlay = document.getElementById(overlayId);
  const closeBtn = document.getElementById(closeId);
  if (!overlay) return;
  if (closeBtn) {
    closeBtn.addEventListener('click', function () { closeModal(overlayId); });
  }
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeModal(overlayId);
  });
}

function openModal(overlayId) {
  const el = document.getElementById(overlayId);
  if (el) el.classList.add('open');
}

function closeModal(overlayId) {
  const el = document.getElementById(overlayId);
  if (el) el.classList.remove('open');
}

// ESC key closes the topmost open modal
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') {
    var overlays = document.querySelectorAll('.modal-overlay.open');
    if (overlays.length) {
      closeModal(overlays[overlays.length - 1].id);
    }
  }
});

function confirm(title, message, onConfirm) {
  const titleEl = document.getElementById('confirmTitle');
  const msgEl = document.getElementById('confirmMessage');
  const okBtn = document.getElementById('confirmOk');
  const cancelBtn = document.getElementById('confirmCancel');

  if (titleEl) titleEl.textContent = title;
  if (msgEl) msgEl.textContent = message;
  openModal('confirmModal');

  function cleanup() {
    okBtn.removeEventListener('click', handleOk);
    cancelBtn.removeEventListener('click', handleCancel);
    closeModal('confirmModal');
  }
  function handleOk() { cleanup(); if (onConfirm) onConfirm(); }
  function handleCancel() { cleanup(); }

  okBtn.addEventListener('click', handleOk);
  cancelBtn.addEventListener('click', handleCancel);
}

// ============================================================
// API helpers
// ============================================================

async function apiPost(url, data) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  const json = await resp.json().catch(function () { return { error: 'Invalid server response' }; });
  if (!resp.ok) throw new Error(json.error || 'Request failed (' + resp.status + ')');
  return json;
}

async function apiGet(url) {
  const resp = await fetch(url);
  const json = await resp.json().catch(function () { return { error: 'Invalid server response' }; });
  if (!resp.ok) throw new Error(json.error || 'Request failed (' + resp.status + ')');
  return json;
}

// ============================================================
// Utilities
// ============================================================

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setLoading(btn, loading) {
  if (!btn) return;
  if (loading) {
    btn.disabled = true;
    btn._originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin:0"></span>';
  } else {
    btn.disabled = false;
    if (btn._originalText !== undefined) btn.innerHTML = btn._originalText;
  }
}

function formatDate(str) {
  if (!str) return '-';
  return str.replace('T', ' ').slice(0, 16);
}
