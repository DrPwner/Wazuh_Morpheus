/**
 * health.js — System health dashboard: live status, disk, network, restart management
 */
document.addEventListener('DOMContentLoaded', function () {

  // ============================================================
  // Initial load and auto-refresh
  // ============================================================
  loadStatus();
  loadRestartHistory();

  var _pollMs = (window.HEALTH_POLL_INTERVAL && window.HEALTH_POLL_INTERVAL >= 5000)
    ? window.HEALTH_POLL_INTERVAL : 30000;
  setInterval(function () { loadStatus(); loadRestartHistory(); }, _pollMs);

  var refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', function () {
      loadStatus();
      loadRestartHistory();
    });
  }

  // ============================================================
  // Restart modal
  // ============================================================
  var restartBtn = document.getElementById('restartBtn');
  if (restartBtn) {
    restartBtn.addEventListener('click', function () {
      var reasonInput = document.getElementById('restartReason');
      if (reasonInput) reasonInput.value = '';
      openModal('restartModal');
    });
  }

  document.getElementById('restartModalClose') &&
    document.getElementById('restartModalClose').addEventListener('click', function () {
      closeModal('restartModal');
    });
  document.getElementById('restartCancelBtn') &&
    document.getElementById('restartCancelBtn').addEventListener('click', function () {
      closeModal('restartModal');
    });

  var restartModal = document.getElementById('restartModal');
  if (restartModal) {
    restartModal.addEventListener('click', function (e) {
      if (e.target === restartModal) closeModal('restartModal');
    });
  }

  document.getElementById('restartStatusClose') &&
    document.getElementById('restartStatusClose').addEventListener('click', function () {
      closeModal('restartStatusModal');
    });

  var restartStatusModal = document.getElementById('restartStatusModal');
  if (restartStatusModal) {
    restartStatusModal.addEventListener('click', function (e) {
      if (e.target === restartStatusModal) closeModal('restartStatusModal');
    });
  }

  var restartConfirmBtn = document.getElementById('restartConfirmBtn');
  if (restartConfirmBtn) {
    restartConfirmBtn.addEventListener('click', async function () {
      var reason = ((document.getElementById('restartReason') || {}).value || '').trim();
      if (!reason) { showToast('Reason is required', 'error'); return; }
      closeModal('restartModal');
      openModal('restartStatusModal');
      setRestartStatus('loading');

      setLoading(restartConfirmBtn, true);
      try {
        var result = await apiPost('/health/api/restart', { reason: reason });
        pollRestartStatus(result.restart_id);
      } catch (e) {
        setRestartStatus('error', e.message);
      } finally {
        setLoading(restartConfirmBtn, false);
      }
    });
  }

  // View restart details from history table
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.view-restart-output-btn');
    if (!btn) return;
    var output = btn.dataset.output || '';
    setRestartStatus('output', output);
    openModal('restartStatusModal');
  });

  // ============================================================
  // Status loading and rendering
  // ============================================================

  async function loadStatus() {
    try {
      var data = await apiGet('/health/api/status');
      renderService(data.service);
      renderCpu(data.cpu);
      renderMemory(data.memory);
      renderIndexers(data.indexers);
      renderDisk(data.disk);
      renderNetwork(data.network);
    } catch (e) {
      // Silent fail — status indicators remain as-is
    }
  }

  function renderService(svc) {
    if (!svc) return;
    var stateEl = document.getElementById('serviceState');
    var indicatorEl = document.getElementById('serviceIndicator');
    var detailEl = document.getElementById('serviceDetail');
    var outputEl = document.getElementById('serviceOutput');

    if (stateEl) {
      stateEl.textContent = svc.state || 'unknown';
      stateEl.className = 'health-card-value ' + (svc.active ? 'text-success' : 'text-danger');
    }
    if (indicatorEl) {
      indicatorEl.innerHTML = svc.active
        ? '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">' +
          '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>'
        : '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">' +
          '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/>' +
          '<line x1="9" y1="9" x2="15" y2="15"/></svg>';
      indicatorEl.className = 'status-indicator ' + (svc.active ? 'status-ok' : 'status-error');
    }
    if (detailEl) {
      detailEl.textContent = svc.error || '';
    }
    if (outputEl) {
      outputEl.textContent = svc.details || 'No service details available.';
    }
  }

  function renderCpu(cpu) {
    if (!cpu) return;
    var pct = cpu.cpu_percent || 0;
    var pctEl = document.getElementById('cpuPct');
    var barEl = document.getElementById('cpuBar');
    if (pctEl) pctEl.textContent = pct + '%';
    if (barEl) {
      barEl.style.width = pct + '%';
      barEl.className = 'progress-bar' + (pct > 85 ? ' bar-danger' : pct > 70 ? ' bar-warning' : '');
    }

    var l1 = document.getElementById('load1');
    var l5 = document.getElementById('load5');
    var l15 = document.getElementById('load15');
    if (l1) l1.textContent = (cpu.load_1 || 0).toFixed(2);
    if (l5) l5.textContent = (cpu.load_5 || 0).toFixed(2);
    if (l15) l15.textContent = (cpu.load_15 || 0).toFixed(2);

    // Render CPU history chart
    renderCpuChart(cpu.history || []);
  }

  function renderCpuChart(history) {
    var canvas = document.getElementById('cpuChart');
    if (!canvas || !canvas.getContext) return;
    var ctx = canvas.getContext('2d');

    // Handle high-DPI displays
    var rect = canvas.getBoundingClientRect();
    var dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    var W = rect.width;
    var H = rect.height;

    // Compute CSS variable colors or fallback
    var cs = getComputedStyle(document.documentElement);
    var gridColor = cs.getPropertyValue('--border-color').trim() || '#e5e5e5';
    var textColor = cs.getPropertyValue('--text-muted').trim() || '#888';
    var lineColor = cs.getPropertyValue('--primary').trim() || '#1d63a0';
    var fillColor = lineColor.replace(')', ', 0.12)').replace('rgb(', 'rgba(');
    if (fillColor === lineColor) fillColor = 'rgba(29, 99, 160, 0.12)';

    ctx.clearRect(0, 0, W, H);

    var padL = 38, padR = 10, padT = 10, padB = 24;
    var chartW = W - padL - padR;
    var chartH = H - padT - padB;

    // Dynamic Y-axis: find max data point, compute yMax
    var dataMax = 0;
    for (var di = 0; di < history.length; di++) {
      var v = history[di].pct || 0;
      if (v > dataMax) dataMax = v;
    }
    var yMax = Math.min(100, Math.max(10, Math.ceil((dataMax + 10) / 10) * 10));
    var gridStep = yMax / 4;

    // Grid lines and Y-axis labels (dynamic)
    ctx.font = '10px system-ui, sans-serif';
    ctx.fillStyle = textColor;
    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 0.5;
    for (var y = 0; y <= 4; y++) {
      var pct = Math.round(y * gridStep);
      var yy = padT + chartH - (pct / yMax) * chartH;
      ctx.beginPath();
      ctx.moveTo(padL, yy);
      ctx.lineTo(padL + chartW, yy);
      ctx.stroke();
      ctx.fillText(pct + '%', 2, yy + 3);
    }

    if (!history.length) {
      ctx.fillStyle = textColor;
      ctx.font = '12px system-ui, sans-serif';
      ctx.fillText('No data yet — collecting samples...', padL + 10, padT + chartH / 2);
      return;
    }

    // X-axis time labels
    if (history.length > 1) {
      ctx.fillStyle = textColor;
      ctx.font = '9px system-ui, sans-serif';
      var labelCount = Math.min(6, history.length);
      for (var xi = 0; xi < labelCount; xi++) {
        var idx = Math.floor(xi * (history.length - 1) / (labelCount - 1));
        var ts = history[idx].t || '';
        var timePart = ts.slice(11, 16); // HH:MM
        var xx = padL + (idx / (history.length - 1)) * chartW;
        ctx.fillText(timePart, xx - 12, H - 4);
      }
    }

    // Draw area fill
    ctx.beginPath();
    for (var i = 0; i < history.length; i++) {
      var px = padL + (history.length > 1 ? (i / (history.length - 1)) * chartW : chartW / 2);
      var py = padT + chartH - (Math.min(yMax, history[i].pct || 0) / yMax) * chartH;
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.lineTo(padL + (history.length > 1 ? chartW : chartW / 2), padT + chartH);
    ctx.lineTo(padL, padT + chartH);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();

    // Draw line
    ctx.beginPath();
    for (var j = 0; j < history.length; j++) {
      var lx = padL + (history.length > 1 ? (j / (history.length - 1)) * chartW : chartW / 2);
      var ly = padT + chartH - (Math.min(yMax, history[j].pct || 0) / yMax) * chartH;
      if (j === 0) ctx.moveTo(lx, ly);
      else ctx.lineTo(lx, ly);
    }
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }

  function renderMemory(memData) {
    if (!memData || !memData.memory) return;
    var mem = memData.memory;
    var pct = mem.percent || 0;
    var pctEl = document.getElementById('memPct');
    var barEl = document.getElementById('memBar');
    var detailEl = document.getElementById('memDetail');
    if (pctEl) pctEl.textContent = pct + '%';
    if (barEl) {
      barEl.style.width = pct + '%';
      barEl.className = 'progress-bar' + (pct > 85 ? ' bar-danger' : pct > 70 ? ' bar-warning' : '');
    }
    if (detailEl) {
      detailEl.textContent = (mem.used || 0) + ' MB used / ' + (mem.total || 0) + ' MB total';
    }
  }

  function renderIndexers(indexers) {
    var section = document.getElementById('indexerSection');
    var container = document.getElementById('indexerHealthContent');
    if (!section || !container) return;

    if (!indexers || !Object.keys(indexers).length) {
      section.style.display = 'none';
      return;
    }
    section.style.display = '';

    var keys = Object.keys(indexers);
    container.innerHTML = '<div class="indexer-grid">' + keys.map(function (name) {
      var idx = indexers[name];
      var type = idx.type || 'cluster_health';
      var cl = idx.cluster || {};
      var doc = idx.latest_doc || {};

      var errorHtml = '';
      if (cl && cl.error) {
        errorHtml = '<div class="idx-error">' + escapeHtml(cl.error) + '</div>';
      } else if (doc && doc.error) {
        errorHtml = '<div class="idx-error">' + escapeHtml(doc.error) + '</div>';
      }

      var typeLabel = type === 'cluster_health' ? 'Cluster Health' : 'Log Activity';
      var bodyHtml = '';

      if (type === 'cluster_health') {
        var status = cl.status || 'unknown';
        var statusCls = status === 'green' ? 'idx-status-green'
          : status === 'yellow' ? 'idx-status-yellow'
          : status === 'red' ? 'idx-status-red' : 'idx-status-unknown';

        bodyHtml =
          '<div class="idx-stats">' +
            '<div class="idx-stat"><span class="idx-stat-val">' + (cl.number_of_nodes || 0) + '</span><span class="idx-stat-lbl">Nodes</span></div>' +
            '<div class="idx-stat"><span class="idx-stat-val">' + (cl.active_primary_shards || 0) + '</span><span class="idx-stat-lbl">Pri Shards</span></div>' +
            '<div class="idx-stat"><span class="idx-stat-val">' + (cl.unassigned_shards || 0) + '</span><span class="idx-stat-lbl">Unassigned</span></div>' +
          '</div>';

        return '<div class="indexer-card">' +
          '<div class="idx-card-header">' +
            '<span class="idx-name">' + escapeHtml(idx.name || name) + '</span>' +
            '<span class="cluster-status-badge ' + statusCls + '">' + escapeHtml(status) + '</span>' +
          '</div>' +
          '<div class="idx-url text-muted font-mono text-sm">' + escapeHtml(idx.url || '') + '</div>' +
          '<div class="idx-type-label text-muted text-sm">' + typeLabel + '</div>' +
          bodyHtml +
          errorHtml +
          (idx.checked_at ? '<div class="idx-checked text-muted text-sm">Checked: ' + escapeHtml(String(idx.checked_at).slice(0, 19).replace('T', ' ')) + ' UTC</div>' : '') +
        '</div>';
      } else {
        // log_activity
        var isFresh = doc && doc.is_current && doc.timestamp_changed !== false;
        var freshCls = isFresh ? 'idx-fresh' : 'idx-stale';
        var freshLabel = isFresh ? 'Fresh' : '';
        if (!isFresh && doc) {
          if (doc.timestamp_changed === false) freshLabel = 'Stale (unchanged)';
          else if (doc.age_minutes != null) freshLabel = 'Stale (' + doc.age_minutes + 'min)';
          else if (doc.age_hours != null) freshLabel = 'Stale (' + doc.age_hours + 'h)';
          else freshLabel = 'Unknown';
        } else if (!doc) {
          freshLabel = 'Pending';
          freshCls = 'idx-stale';
        }

        return '<div class="indexer-card">' +
          '<div class="idx-card-header">' +
            '<span class="idx-name">' + escapeHtml(idx.name || name) + '</span>' +
            '<span class="freshness-badge ' + freshCls + '">' + freshLabel + '</span>' +
          '</div>' +
          '<div class="idx-url text-muted font-mono text-sm">' + escapeHtml(idx.url || '') + '</div>' +
          '<div class="idx-type-label text-muted text-sm">' + typeLabel + (idx.index_pattern ? ' &middot; ' + escapeHtml(idx.index_pattern) : '') + '</div>' +
          (doc && doc.latest_timestamp ? '<div class="idx-freshness"><span class="idx-ts text-muted text-sm">Latest: ' + escapeHtml(String(doc.latest_timestamp).slice(0, 19)) + '</span>' +
            (doc.age_minutes != null ? ' <span class="text-muted text-sm">(' + doc.age_minutes + ' min ago)</span>' : '') +
          '</div>' : '') +
          errorHtml +
          (idx.checked_at ? '<div class="idx-checked text-muted text-sm">Checked: ' + escapeHtml(String(idx.checked_at).slice(0, 19).replace('T', ' ')) + ' UTC</div>' : '') +
        '</div>';
      }
    }).join('') + '</div>';
  }

  function renderDisk(diskData) {
    var container = document.getElementById('diskContent');
    if (!container || !diskData) return;
    if (diskData.error) {
      container.innerHTML = '<p class="text-muted">' + escapeHtml(diskData.error) + '</p>';
      return;
    }
    var disks = diskData.disks || [];
    if (!disks.length) {
      container.innerHTML = '<p class="text-muted">No disk information available.</p>';
      return;
    }
    container.innerHTML = disks.map(function (d) {
      var pct = d.percent || 0;
      var barCls = pct >= 90 ? 'bar-danger' : pct >= 75 ? 'bar-warning' : '';
      var pctCls = pct >= 90 ? 'disk-pct-danger' : pct >= 75 ? 'disk-pct-warn' : '';
      var fstypeHtml = d.fstype
        ? '<span class="disk-fstype text-muted">' + escapeHtml(d.fstype) + '</span>'
        : '';
      return '<div class="disk-item">' +
        '<div class="disk-header">' +
        '<span class="disk-mount font-mono">' + escapeHtml(d.mount) + '</span>' +
        fstypeHtml +
        '<span class="disk-device text-muted text-sm">' + escapeHtml(d.device) + '</span>' +
        '<span class="disk-pct ' + pctCls + '">' + pct + ' %</span>' +
        '</div>' +
        '<div class="progress-bar-wrap">' +
        '<div class="progress-bar ' + barCls + '" style="width:' + pct + '%"></div>' +
        '</div>' +
        '<div class="disk-detail text-muted text-sm">' +
        escapeHtml(d.used) + ' used \u00b7 ' + escapeHtml(d.size) + ' total \u00b7 ' + escapeHtml(d.available) + ' free' +
        '</div>' +
        '</div>';
    }).join('');
  }

  function renderNetwork(netData) {
    var container = document.getElementById('networkContent');
    if (!container || !netData) return;
    if (netData.error) {
      container.innerHTML = '<p class="text-muted p-3">' + escapeHtml(netData.error) + '</p>';
      return;
    }
    var ifaces = netData.interfaces || [];
    if (!ifaces.length) {
      container.innerHTML = '<p class="text-muted p-3">No network interface data available.</p>';
      return;
    }
    container.innerHTML =
      '<table class="data-table"><thead><tr>' +
      '<th>Interface</th><th>RX</th><th>TX</th><th>RX Errors</th><th>TX Errors</th>' +
      '</tr></thead><tbody>' +
      ifaces.map(function (iface) {
        return '<tr>' +
          '<td class="font-mono">' + escapeHtml(iface.interface) + '</td>' +
          '<td>' + _fmtBytes(iface.rx_bytes) + '</td>' +
          '<td>' + _fmtBytes(iface.tx_bytes) + '</td>' +
          '<td class="' + (iface.rx_errors > 0 ? 'text-warning' : '') + '">' + iface.rx_errors + '</td>' +
          '<td class="' + (iface.tx_errors > 0 ? 'text-warning' : '') + '">' + iface.tx_errors + '</td>' +
          '</tr>';
      }).join('') +
      '</tbody></table>';
  }

  // ============================================================
  // Restart history
  // ============================================================

  async function loadRestartHistory() {
    var tbody = document.getElementById('restartBody');
    if (!tbody) return;
    try {
      var rows = await apiGet('/health/api/restart/history');
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-muted text-center p-3">No restart history.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (r) {
        var cls = r.status === 'success' ? 'badge-success'
          : r.status === 'pending' ? 'badge-warning' : 'badge-danger';
        var detailBtn = r.output
          ? '<button class="btn btn-xs btn-ghost view-restart-output-btn"' +
            ' data-output="' + _ea(r.output) + '">Details</button>'
          : '-';
        return '<tr>' +
          '<td class="text-sm font-mono">' + escapeHtml((r.started_at || '').slice(0, 16)) + '</td>' +
          '<td>' + escapeHtml(r.username || '-') + '</td>' +
          '<td class="text-sm">' + escapeHtml(r.reason || '-') + '</td>' +
          '<td><span class="badge ' + cls + '">' + escapeHtml(r.status) + '</span></td>' +
          '<td>' + detailBtn + '</td>' +
          '</tr>';
      }).join('');
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-muted text-center p-3">Failed to load history.</td></tr>';
    }
  }

  // ============================================================
  // Restart status polling
  // ============================================================

  function setRestartStatus(state, message) {
    var content = document.getElementById('restartStatusContent');
    if (!content) return;
    if (state === 'loading') {
      content.innerHTML =
        '<div class="loading-state"><div class="spinner"></div>' +
        '<p>Restarting Wazuh manager...</p></div>';
    } else if (state === 'success') {
      content.innerHTML =
        '<div class="alert alert-success">Wazuh manager restarted successfully.</div>' +
        '<pre class="service-output mt-2">' + escapeHtml(message || '') + '</pre>';
    } else if (state === 'failed') {
      content.innerHTML =
        '<div class="alert alert-danger">Restart failed.</div>' +
        '<pre class="service-output mt-2">' + escapeHtml(message || '') + '</pre>';
    } else if (state === 'error') {
      content.innerHTML =
        '<div class="alert alert-danger">Error: ' + escapeHtml(message || 'Unknown error') + '</div>';
    } else if (state === 'output') {
      content.innerHTML =
        '<pre class="service-output">' + escapeHtml(message || '') + '</pre>';
    }
  }

  function pollRestartStatus(restartId) {
    var attempts = 0;
    var maxAttempts = 30;
    var poll = setInterval(async function () {
      attempts++;
      try {
        var data = await apiGet('/health/api/restart/' + restartId + '/status');
        if (data.status === 'success') {
          clearInterval(poll);
          setRestartStatus('success', data.output || '');
          loadStatus();
          loadRestartHistory();
        } else if (data.status === 'failed') {
          clearInterval(poll);
          setRestartStatus('failed', data.output || '');
          loadRestartHistory();
        } else if (attempts >= maxAttempts) {
          clearInterval(poll);
          setRestartStatus('error', 'Timed out waiting for restart to complete.');
        }
      } catch (e) {
        if (attempts >= maxAttempts) {
          clearInterval(poll);
          setRestartStatus('error', e.message);
        }
      }
    }, 3000);
  }

  // ============================================================
  // Utilities
  // ============================================================

  function _fmtBytes(bytes) {
    if (bytes === undefined || bytes === null) return '-';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
  }

  function _ea(s) {
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
  }
});
