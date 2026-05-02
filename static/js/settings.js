/**
 * settings.js — General settings, user management, and role management pages
 */
document.addEventListener('DOMContentLoaded', function () {

  // ============================================================
  // General Settings — Wazuh Paths
  // ============================================================
  var savePathsBtn = document.getElementById('savePathsBtn');
  if (savePathsBtn) {
    savePathsBtn.addEventListener('click', async function () {
      setLoading(savePathsBtn, true);
      try {
        await apiPost('/settings/wazuh-paths', {
          alerts_json_path:             (document.getElementById('alertsPath') || {}).value || '',
          default_rules_path:           (document.getElementById('defaultRulesPath') || {}).value || '',
          custom_rules_path:            (document.getElementById('customRulesPath') || {}).value || '',
          suppressions_path:            (document.getElementById('suppressionsPath') || {}).value || '',
          default_rules_exceptions_path:(document.getElementById('exceptionsPath') || {}).value || '',
          archives_json_path:           (document.getElementById('archivesPath') || {}).value || '',
          no_log_alert_seconds:         parseInt((document.getElementById('noLogAlertSeconds') || {}).value || '300') || 300,
        });
        showToast('Paths saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(savePathsBtn, false);
      }
    });
  }

  // ============================================================
  // Email Settings
  // ============================================================
  var emailEnabled = document.getElementById('emailEnabled');
  var emailFields  = document.getElementById('emailFields');
  if (emailEnabled && emailFields) {
    emailEnabled.addEventListener('change', async function () {
      emailFields.style.display = this.checked ? 'block' : 'none';
      try {
        await apiPost('/settings/email', { enabled: this.checked });
      } catch (e) {
        showToast(e.message, 'error');
      }
    });
  }

  var saveEmailBtn = document.getElementById('saveEmailBtn');
  if (saveEmailBtn) {
    saveEmailBtn.addEventListener('click', async function () {
      setLoading(saveEmailBtn, true);
      var pw = ((document.getElementById('smtpPassword') || {}).value || '').trim();

      var data = {
        enabled:      !!(document.getElementById('emailEnabled') || {}).checked,
        smtp_host:    ((document.getElementById('smtpHost') || {}).value || '').trim(),
        smtp_port:    parseInt((document.getElementById('smtpPort') || {}).value || '587'),
        smtp_user:    ((document.getElementById('smtpUser') || {}).value || '').trim(),
        smtp_tls:     !!(document.getElementById('smtpTls') || {}).checked,
        from_address: ((document.getElementById('fromAddress') || {}).value || '').trim(),
      };
      if (pw) data.smtp_password = pw;

      try {
        await apiPost('/settings/email', data);
        showToast('Email settings saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveEmailBtn, false);
      }
    });
  }

  var testEmailBtn = document.getElementById('testEmailBtn');
  if (testEmailBtn) {
    testEmailBtn.addEventListener('click', async function () {
      var testTo = ((document.getElementById('smtpTestRecipient') || {}).value || '').trim();
      if (!testTo) { showToast('Enter a test recipient email address', 'warning'); return; }
      setLoading(testEmailBtn, true);
      try {
        await apiPost('/settings/email/test', { recipient: testTo });
        showToast('Test email sent to ' + testTo, 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(testEmailBtn, false);
      }
    });
  }

  // ============================================================
  // Postfix Settings
  // ============================================================
  var postfixEnabled = document.getElementById('postfixEnabled');
  var postfixFields  = document.getElementById('postfixFields');
  if (postfixEnabled && postfixFields) {
    postfixEnabled.addEventListener('change', async function () {
      postfixFields.style.display = this.checked ? 'block' : 'none';
      try {
        await apiPost('/settings/postfix', { enabled: this.checked });
      } catch (e) {
        showToast(e.message, 'error');
      }
    });
  }

  var savePostfixBtn = document.getElementById('savePostfixBtn');
  if (savePostfixBtn) {
    savePostfixBtn.addEventListener('click', async function () {
      setLoading(savePostfixBtn, true);
      try {
        var _pfData = {
          enabled:      !!(document.getElementById('postfixEnabled') || {}).checked,
          host:         ((document.getElementById('postfixHost') || {}).value || '').trim(),
          port:         parseInt((document.getElementById('postfixPort') || {}).value || '25'),
          from_address: ((document.getElementById('postfixFromAddress') || {}).value || '').trim(),
          username:     ((document.getElementById('postfixUsername') || {}).value || '').trim(),
          use_tls:      !!(document.getElementById('postfixTls') || {}).checked,
        };
        var _pfPw = ((document.getElementById('postfixPassword') || {}).value || '').trim();
        if (_pfPw) _pfData.password = _pfPw;
        await apiPost('/settings/postfix', _pfData);
        showToast('Postfix settings saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(savePostfixBtn, false);
      }
    });
  }

  var testPostfixBtn = document.getElementById('testPostfixBtn');
  if (testPostfixBtn) {
    testPostfixBtn.addEventListener('click', async function () {
      var testTo = ((document.getElementById('postfixTestRecipient') || {}).value || '').trim();
      if (!testTo) { showToast('Enter a test recipient email address', 'warning'); return; }
      setLoading(testPostfixBtn, true);
      try {
        await apiPost('/settings/postfix/test', { recipient: testTo });
        showToast('Postfix test email sent to ' + testTo, 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(testPostfixBtn, false);
      }
    });
  }

  // ============================================================
  // Notification Settings
  // ============================================================
  // Show/hide per-event recipients input when toggle changes
  document.querySelectorAll('.notif-toggle').forEach(function (toggle) {
    toggle.addEventListener('change', function () {
      var row = this.closest('.notif-row');
      var wrap = row && row.querySelector('.notif-recipients-wrap');
      if (wrap) wrap.style.display = this.checked ? '' : 'none';
    });
  });

  var saveNotifBtn = document.getElementById('saveNotifBtn');
  if (saveNotifBtn) {
    saveNotifBtn.addEventListener('click', async function () {
      setLoading(saveNotifBtn, true);
      var data = {};
      document.querySelectorAll('.notif-toggle').forEach(function (t) {
        data[t.dataset.key] = t.checked;
      });
      // Collect per-event recipient overrides
      var eventRecipients = {};
      document.querySelectorAll('.notif-recipients-input').forEach(function (inp) {
        eventRecipients[inp.dataset.key] = inp.value.trim();
      });
      data.event_recipients = eventRecipients;
      data.disk_threshold_percent = parseInt(
        (document.getElementById('diskThreshold') || {}).value || '80'
      );
      data.quiet_hours_enabled = !!(document.getElementById('quietHoursEnabled') || {}).checked;
      data.quiet_hours_start = ((document.getElementById('quietHoursStart') || {}).value || '00:00');
      data.quiet_hours_end = ((document.getElementById('quietHoursEnd') || {}).value || '06:00');
      try {
        await apiPost('/settings/notifications', data);
        showToast('Notification settings saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveNotifBtn, false);
      }
    });
  }

  // ============================================================
  // Per-Disk Thresholds
  // ============================================================
  var loadDiskMountsBtn = document.getElementById('loadDiskMountsBtn');
  var diskThresholdsPanel = document.getElementById('diskThresholdsPanel');
  var diskThresholdsList = document.getElementById('diskThresholdsList');
  var _existingDiskThresholds = window.__DISK_THRESHOLDS || [];

  if (loadDiskMountsBtn && diskThresholdsPanel) {
    loadDiskMountsBtn.addEventListener('click', async function () {
      setLoading(loadDiskMountsBtn, true);
      try {
        var data = await apiGet('/settings/disk-mounts');
        var mounts = data.mounts || [];
        // Merge existing config with server mounts
        var existing = {};
        _existingDiskThresholds.forEach(function (t) { existing[t.mount] = t; });
        // Build combined list: existing configured + any mounts from server not yet configured
        var combined = [];
        _existingDiskThresholds.forEach(function (t) { combined.push(t); });
        mounts.forEach(function (m) {
          if (existing[m.mount]) {
            existing[m.mount].device = m.device || '';
          } else {
            combined.push({ mount: m.mount, device: m.device || '', threshold: 80, enabled: false });
          }
        });
        _renderDiskThresholds(combined);
        diskThresholdsPanel.style.display = '';
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(loadDiskMountsBtn, false);
      }
    });

    // Show existing config on page load if any
    if (_existingDiskThresholds.length) {
      _renderDiskThresholds(_existingDiskThresholds);
      diskThresholdsPanel.style.display = '';
    }
  }

  function _renderDiskThresholds(list) {
    if (!diskThresholdsList) return;
    diskThresholdsList.innerHTML = list.map(function (item, i) {
      var label = escapeHtml(item.mount);
      if (item.device) label += ' <span class="text-muted text-xs">(' + escapeHtml(item.device) + ')</span>';
      return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
        '<label style="display:flex;align-items:center;gap:6px;min-width:0;flex:1">' +
          '<input type="checkbox" class="dt-enabled" data-idx="' + i + '"' + (item.enabled ? ' checked' : '') + '>' +
          '<span class="font-mono text-sm" style="word-break:break-all;white-space:normal">' + label + '</span>' +
        '</label>' +
        '<input type="number" class="form-control dt-threshold" data-idx="' + i + '" value="' + (item.threshold || 80) + '" min="1" max="99" style="width:72px;flex-shrink:0">' +
        '<span class="text-muted text-sm" style="flex-shrink:0">%</span>' +
        '<input type="hidden" class="dt-mount" data-idx="' + i + '" value="' + escapeHtml(item.mount) + '">' +
        '</div>';
    }).join('');
    if (!list.length) {
      diskThresholdsList.innerHTML = '<p class="text-muted text-sm">No disk mounts found. Make sure you are running on Linux.</p>';
    }
  }

  var saveDiskThresholdsBtn = document.getElementById('saveDiskThresholdsBtn');
  if (saveDiskThresholdsBtn) {
    saveDiskThresholdsBtn.addEventListener('click', async function () {
      var thresholds = [];
      document.querySelectorAll('.dt-mount').forEach(function (inp) {
        var idx = inp.dataset.idx;
        var enabled = (document.querySelector('.dt-enabled[data-idx="' + idx + '"]') || {}).checked || false;
        var threshold = parseInt((document.querySelector('.dt-threshold[data-idx="' + idx + '"]') || {}).value || '80');
        thresholds.push({ mount: inp.value, threshold: threshold, enabled: enabled });
      });
      setLoading(saveDiskThresholdsBtn, true);
      try {
        await apiPost('/settings/disk-thresholds', { thresholds: thresholds });
        showToast('Disk thresholds saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveDiskThresholdsBtn, false);
      }
    });
  }

  // ============================================================
  // Health Settings
  // ============================================================
  var saveHealthBtn = document.getElementById('saveHealthBtn');
  if (saveHealthBtn) {
    saveHealthBtn.addEventListener('click', async function () {
      setLoading(saveHealthBtn, true);
      try {
        await apiPost('/settings/health', {
          poll_interval_seconds: parseInt((document.getElementById('healthPollInterval') || {}).value || '30') || 30,
        });
        showToast('Health settings saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveHealthBtn, false);
      }
    });
  }

  // ============================================================
  // Indexer Monitoring Settings
  // ============================================================
  var _indexerHosts = [];

  (function _initIndexers() {
    var listEl = document.getElementById('indexerList');
    if (!listEl) return;
    if (window.__INDEXER_HOSTS) {
      _indexerHosts = window.__INDEXER_HOSTS;
    }
    _renderIndexerList();

    // Type toggle: show/hide conditional fields
    var typeSelect = document.getElementById('indexerType');
    if (typeSelect) {
      typeSelect.addEventListener('change', function () { _toggleIndexerTypeFields(this.value); });
    }

    // Help toggles
    var typeHelpBtn = document.getElementById('indexerTypeHelpBtn');
    if (typeHelpBtn) {
      typeHelpBtn.addEventListener('click', function () {
        var el = document.getElementById('indexerTypeDetail');
        if (!el) return;
        if (el.style.display === 'none') {
          _toggleIndexerTypeFields(document.getElementById('indexerType').value);
          el.style.display = '';
        } else {
          el.style.display = 'none';
        }
      });
    }
  })();

  function _toggleIndexerTypeFields(type) {
    var clusterFields = document.getElementById('indexerClusterFields');
    var logFields = document.getElementById('indexerLogFields');
    var hint = document.getElementById('indexerTypeHint');
    var detail = document.getElementById('indexerTypeDetail');
    if (clusterFields) clusterFields.style.display = type === 'cluster_health' ? '' : 'none';
    if (logFields) logFields.style.display = type === 'log_activity' ? '' : 'none';
    if (hint) {
      hint.textContent = type === 'cluster_health'
        ? 'Monitors cluster status via /_cluster/health.'
        : 'Monitors data freshness by checking the latest document timestamp.';
    }
    if (detail) {
      if (type === 'cluster_health') {
        detail.innerHTML =
          '<div class="idx-help-box">' +
          '<strong>Cluster Health Monitor</strong><br>' +
          'Periodically sends the following request to your indexer:<br><br>' +
          '<code>GET https://&lt;url&gt;/_cluster/health</code><br><br>' +
          'This is the OpenSearch/Elasticsearch cluster health API. It returns:<br>' +
          '&bull; <strong>status</strong> &mdash; green (all shards assigned), yellow (replicas unassigned), or red (primary shards unassigned)<br>' +
          '&bull; <strong>number_of_nodes</strong> &mdash; total nodes in the cluster<br>' +
          '&bull; <strong>active_primary_shards</strong> &mdash; number of active primary shards<br>' +
          '&bull; <strong>unassigned_shards</strong> &mdash; shards waiting to be assigned<br><br>' +
          'The "Alert On" setting controls which status triggers an email alert: red only, yellow + red, or any non-green.' +
          '</div>';
      } else {
        detail.innerHTML =
          '<div class="idx-help-box">' +
          '<strong>Log Activity Monitor</strong><br>' +
          'Periodically sends the following request to your indexer:<br><br>' +
          '<code>GET https://&lt;url&gt;/&lt;index-pattern&gt;/_search</code><br>' +
          '<code>{"size":1,"sort":[{"@timestamp":{"order":"desc"}}],"_source":["@timestamp"]}</code><br><br>' +
          'This fetches the single most recent document from the index pattern (e.g. <code>wazuh-alerts-*</code>) sorted by <code>@timestamp</code> descending. It returns the timestamp of the newest document.<br><br>' +
          'The monitor then:<br>' +
          '&bull; Compares the latest timestamp with the previous check &mdash; if unchanged, data is considered <strong>stale</strong><br>' +
          '&bull; Calculates the age of the newest document in minutes<br>' +
          '&bull; Alerts if the age exceeds the "No New Data" threshold (meaning no new logs have arrived for that long)' +
          '</div>';
      }
    }
  }

  function _renderIndexerList() {
    var listEl = document.getElementById('indexerList');
    if (!listEl) return;
    if (!_indexerHosts.length) {
      listEl.innerHTML = '<div class="text-muted text-sm">No monitors configured. Click "Add Monitor" to begin.</div>';
      return;
    }
    listEl.innerHTML = _indexerHosts.map(function (h, i) {
      var statusCls = h.enabled ? 'badge-success' : 'badge-muted';
      var statusLabel = h.enabled ? 'Enabled' : 'Disabled';
      var type = h.type || 'cluster_health';
      var typeBadge = type === 'cluster_health'
        ? '<span class="badge badge-info" style="font-size:10px">Cluster Health</span>'
        : '<span class="badge badge-warning" style="font-size:10px">Log Activity</span>';
      var detail = '';
      if (type === 'cluster_health') {
        detail = 'Alert on: ' + escapeHtml(h.alert_on || 'red');
      } else {
        detail = 'Index: ' + escapeHtml(h.index_pattern || 'wazuh-alerts-*') + ' | No data: ' + (h.no_new_data_minutes || 10) + 'min';
      }
      detail += ' | Interval: ' + (h.check_interval_seconds || 120) + 's';
      return '<div class="silence-item" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">' +
        '<span class="font-mono text-sm" style="flex:1;min-width:0">' +
          '<strong>' + escapeHtml(h.name) + '</strong> &mdash; ' + escapeHtml(h.url) +
        '</span>' +
        typeBadge +
        '<span class="badge ' + statusCls + '" style="font-size:10px">' + statusLabel + '</span>' +
        '<span class="text-muted text-sm">' + detail + '</span>' +
        '<button class="btn btn-xs btn-ghost indexer-edit-btn" data-idx="' + i + '">Edit</button>' +
        '<button class="btn btn-xs btn-ghost indexer-delete-btn" data-idx="' + i + '">Delete</button>' +
      '</div>';
    }).join('');

    listEl.querySelectorAll('.indexer-edit-btn').forEach(function (btn) {
      btn.addEventListener('click', function () { _openIndexerForm(parseInt(this.dataset.idx)); });
    });
    listEl.querySelectorAll('.indexer-delete-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var idx = parseInt(this.dataset.idx);
        var name = _indexerHosts[idx] ? _indexerHosts[idx].name : '';
        if (!window.confirm('Remove "' + name + '" from the list? This won\'t take effect until you click Save.')) return;
        _indexerHosts.splice(idx, 1);
        _renderIndexerList();
      });
    });
  }

  function _openIndexerForm(editIdx) {
    var form = document.getElementById('indexerForm');
    if (!form) return;
    form.style.display = '';
    document.getElementById('indexerEditIdx').value = editIdx != null ? editIdx : -1;
    var saveBtn = document.getElementById('indexerFormSaveBtn');

    if (editIdx != null && editIdx >= 0 && _indexerHosts[editIdx]) {
      var h = _indexerHosts[editIdx];
      var type = h.type || 'cluster_health';
      document.getElementById('indexerType').value = type;
      document.getElementById('indexerName').value = h.name || '';
      document.getElementById('indexerUrl').value = h.url || '';
      document.getElementById('indexerUsername').value = h.username || '';
      document.getElementById('indexerPassword').value = h.password || '';
      document.getElementById('indexerCheckInterval').value = h.check_interval_seconds || 120;
      document.getElementById('indexerAlertOn').value = h.alert_on || 'red';
      document.getElementById('indexerNoNewDataMin').value = h.no_new_data_minutes || 10;
      document.getElementById('indexerIndexPattern').value = h.index_pattern || 'wazuh-alerts-*';
      document.getElementById('indexerVerifySsl').checked = !!h.verify_ssl;
      document.getElementById('indexerEnabled').checked = h.enabled !== false;
      _toggleIndexerTypeFields(type);
      if (saveBtn) saveBtn.textContent = 'Update';
    } else {
      document.getElementById('indexerType').value = 'cluster_health';
      document.getElementById('indexerName').value = '';
      document.getElementById('indexerUrl').value = '';
      document.getElementById('indexerUsername').value = '';
      document.getElementById('indexerPassword').value = '';
      document.getElementById('indexerCheckInterval').value = '120';
      document.getElementById('indexerAlertOn').value = 'red';
      document.getElementById('indexerNoNewDataMin').value = '10';
      document.getElementById('indexerIndexPattern').value = 'wazuh-alerts-*';
      document.getElementById('indexerVerifySsl').checked = false;
      document.getElementById('indexerEnabled').checked = true;
      _toggleIndexerTypeFields('cluster_health');
      if (saveBtn) saveBtn.textContent = 'Add to List';
    }
    document.getElementById('indexerTestResult').style.display = 'none';
  }

  function _closeIndexerForm() {
    var form = document.getElementById('indexerForm');
    if (form) form.style.display = 'none';
  }

  var addIndexerBtn = document.getElementById('addIndexerBtn');
  if (addIndexerBtn) {
    addIndexerBtn.addEventListener('click', function () { _openIndexerForm(-1); });
  }

  var indexerFormCancelBtn = document.getElementById('indexerFormCancelBtn');
  if (indexerFormCancelBtn) {
    indexerFormCancelBtn.addEventListener('click', _closeIndexerForm);
  }

  var indexerFormSaveBtn = document.getElementById('indexerFormSaveBtn');
  if (indexerFormSaveBtn) {
    indexerFormSaveBtn.addEventListener('click', function () {
      var name = (document.getElementById('indexerName').value || '').trim();
      var url = (document.getElementById('indexerUrl').value || '').trim();
      var type = document.getElementById('indexerType').value || 'cluster_health';
      if (!name) { showToast('Name is required', 'warning'); return; }
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        showToast('URL must start with http:// or https://', 'warning');
        return;
      }
      var entry = {
        name: name,
        url: url,
        type: type,
        username: (document.getElementById('indexerUsername').value || '').trim(),
        password: document.getElementById('indexerPassword').value || '',
        check_interval_seconds: parseInt(document.getElementById('indexerCheckInterval').value) || 120,
        verify_ssl: !!document.getElementById('indexerVerifySsl').checked,
        enabled: !!document.getElementById('indexerEnabled').checked,
      };
      if (type === 'cluster_health') {
        entry.alert_on = document.getElementById('indexerAlertOn').value || 'red';
      } else {
        entry.no_new_data_minutes = parseInt(document.getElementById('indexerNoNewDataMin').value) || 10;
        entry.index_pattern = (document.getElementById('indexerIndexPattern').value || '').trim() || 'wazuh-alerts-*';
      }
      var editIdx = parseInt(document.getElementById('indexerEditIdx').value);
      if (editIdx >= 0 && _indexerHosts[editIdx]) {
        _indexerHosts[editIdx] = entry;
      } else {
        _indexerHosts.push(entry);
      }
      _closeIndexerForm();
      _renderIndexerList();
    });
  }

  // Test connection
  var indexerFormTestBtn = document.getElementById('indexerFormTestBtn');
  if (indexerFormTestBtn) {
    indexerFormTestBtn.addEventListener('click', async function () {
      var resultDiv = document.getElementById('indexerTestResult');
      var url = (document.getElementById('indexerUrl').value || '').trim();
      var type = document.getElementById('indexerType').value || 'cluster_health';
      if (!url) { showToast('URL is required to test', 'warning'); return; }

      setLoading(indexerFormTestBtn, true);
      if (resultDiv) { resultDiv.style.display = ''; resultDiv.innerHTML = '<span class="text-muted">Testing...</span>'; }

      try {
        var payload = {
          url: url,
          type: type,
          username: (document.getElementById('indexerUsername').value || '').trim(),
          password: document.getElementById('indexerPassword').value || '',
          verify_ssl: !!document.getElementById('indexerVerifySsl').checked,
        };
        if (type === 'log_activity') {
          payload.index_pattern = (document.getElementById('indexerIndexPattern').value || '').trim() || 'wazuh-alerts-*';
        }
        var data = await apiPost('/settings/indexers/test', payload);
        var html = '<div style="font-size:13px;line-height:1.8">';

        if (type === 'cluster_health') {
          var cl = data.cluster || {};
          var statusCls = cl.status === 'green' ? 'text-success' : cl.status === 'yellow' ? 'text-warning' : 'text-danger';
          if (cl.error) {
            html += '<div class="text-danger"><strong>Connection error:</strong> ' + escapeHtml(cl.error) + '</div>';
          } else {
            html += '<strong>Cluster:</strong> <span class="' + statusCls + '">' + escapeHtml(cl.status) + '</span>';
            html += ' &middot; <strong>Nodes:</strong> ' + cl.number_of_nodes;
            html += ' &middot; <strong>Unassigned:</strong> ' + cl.unassigned_shards;
          }
        } else {
          var doc = data.latest_doc || {};
          if (doc.error) {
            html += '<div class="text-danger"><strong>Error:</strong> ' + escapeHtml(doc.error) + '</div>';
          } else if (doc.latest_timestamp) {
            html += '<strong>Latest doc:</strong> ' + escapeHtml(String(doc.latest_timestamp).slice(0, 19));
            html += ' &middot; Age: ' + (doc.age_minutes != null ? doc.age_minutes + ' min' : 'unknown');
            html += ' &middot; ' + (doc.is_current ? '<span class="text-success">Fresh</span>' : '<span class="text-warning">Stale</span>');
          } else {
            html += '<span class="text-warning">No documents found</span>';
          }
        }

        html += '</div>';
        if (resultDiv) resultDiv.innerHTML = html;
      } catch (e) {
        if (resultDiv) resultDiv.innerHTML = '<span class="text-danger">' + escapeHtml(e.message) + '</span>';
      } finally {
        setLoading(indexerFormTestBtn, false);
      }
    });
  }

  // Save indexers
  var saveIndexersBtn = document.getElementById('saveIndexersBtn');
  if (saveIndexersBtn) {
    saveIndexersBtn.addEventListener('click', async function () {
      setLoading(saveIndexersBtn, true);
      try {
        await apiPost('/settings/indexers', {
          hosts: _indexerHosts,
        });
        showToast('Indexer settings saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveIndexersBtn, false);
      }
    });
  }

  // ============================================================
  // Backup Settings — schedule type tabs
  // ============================================================

  var schedTypeTabs = document.getElementById('schedTypeTabs');
  if (schedTypeTabs) {
    var _initType = schedTypeTabs.dataset.current || 'daily';
    _activateSchedTab(_initType);

    schedTypeTabs.addEventListener('click', function (e) {
      var tab = e.target.closest('.sched-tab');
      if (tab) _activateSchedTab(tab.dataset.type);
    });
  }

  function _activateSchedTab(type) {
    var tabs = document.getElementById('schedTypeTabs');
    if (!tabs) return;
    tabs.querySelectorAll('.sched-tab').forEach(function (b) {
      b.classList.toggle('sched-tab-active', b.dataset.type === type);
    });
    var panelMap = { hourly: 'Hourly', daily: 'Daily', every_n_days: 'Days', weekly: 'Weekly' };
    ['Hourly', 'Daily', 'Days', 'Weekly'].forEach(function (n) {
      var p = document.getElementById('schedPanel' + n);
      if (p) p.style.display = 'none';
    });
    var active = document.getElementById('schedPanel' + (panelMap[type] || 'Daily'));
    if (active) active.style.display = 'block';
  }

  // Day-of-week toggle buttons
  document.querySelectorAll('.dow-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var willDeactivate = this.classList.contains('dow-active');
      // Don't allow deselecting the last active day
      if (willDeactivate) {
        var activeCount = document.querySelectorAll('.dow-btn.dow-active').length;
        if (activeCount <= 1) return;
      }
      this.classList.toggle('dow-active');
    });
  });

  var saveBackupBtn = document.getElementById('saveBackupBtn');
  if (saveBackupBtn) {
    saveBackupBtn.addEventListener('click', async function () {
      setLoading(saveBackupBtn, true);

      // Determine active schedule type
      var activeTab = document.querySelector('.sched-tab.sched-tab-active');
      var schedType = activeTab ? activeTab.dataset.type : 'daily';

      // Read the time input for the active panel
      var timeInputId = { daily: 'scheduleTime', every_n_days: 'scheduleTimeDays', weekly: 'scheduleTimeWeekly' };
      var timeVal = ((document.getElementById(timeInputId[schedType] || 'scheduleTime') || {}).value || '23:59');
      var timeParts = timeVal.split(':');

      // Collect selected days of week
      var dowSelected = [];
      document.querySelectorAll('.dow-btn.dow-active').forEach(function (b) { dowSelected.push(b.dataset.day); });

      var _backupDir = ((document.getElementById('backupDir') || {}).value || '').trim();
      if (_backupDir && !_backupDir.startsWith('/')) {
        showToast('Backup directory must be an absolute path starting with /', 'error');
        setLoading(saveBackupBtn, false);
        return;
      }

      var data = {
        enabled:               !!(document.getElementById('backupEnabled') || {}).checked,
        backup_dir:            _backupDir,
        schedule_type:         schedType,
        schedule_hour:         parseInt(timeParts[0] || 23),
        schedule_minute:       parseInt(timeParts[1] || 59),
        interval_hours:        parseInt((document.getElementById('intervalHours') || {value: '24'}).value || '24'),
        interval_days:         parseInt((document.getElementById('intervalDays') || {value: '2'}).value || '2'),
        schedule_days_of_week: dowSelected.length ? dowSelected : ['mon'],
        files_to_backup:       ((document.getElementById('filesToBackup') || {}).value || '')
                                 .split('\n').map(function (s) { return s.trim(); }).filter(Boolean),
        keep_last_n:           parseInt((document.getElementById('keepLastN') || {value: '7'}).value || '7'),
        compress:              !!(document.getElementById('compressBackup') || {}).checked,
      };
      try {
        await apiPost('/settings/backup', data);
        showToast('Backup settings saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveBackupBtn, false);
      }
    });
  }

  var triggerBackupBtn = document.getElementById('triggerBackupBtn');
  if (triggerBackupBtn) {
    triggerBackupBtn.addEventListener('click', async function () {
      setLoading(triggerBackupBtn, true);
      try {
        var result = await apiPost('/settings/backup/trigger', {});
        var count = result.result && result.result.files_backed_up != null
          ? result.result.files_backed_up + ' file(s)'
          : 'done';
        showToast('Backup completed: ' + count, 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(triggerBackupBtn, false);
      }
    });
  }

  // ============================================================
  // Users page — Create User
  // ============================================================
  var createUserBtn = document.getElementById('createUserBtn');
  if (createUserBtn) {
    createUserBtn.addEventListener('click', function () { openModal('createUserModal'); });
  }
  _setupModalClose('createUserModal', ['createUserClose', 'createUserCancelBtn']);

  var createUserSubmitBtn = document.getElementById('createUserSubmitBtn');
  if (createUserSubmitBtn) {
    createUserSubmitBtn.addEventListener('click', async function () {
      var username = ((document.getElementById('newUsername') || {}).value || '').trim();
      var password = ((document.getElementById('newPassword') || {}).value || '');
      if (!username || !password) {
        showToast('Username and password are required', 'warning');
        return;
      }
      setLoading(createUserSubmitBtn, true);
      try {
        await apiPost('/auth/users/create', {
          username:  username,
          password:  password,
          full_name: ((document.getElementById('newFullName') || {}).value || '').trim(),
          email:     ((document.getElementById('newEmail') || {}).value || '').trim(),
          is_root:   !!(document.getElementById('newIsRoot') || {}).checked,
        });
        showToast('User created', 'success');
        closeModal('createUserModal');
        setTimeout(function () { location.reload(); }, 800);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(createUserSubmitBtn, false);
      }
    });
  }

  // ============================================================
  // Users page — Edit User
  // ============================================================
  document.querySelectorAll('.edit-user-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var d = this.dataset;
      _setVal('editUserId', d.userId);
      var nameEl = document.getElementById('editUserNameDisplay');
      if (nameEl) nameEl.textContent = d.username;
      _setVal('editFullName', d.fullname || '');
      _setVal('editEmail', d.email || '');
      _setVal('editPassword', '');
      var activeEl = document.getElementById('editIsActive');
      if (activeEl) activeEl.checked = (d.active === 'True' || d.active === '1' || d.active === 'true');
      openModal('editUserModal');
    });
  });
  _setupModalClose('editUserModal', ['editUserClose', 'editUserCancelBtn']);

  var editUserSubmitBtn = document.getElementById('editUserSubmitBtn');
  if (editUserSubmitBtn) {
    editUserSubmitBtn.addEventListener('click', async function () {
      var userId = (document.getElementById('editUserId') || {}).value || '';
      if (!userId) return;
      var data = {
        full_name: ((document.getElementById('editFullName') || {}).value || '').trim(),
        email:     ((document.getElementById('editEmail') || {}).value || '').trim(),
        is_active: !!(document.getElementById('editIsActive') || {}).checked,
      };
      var pw = ((document.getElementById('editPassword') || {}).value || '').trim();
      if (pw) data.password = pw;

      setLoading(editUserSubmitBtn, true);
      try {
        await apiPost('/auth/users/' + userId + '/update', data);
        showToast('User updated', 'success');
        closeModal('editUserModal');
        setTimeout(function () { location.reload(); }, 800);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(editUserSubmitBtn, false);
      }
    });
  }

  // ============================================================
  // Users page — Assign Role modal
  // ============================================================
  document.querySelectorAll('.assign-role-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var d = this.dataset;
      _setVal('assignRoleUserId', d.userId);
      var nameEl = document.getElementById('assignRoleUserName');
      if (nameEl) nameEl.textContent = d.username;
      var select = document.getElementById('assignRoleSelect');
      if (select) select.value = d.roleId || '';
      openModal('assignRoleModal');
    });
  });
  _setupModalClose('assignRoleModal', ['assignRoleClose', 'assignRoleCancelBtn']);

  var assignRoleSubmitBtn = document.getElementById('assignRoleSubmitBtn');
  if (assignRoleSubmitBtn) {
    assignRoleSubmitBtn.addEventListener('click', async function () {
      var userId = ((document.getElementById('assignRoleUserId') || {}).value || '');
      var roleId = ((document.getElementById('assignRoleSelect') || {}).value || '');
      if (!userId) return;
      setLoading(assignRoleSubmitBtn, true);
      try {
        var roleIds = roleId ? [parseInt(roleId, 10)] : [];
        await apiPost('/auth/users/' + userId + '/roles', { role_ids: roleIds });
        // Assigning a role clears custom permission overrides
        if (roleId) {
          await apiPost('/auth/users/' + userId + '/permissions', { permissions: {} });
        }
        showToast('Role updated', 'success');
        closeModal('assignRoleModal');
        setTimeout(function () { location.reload(); }, 800);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(assignRoleSubmitBtn, false);
      }
    });
  }

  // ============================================================
  // Users page — Custom Permissions modal (only when no role assigned)
  // ============================================================
  var currentPermsUserId = null;

  document.querySelectorAll('.perms-btn').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      if (this.disabled) return;
      currentPermsUserId = this.dataset.userId;
      var nameEl = document.getElementById('permsUserName');
      if (nameEl) nameEl.textContent = this.dataset.username;
      var content = document.getElementById('permsContent');
      if (content) content.innerHTML = '<div class="loading-placeholder">Loading...</div>';
      openModal('permsModal');
      try {
        var userData = await apiGet('/auth/users/' + currentPermsUserId);
        var allPerms = await apiGet('/auth/permissions');
        _renderUserPerms(content, allPerms, userData.permissions || []);
      } catch (e) {
        if (content) content.innerHTML = '<p class="text-danger">' + escapeHtml(e.message) + '</p>';
      }
    });
  });
  _setupModalClose('permsModal', ['permsClose', 'permsCancelBtn']);

  var permsSubmitBtn = document.getElementById('permsSubmitBtn');
  if (permsSubmitBtn) {
    permsSubmitBtn.addEventListener('click', async function () {
      if (!currentPermsUserId) return;
      var content = document.getElementById('permsContent');
      if (!content) return;
      var permissions = {};
      content.querySelectorAll('input[data-perm]:checked').forEach(function (cb) {
        permissions[cb.dataset.perm] = true;
      });
      setLoading(permsSubmitBtn, true);
      try {
        await apiPost('/auth/users/' + currentPermsUserId + '/permissions', { permissions: permissions });
        showToast('Permissions updated', 'success');
        closeModal('permsModal');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(permsSubmitBtn, false);
      }
    });
  }

  function _renderUserPerms(container, allPerms, userPerms) {
    // Build granted set from explicit user_permissions records
    var grantedSet = new Set();
    userPerms.forEach(function (p) { if (p.granted) grantedSet.add(p.name); });

    var cats = _groupByCategory(allPerms);
    var html = '<p class="perms-hint">Check permissions to grant them to this user. ' +
               'These apply directly — no role is assigned.</p>' +
               '<div class="perms-grid">';
    Object.keys(cats).forEach(function (cat) {
      html += '<div class="perms-category">';
      html += '<div class="category-label">' + escapeHtml(cat) + '</div>';
      cats[cat].forEach(function (p) {
        html +=
          '<label class="perm-checkbox-row">' +
          '<input type="checkbox" data-perm="' + escapeHtml(p.name) + '"' +
          (grantedSet.has(p.name) ? ' checked' : '') + '>' +
          '<span class="perm-label-name">' + escapeHtml(p.name) + '</span>' +
          (p.description ? '<span class="perm-label-desc">' + escapeHtml(p.description) + '</span>' : '') +
          '</label>';
      });
      html += '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
  }

  // ============================================================
  // Roles page — Create Role
  // ============================================================
  var createRoleBtn = document.getElementById('createRoleBtn');
  if (createRoleBtn) {
    createRoleBtn.addEventListener('click', function () { openModal('createRoleModal'); });
  }
  _setupModalClose('createRoleModal', ['createRoleClose', 'createRoleCancelBtn']);

  var createRoleSubmitBtn = document.getElementById('createRoleSubmitBtn');
  if (createRoleSubmitBtn) {
    createRoleSubmitBtn.addEventListener('click', async function () {
      var name = ((document.getElementById('newRoleName') || {}).value || '').trim();
      var desc = ((document.getElementById('newRoleDesc') || {}).value || '').trim();
      if (!name) { showToast('Role name is required', 'warning'); return; }
      setLoading(createRoleSubmitBtn, true);
      try {
        await apiPost('/auth/roles/create', { name: name, description: desc });
        showToast('Role created', 'success');
        closeModal('createRoleModal');
        setTimeout(function () { location.reload(); }, 800);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(createRoleSubmitBtn, false);
      }
    });
  }

  // ============================================================
  // Roles page — Edit Role Permissions
  // ============================================================
  var currentRoleId = null;

  document.querySelectorAll('.edit-role-perms-btn').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      currentRoleId = this.dataset.roleId;
      var nameEl = document.getElementById('editRoleName');
      if (nameEl) nameEl.textContent = this.dataset.roleName;
      var content = document.getElementById('editRolePermsContent');
      if (content) content.innerHTML = '<div class="loading-placeholder">Loading...</div>';
      openModal('editRoleModal');
      try {
        var allPerms   = window.ALL_PERMISSIONS || await apiGet('/auth/permissions');
        var roleData   = await apiGet('/auth/roles/' + currentRoleId);
        var activeSet  = new Set(roleData.permissions || []);
        _renderRolePerms(content, allPerms, activeSet);
      } catch (e) {
        if (content) content.innerHTML = '<p class="text-danger">' + escapeHtml(e.message) + '</p>';
      }
    });
  });
  _setupModalClose('editRoleModal', ['editRoleClose', 'editRoleCancelBtn']);

  var editRoleSubmitBtn = document.getElementById('editRoleSubmitBtn');
  if (editRoleSubmitBtn) {
    editRoleSubmitBtn.addEventListener('click', async function () {
      if (!currentRoleId) return;
      var content = document.getElementById('editRolePermsContent');
      if (!content) return;
      var perms = Array.from(content.querySelectorAll('[data-perm]:checked'))
        .map(function (cb) { return cb.dataset.perm; });
      setLoading(editRoleSubmitBtn, true);
      try {
        await apiPost('/auth/roles/' + currentRoleId + '/permissions', { permissions: perms });
        showToast('Role permissions updated', 'success');
        closeModal('editRoleModal');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(editRoleSubmitBtn, false);
      }
    });
  }

  function _renderRolePerms(container, allPerms, activeSet) {
    var cats = _groupByCategory(allPerms);
    var html = '<div class="perms-grid">';
    Object.keys(cats).forEach(function (cat) {
      html += '<div class="perms-category">';
      html += '<div class="category-label">' + escapeHtml(cat) + '</div>';
      cats[cat].forEach(function (p) {
        html +=
          '<label class="perm-checkbox-row">' +
          '<input type="checkbox" data-perm="' + escapeHtml(p.name) + '"' +
          (activeSet.has(p.name) ? ' checked' : '') + '>' +
          '<span class="perm-label-name">' + escapeHtml(p.name) + '</span>' +
          (p.description ? '<span class="perm-label-desc">' + escapeHtml(p.description) + '</span>' : '') +
          '</label>';
      });
      html += '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
  }

  // ============================================================
  // Roles page — Delete Role
  // ============================================================
  document.querySelectorAll('.delete-role-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var roleId = this.dataset.roleId;
      confirm(
        'Delete Role',
        'Are you sure? Users assigned this role will lose its permissions.',
        async function () {
          try {
            var resp = await fetch('/auth/roles/' + roleId, { method: 'DELETE' });
            var json = await resp.json().catch(function () { return {}; });
            if (!resp.ok) throw new Error(json.error || 'Request failed');
            showToast('Role deleted', 'success');
            setTimeout(function () { location.reload(); }, 800);
          } catch (e) {
            showToast(e.message, 'error');
          }
        }
      );
    });
  });

  // ============================================================
  // Shared helpers
  // ============================================================

  function _setupModalClose(overlayId, closeBtnIds) {
    var overlay = document.getElementById(overlayId);
    if (!overlay) return;
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) closeModal(overlayId);
    });
    (closeBtnIds || []).forEach(function (id) {
      var btn = document.getElementById(id);
      if (btn) btn.addEventListener('click', function () { closeModal(overlayId); });
    });
  }

  function _setVal(id, val) {
    var el = document.getElementById(id);
    if (el) el.value = val;
  }

  function _groupByCategory(perms) {
    var cats = {};
    (perms || []).forEach(function (p) {
      var cat = p.category || 'General';
      if (!cats[cat]) cats[cat] = [];
      cats[cat].push(p);
    });
    return cats;
  }

  // ============================================================
  // Silence List
  // ============================================================
  var silenceList = document.getElementById('silenceFieldList');
  var silenceInput = document.getElementById('silenceFieldInput');
  var addSilenceBtn = document.getElementById('addSilenceFieldBtn');
  var saveSilencedBtn = document.getElementById('saveSilencedFieldsBtn');

  function _getSilencedFields() {
    var fields = [];
    if (!silenceList) return fields;
    silenceList.querySelectorAll('.silence-item').forEach(function (item) {
      var f = item.dataset.field;
      if (f) fields.push(f);
    });
    return fields;
  }

  function _renderSilenceItem(field) {
    var emptyMsg = document.getElementById('silenceEmptyMsg');
    if (emptyMsg) emptyMsg.remove();
    var item = document.createElement('div');
    item.className = 'silence-item';
    item.dataset.field = field;
    item.innerHTML = '<span class="font-mono text-sm">' + escapeHtml(field) + '</span>' +
      '<button class="btn btn-xs btn-ghost silence-remove-btn" data-field="' + escapeHtml(field) + '">Remove</button>';
    item.querySelector('.silence-remove-btn').addEventListener('click', function () {
      item.remove();
      if (silenceList && !silenceList.querySelector('.silence-item')) {
        var msg = document.createElement('div');
        msg.className = 'text-muted text-sm';
        msg.id = 'silenceEmptyMsg';
        msg.textContent = 'No fields silenced.';
        silenceList.appendChild(msg);
      }
    });
    silenceList.appendChild(item);
  }

  if (addSilenceBtn) {
    // Wire up remove buttons that were server-rendered
    silenceList && silenceList.querySelectorAll('.silence-remove-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var item = btn.closest('.silence-item');
        if (item) {
          item.remove();
          if (!silenceList.querySelector('.silence-item')) {
            var msg = document.createElement('div');
            msg.className = 'text-muted text-sm';
            msg.id = 'silenceEmptyMsg';
            msg.textContent = 'No fields silenced.';
            silenceList.appendChild(msg);
          }
        }
      });
    });

    addSilenceBtn.addEventListener('click', function () {
      var val = (silenceInput.value || '').trim();
      if (!val) return;
      // Prevent duplicates
      var existing = _getSilencedFields();
      if (existing.indexOf(val) !== -1) {
        showToast('Field already in silence list', 'warning');
        return;
      }
      _renderSilenceItem(val);
      silenceInput.value = '';
    });

    silenceInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') addSilenceBtn.click();
    });
  }

  if (saveSilencedBtn) {
    saveSilencedBtn.addEventListener('click', async function () {
      setLoading(saveSilencedBtn, true);
      try {
        await apiPost('/settings/silenced-fields', { fields: _getSilencedFields() });
        showToast('Silence list saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveSilencedBtn, false);
      }
    });
  }

  // ============================================================
  // Alert Event Columns
  // ============================================================
  var eventColsList = document.getElementById('eventColumnsList');
  var addEventColBtn = document.getElementById('addEventColBtn');
  var saveEventColsBtn = document.getElementById('saveEventColsBtn');
  var eventColFieldWrap = document.getElementById('eventColFieldWrap');
  var eventColFieldInput = document.getElementById('eventColFieldInput');
  var eventColFieldList = document.getElementById('eventColFieldList');
  var _eventColFields = []; // populated from API

  function _wireEventColRemove(item) {
    var btn = item.querySelector('.event-col-remove-btn');
    if (btn) btn.addEventListener('click', function () { item.remove(); });
  }

  if (eventColsList) {
    eventColsList.querySelectorAll('.silence-item').forEach(_wireEventColRemove);
  }

  // Fetch known fields from WazuhFields.json via the rules API
  if (eventColFieldList) {
    (async function () {
      try {
        var data = await apiGet('/rules/api/fields');
        _eventColFields = data.fields || [];
        _eventColFields.forEach(function (f) {
          var opt = document.createElement('div');
          opt.className = 'search-dropdown-opt';
          opt.dataset.field = f;
          opt.textContent = f;
          eventColFieldList.appendChild(opt);
        });
      } catch (e) { /* WazuhFields not available — user can still type manually */ }
    })();

    // Open dropdown on focus / click
    eventColFieldInput.addEventListener('focus', function () {
      eventColFieldWrap.dataset.open = '1';
    });
    eventColFieldInput.addEventListener('click', function () {
      eventColFieldWrap.dataset.open = '1';
    });
    // Close on blur (delayed so click on option fires first)
    eventColFieldInput.addEventListener('blur', function () {
      setTimeout(function () { delete eventColFieldWrap.dataset.open; }, 180);
    });

    // Filter as user types
    eventColFieldInput.addEventListener('input', function () {
      var q = this.value.toLowerCase();
      eventColFieldList.querySelectorAll('.search-dropdown-opt').forEach(function (opt) {
        opt.classList.toggle('hidden', q && opt.dataset.field.toLowerCase().indexOf(q) === -1);
      });
    });

    // Select on click
    eventColFieldList.addEventListener('mousedown', function (e) {
      var opt = e.target.closest('.search-dropdown-opt');
      if (!opt) return;
      eventColFieldInput.value = opt.dataset.field;
      delete eventColFieldWrap.dataset.open;
      // Auto-generate label from the last segment of the field path
      var labelInput = document.getElementById('eventColLabelInput');
      if (labelInput && !labelInput.value.trim()) {
        var parts = opt.dataset.field.split('.');
        var last = parts[parts.length - 1];
        // Title-case the last segment
        labelInput.value = last.charAt(0).toUpperCase() + last.slice(1);
      }
    });
  }

  if (addEventColBtn) {
    addEventColBtn.addEventListener('click', function () {
      var fieldInput = document.getElementById('eventColFieldInput');
      var labelInput = document.getElementById('eventColLabelInput');
      var field = (fieldInput.value || '').trim();
      var label = (labelInput.value || '').trim();
      if (!field || !label) { showToast('Both field and label are required', 'warning'); return; }
      var item = document.createElement('div');
      item.className = 'silence-item';
      item.dataset.field = field;
      item.dataset.label = label;
      item.innerHTML = '<span class="font-mono text-sm">' + escapeHtml(field) + '</span>' +
        '<span class="text-muted text-sm" style="margin-left:8px">' + escapeHtml(label) + '</span>' +
        '<button class="btn btn-xs btn-ghost event-col-remove-btn" type="button">Remove</button>';
      _wireEventColRemove(item);
      eventColsList.appendChild(item);
      fieldInput.value = '';
      labelInput.value = '';
    });
  }

  if (saveEventColsBtn) {
    saveEventColsBtn.addEventListener('click', async function () {
      var columns = [];
      eventColsList.querySelectorAll('.silence-item').forEach(function (item) {
        var f = (item.dataset.field || '').trim();
        var l = (item.dataset.label || '').trim();
        if (f && l) columns.push({ field: f, label: l });
      });
      if (!columns.length) { showToast('At least one column is required', 'warning'); return; }
      setLoading(saveEventColsBtn, true);
      try {
        await apiPost('/settings/alert-columns', { columns: columns });
        showToast('Event columns saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveEventColsBtn, false);
      }
    });
  }

  // ============================================================
  // Customer Field — case separation
  // ============================================================
  var customerFieldInput = document.getElementById('customerFieldInput');
  var customerFieldList = document.getElementById('customerFieldList');
  var saveCustomerFieldBtn = document.getElementById('saveCustomerFieldBtn');
  var clearCustomerFieldBtn = document.getElementById('clearCustomerFieldBtn');

  if (customerFieldList) {
    (async function () {
      try {
        var data = await apiGet('/rules/api/fields');
        var fields = data.fields || [];
        fields.forEach(function (f) {
          var opt = document.createElement('div');
          opt.className = 'search-dropdown-opt';
          opt.dataset.field = f;
          opt.textContent = f;
          customerFieldList.appendChild(opt);
        });
      } catch (e) { /* fields not available */ }
    })();

    customerFieldInput.addEventListener('focus', function () {
      customerFieldList.style.display = 'block';
    });
    customerFieldInput.addEventListener('input', function () {
      var val = this.value.toLowerCase();
      customerFieldList.querySelectorAll('.search-dropdown-opt').forEach(function (opt) {
        opt.style.display = opt.textContent.toLowerCase().indexOf(val) !== -1 ? '' : 'none';
      });
      customerFieldList.style.display = 'block';
    });
    customerFieldList.addEventListener('click', function (e) {
      var opt = e.target.closest('.search-dropdown-opt');
      if (!opt) return;
      customerFieldInput.value = opt.dataset.field;
      customerFieldList.style.display = 'none';
    });
    document.addEventListener('click', function (e) {
      if (!e.target.closest('#customerFieldWrap')) {
        customerFieldList.style.display = 'none';
      }
    });
  }

  if (clearCustomerFieldBtn) {
    clearCustomerFieldBtn.addEventListener('click', function () {
      if (customerFieldInput) customerFieldInput.value = '';
    });
  }

  if (saveCustomerFieldBtn) {
    saveCustomerFieldBtn.addEventListener('click', async function () {
      var field = (customerFieldInput || {}).value || '';
      setLoading(saveCustomerFieldBtn, true);
      try {
        await apiPost('/settings/customer-field', { field: field.trim() });
        showToast(field ? 'Customer field saved' : 'Customer field cleared', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveCustomerFieldBtn, false);
      }
    });
  }

  // ============================================================
  // WazuhFields — update index mapping
  // ============================================================
  var saveFieldsBtn = document.getElementById('saveWazuhFieldsBtn');
  if (saveFieldsBtn) {
    saveFieldsBtn.addEventListener('click', async function () {
      var textarea = document.getElementById('wazuhFieldsJson');
      var content = (textarea || {}).value || '';
      if (!content.trim()) {
        showToast('Paste the GET /*/_mapping output first', 'warning');
        return;
      }
      // Quick client-side JSON validation before sending
      try {
        JSON.parse(content);
      } catch (e) {
        showToast('Invalid JSON: ' + e.message, 'error');
        return;
      }
      setLoading(saveFieldsBtn, true);
      try {
        await apiPost('/settings/wazuh-fields', { content: content });
        showToast('WazuhFields.json updated — previous version backed up as .bak', 'success');
        if (textarea) textarea.value = '';
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(saveFieldsBtn, false);
      }
    });
  }

  // ============================================================
  // Email Templates
  // ============================================================
  var _tplCurrentEvent = null;
  var _tplDefaultContent = '';
  var _tplCustomContent = '';
  var _tplVars = [];

  // Disabled toggle: clicking the label opens the edit modal with guidance
  document.querySelectorAll('.tpl-row').forEach(function (row) {
    var cb   = row.querySelector('.tpl-use-custom-cb');
    var wrap = row.querySelector('.tpl-use-custom-wrap');
    if (!cb || !cb.disabled || !wrap) return;
    wrap.title = 'Save a custom template first to enable this toggle';
    wrap.style.cursor = 'pointer';
    wrap.addEventListener('click', function (e) {
      e.preventDefault();
      var editBtn = row.querySelector('.tpl-edit-btn');
      if (editBtn) editBtn.click();
      setTimeout(function () {
        showToast('Save a custom template first, then you can activate it here.', 'info');
      }, 350);
    });
  });

  // Toggle "use custom" directly from the list row
  document.querySelectorAll('.tpl-use-custom-cb').forEach(function (cb) {
    cb.addEventListener('change', async function () {
      var eventType = this.dataset.event;
      var useCustom = this.checked;
      var row = this.closest('.tpl-row');
      try {
        await apiPost('/settings/email-templates/' + eventType + '/toggle', { use_custom: useCustom });
        var badge = row ? row.querySelector('.tpl-row-type') : null;
        if (badge) {
          badge.textContent = useCustom ? 'Custom' : 'Default';
          badge.className = 'tpl-row-type tpl-type-' + (useCustom ? 'custom' : 'default');
        }
        showToast((useCustom ? 'Custom' : 'Default') + ' template active for ' + eventType.replace(/_/g, ' '), 'success');
      } catch (e) {
        this.checked = !useCustom;
        showToast('Failed: ' + e.message, 'error');
      }
    });
  });

  // Reset (delete custom) button
  document.querySelectorAll('.tpl-reset-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var eventType = this.dataset.event;
      confirm('Reset Template', 'Delete the custom template for "' + eventType.replace(/_/g, ' ') + '" and revert to default?', async function () {
        try {
          await apiPost('/settings/email-templates/' + eventType + '/reset', {});
          showToast('Template reset to default', 'success');
          setTimeout(function () { location.reload(); }, 700);
        } catch (e) {
          showToast('Failed: ' + e.message, 'error');
        }
      });
    });
  });

  // Open template editor modal
  document.querySelectorAll('.tpl-edit-btn').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      _tplCurrentEvent = this.dataset.event;
      var label = this.dataset.label || _tplCurrentEvent;
      document.getElementById('tplEditModalTitle').textContent = 'Edit Template — ' + label;

      // Reset to custom tab
      _tplSwitchTab('custom');
      document.getElementById('tplCustomEditor').value = 'Loading...';
      document.getElementById('tplDefaultViewer').value = 'Loading...';
      openModal('tplEditModal');

      try {
        var data = await apiGet('/settings/email-templates/' + _tplCurrentEvent);
        _tplDefaultContent = data.default_content || '';
        _tplCustomContent = data.custom_content || '';
        _tplVars = data.variables || [];

        document.getElementById('tplCustomEditor').value = _tplCustomContent || _tplDefaultContent;
        document.getElementById('tplDefaultViewer').value = _tplDefaultContent;
        document.getElementById('tplUseCustomCheck').checked = data.use_custom || false;

        // Build variable reference chips
        var varsBar = document.getElementById('tplVarsBar');
        if (varsBar) {
          varsBar.innerHTML = '<span class="tpl-vars-label">Variables:</span>' +
            _tplVars.map(function (v) {
              return '<code class="tpl-var-chip" title="Click to insert" data-var="' + v + '">{{ ' + v + ' }}</code>';
            }).join('');
          varsBar.querySelectorAll('.tpl-var-chip').forEach(function (chip) {
            chip.addEventListener('click', function () {
              var ed = document.getElementById('tplCustomEditor');
              if (!ed) return;
              var start = ed.selectionStart, end = ed.selectionEnd;
              var ins = '{{ ' + this.dataset.var + ' }}';
              ed.value = ed.value.substring(0, start) + ins + ed.value.substring(end);
              ed.selectionStart = ed.selectionEnd = start + ins.length;
              ed.focus({ preventScroll: true });
            });
          });
        }
      } catch (e) {
        showToast('Failed to load template: ' + e.message, 'error');
      }
    });
  });

  // ── Preview ──────────────────────────────────────────────────
  var _TPL_SAMPLE = {
    exception_created:   { rule_id: '100001', rule_source: 'custom', rule_description: 'Detects suspicious PowerShell activity', rule_level: '10', field_name: 'data.win.eventdata.commandLine', field_value: 'C:\\Windows\\system32\\svchost.exe', match_type: 'pcre2', created_by: 'admin', notes: 'Whitelisted system process', timestamp: '2026-04-15 10:30:00' },
    suppression_created: { rule_id: '60107', rule_source: 'default', rule_description: 'Windows Logon Failure', rule_level: '5', created_by: 'admin', notes: 'Known false positive — suppressed', timestamp: '2026-04-15 10:30:00' },
    rule_created:        { rule_id: '100050', description: 'Detects unusual PowerShell execution', level: '10', if_sid: '60100', groups: 'windows,powershell', match: '(?i)powershell.*-enc', match_type: 'pcre2', frequency: '', timeframe: '', raw_xml: '<rule id="100050" level="10">\n  <if_sid>60100</if_sid>\n  <match type="pcre2">(?i)powershell.*-enc</match>\n  <description>Detects unusual PowerShell execution</description>\n  <group>windows,powershell</group>\n</rule>', created_by: 'admin', timestamp: '2026-04-15 10:30:00' },
    wazuh_restart_success: { triggered_by: 'admin', reason: 'New rules deployed', output: 'Wazuh Manager restarted successfully.', timestamp: '2026-04-15 10:30:00' },
    wazuh_restart_failure: { triggered_by: 'admin', reason: 'New rules deployed', output: 'Error: Failed to bind socket on port 1514.', timestamp: '2026-04-15 10:30:00' },
    disk_threshold:      { mount: '/var/ossec', percent: '87', threshold: '80', timestamp: '2026-04-15 10:30:00' },
    case_ignored:        { rule_id: '60107', rule_description: 'Windows Logon Failure', rule_level: '5', first_seen: '2026-04-10 08:15:00', last_seen: '2026-04-15 09:45:00', total_count: '142', created_by: 'admin', notes: 'Not actionable — noise', timestamp: '2026-04-15 10:30:00' },
    archives_no_log:     { elapsed: '15 minutes', path: '/var/ossec/logs/archives/archives.json', timestamp: '2026-04-15 10:30:00' },
    indexer_issue:       { indexer_name: 'Primary Indexer', indexer_url: 'https://192.168.1.10:9200', cluster_status: 'red', nodes: '3', unassigned_shards: '12', latest_document: '2026-04-14T23:45:00Z', document_age: '10.8 hours', error: '', timestamp: '2026-04-15 10:30:00' },
  };

  var _previewTimer = null;

  function _renderPreview() {
    var ed    = document.getElementById('tplCustomEditor');
    var frame = document.getElementById('tplPreviewFrame');
    if (!ed || !frame) return;
    var ctx = _TPL_SAMPLE[_tplCurrentEvent] || {};
    var html = (ed.value || '').replace(/\{\{\s*(\w+)\s*(?::\s*([^}]*?)\s*)?\}\}/g, function (_, key, fallback) {
      var val = ctx[key];
      if (val === undefined || val === null || String(val).trim() === '') {
        return fallback !== undefined ? fallback.trim() : '';
      }
      return String(val);
    });
    var doc = frame.contentDocument || (frame.contentWindow && frame.contentWindow.document);
    if (!doc) return;
    doc.open(); doc.write(html); doc.close();
  }

  // Auto-update preview when editor changes
  var _tplCustomEditor = document.getElementById('tplCustomEditor');
  if (_tplCustomEditor) {
    _tplCustomEditor.addEventListener('input', function () {
      clearTimeout(_previewTimer);
      _previewTimer = setTimeout(_renderPreview, 500);
    });
  }

  // Manual refresh button
  var tplRefreshPreviewBtn = document.getElementById('tplRefreshPreviewBtn');
  if (tplRefreshPreviewBtn) {
    tplRefreshPreviewBtn.addEventListener('click', _renderPreview);
  }

  // Tab switching
  function _tplSwitchTab(tab) {
    document.querySelectorAll('.tpl-modal-tab').forEach(function (t) {
      t.classList.toggle('active', t.dataset.tab === tab);
    });
    document.getElementById('tplTabCustom').style.display   = tab === 'custom'  ? 'flex' : 'none';
    document.getElementById('tplTabDefault').style.display  = tab === 'default' ? 'flex' : 'none';
    document.getElementById('tplTabPreview').style.display  = tab === 'preview' ? 'flex' : 'none';
    var copyBtn = document.getElementById('tplCopyDefaultBtn');
    if (copyBtn) copyBtn.style.display = tab === 'default' ? '' : 'none';
    if (tab === 'preview') _renderPreview();
  }

  document.querySelectorAll('.tpl-modal-tab').forEach(function (tab) {
    tab.addEventListener('click', function () { _tplSwitchTab(this.dataset.tab); });
  });

  // Copy default into custom editor
  var tplCopyDefaultBtn = document.getElementById('tplCopyDefaultBtn');
  if (tplCopyDefaultBtn) {
    tplCopyDefaultBtn.style.display = 'none';
    tplCopyDefaultBtn.addEventListener('click', function () {
      document.getElementById('tplCustomEditor').value = _tplDefaultContent;
      _tplSwitchTab('custom');
      showToast('Default copied to custom editor', 'info');
    });
  }

  // Close / cancel
  var tplEditModal = document.getElementById('tplEditModal');
  if (tplEditModal) {
    document.getElementById('tplEditModalClose').addEventListener('click', function () { closeModal('tplEditModal'); });
    document.getElementById('tplCancelBtn').addEventListener('click', function () { closeModal('tplEditModal'); });
  }

  // Save custom template
  var tplSaveBtn = document.getElementById('tplSaveBtn');
  if (tplSaveBtn) {
    tplSaveBtn.addEventListener('click', async function () {
      if (!_tplCurrentEvent) return;
      var content = (document.getElementById('tplCustomEditor').value || '').trim();
      if (!content) {
        showToast('Template content cannot be empty', 'warning');
        return;
      }
      var useCustom = document.getElementById('tplUseCustomCheck').checked;
      setLoading(tplSaveBtn, true);
      try {
        await apiPost('/settings/email-templates/' + _tplCurrentEvent, {
          html_content: content,
          use_custom: useCustom,
        });
        showToast('Template saved' + (useCustom ? ' and activated' : ''), 'success');
        closeModal('tplEditModal');
        setTimeout(function () { location.reload(); }, 700);
      } catch (e) {
        showToast('Failed: ' + e.message, 'error');
      } finally {
        setLoading(tplSaveBtn, false);
      }
    });
  }

  // ============================================================
  // Integration / Webhook Settings
  // ============================================================

  var integrationHelpBtn = document.getElementById('integrationHelpBtn');
  if (integrationHelpBtn) {
    integrationHelpBtn.addEventListener('click', function () {
      var box = document.getElementById('integrationHelpBox');
      if (box) box.style.display = box.style.display === 'none' ? '' : 'none';
    });
  }

  var integrationEnabled = document.getElementById('integrationEnabled');
  var integrationFields = document.getElementById('integrationFields');
  if (integrationEnabled && integrationFields) {
    integrationEnabled.addEventListener('change', async function () {
      integrationFields.style.display = this.checked ? 'block' : 'none';
      try {
        await apiPost('/settings/integration/save', { enabled: this.checked });
        showToast(this.checked ? 'Integration enabled' : 'Integration disabled', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      }
    });
  }

  var integrationAuthType = document.getElementById('integrationAuthType');
  var customHeaderGroup = document.getElementById('customHeaderGroup');
  if (integrationAuthType && customHeaderGroup) {
    integrationAuthType.addEventListener('change', function () {
      customHeaderGroup.style.display = this.value === 'custom' ? 'block' : 'none';
    });
  }

  var integrationSaveBtn = document.getElementById('integrationSaveBtn');
  if (integrationSaveBtn) {
    integrationSaveBtn.addEventListener('click', async function () {
      setLoading(integrationSaveBtn, true);
      try {
        await apiPost('/settings/integration/save', {
          enabled: (document.getElementById('integrationEnabled') || {}).checked || false,
          webhook_url: (document.getElementById('integrationUrl') || {}).value || '',
          auth_type: (document.getElementById('integrationAuthType') || {}).value || 'bearer',
          auth_token: (document.getElementById('integrationAuthToken') || {}).value || '',
          auth_header_name: (document.getElementById('integrationAuthHeaderName') || {}).value || 'Authorization',
          timeout_seconds: parseInt((document.getElementById('integrationTimeout') || {}).value || '10') || 10,
          retry_count: parseInt((document.getElementById('integrationRetry') || {}).value || '2') || 2,
        });
        showToast('Integration settings saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(integrationSaveBtn, false);
      }
    });
  }

  var integrationTestBtn = document.getElementById('integrationTestBtn');
  if (integrationTestBtn) {
    integrationTestBtn.addEventListener('click', async function () {
      var resultEl = document.getElementById('integrationTestResult');
      setLoading(integrationTestBtn, true);
      if (resultEl) { resultEl.style.display = 'none'; resultEl.textContent = ''; }
      try {
        var res = await apiPost('/settings/integration/test', {
          webhook_url: (document.getElementById('integrationUrl') || {}).value || '',
          auth_type: (document.getElementById('integrationAuthType') || {}).value || 'bearer',
          auth_token: (document.getElementById('integrationAuthToken') || {}).value || '',
          auth_header_name: (document.getElementById('integrationAuthHeaderName') || {}).value || 'Authorization',
        });
        if (resultEl) {
          resultEl.style.display = 'block';
          resultEl.className = res.success ? 'text-success' : 'text-danger';
          resultEl.textContent = res.success
            ? 'Success (HTTP ' + res.status + ')'
            : 'Failed (HTTP ' + res.status + '): ' + (res.body || '').substring(0, 200);
        }
      } catch (e) {
        if (resultEl) {
          resultEl.style.display = 'block';
          resultEl.className = 'text-danger';
          resultEl.textContent = 'Error: ' + e.message;
        }
      } finally {
        setLoading(integrationTestBtn, false);
      }
    });
  }

  // Resolution categories CRUD
  var resolutionAddBtn = document.getElementById('resolutionAddBtn');
  if (resolutionAddBtn) {
    resolutionAddBtn.addEventListener('click', function () {
      var list = document.getElementById('resolutionList');
      var div = document.createElement('div');
      div.className = 'resolution-item';
      div.style.cssText = 'display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;';
      div.innerHTML = '<input type="text" class="form-control resolution-input" value="" placeholder="New category" style="flex:1">'
        + '<button class="btn btn-ghost btn-sm resolution-remove-btn" title="Remove">&times;</button>';
      list.appendChild(div);
      div.querySelector('input').focus();
    });
  }

  document.addEventListener('click', function (e) {
    if (e.target.classList.contains('resolution-remove-btn')) {
      e.target.closest('.resolution-item').remove();
    }
  });

  var resolutionSaveBtn = document.getElementById('resolutionSaveBtn');
  if (resolutionSaveBtn) {
    resolutionSaveBtn.addEventListener('click', async function () {
      var opts = [];
      document.querySelectorAll('.resolution-input').forEach(function (inp) {
        var v = (inp.value || '').trim();
        if (v) opts.push(v);
      });
      if (!opts.length) { showToast('Add at least one resolution option', 'warning'); return; }
      setLoading(resolutionSaveBtn, true);
      try {
        await apiPost('/settings/integration/save', { resolution_options: opts });
        showToast('Resolution categories saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(resolutionSaveBtn, false);
      }
    });
  }

  // Webhook events save
  var webhookEventsSaveBtn = document.getElementById('webhookEventsSaveBtn');
  if (webhookEventsSaveBtn) {
    webhookEventsSaveBtn.addEventListener('click', async function () {
      var evts = {};
      document.querySelectorAll('.webhook-event-cb').forEach(function (cb) {
        evts[cb.dataset.event] = cb.checked;
      });
      setLoading(webhookEventsSaveBtn, true);
      try {
        await apiPost('/settings/integration/save', { webhook_events: evts });
        showToast('Webhook events saved', 'success');
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(webhookEventsSaveBtn, false);
      }
    });
  }

  // Webhook logs table
  function _loadWebhookLogs() {
    var tbody = document.getElementById('webhookLogsBody');
    if (!tbody) return;
    apiGet('/settings/integration/logs').then(function (rows) {
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-muted" style="text-align:center;">No deliveries yet</td></tr>';
        return;
      }
      tbody.innerHTML = '';
      rows.forEach(function (r) {
        var tr = document.createElement('tr');
        tr.innerHTML = '<td>' + escapeHtml(r.created_at || '') + '</td>'
          + '<td>' + escapeHtml(r.event_type || '') + '</td>'
          + '<td>' + escapeHtml(r.rule_id || '') + '</td>'
          + '<td>' + escapeHtml(r.resolution || '') + '</td>'
          + '<td>' + (r.response_status || '-') + '</td>'
          + '<td>' + (r.success ? '<span class="badge badge-success">OK</span>' : '<span class="badge badge-danger">FAIL</span>') + '</td>'
          + '<td>' + escapeHtml(r.error || '') + '</td>';
        tbody.appendChild(tr);
      });
    }).catch(function () {
      tbody.innerHTML = '<tr><td colspan="7" class="text-danger" style="text-align:center;">Failed to load logs</td></tr>';
    });
  }

  if (document.getElementById('webhookLogsBody')) {
    _loadWebhookLogs();
  }

  var webhookLogsRefreshBtn = document.getElementById('webhookLogsRefreshBtn');
  if (webhookLogsRefreshBtn) {
    webhookLogsRefreshBtn.addEventListener('click', _loadWebhookLogs);
  }
});
