/**
 * alerts.js — Alert cases list and case detail behavior
 */
document.addEventListener('DOMContentLoaded', function () {

  // ============================================================
  // Wazuh field-name normalization
  // ============================================================
  // Static fields keep the "data." prefix; dynamic fields strip it.
  var _WAZUH_STATIC = ['user','srcip','dstip','srcport','dstport','protocol',
    'action','id','url','data','extra_data','status','system_name',
    'srcuser','dstuser'];
  function _wazuhField(name) {
    var stripped = name.replace(/^data\./, '');
    if (stripped === name) return name;
    return _WAZUH_STATIC.indexOf(stripped) !== -1 ? name : stripped;
  }

  // ============================================================
  // Integration — Resolution dropdown injection
  // ============================================================

  var _integrationEnabled = false;
  var _resolutionOptions = [];

  function _injectResolutionDropdown(textareaId) {
    var textarea = document.getElementById(textareaId);
    if (!textarea || textarea.parentNode.querySelector('.resolution-select')) return;
    var wrapper = document.createElement('div');
    wrapper.className = 'form-group';
    wrapper.style.marginTop = '0.75rem';
    wrapper.innerHTML = '<label class="form-label">Resolution <span class="text-danger">*</span></label>'
      + '<select class="form-control resolution-select" id="' + textareaId + 'Resolution">'
      + '<option value="">-- Select Resolution --</option>'
      + _resolutionOptions.map(function (o) { return '<option value="' + escapeHtml(o) + '">' + escapeHtml(o) + '</option>'; }).join('')
      + '</select>';
    textarea.parentNode.insertBefore(wrapper, textarea.nextSibling);
  }

  function _getResolution(textareaId) {
    var sel = document.getElementById(textareaId + 'Resolution');
    return sel ? (sel.value || '').trim() : '';
  }

  function _validateResolution(textareaId) {
    if (!_integrationEnabled) return true;
    if (!_getResolution(textareaId)) {
      showToast('Resolution is required', 'error');
      return false;
    }
    return true;
  }

  // Fetch integration status and inject dropdowns if enabled
  (function () {
    try {
      apiGet('/settings/integration/status').then(function (data) {
        if (data && data.enabled) {
          _integrationEnabled = true;
          _resolutionOptions = data.resolution_options || [];
          // Inject into all known notes textareas
          var targets = ['ignoreNotes', 'bulkIgnoreNotes', 'bulkSuppressNotes', 'supNotes', 'exNotes', 'listExNotes'];
          targets.forEach(function (id) { _injectResolutionDropdown(id); });
        }
      }).catch(function () { /* integration check failed — leave disabled */ });
    } catch (e) { /* apiGet not available yet */ }
  })();

  // ============================================================
  // Cases LIST page
  // ============================================================

  // Refresh alerts button — re-imports from alerts.json
  var refreshAlertsBtn = document.getElementById('refreshAlertsBtn');
  if (refreshAlertsBtn) {
    refreshAlertsBtn.addEventListener('click', async function () {
      setLoading(refreshAlertsBtn, true);
      try {
        var res = await apiPost('/alerts/api/import', {});
        var msg = res.inserted + ' new alert(s) imported';
        if (res.skip_dedup) msg += ', ' + res.skip_dedup + ' duplicate(s) skipped';
        showToast(msg, res.inserted ? 'success' : 'info');
        if (res.inserted) {
          setTimeout(function () { location.reload(); }, 800);
        }
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(refreshAlertsBtn, false);
      }
    });
  }

  // Ignore case buttons
  let currentIgnoreCaseId = null;
  document.querySelectorAll('.ignore-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      currentIgnoreCaseId = this.dataset.caseId;
      openModal('ignoreModal');
    });
  });

  const ignoreModal = document.getElementById('ignoreModal');
  if (ignoreModal) {
    document.getElementById('ignoreModalClose').addEventListener('click', function () { closeModal('ignoreModal'); });
    document.getElementById('ignoreCancelBtn').addEventListener('click', function () { closeModal('ignoreModal'); });
    document.getElementById('ignoreConfirmBtn').addEventListener('click', async function () {
      if (!currentIgnoreCaseId) return;
      const notes = (document.getElementById('ignoreNotes').value || '').trim();
      if (!notes) { showToast('Notes are required', 'error'); return; }
      if (!_validateResolution('ignoreNotes')) return;
      const btn = this;
      setLoading(btn, true);
      try {
        var body = { status: 'ignored', notes: notes };
        if (_integrationEnabled) body.resolution = _getResolution('ignoreNotes');
        await apiPost('/alerts/' + currentIgnoreCaseId + '/close', body);
        showToast('Case marked as ignored', 'success');
        closeModal('ignoreModal');
        setTimeout(function () { location.reload(); }, 800);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
    ignoreModal.addEventListener('click', function (e) {
      if (e.target === ignoreModal) closeModal('ignoreModal');
    });
  }

  // ============================================================
  // Bulk actions — select/deselect, bar, bulk ignore
  // ============================================================
  var bulkActionBar = document.getElementById('bulkActionBar');
  var bulkCountEl = document.getElementById('bulkCount');
  var selectAllCb = document.getElementById('selectAllCases');

  function _getSelectedIds() {
    var ids = [];
    document.querySelectorAll('.case-select-cb:checked').forEach(function (cb) {
      ids.push(parseInt(cb.dataset.caseId));
    });
    return ids;
  }

  function _updateBulkBar() {
    var ids = _getSelectedIds();
    if (bulkActionBar) {
      bulkActionBar.style.display = ids.length >= 2 ? 'flex' : 'none';
    }
    if (bulkCountEl) {
      bulkCountEl.textContent = ids.length + ' selected';
    }
  }

  if (selectAllCb) {
    selectAllCb.addEventListener('change', function () {
      var checked = this.checked;
      document.querySelectorAll('.case-select-cb').forEach(function (cb) {
        cb.checked = checked;
      });
      _updateBulkBar();
    });
  }

  document.addEventListener('change', function (e) {
    if (e.target.classList.contains('case-select-cb')) {
      _updateBulkBar();
      // Uncheck select-all if any individual is unchecked
      if (selectAllCb && !e.target.checked) selectAllCb.checked = false;
    }
  });

  var bulkClearBtn = document.getElementById('bulkClearBtn');
  if (bulkClearBtn) {
    bulkClearBtn.addEventListener('click', function () {
      document.querySelectorAll('.case-select-cb').forEach(function (cb) { cb.checked = false; });
      if (selectAllCb) selectAllCb.checked = false;
      _updateBulkBar();
    });
  }

  var bulkIgnoreBtn = document.getElementById('bulkIgnoreBtn');
  if (bulkIgnoreBtn) {
    bulkIgnoreBtn.addEventListener('click', function () {
      var ids = _getSelectedIds();
      if (ids.length < 2) return;
      var countEl = document.getElementById('bulkIgnoreCount');
      if (countEl) countEl.textContent = ids.length;
      var notesEl = document.getElementById('bulkIgnoreNotes');
      if (notesEl) notesEl.value = '';
      openModal('bulkIgnoreModal');
    });
  }

  var bulkIgnoreModal = document.getElementById('bulkIgnoreModal');
  if (bulkIgnoreModal) {
    document.getElementById('bulkIgnoreModalClose').addEventListener('click', function () { closeModal('bulkIgnoreModal'); });
    document.getElementById('bulkIgnoreCancelBtn').addEventListener('click', function () { closeModal('bulkIgnoreModal'); });
    bulkIgnoreModal.addEventListener('click', function (e) { if (e.target === bulkIgnoreModal) closeModal('bulkIgnoreModal'); });

    document.getElementById('bulkIgnoreConfirmBtn').addEventListener('click', async function () {
      var ids = _getSelectedIds();
      if (!ids.length) return;
      var notes = ((document.getElementById('bulkIgnoreNotes') || {}).value || '').trim();
      if (!notes) { showToast('Notes are required', 'error'); return; }
      if (!_validateResolution('bulkIgnoreNotes')) return;
      var btn = this;
      setLoading(btn, true);
      try {
        var body = { case_ids: ids, notes: notes };
        if (_integrationEnabled) body.resolution = _getResolution('bulkIgnoreNotes');
        var res = await apiPost('/alerts/bulk/ignore', body);
        var ok = (res.results || []).length;
        var fail = (res.errors || []).length;
        showToast(ok + ' case(s) ignored' + (fail ? ', ' + fail + ' failed' : ''), ok ? 'success' : 'error');
        closeModal('bulkIgnoreModal');
        setTimeout(function () { location.reload(); }, 800);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // ============================================================
  // Bulk suppress
  // ============================================================
  var bulkSuppressBtn = document.getElementById('bulkSuppressBtn');
  if (bulkSuppressBtn) {
    bulkSuppressBtn.addEventListener('click', function () {
      var ids = _getSelectedIds();
      if (ids.length < 2) return;
      var countEl = document.getElementById('bulkSuppressCount');
      if (countEl) countEl.textContent = ids.length;
      var notesEl = document.getElementById('bulkSuppressNotes');
      if (notesEl) notesEl.value = '';
      openModal('bulkSuppressModal');
    });
  }

  var bulkSuppressModal = document.getElementById('bulkSuppressModal');
  if (bulkSuppressModal) {
    document.getElementById('bulkSuppressModalClose').addEventListener('click', function () { closeModal('bulkSuppressModal'); });
    document.getElementById('bulkSuppressCancelBtn').addEventListener('click', function () { closeModal('bulkSuppressModal'); });
    bulkSuppressModal.addEventListener('click', function (e) { if (e.target === bulkSuppressModal) closeModal('bulkSuppressModal'); });

    document.getElementById('bulkSuppressConfirmBtn').addEventListener('click', async function () {
      var ids = _getSelectedIds();
      if (!ids.length) return;
      var notes = ((document.getElementById('bulkSuppressNotes') || {}).value || '').trim();
      if (!notes) { showToast('Notes are required', 'error'); return; }
      if (!_validateResolution('bulkSuppressNotes')) return;
      var btn = this;
      setLoading(btn, true);
      try {
        var body = { case_ids: ids, notes: notes };
        if (_integrationEnabled) body.resolution = _getResolution('bulkSuppressNotes');
        var res = await apiPost('/alerts/bulk/suppress', body);
        var ok = (res.results || []).length;
        var fail = (res.errors || []).length;
        showToast(ok + ' case(s) suppressed' + (fail ? ', ' + fail + ' failed' : ''), ok ? 'success' : 'error');
        closeModal('bulkSuppressModal');
        setTimeout(function () { location.reload(); }, 800);
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // ============================================================
  // Live polling for cases list (page 1 only, respects current filters)
  // ============================================================

  var casesTable = document.getElementById('casesTable');
  if (casesTable) {
    var _params   = new URLSearchParams(location.search);
    var _pollPage = parseInt(_params.get('page') || '1');
    var _pollSt   = _params.get('status') || 'open';
    var _pollQ    = _params.get('q') || '';

    var _knownIds = new Set();
    casesTable.querySelectorAll('.case-row[data-case-id]').forEach(function (tr) {
      _knownIds.add(String(tr.dataset.caseId));
    });

    if (_pollPage === 1) {
      setInterval(_pollCases, 10000);
    }

    function _pollCases() {
      apiGet('/alerts/api/cases?status=' + encodeURIComponent(_pollSt) + '&q=' + encodeURIComponent(_pollQ))
        .then(function (data) {
          _updateSummaryCards(data.summary || {});
          var cases = data.cases || [];
          var tbody = casesTable.querySelector('tbody');
          if (!tbody) return;
          // Update existing rows
          cases.forEach(function (c) {
            var row = tbody.querySelector('.case-row[data-case-id="' + c.id + '"]');
            if (row) _updateCaseRow(row, c);
          });
          // Prepend genuinely new rows
          cases.filter(function (c) { return !_knownIds.has(String(c.id)); })
            .forEach(function (c) {
              _knownIds.add(String(c.id));
              var tmp = document.createElement('tbody');
              tmp.innerHTML = _caseRowHtml(c);
              var newRow = tmp.firstElementChild;
              if (!newRow) return;
              newRow.classList.add('case-row-new');
              var firstRow = tbody.querySelector('.case-row');
              if (firstRow) tbody.insertBefore(newRow, firstRow);
              else tbody.appendChild(newRow);
              // Remove "no cases" empty row if present
              var emptyRow = tbody.querySelector('td[colspan]');
              if (emptyRow) emptyRow.closest('tr').remove();
              // Wire the ignore button on the new row
              var ignBtn2 = newRow.querySelector('.ignore-btn');
              if (ignBtn2) {
                ignBtn2.addEventListener('click', function () {
                  currentIgnoreCaseId = this.dataset.caseId;
                  openModal('ignoreModal');
                });
              }
              // Wire the exception button on the new row
              var exBtn2 = newRow.querySelector('.case-exception-btn');
              if (exBtn2 && typeof window._wireCaseExceptionBtn === 'function') {
                window._wireCaseExceptionBtn(exBtn2);
              }
              setTimeout(function () { newRow.classList.remove('case-row-new'); }, 3000);
            });
        })
        .catch(function () { /* silent fail */ });
    }

    function _updateSummaryCards(summary) {
      var map = { open: '.stat-open', excepted: '.stat-excepted', suppressed: '.stat-suppressed', ignored: '.stat-ignored' };
      Object.keys(map).forEach(function (k) {
        var el = document.querySelector(map[k] + ' .stat-value');
        if (el && summary[k] !== undefined) el.textContent = summary[k];
      });
    }

    function _updateCaseRow(row, c) {
      var countBadge = row.querySelector('.count-badge');
      if (countBadge) countBadge.textContent = c.total_count;
      var cells = row.querySelectorAll('td');
      if (cells[6]) cells[6].textContent = (c.last_seen || '').slice(0, 16);
      var statusBadge = row.querySelector('.status-badge');
      if (statusBadge) {
        statusBadge.textContent = c.status;
        statusBadge.className = 'status-badge status-' + c.status;
      }
    }

    function _caseRowHtml(c) {
      var lvl  = escapeHtml(String(c.rule_level || ''));
      var rid  = escapeHtml(String(c.rule_id || ''));
      var desc = escapeHtml(c.rule_description || 'No description');
      var fs   = escapeHtml((c.first_seen || '').slice(0, 16));
      var ls   = escapeHtml((c.last_seen  || '').slice(0, 16));
      var st   = escapeHtml(c.status || '');
      var openBtns = '';
      if (c.status === 'open') {
        openBtns =
          '<button class="btn btn-xs btn-ghost case-exception-btn" data-rule-id="' + rid + '" data-case-id="' + c.id + '" title="Create exception">Exception</button>' +
          '<button class="btn btn-xs btn-ghost ignore-btn" data-case-id="' + c.id + '">Ignore</button>';
      }
      return '<tr class="case-row" data-case-id="' + c.id + '" data-status="' + st + '">' +
        '<td><span class="level-badge level-' + lvl + '">' + lvl + '</span></td>' +
        '<td class="font-mono">' + rid + '</td>' +
        '<td class="description-cell"><a href="/alerts/' + c.id + '" class="case-link">' + desc + '</a></td>' +
        '<td class="font-mono text-sm">' + (c.agent_count || 0) + '</td>' +
        '<td><span class="count-badge">' + (c.total_count || 0) + '</span></td>' +
        '<td class="text-sm text-muted">' + fs + '</td>' +
        '<td class="text-sm text-muted">' + ls + '</td>' +
        '<td><span class="status-badge status-' + st + '">' + st + '</span></td>' +
        '<td class="actions-cell">' +
          '<a href="/alerts/' + c.id + '" class="btn btn-xs btn-ghost">View</a>' +
          openBtns +
        '</td></tr>';
    }
  }

  // ============================================================
  // Exception modal — cases LIST page
  // ============================================================

  (function _initCaseListExModal() {
    var _listExCaseId = null;
    var _listExRuleId = null;
    var _listExBaseXml = null;
    var _listExFieldsCache = null;
    var _listExRemovedFields = [];
    var _listExLastDiff = null;
    var _listExHasDirectDeletes = false;

    function _excXml(s) {
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function _buildPreviewXml() {
      if (_listExBaseXml === null) return null;

      function _escRe(s) {
        return String(s).replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
      }

      var xml = _listExBaseXml;
      var newFields = [];

      document.querySelectorAll('#listExFieldGroups .rex-field-group').forEach(function (grp) {
        var fieldName = _wazuhField((grp.dataset.fieldName || '').trim());
        if (!fieldName) return;

        var matchType = (grp.querySelector('.rex-match-type') || { value: 'pcre2' }).value;

        var existingVals = [];
        grp.querySelectorAll('.rex-chip[data-existing]').forEach(function (c) {
          if (c.dataset.value) existingVals.push(c.dataset.value);
        });
        var newVals = [];
        grp.querySelectorAll('.rex-chip:not([data-existing])').forEach(function (c) {
          if (c.dataset.value) newVals.push(c.dataset.value);
        });

        if (grp.dataset.isExisting === '1') {
          var allVals = existingVals.concat(newVals);
          var fieldRe = new RegExp(
            '([ \\t]*)<field\\s[^>]*name="' + _escRe(fieldName) + '"[^>]*negate="yes"[^>]*>[^<]*<\\/field>',
            'g'
          );
          if (allVals.length) {
            var pat = matchType === 'pcre2'
              ? '(?i)(' + allVals.map(_excXml).join('|') + ')'
              : allVals.map(_excXml).join('|');
            xml = xml.replace(fieldRe, function (m, indent) {
              return indent + '<field name="' + _excXml(fieldName) + '" type="' + matchType + '" negate="yes">' + pat + '</field>';
            });
          } else {
            xml = xml.replace(
              new RegExp('\\r?\\n[ \\t]*<field\\s[^>]*name="' + _escRe(fieldName) + '"[^>]*negate="yes"[^>]*>[^<]*<\\/field>', 'g'),
              ''
            );
          }
        } else {
          if (!newVals.length) return;
          var pat = matchType === 'pcre2'
            ? '(?i)(' + newVals.map(_excXml).join('|') + ')'
            : newVals.map(_excXml).join('|');
          newFields.push('  <field name="' + _excXml(fieldName) + '" type="' + matchType + '" negate="yes">' + pat + '</field>');
        }
      });

      // Remove fields whose groups were deleted from the UI via the remove button
      _listExRemovedFields.forEach(function (fn) {
        xml = xml.replace(
          new RegExp('\\r?\\n[ \\t]*<field\\s[^>]*name="' + _escRe(fn) + '"[^>]*negate="yes"[^>]*>[^<]*<\\/field>', 'g'),
          ''
        );
      });

      if (!newFields.length) return xml;
      var lines = xml.split('\n');
      var insertAt = -1;
      for (var li = 0; li < lines.length; li++) {
        if (/^\s*<(description|mitre|options|group)[\s>\/]/.test(lines[li])) { insertAt = li; break; }
      }
      if (insertAt === -1) {
        for (var lj = 0; lj < lines.length; lj++) {
          if (/^\s*<\/rule>/.test(lines[lj])) { insertAt = lj; break; }
        }
      }
      if (insertAt === -1) return xml + '\n' + newFields.join('\n');
      var result = lines.slice(0, insertAt);
      newFields.forEach(function (f) { result.push(f); });
      lines.slice(insertAt).forEach(function (l) { result.push(l); });
      return result.join('\n');
    }

    function _updatePreview() {
      var el = document.getElementById('listExXmlPreview');
      if (!el) return;
      var xml = _buildPreviewXml();
      if (xml === null) {
        el.innerHTML = '<span class="text-muted" style="font-size:12px">Loading rule XML...</span>';
        return;
      }
      if (typeof highlightXml === 'function') {
        el.innerHTML = highlightXml(escapeHtml(xml));
      } else {
        el.textContent = xml;
      }
    }

    function _loadFields(callback) {
      if (_listExFieldsCache !== null) { callback(_listExFieldsCache); return; }
      apiGet('/rules/api/fields').then(function (data) {
        _listExFieldsCache = data.fields || [];
        callback(_listExFieldsCache);
      }).catch(function () {
        _listExFieldsCache = [];
        callback([]);
      });
    }

    function _addFieldGroup(fields, prefill) {
      var container = document.getElementById('listExFieldGroups');
      if (!container) return;

      var group = document.createElement('div');
      group.className = 'rex-field-group';

      var initMatchType = (prefill && prefill.matchType) ? prefill.matchType : 'pcre2';

      group.innerHTML =
        '<div class="rex-field-header">' +
          '<div class="rex-search-wrap">' +
            '<input type="text" class="form-control form-control-sm rex-search" placeholder="Search or type a field name..." autocomplete="off">' +
            '<div class="rex-dropdown">' +
              fields.map(function (f) {
                return '<div class="rex-opt" data-field="' + escapeHtml(f) + '">' + escapeHtml(f) + '</div>';
              }).join('') +
            '</div>' +
          '</div>' +
          '<select class="form-control form-control-sm rex-match-type" style="max-width:140px" title="Match type for this field">' +
            '<option value="pcre2"'   + (initMatchType === 'pcre2'   ? ' selected' : '') + '>PCRE2</option>' +
            '<option value="osmatch"' + (initMatchType === 'osmatch' ? ' selected' : '') + '>OS Match</option>' +
            '<option value="osregex"' + (initMatchType === 'osregex' ? ' selected' : '') + '>OS Regex</option>' +
          '</select>' +
          '<button type="button" class="btn btn-xs btn-ghost rex-remove-group">Remove</button>' +
        '</div>' +
        '<div class="rex-field-body" style="display:none">' +
          '<div class="rex-value-chips"></div>' +
          '<div class="rex-add-row">' +
            '<input type="text" class="form-control form-control-sm rex-value-input" placeholder="Enter a value...">' +
            '<button type="button" class="btn btn-xs btn-secondary rex-value-add">Add</button>' +
          '</div>' +
        '</div>';

      var searchInput  = group.querySelector('.rex-search');
      var dropdown     = group.querySelector('.rex-dropdown');
      var searchWrap   = group.querySelector('.rex-search-wrap');
      var fieldBody    = group.querySelector('.rex-field-body');
      var chips        = group.querySelector('.rex-value-chips');
      var valueInput   = group.querySelector('.rex-value-input');
      var addBtn       = group.querySelector('.rex-value-add');
      var removeBtn    = group.querySelector('.rex-remove-group');
      var matchTypeSel = group.querySelector('.rex-match-type');

      matchTypeSel.addEventListener('change', _updatePreview);

      searchInput.addEventListener('focus', function () { searchWrap.dataset.open = '1'; });
      searchInput.addEventListener('click', function () { searchWrap.dataset.open = '1'; });
      searchInput.addEventListener('blur', function () {
        setTimeout(function () {
          delete searchWrap.dataset.open;
          var v = searchInput.value.trim();
          if (v && !group.dataset.fieldName) {
            group.dataset.fieldName = v;
            fieldBody.style.display = 'block';
          }
        }, 180);
      });
      searchInput.addEventListener('input', function () {
        var q = this.value.toLowerCase();
        group.dataset.fieldName = this.value.trim();
        if (this.value.trim()) fieldBody.style.display = 'block';
        dropdown.querySelectorAll('.rex-opt').forEach(function (opt) {
          opt.style.display = (!q || opt.dataset.field.toLowerCase().indexOf(q) !== -1) ? '' : 'none';
        });
        searchWrap.dataset.open = '1';
        _updatePreview();
      });

      dropdown.addEventListener('mousedown', function (e) {
        e.preventDefault();
        var opt = e.target.closest('.rex-opt');
        if (!opt) return;
        searchInput.value = opt.dataset.field;
        group.dataset.fieldName = opt.dataset.field;
        delete searchWrap.dataset.open;
        fieldBody.style.display = 'block';
        valueInput.focus();
        _updatePreview();
      });

      function _addChip(v) {
        v = (v || valueInput.value).trim();
        if (!v) return;
        var dup = false;
        chips.querySelectorAll('.rex-chip').forEach(function (c) { if (c.dataset.value === v) dup = true; });
        if (dup) { valueInput.select(); return; }
        var chip = document.createElement('div');
        chip.className = 'rex-chip';
        chip.dataset.value = v;
        chip.innerHTML =
          '<span class="rex-chip-text font-mono">' + escapeHtml(v) + '</span>' +
          '<button type="button" class="rex-chip-rm" title="Remove">&times;</button>';
        chip.querySelector('.rex-chip-rm').addEventListener('click', function () { chip.remove(); _updatePreview(); });
        chips.appendChild(chip);
        valueInput.value = '';
        valueInput.focus();
        _updatePreview();
      }

      addBtn.addEventListener('click', function () { _addChip(); });
      valueInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); _addChip(); }
      });

      removeBtn.addEventListener('click', function () {
        if (group.dataset.isExisting && group.dataset.origFieldName) {
          _listExRemovedFields.push(group.dataset.origFieldName);
        }
        if (container.querySelectorAll('.rex-field-group').length > 1) {
          group.remove();
        } else {
          searchInput.value = '';
          delete group.dataset.fieldName;
          delete group.dataset.isExisting;
          delete group.dataset.origFieldName;
          fieldBody.style.display = 'none';
          chips.innerHTML = '';
          valueInput.value = '';
          matchTypeSel.value = 'pcre2';
          dropdown.querySelectorAll('.rex-opt').forEach(function (o) { o.style.display = ''; });
        }
        _updatePreview();
      });

      container.appendChild(group);

      if (prefill && prefill.fieldName) {
        searchInput.value = prefill.fieldName;
        group.dataset.fieldName = prefill.fieldName;
        if (prefill.isExisting === true) {
          group.dataset.isExisting = '1';
          group.dataset.origFieldName = prefill.fieldName;
        }
        fieldBody.style.display = 'block';
        (prefill.existingValues || []).forEach(function (v) {
          var chip = document.createElement('div');
          chip.className = 'rex-chip rex-chip-existing';
          chip.dataset.value = v;
          chip.dataset.existing = '1';
          chip.title = 'Already in exception';
          chip.innerHTML =
            '<span class="rex-chip-text font-mono">' + escapeHtml(v) + '</span>' +
            '<span class="rex-chip-tag">existing</span>' +
            '<button type="button" class="rex-chip-rm" title="Delete this value">&times;</button>';
          chip.querySelector('.rex-chip-rm').addEventListener('click', function () {
            var src = parseInt(_listExRuleId, 10) < 100000 ? 'default' : 'custom';
            confirm('Delete Value', 'Delete "' + v + '" from this exception?', function () {
              apiPost('/rules/exceptions/delete', {
                rule_id: _listExRuleId,
                rule_source: src,
                field_name: group.dataset.origFieldName,
                field_value: v,
              }).then(function () {
                chip.remove();
                _listExHasDirectDeletes = true;
                _updatePreview();
                showToast('Value deleted', 'success');
              }).catch(function (e) {
                showToast('Failed: ' + e.message, 'error');
              });
            });
          });
          chips.appendChild(chip);
        });
        setTimeout(function () { valueInput.focus(); }, 0);
      }
    }

    function _openListExModal(ruleId, caseId) {
      _listExRuleId = String(ruleId);
      _listExCaseId = caseId ? String(caseId) : null;
      _listExBaseXml = null;
      _listExRemovedFields = [];
      _listExLastDiff = null;
      _listExHasDirectDeletes = false;
      _listExFieldsCache = null; // reset so fields are re-fetched for this case
      var ruleIdEl = document.getElementById('listExRuleId');
      if (ruleIdEl) ruleIdEl.value = _listExRuleId;
      var notesEl = document.getElementById('listExNotes');
      if (notesEl) notesEl.value = '';
      var groups = document.getElementById('listExFieldGroups');
      if (groups) groups.innerHTML = '';
      // Hide common/similar fields wraps until data arrives
      var commonWrap = document.getElementById('listExCommonFieldsWrap');
      if (commonWrap) commonWrap.style.display = 'none';
      var similarWrap = document.getElementById('listExSimilarFieldsWrap');
      if (similarWrap) similarWrap.style.display = 'none';
      _updatePreview();
      openModal('listExModal');

      var _apiSrc = (parseInt(_listExRuleId, 10) < 100000) ? 'default' : 'custom';
      var fieldsReady = false, existingReady = false;
      var _fields = [], _existing = [];

      function _buildGroups() {
        if (!fieldsReady || !existingReady) return;
        _existing.forEach(function (nf) {
          _addFieldGroup(_fields, {
            fieldName: nf.field_name,
            existingValues: nf.values || [],
            matchType: nf.match_type || 'pcre2',
            isExisting: true,
          });
        });
        _addFieldGroup(_fields, null);
        _updatePreview();
      }

      function _showCommonFields(commonFields) {
        var wrap = document.getElementById('listExCommonFieldsWrap');
        var chipsEl = document.getElementById('listExCommonFieldsChips');
        if (!wrap || !chipsEl) return;
        var keys = Object.keys(commonFields || {});
        if (!keys.length) { wrap.style.display = 'none'; return; }
        chipsEl.innerHTML = '';
        keys.sort().forEach(function (field) {
          var value = commonFields[field];
          var chip = document.createElement('button');
          chip.type = 'button';
          chip.className = 'btn btn-xs btn-ghost common-field-chip';
          chip.textContent = field;
          chip.title = String(value).slice(0, 80);
          chip.addEventListener('click', function () {
            // Check if a group for this field already exists
            var existingGrp = null;
            document.querySelectorAll('#listExFieldGroups .rex-field-group').forEach(function (g) {
              if (g.dataset.fieldName === field) existingGrp = g;
            });
            if (!existingGrp) {
              // Reuse an empty group if one exists
              var emptyGrp = null;
              document.querySelectorAll('#listExFieldGroups .rex-field-group').forEach(function (g) {
                if (!g.dataset.fieldName && !emptyGrp) emptyGrp = g;
              });
              if (emptyGrp) {
                // Fill the empty group with this field
                var searchIn = emptyGrp.querySelector('.rex-search');
                if (searchIn) searchIn.value = field;
                emptyGrp.dataset.fieldName = field;
                var fb = emptyGrp.querySelector('.rex-field-body');
                if (fb) fb.style.display = 'block';
              } else {
                var prefill = { fieldName: field, existingValues: [] };
                _addFieldGroup(_listExFieldsCache || _fields, prefill);
              }
              // Auto-add the common value as a chip
              if (value) {
                var grps = document.querySelectorAll('#listExFieldGroups .rex-field-group');
                var targetGrp = emptyGrp || grps[grps.length - 1];
                if (targetGrp) {
                  var valInput = targetGrp.querySelector('.rex-value-input');
                  if (valInput) { valInput.value = value; }
                  var addValBtn = targetGrp.querySelector('.rex-value-add');
                  if (addValBtn) addValBtn.click();
                }
              }
            }
          });
          chipsEl.appendChild(chip);
        });
        wrap.style.display = '';
      }

      function _showSimilarFields(similarFields) {
        var wrap = document.getElementById('listExSimilarFieldsWrap');
        var chipsEl = document.getElementById('listExSimilarFieldsChips');
        if (!wrap || !chipsEl) return;
        var keys = Object.keys(similarFields || {});
        if (!keys.length) { wrap.style.display = 'none'; return; }
        chipsEl.innerHTML = '';
        keys.sort().forEach(function (field) {
          var subs = similarFields[field];
          var row = document.createElement('div');
          row.style.marginBottom = '8px';
          var label = document.createElement('span');
          label.className = 'font-mono text-sm';
          label.style.color = 'var(--text-secondary)';
          label.textContent = field + ':';
          row.appendChild(label);
          subs.forEach(function (sub) {
            var chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'btn btn-xs btn-ghost common-field-chip';
            chip.textContent = sub;
            chip.title = 'Use \'' + sub + '\' as negation pattern for ' + field;
            chip.style.marginLeft = '6px';
            chip.addEventListener('click', function () {
              var existingGrp = null;
              document.querySelectorAll('#listExFieldGroups .rex-field-group').forEach(function (g) {
                if (g.dataset.fieldName === field) existingGrp = g;
              });
              if (!existingGrp) {
                var emptyGrp = null;
                document.querySelectorAll('#listExFieldGroups .rex-field-group').forEach(function (g) {
                  if (!g.dataset.fieldName && !emptyGrp) emptyGrp = g;
                });
                if (emptyGrp) {
                  var searchIn = emptyGrp.querySelector('.rex-search');
                  if (searchIn) searchIn.value = field;
                  emptyGrp.dataset.fieldName = field;
                  var fb = emptyGrp.querySelector('.rex-field-body');
                  if (fb) fb.style.display = 'block';
                } else {
                  _addFieldGroup(_listExFieldsCache || _fields, { fieldName: field, existingValues: [] });
                }
              }
              var grps = document.querySelectorAll('#listExFieldGroups .rex-field-group');
              var targetGrp = existingGrp || grps[grps.length - 1];
              if (targetGrp) {
                var valInput = targetGrp.querySelector('.rex-value-input');
                if (valInput) { valInput.value = sub; }
                var addValBtn = targetGrp.querySelector('.rex-value-add');
                if (addValBtn) addValBtn.click();
              }
            });
            row.appendChild(chip);
          });
          chipsEl.appendChild(row);
        });
        wrap.style.display = '';
      }

      // Collapsible toggle handlers for common/similar sections
      ['listExCommonToggle', 'listExSimilarToggle'].forEach(function (id) {
        var toggle = document.getElementById(id);
        if (toggle) {
          toggle.addEventListener('click', function () {
            this.classList.toggle('collapsed');
          });
        }
      });

      // Use fields from this specific alert's events when available.
      // Store result in _listExFieldsCache so the "Add Another Field" button
      // also gets the case-specific list, not the full generic field list.
      if (_listExCaseId) {
        apiGet('/alerts/api/fields/' + _listExCaseId).then(function (data) {
          _listExFieldsCache = data.fields || [];
          _fields = _listExFieldsCache;
          _showCommonFields(data.common_fields || {});
          _showSimilarFields(data.similar_fields || {});
          fieldsReady = true;
          _buildGroups();
        }).catch(function () {
          _loadFields(function (fields) { _fields = fields; fieldsReady = true; _buildGroups(); });
        });
      } else {
        _loadFields(function (fields) {
          _fields = fields;
          fieldsReady = true;
          _buildGroups();
        });
      }

      apiGet('/rules/api/exceptions/' + _listExRuleId).then(function (data) {
        _existing = data.negate_fields || [];
        existingReady = true;
        _buildGroups();
      }).catch(function () {
        _existing = [];
        existingReady = true;
        _buildGroups();
      });

      apiGet('/rules/api/rule/' + _apiSrc + '/' + _listExRuleId).then(function (data) {
        _listExBaseXml = data.raw_xml || '';
        _updatePreview();
      }).catch(function () {
        _listExBaseXml = '';
        _updatePreview();
      });
    }

    function _wireExBtn(btn) {
      btn.addEventListener('click', function () {
        _openListExModal(this.dataset.ruleId, this.dataset.caseId);
      });
    }

    document.querySelectorAll('.case-exception-btn').forEach(_wireExBtn);

    var modal = document.getElementById('listExModal');
    if (!modal) return;

    document.getElementById('listExModalClose').addEventListener('click', function () { closeModal('listExModal'); });
    document.getElementById('listExCancelBtn').addEventListener('click', function () { closeModal('listExModal'); });
    // No backdrop-click close on exception modal

    var diffModal = document.getElementById('listExDiffModal');
    if (diffModal) {
      document.getElementById('listExDiffModalClose').addEventListener('click', function () {
        closeModal('listExDiffModal'); location.reload();
      });
      document.getElementById('listExDiffDoneBtn').addEventListener('click', function () {
        closeModal('listExDiffModal'); location.reload();
      });
      diffModal.addEventListener('click', function (e) {
        if (e.target === diffModal) { closeModal('listExDiffModal'); location.reload(); }
      });
    }

    document.getElementById('listExAddFieldBtn').addEventListener('click', function () {
      _loadFields(function (fields) { _addFieldGroup(fields, null); });
    });

    document.getElementById('listExSubmitBtn').addEventListener('click', async function () {
      var notes = (document.getElementById('listExNotes').value || '').trim();
      if (!notes) { showToast('Notes are required', 'error'); return; }
      if (!_validateResolution('listExNotes')) return;

      var entries = [];
      document.querySelectorAll('#listExFieldGroups .rex-field-group').forEach(function (grp) {
        var fieldName = (grp.dataset.fieldName || '').trim();
        if (!fieldName) return;
        var matchType = (grp.querySelector('.rex-match-type') || { value: 'pcre2' }).value;
        var values = [];
        grp.querySelectorAll('.rex-chip:not([data-existing])').forEach(function (c) {
          if (c.dataset.value) values.push(c.dataset.value);
        });
        if (!values.length) return;
        entries.push({ field_name: fieldName, field_values: values, match_type: matchType });
      });

      if (!entries.length && !_listExRemovedFields.length && !_listExHasDirectDeletes) {
        showToast('Add at least one new value to a field', 'warning');
        return;
      }

      var btn = this;
      setLoading(btn, true);
      var errors = [];
      var _apiSrc = parseInt(_listExRuleId, 10) < 100000 ? 'default' : 'custom';

      // Delete removed existing fields first
      for (var j = 0; j < _listExRemovedFields.length; j++) {
        try {
          var delResp = await apiPost('/rules/exceptions/delete', {
            rule_id: _listExRuleId,
            rule_source: _apiSrc,
            field_name: _listExRemovedFields[j],
            field_value: '',
          });
          if (delResp && delResp.diff) _listExLastDiff = delResp.diff;
        } catch (e) {
          errors.push('Delete ' + _listExRemovedFields[j] + ': ' + e.message);
        }
      }

      // Create new exception entries
      for (var i = 0; i < entries.length; i++) {
        try {
          var exBody = {
            rule_id:      _listExRuleId,
            field_name:   entries[i].field_name,
            field_values: entries[i].field_values,
            match_type:   entries[i].match_type,
            case_id:      _listExCaseId,
            notes:        notes,
          };
          if (_integrationEnabled) exBody.resolution = _getResolution('listExNotes');
          var resp = await apiPost('/rules/exceptions/create', exBody);
          if (resp && resp.diff) _listExLastDiff = resp.diff;
        } catch (e) {
          errors.push(entries[i].field_name + ': ' + e.message);
        }
      }

      setLoading(btn, false);
      if (errors.length) {
        showToast('Failed: ' + errors.join('; '), 'error');
      } else {
        var msg = [];
        if (_listExRemovedFields.length) msg.push(_listExRemovedFields.length + ' field' + (_listExRemovedFields.length > 1 ? 's' : '') + ' deleted');
        if (entries.length) msg.push(entries.length + ' exception' + (entries.length > 1 ? 's' : '') + ' created');
        showToast((msg.join(', ') || 'Done') + ' for rule ' + _listExRuleId, 'success');
        closeModal('listExModal');
        // Show diff modal if we have a diff from the last create
        if (_listExLastDiff) {
          var diffEl = document.getElementById('listExDiffContent');
          if (diffEl && typeof renderDiff === 'function') {
            renderDiff(_listExLastDiff, diffEl);
            openModal('listExDiffModal');
          } else {
            setTimeout(function () { location.reload(); }, 600);
          }
        } else {
          setTimeout(function () { location.reload(); }, 600);
        }
      }
    });

    // Expose wire function so the live-poll callback can wire newly inserted rows
    window._wireCaseExceptionBtn = _wireExBtn;
  })();

  // ============================================================
  // CASE DETAIL page
  // ============================================================

  if (typeof window.CASE_ID === 'undefined') return;

  // Tracks whether a page reload should happen when the diff modal is dismissed
  var _pendingReload = false;

  // ============================================================
  // Highlight similar substrings in field values
  // ============================================================
  function _applySimilarHighlights() {
    document.querySelectorAll('.field-row.field-similar .field-val[data-similar]').forEach(function (el) {
      var subs = (el.dataset.similar || '').split(',').filter(function (s) { return s.length >= 4; });
      if (!subs.length) return;
      var html = escapeHtml(el.textContent);
      subs.sort(function (a, b) { return b.length - a.length; });
      subs.forEach(function (sub) {
        var escaped = sub.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        var re = new RegExp('(' + escaped + ')', 'gi');
        html = html.replace(re, '<span class="sim-match">$1</span>');
      });
      el.innerHTML = html;
    });
  }
  function _removeSimilarHighlights() {
    document.querySelectorAll('.field-row.field-similar .field-val[data-similar]').forEach(function (el) {
      el.textContent = el.textContent; // strips HTML, keeps text
    });
  }
  _applySimilarHighlights();

  // ============================================================
  // Legend swatch toggle — click to turn highlighting on/off
  // ============================================================
  document.querySelectorAll('.field-legend-toggle').forEach(function (item) {
    item.addEventListener('click', function () {
      var type = this.dataset.highlight;
      var isOff = this.classList.toggle('hl-off');
      if (type === 'common') {
        document.querySelectorAll('.field-row.field-common').forEach(function (r) {
          r.classList.toggle('field-common-off', isOff);
        });
      } else if (type === 'similar') {
        document.querySelectorAll('.field-row.field-similar').forEach(function (r) {
          r.classList.toggle('field-similar-off', isOff);
        });
        if (isOff) { _removeSimilarHighlights(); } else { _applySimilarHighlights(); }
      }
    });
  });

  // ============================================================
  // Collapsible headers in exception builder
  // ============================================================
  document.querySelectorAll('#exceptionBuilder .collapsible-header[data-collapse]').forEach(function (hdr) {
    hdr.addEventListener('click', function () {
      this.classList.toggle('collapsed');
    });
  });

  // ============================================================
  // Load All Events — field resolver (mirrors Jinja2 resolve_event_col)
  // ============================================================
  function _resolveField(parsed, ev, field) {
    var shortcuts = {
      'timestamp': function () { return (ev.timestamp || '').slice(0, 19) || '-'; },
      'agent.name': function () { return ev.agent_name || ev.agent_id || '-'; },
      'agent.ip': function () { return ev.agent_ip || '-'; },
      'agent.id': function () { return ev.agent_id || '-'; }
    };
    if (shortcuts[field]) return shortcuts[field]();
    var parts = field.split('.');
    var obj = parsed;
    for (var i = 0; i < parts.length; i++) {
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        obj = obj[parts[i]];
      } else {
        return '-';
      }
      if (obj === undefined || obj === null) return '-';
    }
    return String(obj);
  }

  // ============================================================
  // Load All Events button
  // ============================================================
  var loadAllBtn = document.getElementById('loadAllEventsBtn');
  if (loadAllBtn) {
    loadAllBtn.addEventListener('click', async function () {
      setLoading(loadAllBtn, true);
      var page = 1;
      var allEvents = [];
      var columns = window.EVENT_COLUMNS || [
        {field: 'timestamp', label: 'Timestamp'},
        {field: 'agent.name', label: 'Endpoint'},
        {field: 'agent.ip', label: 'IP Address'}
      ];
      try {
        while (true) {
          var data = await apiGet('/alerts/api/events/' + window.CASE_ID + '?page=' + page);
          var events = data.events || [];
          if (!events.length) break;
          allEvents = allEvents.concat(events);
          if (allEvents.length >= data.total) break;
          page++;
        }
        var accordion = document.getElementById('eventsAccordion');
        if (!accordion) return;
        accordion.innerHTML = '';
        allEvents.forEach(function (ev, idx) {
          var parsed = {};
          try { parsed = ev.raw_json ? JSON.parse(ev.raw_json) : {}; } catch (e) { parsed = {}; }
          var flatPairs = _flattenObj(parsed);
          var colSpans = columns.map(function (col) {
            var val = _resolveField(parsed, ev, col.field);
            return '<span class="event-col font-mono">' + escapeHtml(val) + '</span>';
          }).join('');
          var fieldsHtml = flatPairs.map(function (kv) {
            var useBtn = window.CASE_STATUS === 'open'
              ? '<button class="btn btn-xs btn-ghost use-field-btn" data-field="' + escapeHtml(kv[0]) + '" data-value="' + escapeHtml(kv[1]) + '" title="Use this field for exception">Use</button>'
              : '';
            return '<div class="field-row"><span class="field-key font-mono">' + escapeHtml(kv[0]) + '</span><span class="field-val">' + escapeHtml(kv[1]) + '</span>' + useBtn + '</div>';
          }).join('');
          var rawJson = '';
          try { rawJson = JSON.stringify(parsed, null, 2); } catch (e) { rawJson = ev.raw_json || ''; }
          var html =
            '<div class="event-item">' +
              '<div class="event-header" data-event-index="' + (idx + 1) + '">' +
                '<div class="event-meta">' +
                  colSpans +
                '</div>' +
                '<button class="event-toggle">' +
                  '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>' +
                '</button>' +
              '</div>' +
              '<div class="event-body" id="event-body-' + (idx + 1) + '" style="display:none">' +
                '<div class="event-fields">' + fieldsHtml + '</div>' +
                '<details class="raw-json-details"><summary>Raw JSON</summary><pre class="raw-json">' + escapeHtml(rawJson) + '</pre></details>' +
              '</div>' +
            '</div>';
          accordion.insertAdjacentHTML('beforeend', html);
        });
        // Re-wire event accordion
        accordion.querySelectorAll('.event-header').forEach(function (header) {
          header.addEventListener('click', function () {
            var idx2 = this.dataset.eventIndex;
            var body = document.getElementById('event-body-' + idx2);
            var toggle = this.querySelector('.event-toggle');
            if (!body) return;
            var open = body.style.display !== 'none';
            body.style.display = open ? 'none' : 'block';
            if (toggle) toggle.classList.toggle('open', !open);
          });
        });
        loadAllBtn.parentElement.remove();
      } catch (e) {
        showToast('Failed to load events: ' + e.message, 'error');
      } finally {
        setLoading(loadAllBtn, false);
      }
    });
  }

  function _flattenObj(obj, prefix, result) {
    if (!result) result = [];
    if (!prefix) prefix = '';
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      Object.keys(obj).forEach(function (k) {
        _flattenObj(obj[k], prefix ? prefix + '.' + k : k, result);
      });
    } else if (Array.isArray(obj)) {
      obj.forEach(function (item) { _flattenObj(item, prefix, result); });
    } else if (obj !== null && obj !== undefined && prefix && prefix !== 'timestamp') {
      result.push([prefix, String(obj)]);
    }
    return result;
  }

  // ============================================================
  // Edit Raw — Rule Logic card (inline edit)
  // ============================================================

  var _editRawBtn   = document.getElementById('editRawBtn');
  var _cancelRawBtn = document.getElementById('cancelRawEditBtn');
  var _saveRawBtn   = document.getElementById('saveRawEditBtn');

  function _exitDetailRawEdit() {
    var viewer   = document.getElementById('ruleLogicXml');
    var editWrap = document.getElementById('ruleRawEditWrap');
    if (viewer)    viewer.style.display   = '';
    if (editWrap)  editWrap.style.display = 'none';
    if (_editRawBtn) _editRawBtn.style.display = '';
  }

  if (_editRawBtn) {
    _editRawBtn.addEventListener('click', function () {
      var viewer   = document.getElementById('ruleLogicXml');
      var editWrap = document.getElementById('ruleRawEditWrap');
      var editArea = document.getElementById('ruleRawXml');
      if (!editWrap || !editArea) return;
      editArea.value = window.RULE_XML || '';
      if (viewer)    viewer.style.display   = 'none';
      editWrap.style.display = 'block';
      _editRawBtn.style.display = 'none';
      editArea.focus();
    });
  }

  if (_cancelRawBtn) {
    _cancelRawBtn.addEventListener('click', _exitDetailRawEdit);
  }

  if (_saveRawBtn) {
    _saveRawBtn.addEventListener('click', async function () {
      var editArea = document.getElementById('ruleRawXml');
      if (!editArea) return;
      var newXml = editArea.value;
      setLoading(_saveRawBtn, true);
      try {
        var result = await apiPost('/alerts/' + window.CASE_ID + '/rule/raw', { xml: newXml });
        window.RULE_XML = newXml;
        var viewer = document.getElementById('ruleLogicXml');
        if (viewer && typeof highlightXml === 'function') {
          viewer.innerHTML = highlightXml(escapeHtml(newXml));
        }
        _exitDetailRawEdit();
        showToast('Rule XML updated', 'success');
        if (result.diff) {
          renderDiff(result.diff, document.getElementById('diffContent'));
          _pendingReload = true;
          openModal('diffModal');
        }
      } catch (e) {
        showToast('Save failed: ' + (e.message || String(e)), 'error');
      } finally {
        setLoading(_saveRawBtn, false);
      }
    });
  }

  // Event accordion
  document.querySelectorAll('.event-header').forEach(function (header) {
    header.addEventListener('click', function () {
      const idx = this.dataset.eventIndex;
      const body = document.getElementById('event-body-' + idx);
      const toggle = this.querySelector('.event-toggle');
      if (!body) return;
      const open = body.style.display !== 'none';
      body.style.display = open ? 'none' : 'block';
      if (toggle) toggle.classList.toggle('open', !open);
    });
  });

  // "Use" field button — opens exception builder and fills the field
  document.addEventListener('click', function (e) {
    const useBtn = e.target.closest('.use-field-btn');
    if (!useBtn) return;
    const field = useBtn.dataset.field;
    const value = useBtn.dataset.value;
    var builder = document.getElementById('exceptionBuilder');
    if (!builder) return;

    // Check if this field is already in the exception builder
    var alreadyAdded = false;
    document.querySelectorAll('.ex-entry-row').forEach(function (r) {
      if (r.dataset.fieldName === field) alreadyAdded = true;
    });
    if (alreadyAdded) {
      showToast('Field "' + field + '" is already added', 'info');
      return;
    }

    if (!builder.style.display || builder.style.display === 'none') {
      openExceptionBuilder();
      hideBuilder('suppressionBuilder');
      // Wait for load then fill
      setTimeout(function () {
        fillOrAddExceptionRow(field, value);
        showToast('Field "' + field + '" added to exception', 'success');
      }, 200);
    } else {
      fillOrAddExceptionRow(field, value);
      showToast('Field "' + field + '" added to exception', 'success');
    }
  });

  // Show/hide builders
  const exBtn = document.getElementById('exceptionBtn');
  const supBtn = document.getElementById('suppressionBtn');
  const ignBtn = document.getElementById('ignoreBtn');

  if (exBtn) {
    exBtn.addEventListener('click', function () {
      const el = document.getElementById('exceptionBuilder');
      if (!el) return;
      if (!el.style.display || el.style.display === 'none') {
        openExceptionBuilder();
        hideBuilder('suppressionBuilder');
      } else {
        hideBuilder('exceptionBuilder');
      }
    });
  }
  if (supBtn) {
    supBtn.addEventListener('click', function () {
      toggleBuilder('suppressionBuilder');
      hideBuilder('exceptionBuilder');
    });
  }
  if (ignBtn) {
    ignBtn.addEventListener('click', function () {
      openModal('ignoreModal');
    });
  }

  document.getElementById('exCancelBtn') && document.getElementById('exCancelBtn').addEventListener('click', function () {
    hideBuilder('exceptionBuilder');
  });
  document.getElementById('supCancelBtn') && document.getElementById('supCancelBtn').addEventListener('click', function () {
    hideBuilder('suppressionBuilder');
  });

  // Add another field row button
  const addRowBtn = document.getElementById('addExceptionRowBtn');
  if (addRowBtn) {
    addRowBtn.addEventListener('click', function () {
      addExceptionRow('');
    });
  }

  // Match type change — update previews on all existing rows
  const exMatchType = document.getElementById('exMatchType');
  if (exMatchType) {
    exMatchType.addEventListener('change', function () {
      document.querySelectorAll('.ex-entry-row').forEach(function (row) {
        updateRowPreview(row);
      });
    });
  }

  // Common field chips — click to add that field as an exception row with auto-populated value
  document.addEventListener('click', function (e) {
    var chip = e.target.closest('.ex-vary-chip');
    if (!chip) return;
    var field = chip.dataset.field;
    var value = chip.dataset.value || '';
    if (!field) return;
    // Open builder if closed
    if (document.getElementById('exceptionBuilder').style.display === 'none') {
      openExceptionBuilder();
      hideBuilder('suppressionBuilder');
    }
    // Check if a row with this field already exists
    var existing = null;
    document.querySelectorAll('.ex-entry-row').forEach(function (r) {
      if (r.dataset.fieldName === field) existing = r;
    });
    if (existing) {
      existing.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      existing.classList.add('ex-row-highlight');
      setTimeout(function () { existing.classList.remove('ex-row-highlight'); }, 1400);
    } else {
      // Reuse an empty row if one exists, otherwise add new
      if (value) {
        fillOrAddExceptionRow(field, value);
      } else {
        // Check for empty rows first
        var emptyRow = null;
        document.querySelectorAll('.ex-entry-row').forEach(function (r) {
          if (!r.dataset.fieldName && !emptyRow) emptyRow = r;
        });
        if (emptyRow) {
          _selectField(emptyRow, field);
        } else {
          addExceptionRow(field);
        }
      }
    }
  });

  // Submit exception — create new values, delete deselected existing values, delete removed fields
  const exSubmitBtn = document.getElementById('exSubmitBtn');
  if (exSubmitBtn) {
    exSubmitBtn.addEventListener('click', async function () {
      const matchType = document.getElementById('exMatchType').value;
      const notes = (document.getElementById('exNotes').value || '').trim();
      if (!notes) { showToast('Notes are required', 'error'); return; }
      if (!_validateResolution('exNotes')) return;
      var ruleSource = (parseInt(window.RULE_ID, 10) < 100000) ? 'default' : 'custom';

      // Collect new values to add and existing values to remove per row
      const toAdd = [];    // { field_name, field_values }
      const toDelVal = []; // { field_name, field_value } — deselected existing values
      const toDelField = _exRemovedFields.slice(); // whole fields removed via Remove button

      document.querySelectorAll('.ex-entry-row').forEach(function (row) {
        var fieldName = row.dataset.fieldName || '';
        if (!fieldName) return;
        var newVals = [];
        var deselectedExisting = [];
        row.querySelectorAll('.ex-val-check').forEach(function (cb) {
          if (cb.dataset.alreadyVal === '1') {
            if (!cb.checked) deselectedExisting.push(cb.value);
          } else {
            if (cb.checked) newVals.push(cb.value);
          }
        });
        if (newVals.length) toAdd.push({ field_name: fieldName, field_values: newVals });
        deselectedExisting.forEach(function (v) { toDelVal.push({ field_name: fieldName, field_value: v }); });
      });

      var hasWork = toAdd.length || toDelVal.length || toDelField.length;
      if (!hasWork) {
        showToast('Select at least one field and value', 'warning');
        return;
      }

      setLoading(exSubmitBtn, true);
      var lastDiff = null;
      var errors = [];

      // Delete entire removed fields
      for (var j = 0; j < toDelField.length; j++) {
        try {
          var dr = await apiPost('/rules/exceptions/delete', {
            rule_id: window.RULE_ID,
            rule_source: ruleSource,
            field_name: toDelField[j],
            field_value: '',
          });
          if (dr.diff) lastDiff = dr.diff;
        } catch (e) { errors.push('Delete field ' + toDelField[j] + ': ' + e.message); }
      }

      // Delete individual deselected values
      for (var k = 0; k < toDelVal.length; k++) {
        try {
          var dv = await apiPost('/rules/exceptions/delete', {
            rule_id: window.RULE_ID,
            rule_source: ruleSource,
            field_name: toDelVal[k].field_name,
            field_value: toDelVal[k].field_value,
          });
          if (dv.diff) lastDiff = dv.diff;
        } catch (e) { errors.push('Delete value ' + toDelVal[k].field_value + ': ' + e.message); }
      }

      // Add new values
      for (var i = 0; i < toAdd.length; i++) {
        try {
          var exPayload = {
            rule_id: window.RULE_ID,
            field_name: toAdd[i].field_name,
            field_values: toAdd[i].field_values,
            match_type: matchType,
            case_id: window.CASE_ID,
            notes: notes,
          };
          if (_integrationEnabled) exPayload.resolution = _getResolution('exNotes');
          var res = await apiPost('/rules/exceptions/create', exPayload);
          if (res.diff) lastDiff = res.diff;
        } catch (e) { errors.push(toAdd[i].field_name + ': ' + e.message); }
      }

      setLoading(exSubmitBtn, false);

      if (errors.length) {
        showToast('Failed: ' + errors.join('; '), 'error');
      } else {
        showToast('Exception changes saved', 'success');
        hideBuilder('exceptionBuilder');
        if (lastDiff) {
          renderDiff(lastDiff, document.getElementById('diffContent'));
          _pendingReload = true;
          openModal('diffModal');
        } else {
          setTimeout(function () { location.reload(); }, 600);
        }
      }
    });
  }

  // Submit suppression
  const supSubmitBtn = document.getElementById('supSubmitBtn');
  if (supSubmitBtn) {
    supSubmitBtn.addEventListener('click', async function () {
      const notes = (document.getElementById('supNotes').value || '').trim();
      if (!notes) { showToast('Notes are required', 'error'); return; }
      if (!_validateResolution('supNotes')) return;
      confirm('Suppress Rule ' + window.RULE_ID,
        'This will set the rule level to 0, silencing ALL alerts from this rule. Continue?',
        async function () {
          setLoading(supSubmitBtn, true);
          try {
            var supBody = {
              rule_id: window.RULE_ID,
              case_id: window.CASE_ID,
              notes: notes,
            };
            if (_integrationEnabled) supBody.resolution = _getResolution('supNotes');
            const result = await apiPost('/rules/suppressions/create', supBody);
            showToast('Suppression applied', 'success');
            hideBuilder('suppressionBuilder');
            if (result.diff) {
              renderDiff(result.diff, document.getElementById('diffContent'));
              _pendingReload = true;
              openModal('diffModal');
            } else {
              setTimeout(function () { location.reload(); }, 600);
            }
          } catch (e) {
            if (e.message && e.message.indexOf('already suppressed') !== -1) {
              showToast(e.message, 'info');
              hideBuilder('suppressionBuilder');
            } else {
              showToast('Failed: ' + e.message, 'error');
            }
          } finally {
            setLoading(supSubmitBtn, false);
          }
        }
      );
    });
  }

  // Reopen case
  const reopenBtn = document.getElementById('reopenBtn');
  if (reopenBtn) {
    reopenBtn.addEventListener('click', async function () {
      try {
        await apiPost('/alerts/' + window.CASE_ID + '/reopen', {});
        showToast('Case reopened', 'success');
        setTimeout(function () { location.reload(); }, 600);
      } catch (e) {
        showToast(e.message, 'error');
      }
    });
  }

  // Ignore modal
  const ignoreModalEl = document.getElementById('ignoreModal');
  if (ignoreModalEl) {
    const ignClose = document.getElementById('ignoreModalClose');
    const ignCancel = document.getElementById('ignoreCancelBtn');
    const ignConfirm = document.getElementById('ignoreConfirmBtn');
    if (ignClose) ignClose.addEventListener('click', function () { closeModal('ignoreModal'); });
    if (ignCancel) ignCancel.addEventListener('click', function () { closeModal('ignoreModal'); });
    if (ignConfirm) {
      ignConfirm.addEventListener('click', async function () {
        const notes = (document.getElementById('ignoreNotes').value || '').trim();
        if (!notes) { showToast('Notes are required', 'error'); return; }
        if (!_validateResolution('ignoreNotes')) return;
        setLoading(this, true);
        try {
          var ignBody = { status: 'ignored', notes: notes };
          if (_integrationEnabled) ignBody.resolution = _getResolution('ignoreNotes');
          await apiPost('/alerts/' + window.CASE_ID + '/close', ignBody);
          showToast('Case ignored', 'success');
          closeModal('ignoreModal');
          setTimeout(function () { location.reload(); }, 600);
        } catch (e) {
          showToast(e.message, 'error');
        } finally {
          setLoading(this, false);
        }
      });
    }
    ignoreModalEl.addEventListener('click', function (e) {
      if (e.target === ignoreModalEl) closeModal('ignoreModal');
    });
  }

  // Diff modal — close with optional pending reload
  function _closeDiffAndMaybeReload() {
    closeModal('diffModal');
    if (_pendingReload) {
      _pendingReload = false;
      location.reload();
    }
  }

  const diffCloseBtn = document.getElementById('diffModalClose');
  if (diffCloseBtn) diffCloseBtn.addEventListener('click', _closeDiffAndMaybeReload);

  const diffOkBtn = document.getElementById('diffModalOk');
  if (diffOkBtn) diffOkBtn.addEventListener('click', _closeDiffAndMaybeReload);

  // diffModal intentionally has no backdrop-click close — only OK / X dismisses it

  // Existing-action diff buttons (View Diff on past actions table)
  document.querySelectorAll('.diff-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      renderDiff(this.dataset.diff, document.getElementById('diffContent'));
      openModal('diffModal');
    });
  });

  // ============================================================
  // Exception builder helpers
  // ============================================================

  var _exRowCounter = 0;
  // Cache of existing negate fields for this rule: { fieldName -> {match_type, values} }
  var _existingNegateMap = {};
  // Field names whose entire row was removed (for delete-on-submit)
  var _exRemovedFields = [];

  function openExceptionBuilder() {
    var el = document.getElementById('exceptionBuilder');
    if (!el) return;
    el.style.display = 'block';
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (!el.dataset.loaded) {
      el.dataset.loaded = '1';
      _exRemovedFields = [];
      // Load existing exceptions, pre-populate rows for each, then add an empty row
      apiGet('/rules/api/exceptions/' + window.RULE_ID).then(function (data) {
        _existingNegateMap = {};
        (data.negate_fields || []).forEach(function (nf) {
          _existingNegateMap[nf.field_name] = nf;
        });
        // Start with a single empty row — user selects fields on demand
        addExceptionRow('');
      }).catch(function () {
        if (!document.querySelector('.ex-entry-row')) addExceptionRow('');
      });
    }
  }

  function addExceptionRow(preselectedField) {
    var container = document.getElementById('exceptionEntriesList');
    if (!container) return null;
    _exRowCounter++;
    var idx = _exRowCounter;

    var row = document.createElement('div');
    row.className = 'ex-entry-row';
    row.dataset.rowIdx = idx;

    // ---- Field searchable dropdown ----
    var allFieldKeys = window.ALERT_FIELDS ? Object.keys(window.ALERT_FIELDS).sort() : [];

    row.innerHTML =
      '<div class="ex-row-header">' +
        '<div class="ex-field-selector">' +
          '<div class="ex-field-search-wrap">' +
            '<input type="text" class="form-control form-control-sm ex-field-search" placeholder="Search field..." autocomplete="off">' +
          '</div>' +
          '<div class="ex-field-dropdown">' +
            allFieldKeys.map(function (f) {
              var isCommon = window.COMMON_FIELDS && window.COMMON_FIELDS[f];
              return '<div class="ex-field-opt' + (isCommon ? ' ex-field-varying' : '') + '" data-field="' + escapeHtml(f) + '">' +
                escapeHtml(f) +
                (isCommon ? '<span class="ex-vary-badge">' + window.COMMON_FIELDS[f] + '</span>' : '') +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
        '<button class="btn btn-xs btn-ghost ex-remove-row" type="button">Remove</button>' +
      '</div>' +
      '<div class="ex-row-body" style="display:none">' +
        '<div class="ex-selected-field font-mono text-sm mb-1"></div>' +
        '<div class="ex-existing-notice" style="display:none"></div>' +
        '<div class="ex-values-list"></div>' +
        '<div class="ex-row-preview-wrap">' +
          '<div class="ex-row-preview font-mono text-sm"></div>' +
        '</div>' +
      '</div>';

    var fieldSearch = row.querySelector('.ex-field-search');
    var fieldDropdown = row.querySelector('.ex-field-dropdown');
    var rowBody = row.querySelector('.ex-row-body');
    var selectedFieldLabel = row.querySelector('.ex-selected-field');
    var existingNotice = row.querySelector('.ex-existing-notice');
    var valuesList = row.querySelector('.ex-values-list');
    var removeBtn = row.querySelector('.ex-remove-row');

    var fieldSelector = row.querySelector('.ex-field-selector');

    // Open dropdown on focus
    fieldSearch.addEventListener('focus', function () {
      fieldSelector.dataset.open = '1';
    });
    // Close on blur — delayed so mousedown on an option fires first
    fieldSearch.addEventListener('blur', function () {
      setTimeout(function () { delete fieldSelector.dataset.open; }, 180);
    });
    // Also open on click in case it was already focused
    fieldSearch.addEventListener('click', function () {
      fieldSelector.dataset.open = '1';
    });

    // Search filter
    fieldSearch.addEventListener('input', function () {
      var q = this.value.toLowerCase();
      fieldDropdown.querySelectorAll('.ex-field-opt').forEach(function (opt) {
        opt.style.display = (!q || opt.dataset.field.toLowerCase().indexOf(q) !== -1) ? '' : 'none';
      });
    });

    // Field selection — use mousedown so it fires before blur collapses the dropdown
    fieldDropdown.addEventListener('mousedown', function (e) {
      e.preventDefault(); // keep focus on the search input
      var opt = e.target.closest('.ex-field-opt');
      if (!opt) return;
      _selectField(row, opt.dataset.field);
      delete fieldSelector.dataset.open;
    });

    removeBtn.addEventListener('click', function () {
      // If this row had existing exception data, queue the field for deletion on submit
      var fn = row.dataset.fieldName;
      if (fn && _existingNegateMap[fn]) {
        _exRemovedFields.push(fn);
      }
      if (container.querySelectorAll('.ex-entry-row').length <= 1) {
        // Reset instead of remove
        row.dataset.fieldName = '';
        fieldSearch.value = '';
        delete fieldSelector.dataset.open;
        fieldDropdown.querySelectorAll('.ex-field-opt').forEach(function (o) { o.style.display = ''; o.classList.remove('selected'); });
        rowBody.style.display = 'none';
        selectedFieldLabel.textContent = '';
      } else {
        row.remove();
      }
    });

    container.appendChild(row);

    if (preselectedField && allFieldKeys.indexOf(preselectedField) !== -1) {
      _selectField(row, preselectedField);
    }

    return row;
  }

  function _selectField(row, field) {
    row.dataset.fieldName = field;

    var fieldSearch = row.querySelector('.ex-field-search');
    var fieldDropdown = row.querySelector('.ex-field-dropdown');
    var rowBody = row.querySelector('.ex-row-body');
    var selectedFieldLabel = row.querySelector('.ex-selected-field');
    var existingNotice = row.querySelector('.ex-existing-notice');
    var valuesList = row.querySelector('.ex-values-list');

    // Mark selected in dropdown
    fieldDropdown.querySelectorAll('.ex-field-opt').forEach(function (o) {
      o.classList.toggle('selected', o.dataset.field === field);
    });
    fieldSearch.value = field;

    // Show row body
    rowBody.style.display = 'block';
    selectedFieldLabel.textContent = field;

    // Show existing exception notice if this field already has one
    var existing = _existingNegateMap[field];
    if (existing) {
      var existingVals = (existing.values || []).map(function (v) {
        return '<span class="value-tag">' + escapeHtml(v) + '</span>';
      }).join('');
      existingNotice.innerHTML =
        '<div class="ex-existing-item">' +
          '<div class="ex-existing-header">' +
            '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>' +
            '<span>Already negated (' + escapeHtml(existing.match_type) + '):</span>' +
          '</div>' +
          '<div class="ex-existing-values">' + existingVals + '</div>' +
          '<div class="ex-existing-hint">New values will be appended to the existing pattern.</div>' +
        '</div>';
      existingNotice.style.display = 'block';
    } else {
      existingNotice.style.display = 'none';
    }

    // Build value checkboxes — all values across all alerts for this field
    var vals = (window.ALERT_FIELDS && window.ALERT_FIELDS[field]) || [];
    // Exclude values already in the existing exception
    var existingValsSet = new Set((existing && existing.values) ? existing.values : []);
    var newVals = vals.filter(function (v) { return !existingValsSet.has(v); });
    var alreadyVals = vals.filter(function (v) { return existingValsSet.has(v); });

    valuesList.innerHTML = '';
    if (!newVals.length && !alreadyVals.length) {
      valuesList.innerHTML = '<div class="text-muted text-sm">No values found for this field in the current alerts.</div>';
    } else {
      // Already-excepted values — shown as checked but deselectable to remove them
      alreadyVals.forEach(function (v) {
        var wrap = document.createElement('label');
        wrap.className = 'ex-val-label ex-val-already';
        wrap.title = 'Uncheck to remove this value from the exception';
        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'ex-val-check';
        cb.value = v;
        cb.checked = true;
        cb.dataset.alreadyVal = '1';
        var span = document.createElement('span');
        span.className = 'ex-val-check-wrap';
        span.appendChild(cb);
        var text = document.createElement('span');
        text.className = 'ex-val-text font-mono';
        text.textContent = v;
        var badge = document.createElement('span');
        badge.className = 'ex-val-badge';
        badge.textContent = 'existing';
        wrap.appendChild(span);
        wrap.appendChild(text);
        wrap.appendChild(badge);
        valuesList.appendChild(wrap);
        cb.addEventListener('change', function () { updateRowPreview(row); });
      });
      // New values (checkable, unchecked by default)
      newVals.forEach(function (v) {
        var wrap = document.createElement('label');
        wrap.className = 'ex-val-label';
        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'ex-val-check';
        cb.value = v;
        cb.checked = false;
        var span = document.createElement('span');
        span.className = 'ex-val-check-wrap';
        span.appendChild(cb);
        var text = document.createElement('span');
        text.className = 'ex-val-text font-mono';
        text.textContent = v;
        wrap.appendChild(span);
        wrap.appendChild(text);
        valuesList.appendChild(wrap);
        cb.addEventListener('change', function () { updateRowPreview(row); });
      });
    }

    // Manual value input — appended below the checkboxes
    // Remove any existing manual input from a previous selection
    var existingManual = valuesList.parentNode.querySelector('.ex-manual-input');
    if (existingManual) existingManual.remove();
    var manualWrap = document.createElement('div');
    manualWrap.className = 'ex-manual-input';
    var manualInput = document.createElement('input');
    manualInput.type = 'text';
    manualInput.className = 'form-control form-control-sm ex-manual-value';
    manualInput.placeholder = 'Enter value manually...';
    var manualBtn = document.createElement('button');
    manualBtn.type = 'button';
    manualBtn.className = 'btn btn-xs btn-secondary ex-manual-add';
    manualBtn.textContent = 'Add';
    manualWrap.appendChild(manualInput);
    manualWrap.appendChild(manualBtn);
    valuesList.parentNode.insertBefore(manualWrap, valuesList.nextSibling);

    function _addManualValue() {
      var v = manualInput.value.trim();
      if (!v) return;
      // Avoid duplicates
      var duplicate = false;
      valuesList.querySelectorAll('.ex-val-check').forEach(function (cb) {
        if (cb.value === v) duplicate = true;
      });
      if (duplicate) { manualInput.select(); return; }
      var wrap = document.createElement('label');
      wrap.className = 'ex-val-label';
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'ex-val-check';
      cb.value = v;
      cb.checked = true;
      var span = document.createElement('span');
      span.className = 'ex-val-check-wrap';
      span.appendChild(cb);
      var text = document.createElement('span');
      text.className = 'ex-val-text font-mono';
      text.textContent = v;
      wrap.appendChild(span);
      wrap.appendChild(text);
      // Append to the values list
      valuesList.appendChild(wrap);
      cb.addEventListener('change', function () { updateRowPreview(row); });
      manualInput.value = '';
      updateRowPreview(row);
    }
    manualBtn.addEventListener('click', _addManualValue);
    manualInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); _addManualValue(); }
    });

    updateRowPreview(row);
  }

  function fillOrAddExceptionRow(fieldName, fieldValue) {
    // For "Use" button: find an empty row or add new one
    var container = document.getElementById('exceptionEntriesList');
    if (container) {
      var rows = container.querySelectorAll('.ex-entry-row');
      for (var i = 0; i < rows.length; i++) {
        if (!rows[i].dataset.fieldName) {
          _selectField(rows[i], fieldName);
          // Pre-select only this specific value
          rows[i].querySelectorAll('.ex-val-check').forEach(function (cb) {
            cb.checked = (cb.value === fieldValue);
          });
          updateRowPreview(rows[i]);
          return;
        }
      }
    }
    addExceptionRow(fieldName);
    // After adding, deselect all and select only the one value
    var newRow = container && container.querySelector('.ex-entry-row:last-child');
    if (newRow) {
      newRow.querySelectorAll('.ex-val-check').forEach(function (cb) {
        cb.checked = (cb.value === fieldValue);
      });
      updateRowPreview(newRow);
    }
  }

  function updateRowPreview(row) {
    var field = row.dataset.fieldName || '';
    var previewEl = row.querySelector('.ex-row-preview');
    if (!field || !previewEl) return;

    // Include all checked values (both existing and new)
    var selectedValues = [];
    row.querySelectorAll('.ex-val-check:checked').forEach(function (cb) {
      selectedValues.push(cb.value);
    });

    if (!selectedValues.length) {
      previewEl.innerHTML = '';
      return;
    }

    var matchType = (document.getElementById('exMatchType') || { value: 'pcre2' }).value;
    var pattern;
    if (matchType === 'pcre2') {
      pattern = '(?i)(' + selectedValues.map(escapeHtml).join('|') + ')';
    } else {
      pattern = selectedValues.map(escapeHtml).join('|');
    }
    var fieldAttr = _wazuhField(field);
    var xml = '&lt;field name="' + escapeHtml(fieldAttr) + '" type="' + escapeHtml(matchType) + '" negate="yes"&gt;' + pattern + '&lt;/field&gt;';
    previewEl.innerHTML = highlightXml(xml);
  }

  function toggleBuilder(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var hidden = el.style.display === 'none' || !el.style.display;
    el.style.display = hidden ? 'block' : 'none';
    if (hidden) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function hideBuilder(id) {
    var el = document.getElementById(id);
    if (el) el.style.display = 'none';
  }
});
