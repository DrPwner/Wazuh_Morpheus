/**
 * rules.js — Rules list, create rule form, exceptions/suppressions pages
 */
document.addEventListener('DOMContentLoaded', function () {

  // ============================================================
  // Wazuh field-name normalization
  // ============================================================
  var _WAZUH_STATIC = ['user','srcip','dstip','srcport','dstport','protocol',
    'action','id','url','data','extra_data','status','system_name',
    'srcuser','dstuser'];
  function _wazuhField(name) {
    var stripped = name.replace(/^data\./, '');
    if (stripped === name) return name;
    return _WAZUH_STATIC.indexOf(stripped) !== -1 ? name : stripped;
  }

  // ============================================================
  // Collapsible sections (Advanced: Frequency / Timeframe)
  // ============================================================
  const freqToggle = document.getElementById('freqToggle');
  const freqBody = document.getElementById('freqBody');
  if (freqToggle && freqBody) {
    freqToggle.addEventListener('click', function () {
      const open = freqBody.style.display !== 'none';
      freqBody.style.display = open ? 'none' : 'block';
      freqToggle.classList.toggle('open', !open);
    });
  }

  // ============================================================
  // CREATE RULE page
  // ============================================================
  const fieldsContainer = document.getElementById('fieldsContainer');
  const addFieldBtn = document.getElementById('addFieldBtn');

  if (!addFieldBtn || !fieldsContainer) return _initListPage();

  // Cache for field names used in the create-rule field condition dropdown
  var _fieldBuilderCache = null;
  function _loadFieldBuilderFields(callback) {
    if (_fieldBuilderCache !== null) { callback(_fieldBuilderCache); return; }
    apiGet('/rules/api/fields').then(function (data) {
      _fieldBuilderCache = data.fields || [];
      callback(_fieldBuilderCache);
    }).catch(function () {
      _fieldBuilderCache = [];
      callback([]);
    });
  }

  addFieldBtn.addEventListener('click', function () {
    _loadFieldBuilderFields(function (fields) { addFieldRow(null, fields); });
  });

  // Auto-preview on any form change
  [
    'ruleId', 'ruleLevel', 'ruleDesc', 'triggerType', 'triggerValue',
    'ruleMatch', 'ruleMatchType', 'ruleMitre',
    'ruleFrequency', 'ruleTimeframe', 'ruleIgnore',
    'optNoFullLog', 'optNoEmailAlert',
  ].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', buildXmlPreview);
      el.addEventListener('change', buildXmlPreview);
    }
  });

  buildXmlPreview();

  // Submit rule
  var submitRuleBtn = document.getElementById('submitRuleBtn');
  if (submitRuleBtn) {
    submitRuleBtn.addEventListener('click', async function () {
      var data = collectRuleFormData();
      if (!data.id || data.id < 100000 || data.id > 999999) {
        showToast('Rule ID must be between 100000 and 999999', 'warning');
        return;
      }
      if (!data.description) {
        showToast('Description is required', 'warning');
        return;
      }
      setLoading(submitRuleBtn, true);
      try {
        var result = await apiPost('/rules/create', data);
        showToast('Rule ' + data.id + ' created successfully', 'success');
        setTimeout(function () { window.location.href = '/rules/'; }, 1200);
      } catch (e) {
        showToast('Failed: ' + e.message, 'error');
      } finally {
        setLoading(submitRuleBtn, false);
      }
    });
  }

  // ============================================================
  // Field row builder (with searchable dropdown for field name)
  // ============================================================

  function addFieldRow(field, fields) {
    field = field || {};
    fields = fields || [];
    var row = document.createElement('div');
    row.className = 'field-builder-row';

    row.innerHTML =
      '<div class="rex-search-wrap" style="flex:1;min-width:0">' +
        '<input type="text" class="form-control rex-search" placeholder="Field name..." autocomplete="off"' +
        ' data-role="fname" value="' + _ea(field.name || '') + '">' +
        '<div class="rex-dropdown">' +
          fields.map(function (f) {
            return '<div class="rex-opt" data-field="' + _ea(f) + '">' + _ea(f) + '</div>';
          }).join('') +
        '</div>' +
      '</div>' +
      '<select class="form-control" data-role="ftype" style="max-width:110px">' +
        '<option value="pcre2"'    + (field.type === 'pcre2'    ? ' selected' : '') + '>pcre2</option>' +
        '<option value="osmatch"'  + (field.type === 'osmatch'  ? ' selected' : '') + '>osmatch</option>' +
        '<option value="osregex"'  + (field.type === 'osregex'  ? ' selected' : '') + '>osregex</option>' +
      '</select>' +
      '<input type="text" class="form-control" placeholder="Value / pattern"' +
      ' value="' + _ea(field.value || '') + '" data-role="fvalue">' +
      '<label class="checkbox-label">' +
        '<input type="checkbox" data-role="fnegate"' + (field.negate ? ' checked' : '') + '> negate' +
      '</label>' +
      '<button class="btn btn-xs btn-ghost remove-field-btn" type="button">Remove</button>';

    // Wire searchable dropdown
    var searchInput = row.querySelector('.rex-search');
    var dropdown    = row.querySelector('.rex-dropdown');
    var searchWrap  = row.querySelector('.rex-search-wrap');

    searchInput.addEventListener('focus', function () { searchWrap.dataset.open = '1'; });
    searchInput.addEventListener('click', function () { searchWrap.dataset.open = '1'; });
    searchInput.addEventListener('blur', function () {
      setTimeout(function () { delete searchWrap.dataset.open; }, 180);
    });
    searchInput.addEventListener('input', function () {
      var q = this.value.toLowerCase();
      dropdown.querySelectorAll('.rex-opt').forEach(function (opt) {
        opt.style.display = (!q || opt.dataset.field.toLowerCase().indexOf(q) !== -1) ? '' : 'none';
      });
      searchWrap.dataset.open = '1';
      buildXmlPreview();
    });
    dropdown.addEventListener('mousedown', function (e) {
      e.preventDefault();
      var opt = e.target.closest('.rex-opt');
      if (!opt) return;
      searchInput.value = opt.dataset.field;
      delete searchWrap.dataset.open;
      buildXmlPreview();
    });

    row.querySelector('.remove-field-btn').addEventListener('click', function () {
      row.remove();
      buildXmlPreview();
    });
    row.querySelectorAll('select, input[data-role="fvalue"], input[data-role="fnegate"]').forEach(function (el) {
      el.addEventListener('input', buildXmlPreview);
      el.addEventListener('change', buildXmlPreview);
    });
    fieldsContainer.appendChild(row);
    buildXmlPreview();
  }

  function getFieldRows() {
    return Array.from(fieldsContainer.querySelectorAll('.field-builder-row')).map(function (row) {
      return {
        name:  _wazuhField(row.querySelector('[data-role="fname"]').value.trim()),
        type:  row.querySelector('[data-role="ftype"]').value,
        value: row.querySelector('[data-role="fvalue"]').value.trim(),
        negate: row.querySelector('[data-role="fnegate"]').checked,
      };
    }).filter(function (f) { return f.name && f.value; });
  }

  function collectRuleFormData() {
    var triggerType  = (document.getElementById('triggerType')  || { value: 'if_group' }).value;
    var triggerValue = ((document.getElementById('triggerValue') || { value: '' }).value || '').trim();
    var ruleMatch    = ((document.getElementById('ruleMatch')    || { value: '' }).value || '').trim();
    var matchType    = (document.getElementById('ruleMatchType') || { value: 'pcre2' }).value;
    var mitreTxt     = ((document.getElementById('ruleMitre')    || { value: '' }).value || '');
    var mitre = mitreTxt.split(',').map(function (s) { return s.trim(); }).filter(Boolean);

    var options = [];
    if ((document.getElementById('optNoFullLog')    || {}).checked) options.push('no_full_log');
    if ((document.getElementById('optNoEmailAlert') || {}).checked) options.push('no_email_alert');

    var freq      = ((document.getElementById('ruleFrequency') || { value: '' }).value || '').trim();
    var timeframe = ((document.getElementById('ruleTimeframe') || { value: '' }).value || '').trim();
    var ignore    = ((document.getElementById('ruleIgnore')    || { value: '' }).value || '').trim();

    return {
      id:          parseInt((document.getElementById('ruleId')    || { value: '0' }).value || 0),
      level:       parseInt((document.getElementById('ruleLevel') || { value: '8' }).value || 8),
      description: ((document.getElementById('ruleDesc')         || { value: '' }).value || '').trim(),
      if_group:    triggerType === 'if_group' ? triggerValue : '',
      if_sid:      triggerType === 'if_sid'   ? triggerValue : '',
      fields:      getFieldRows(),
      match:       ruleMatch,
      match_type:  matchType,
      mitre_ids:   mitre,
      options:     options,
      frequency:   freq      || null,
      timeframe:   timeframe || null,
      ignore:      ignore    || null,
    };
  }

  // ============================================================
  // XML preview generator
  // ============================================================

  function buildXmlPreview() {
    var preview = document.getElementById('rulePreviewXml');
    if (!preview) return;

    var data = collectRuleFormData();
    if (!data.id || !data.description) {
      preview.innerHTML = '<p class="text-muted text-sm">Fill in Rule ID and Description to see a preview...</p>';
      return;
    }

    // frequency, timeframe, ignore go as attributes on the rule tag
    var ruleTag = '<rule id="' + data.id + '" level="' + data.level + '"';
    if (data.frequency) ruleTag += ' frequency="' + data.frequency + '"';
    if (data.timeframe) ruleTag += ' timeframe="' + data.timeframe + '"';
    if (data.ignore)    ruleTag += ' ignore="'    + data.ignore    + '"';
    ruleTag += '>';

    var lines = [];
    lines.push(ruleTag);

    if (data.if_sid) {
      lines.push('  <if_sid>' + escapeHtml(data.if_sid) + '</if_sid>');
    } else if (data.if_group) {
      lines.push('  <if_group>' + escapeHtml(data.if_group) + '</if_group>');
    }

    data.fields.forEach(function (f) {
      var attrs = 'name="' + escapeHtml(f.name) + '" type="' + f.type + '"';
      if (f.negate) attrs += ' negate="yes"';
      var val = (f.type === 'pcre2' && !f.value.startsWith('(?'))
        ? '(?i)(' + escapeHtml(f.value) + ')'
        : escapeHtml(f.value);
      lines.push('  <field ' + attrs + '>' + val + '</field>');
    });

    if (data.match) {
      lines.push('  <' + data.match_type + '>' + escapeHtml(data.match) + '</' + data.match_type + '>');
    }

    lines.push('  <description>' + escapeHtml(data.description) + '</description>');

    if (data.mitre_ids && data.mitre_ids.length > 0) {
      lines.push('  <mitre>');
      data.mitre_ids.forEach(function (mid) {
        lines.push('    <id>' + escapeHtml(mid) + '</id>');
      });
      lines.push('  </mitre>');
    }

    data.options.forEach(function (opt) {
      lines.push('  <options>' + escapeHtml(opt) + '</options>');
    });

    lines.push('</rule>');

    var xml = lines.join('\n');
    if (typeof highlightXml === 'function') {
      preview.innerHTML = highlightXml(escapeHtml(xml));
    } else {
      preview.textContent = xml;
    }
  }

  // ============================================================
  // Helper
  // ============================================================

  function _ea(s) {
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function _initListPage() {

    // ============================================================
    // Bulk suppress (All Rules tab only)
    // ============================================================
    var _selectedRuleIds = new Set();

    function _updateBulkToolbar() {
      var toolbar = document.getElementById('bulkToolbar');
      var countEl = document.getElementById('bulkSelectedCount');
      if (!toolbar) return;
      if (_selectedRuleIds.size > 0) {
        toolbar.style.display = 'flex';
        if (countEl) countEl.textContent = _selectedRuleIds.size + ' selected';
      } else {
        toolbar.style.display = 'none';
      }
    }

    var selectAllCb = document.getElementById('selectAllRules');
    if (selectAllCb) {
      selectAllCb.addEventListener('change', function () {
        document.querySelectorAll('.rule-select-cb').forEach(function (cb) {
          cb.checked = selectAllCb.checked;
          var ruleId = cb.dataset.ruleId;
          var ruleSource = cb.dataset.ruleSource;
          if (selectAllCb.checked) {
            _selectedRuleIds.add(ruleId + ':' + ruleSource);
          } else {
            _selectedRuleIds.delete(ruleId + ':' + ruleSource);
          }
        });
        _updateBulkToolbar();
      });
    }

    document.querySelectorAll('.rule-select-cb').forEach(function (cb) {
      cb.addEventListener('change', function () {
        var key = cb.dataset.ruleId + ':' + cb.dataset.ruleSource;
        if (cb.checked) {
          _selectedRuleIds.add(key);
        } else {
          _selectedRuleIds.delete(key);
          if (selectAllCb) selectAllCb.checked = false;
        }
        _updateBulkToolbar();
      });
    });

    var bulkSuppressBtn = document.getElementById('bulkSuppressBtn');
    if (bulkSuppressBtn) {
      bulkSuppressBtn.addEventListener('click', function () {
        var n = _selectedRuleIds.size;
        var countEl = document.getElementById('bulkSupCount');
        if (countEl) countEl.textContent = n;
        document.getElementById('bulkSupNotes').value = '';
        var phrase = 'I hereby, confirm the suppression of ' + n + ' rules.';
        var phraseEl = document.getElementById('bulkSupConfirmPhrase');
        if (phraseEl) phraseEl.textContent = phrase;
        var confirmInput = document.getElementById('bulkSupConfirmInput');
        if (confirmInput) confirmInput.value = '';
        var submitBtn = document.getElementById('bulkSupSubmitBtn');
        if (submitBtn) submitBtn.disabled = true;
        openModal('bulkSuppressModal');
      });
    }

    var bulkSupConfirmInput = document.getElementById('bulkSupConfirmInput');
    if (bulkSupConfirmInput) {
      bulkSupConfirmInput.addEventListener('input', function () {
        var n = _selectedRuleIds.size;
        var expected = 'I hereby, confirm the suppression of ' + n + ' rules.';
        var submitBtn = document.getElementById('bulkSupSubmitBtn');
        if (submitBtn) submitBtn.disabled = (this.value !== expected);
      });
    }

    var bulkCancelBtn = document.getElementById('bulkCancelBtn');
    if (bulkCancelBtn) {
      bulkCancelBtn.addEventListener('click', function () {
        _selectedRuleIds.clear();
        document.querySelectorAll('.rule-select-cb').forEach(function (cb) { cb.checked = false; });
        if (selectAllCb) selectAllCb.checked = false;
        _updateBulkToolbar();
      });
    }

    var bulkSupModal = document.getElementById('bulkSuppressModal');
    if (bulkSupModal) {
      document.getElementById('bulkSupModalClose').addEventListener('click', function () { closeModal('bulkSuppressModal'); });
      document.getElementById('bulkSupCancelBtn').addEventListener('click', function () { closeModal('bulkSuppressModal'); });
      bulkSupModal.addEventListener('click', function (e) { if (e.target === bulkSupModal) closeModal('bulkSuppressModal'); });

      document.getElementById('bulkSupSubmitBtn').addEventListener('click', async function () {
        var n = _selectedRuleIds.size;
        var expected = 'I hereby, confirm the suppression of ' + n + ' rules.';
        var confirmInput = document.getElementById('bulkSupConfirmInput');
        if (!confirmInput || confirmInput.value !== expected) {
          showToast('Please type the confirmation phrase exactly', 'warning');
          return;
        }
        var notes = (document.getElementById('bulkSupNotes').value || '').trim();
        if (!notes) { showToast('Notes are required', 'error'); return; }
        var ruleIds = Array.from(_selectedRuleIds).map(function (key) { return key.split(':')[0]; });
        var btn = this;
        setLoading(btn, true);
        try {
          var result = await apiPost('/rules/suppressions/bulk', { rule_ids: ruleIds, notes: notes });
          var succeeded = (result.results || []).length;
          var failed    = (result.errors  || []).length;
          var msg = succeeded + ' rule' + (succeeded !== 1 ? 's' : '') + ' suppressed';
          if (failed) msg += ', ' + failed + ' failed';
          showToast(msg, failed ? 'warning' : 'success');
          closeModal('bulkSuppressModal');
          _selectedRuleIds.clear();
          _updateBulkToolbar();
          setTimeout(function () { location.reload(); }, 800);
        } catch (e) {
          showToast('Bulk suppress failed: ' + e.message, 'error');
        } finally {
          setLoading(btn, false);
        }
      });
    }

    // ---- Exception from rule list ----
    var currentExRuleId = null;
    var _currentSource = 'custom';
    var _baseXml = null;
    var _rexFieldsCache = null; // null = not loaded yet
    var _removedExistingFields = []; // field names removed from existing exception groups
    var _hasDirectDeletes = false;   // true when X-button deleted a value immediately

    // Escape XML attribute/content values for injection into preview
    function _excXml(s) {
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function _buildPreviewXml() {
      if (_baseXml === null) return null;

      function _escRe(s) {
        return String(s).replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
      }

      var xml = _baseXml;
      var newFields = [];

      document.querySelectorAll('#ruleExFieldGroups .rex-field-group').forEach(function (grp) {
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
      _removedExistingFields.forEach(function (fn) {
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
      var el = document.getElementById('ruleExXmlPreview');
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

    function _loadRexFields(callback) {
      if (_rexFieldsCache !== null) { callback(_rexFieldsCache); return; }
      apiGet('/rules/api/fields').then(function (data) {
        _rexFieldsCache = data.fields || [];
        callback(_rexFieldsCache);
      }).catch(function () {
        _rexFieldsCache = [];
        callback([]);
      });
    }

    // prefill = { fieldName, existingValues, matchType } | null
    function _addRexFieldGroup(fields, prefill) {
      var container = document.getElementById('ruleExFieldGroups');
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

      // Searchable dropdown
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

      // Add a new (non-existing) value chip
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

      // Remove group
      removeBtn.addEventListener('click', function () {
        if (group.dataset.isExisting && group.dataset.origFieldName) {
          _removedExistingFields.push(group.dataset.origFieldName);
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

      // Pre-fill with existing exception data if provided
      if (prefill && prefill.fieldName) {
        searchInput.value = prefill.fieldName;
        group.dataset.fieldName = prefill.fieldName;
        group.dataset.isExisting = '1';
        group.dataset.origFieldName = prefill.fieldName;
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
            var src = parseInt(currentExRuleId, 10) < 100000 ? 'default' : 'custom';
            confirm('Delete Value', 'Delete "' + v + '" from this exception?', function () {
              apiPost('/rules/exceptions/delete', {
                rule_id: currentExRuleId,
                rule_source: src,
                field_name: group.dataset.origFieldName,
                field_value: v,
              }).then(function () {
                chip.remove();
                _hasDirectDeletes = true;
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

    document.querySelectorAll('.rule-exception-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        currentExRuleId = this.dataset.ruleId;
        _currentSource = this.dataset.source || 'custom';
        _baseXml = null;
        _removedExistingFields = [];
        _hasDirectDeletes = false;
        document.getElementById('ruleExRuleId').value = currentExRuleId;
        document.getElementById('ruleExNotes').value = '';
        var groups = document.getElementById('ruleExFieldGroups');
        if (groups) groups.innerHTML = '';
        _updatePreview();
        openModal('ruleExceptionModal');

        var _apiSrc = (parseInt(currentExRuleId, 10) < 100000) ? 'default' : 'custom';

        var fieldsReady = false, existingReady = false;
        var _fields = [], _existing = [];

        function _buildGroups() {
          if (!fieldsReady || !existingReady) return;
          _existing.forEach(function (nf) {
            _addRexFieldGroup(_fields, {
              fieldName: nf.field_name,
              existingValues: nf.values || [],
              matchType: nf.match_type || 'pcre2',
            });
          });
          _addRexFieldGroup(_fields, null);
          _updatePreview();
        }

        _loadRexFields(function (fields) {
          _fields = fields;
          fieldsReady = true;
          _buildGroups();
        });

        apiGet('/rules/api/exceptions/' + currentExRuleId).then(function (data) {
          _existing = data.negate_fields || [];
          existingReady = true;
          _buildGroups();
        }).catch(function () {
          _existing = [];
          existingReady = true;
          _buildGroups();
        });

        apiGet('/rules/api/rule/' + _apiSrc + '/' + currentExRuleId).then(function (data) {
          _baseXml = data.raw_xml || '';
          _updatePreview();
        }).catch(function () {
          _baseXml = '';
          _updatePreview();
        });
      });
    });

    var ruleExModal = document.getElementById('ruleExceptionModal');
    if (ruleExModal) {
      document.getElementById('ruleExModalClose').addEventListener('click', function () { closeModal('ruleExceptionModal'); });
      document.getElementById('ruleExCancelBtn').addEventListener('click', function () { closeModal('ruleExceptionModal'); });

      document.getElementById('ruleExAddFieldBtn').addEventListener('click', function () {
        _loadRexFields(function (fields) { _addRexFieldGroup(fields, null); });
      });

      document.getElementById('ruleExSubmitBtn').addEventListener('click', async function () {
        var notes = (document.getElementById('ruleExNotes').value || '').trim();
        if (!notes) { showToast('Notes are required', 'error'); return; }

        var entries = [];
        document.querySelectorAll('#ruleExFieldGroups .rex-field-group').forEach(function (grp) {
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

        if (!entries.length && !_removedExistingFields.length && !_hasDirectDeletes) {
          showToast('Add at least one new value to a field', 'warning');
          return;
        }

        var btn = this;
        setLoading(btn, true);
        var errors = [];
        var lastDiff = null;
        var _apiSrc = parseInt(currentExRuleId, 10) < 100000 ? 'default' : 'custom';

        for (var j = 0; j < _removedExistingFields.length; j++) {
          try {
            var delRes = await apiPost('/rules/exceptions/delete', {
              rule_id: currentExRuleId,
              rule_source: _apiSrc,
              field_name: _removedExistingFields[j],
              field_value: '',
            });
            if (delRes.diff) lastDiff = delRes.diff;
          } catch (e) {
            errors.push('Delete ' + _removedExistingFields[j] + ': ' + e.message);
          }
        }

        for (var i = 0; i < entries.length; i++) {
          try {
            var res = await apiPost('/rules/exceptions/create', {
              rule_id:      currentExRuleId,
              field_name:   entries[i].field_name,
              field_values: entries[i].field_values,
              match_type:   entries[i].match_type,
              notes:        notes,
            });
            if (res.diff) lastDiff = res.diff;
          } catch (e) {
            errors.push(entries[i].field_name + ': ' + e.message);
          }
        }

        setLoading(btn, false);
        if (errors.length) {
          showToast('Failed: ' + errors.join('; '), 'error');
        } else {
          var msg = [];
          if (_removedExistingFields.length) msg.push(_removedExistingFields.length + ' field' + (_removedExistingFields.length > 1 ? 's' : '') + ' deleted');
          if (entries.length) msg.push(entries.length + ' exception' + (entries.length > 1 ? 's' : '') + ' created');
          showToast(msg.join(', ') + ' for rule ' + currentExRuleId, 'success');
          closeModal('ruleExceptionModal');
          if (lastDiff) {
            var diffEl = document.getElementById('diffContent');
            if (diffEl && typeof renderDiff === 'function') {
              renderDiff(lastDiff, diffEl);
              var dm = document.getElementById('diffModal');
              if (dm) dm.dataset.pendingReload = '1';
              openModal('diffModal');
            }
          }
        }
      });
    }

    // ---- Suppress from rule list ----
    var currentSupRuleId = null;
    document.querySelectorAll('.rule-suppress-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        currentSupRuleId = this.dataset.ruleId;
        document.getElementById('ruleSupRuleId').textContent = currentSupRuleId;
        document.getElementById('ruleSupNotes').value = '';
        openModal('ruleSuppressModal');
      });
    });

    var ruleSupModal = document.getElementById('ruleSuppressModal');
    if (ruleSupModal) {
      document.getElementById('ruleSupModalClose').addEventListener('click', function () { closeModal('ruleSuppressModal'); });
      document.getElementById('ruleSupCancelBtn').addEventListener('click', function () { closeModal('ruleSuppressModal'); });
      ruleSupModal.addEventListener('click', function (e) { if (e.target === ruleSupModal) closeModal('ruleSuppressModal'); });

      document.getElementById('ruleSupSubmitBtn').addEventListener('click', async function () {
        var notes = (document.getElementById('ruleSupNotes').value || '').trim();
        if (!notes) { showToast('Notes are required', 'error'); return; }
        var btn = this;
        setLoading(btn, true);
        try {
          var result = await apiPost('/rules/suppressions/create', {
            rule_id: currentSupRuleId,
            notes: notes,
          });
          showToast('Rule ' + currentSupRuleId + ' suppressed', 'success');
          closeModal('ruleSuppressModal');
          if (result.diff) {
            var diffEl = document.getElementById('diffContent');
            if (diffEl && typeof renderDiff === 'function') {
              renderDiff(result.diff, diffEl);
              var dm = document.getElementById('diffModal');
              if (dm) dm.dataset.pendingReload = '1';
              openModal('diffModal');
            }
          }
        } catch (e) {
          if (e.status === 409 || (e.message && e.message.indexOf('already suppressed') !== -1)) {
            showToast(e.message, 'info');
            closeModal('ruleSuppressModal');
          } else {
            showToast(e.message, 'error');
          }
        } finally {
          setLoading(btn, false);
        }
      });
    }

    // ---- Delete rule ----
    var _deleteRuleId = null;
    var _deleteRuleSource = null;

    document.querySelectorAll('.rule-delete-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        _deleteRuleId = this.dataset.ruleId;
        _deleteRuleSource = this.dataset.source;
        document.getElementById('deleteRuleId').textContent = _deleteRuleId;
        document.getElementById('deleteRuleDesc').textContent = this.dataset.description || '';
        document.getElementById('deleteRuleNotes').value = '';
        openModal('deleteRuleModal');
      });
    });

    var deleteRuleModal = document.getElementById('deleteRuleModal');
    if (deleteRuleModal) {
      document.getElementById('deleteRuleModalClose').addEventListener('click', function () { closeModal('deleteRuleModal'); });
      document.getElementById('deleteRuleCancelBtn').addEventListener('click', function () { closeModal('deleteRuleModal'); });
      deleteRuleModal.addEventListener('click', function (e) { if (e.target === deleteRuleModal) closeModal('deleteRuleModal'); });

      document.getElementById('deleteRuleConfirmBtn').addEventListener('click', async function () {
        if (!_deleteRuleId) return;
        var notes = (document.getElementById('deleteRuleNotes').value || '').trim();
        if (!notes) { showToast('Notes are required', 'error'); return; }
        // Map source to rule_source param
        var sourceMap = { 'custom': 'custom', 'exceptions': 'default_exception', 'suppressions': 'suppression' };
        var ruleSource = sourceMap[_deleteRuleSource] || 'custom';
        var btn = this;
        setLoading(btn, true);
        try {
          var result = await apiPost('/rules/delete', {
            rule_id: _deleteRuleId,
            rule_source: ruleSource,
            notes: notes,
          });
          showToast('Rule ' + _deleteRuleId + ' deleted', 'success');
          closeModal('deleteRuleModal');
          if (result.diff) {
            var diffEl = document.getElementById('diffContent');
            if (diffEl && typeof renderDiff === 'function') {
              renderDiff(result.diff, diffEl);
              var dm = document.getElementById('diffModal');
              if (dm) dm.dataset.pendingReload = '1';
              openModal('diffModal');
            }
          } else {
            setTimeout(function () { location.reload(); }, 800);
          }
        } catch (e) {
          showToast('Failed: ' + e.message, 'error');
        } finally {
          setLoading(btn, false);
        }
      });
    }

    // ---- Restore suppression (suppressions page) ----
    var _restoreRuleId = null;

    document.querySelectorAll('.restore-custom-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        _restoreRuleId = this.dataset.ruleId;
        document.getElementById('restoreCustomRuleId').textContent = _restoreRuleId;
        document.getElementById('restoreCustomNotes').value = '';
        document.getElementById('restoreCustomLevel').value = '8';
        openModal('restoreCustomModal');
      });
    });

    var restoreCustomModal = document.getElementById('restoreCustomModal');
    if (restoreCustomModal) {
      document.getElementById('restoreCustomModalClose').addEventListener('click', function () { closeModal('restoreCustomModal'); });
      document.getElementById('restoreCustomCancelBtn').addEventListener('click', function () { closeModal('restoreCustomModal'); });
      restoreCustomModal.addEventListener('click', function (e) { if (e.target === restoreCustomModal) closeModal('restoreCustomModal'); });

      document.getElementById('restoreCustomSubmitBtn').addEventListener('click', async function () {
        var notes = (document.getElementById('restoreCustomNotes').value || '').trim();
        if (!notes) { showToast('Notes are required', 'error'); return; }
        var level = parseInt(document.getElementById('restoreCustomLevel').value, 10);
        var btn = this;
        setLoading(btn, true);
        try {
          var result = await apiPost('/rules/suppressions/restore', {
            rule_id: _restoreRuleId,
            rule_source: 'custom',
            new_level: level,
            notes: notes,
          });
          showToast('Rule ' + _restoreRuleId + ' restored to level ' + level, 'success');
          closeModal('restoreCustomModal');
          if (result.diff) {
            var diffEl = document.getElementById('diffContent');
            if (diffEl && typeof renderDiff === 'function') {
              renderDiff(result.diff, diffEl);
              var dm = document.getElementById('diffModal');
              if (dm) dm.dataset.pendingReload = '1';
              openModal('diffModal');
            }
          } else {
            setTimeout(function () { location.reload(); }, 800);
          }
        } catch (e) {
          showToast('Failed: ' + e.message, 'error');
        } finally {
          setLoading(btn, false);
        }
      });
    }

    document.querySelectorAll('.restore-default-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        _restoreRuleId = this.dataset.ruleId;
        document.getElementById('restoreDefaultRuleId').textContent = _restoreRuleId;
        document.getElementById('restoreDefaultNotes').value = '';
        openModal('restoreDefaultModal');
      });
    });

    var restoreDefaultModal = document.getElementById('restoreDefaultModal');
    if (restoreDefaultModal) {
      document.getElementById('restoreDefaultModalClose').addEventListener('click', function () { closeModal('restoreDefaultModal'); });
      document.getElementById('restoreDefaultCancelBtn').addEventListener('click', function () { closeModal('restoreDefaultModal'); });
      restoreDefaultModal.addEventListener('click', function (e) { if (e.target === restoreDefaultModal) closeModal('restoreDefaultModal'); });

      document.getElementById('restoreDefaultSubmitBtn').addEventListener('click', async function () {
        var notes = (document.getElementById('restoreDefaultNotes').value || '').trim();
        if (!notes) { showToast('Notes are required', 'error'); return; }
        var btn = this;
        setLoading(btn, true);
        try {
          var result = await apiPost('/rules/suppressions/restore', {
            rule_id: _restoreRuleId,
            rule_source: 'default',
            notes: notes,
          });
          showToast('Suppression removed for rule ' + _restoreRuleId, 'success');
          closeModal('restoreDefaultModal');
          if (result.diff) {
            var diffEl = document.getElementById('diffContent');
            if (diffEl && typeof renderDiff === 'function') {
              renderDiff(result.diff, diffEl);
              var dm = document.getElementById('diffModal');
              if (dm) dm.dataset.pendingReload = '1';
              openModal('diffModal');
            }
          } else {
            setTimeout(function () { location.reload(); }, 800);
          }
        } catch (e) {
          showToast('Failed: ' + e.message, 'error');
        } finally {
          setLoading(btn, false);
        }
      });
    }
  }
});
