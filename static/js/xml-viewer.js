/**
 * xml-viewer.js — Syntax-highlighted XML rendering + edit-raw modal support
 */

function renderXml(xml, container) {
  if (!container) return;
  container.innerHTML = highlightXml(escapeHtml(xml));
}

function highlightXml(escaped) {
  let html = escaped;

  // Comments
  html = html.replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="xml-comment">$1</span>');

  // Tags — input is already HTML-escaped: " → &quot;, > → &gt;, < → &lt;
  // Attribute value alternatives:
  //   &quot;...&quot;  (double-quoted, non-greedy, no < or > inside)
  //   &#39;...&#39;   (single-quoted)
  //   [^\s&<>'"]+     (unquoted alphanumeric — does NOT consume &gt;)
  html = html.replace(
    /(&lt;\/?)([\w:-]+)((?:\s+[\w:-]+(?:\s*=\s*(?:&quot;[^<>]*?&quot;|&#39;[^<>]*?&#39;|[^\s&<>'"]+))?)*)\s*(\/?&gt;)/g,
    function (match, open, tagName, attrs, close) {
      // Color attribute names and values
      var attrHtml = attrs.replace(
        /([\w:-]+)(\s*=\s*)(&quot;[^<>]*?&quot;|&#39;[^<>]*?&#39;)/g,
        function (m, name, eq, val) {
          return '<span class="xml-attr-name">' + name + '</span>' + eq +
                 '<span class="xml-attr-val">' + val + '</span>';
        }
      );
      // Separate bracket/slash from tagName so both get their own color span
      return '<span class="xml-tag">' + open + '</span>' +
             '<span class="xml-id">' + tagName + '</span>' +
             attrHtml +
             '<span class="xml-tag">' + close + '</span>';
    }
  );

  // PCRE2 patterns in text content (e.g. (?i)(mimikatz) )
  html = html.replace(
    /((?:\(\?[ximsu]+\))?\([^)]+\))/g,
    function (m) {
      if (m.includes('class="xml-')) return m;
      return '<span class="xml-pcre2">' + m + '</span>';
    }
  );

  return html;
}

// ============================================================
// Edit-raw state for the XML modal
// ============================================================
var _currentRuleId = null;
var _currentSource = null;   // tab source (custom / default / exceptions / suppressions)
var _currentXml    = null;   // raw XML string currently displayed

// Map a tab source to the edit-API source parameter
function _editSrc(tabSrc) {
  if (tabSrc === 'custom')       return 'custom';
  if (tabSrc === 'exceptions')   return 'default';
  if (tabSrc === 'suppressions') return 'suppression';
  return null; // default rules tab — not directly editable
}

function _enterXmlEditMode() {
  var content     = document.getElementById('xmlContent');
  var editArea    = document.getElementById('xmlEditArea');
  var editRawBtn  = document.getElementById('xmlEditRawBtn');
  var editActions = document.getElementById('xmlEditActions');
  if (!editArea) return;
  editArea.value = _currentXml || '';
  if (content)     content.style.display     = 'none';
  editArea.style.display = 'block';
  if (editRawBtn)  editRawBtn.style.display  = 'none';
  if (editActions) { editActions.style.display = 'flex'; }
  editArea.focus();
}

function _exitXmlEditMode() {
  var content     = document.getElementById('xmlContent');
  var editArea    = document.getElementById('xmlEditArea');
  var editRawBtn  = document.getElementById('xmlEditRawBtn');
  var editActions = document.getElementById('xmlEditActions');
  if (content)     content.style.display     = '';
  if (editArea)    editArea.style.display     = 'none';
  if (editActions) editActions.style.display  = 'none';
  // Only show Edit Raw button when current source is editable
  if (editRawBtn)  editRawBtn.style.display   = _editSrc(_currentSource) ? '' : 'none';
}

// ============================================================
// Attach to view-xml-btn clicks — always fetches live from the server
// ============================================================
document.addEventListener('DOMContentLoaded', function () {
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.view-xml-btn');
    if (!btn) return;

    var ruleId = btn.dataset.ruleId || '';
    var source = btn.dataset.source || 'custom';

    var modal   = document.getElementById('xmlModal');
    var titleEl = document.getElementById('xmlModalTitle');
    var content = document.getElementById('xmlContent');

    if (!modal || !content) return;

    // Reset any previous edit state
    _currentRuleId = ruleId;
    _currentSource = source;
    _currentXml    = null;
    _exitXmlEditMode();

    if (titleEl && ruleId) titleEl.textContent = 'Rule ' + ruleId + ' XML';
    content.innerHTML = '<span class="text-muted">Loading...</span>';
    openModal('xmlModal');

    apiGet('/rules/api/rule/' + encodeURIComponent(source) + '/' + encodeURIComponent(ruleId))
      .then(function (data) {
        _currentXml = data.raw_xml || '';
        renderXml(_currentXml, content);
        // Show Edit Raw button only for editable sources
        var editRawBtn = document.getElementById('xmlEditRawBtn');
        if (editRawBtn) editRawBtn.style.display = _editSrc(source) ? '' : 'none';
      })
      .catch(function (err) {
        content.innerHTML = '<span class="text-muted">Failed to load XML: ' + escapeHtml(err.message || String(err)) + '</span>';
      });
  });

  // Edit Raw button
  var editRawBtn = document.getElementById('xmlEditRawBtn');
  if (editRawBtn) {
    editRawBtn.addEventListener('click', function () { _enterXmlEditMode(); });
  }

  // Cancel edit
  var cancelEditBtn = document.getElementById('xmlCancelEditBtn');
  if (cancelEditBtn) {
    cancelEditBtn.addEventListener('click', function () { _exitXmlEditMode(); });
  }

  // Save edit
  var saveRawBtn = document.getElementById('xmlSaveRawBtn');
  if (saveRawBtn) {
    saveRawBtn.addEventListener('click', async function () {
      var editArea = document.getElementById('xmlEditArea');
      if (!editArea) return;
      var newXml   = editArea.value;
      var editSrc  = _editSrc(_currentSource);
      if (!editSrc || !_currentRuleId) return;

      setLoading(saveRawBtn, true);
      try {
        var result = await apiPost(
          '/rules/api/rule/' + encodeURIComponent(editSrc) + '/' + encodeURIComponent(_currentRuleId) + '/raw',
          { xml: newXml }
        );
        // Update cached XML and re-render viewer
        _currentXml = newXml;
        var content = document.getElementById('xmlContent');
        if (content) renderXml(_currentXml, content);
        _exitXmlEditMode();
        showToast('Rule XML updated', 'success');
        // Show diff if available (reload page after dismissal so rule list refreshes)
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
        showToast('Save failed: ' + (e.message || String(e)), 'error');
      } finally {
        setLoading(saveRawBtn, false);
      }
    });
  }

  // Close XML modal — also exits edit mode
  var closeBtn = document.getElementById('xmlModalClose');
  if (closeBtn) {
    closeBtn.addEventListener('click', function () {
      _exitXmlEditMode();
      closeModal('xmlModal');
    });
  }
  var xmlModal = document.getElementById('xmlModal');
  if (xmlModal) {
    xmlModal.addEventListener('click', function (e) {
      if (e.target === xmlModal) { _exitXmlEditMode(); closeModal('xmlModal'); }
    });
  }

  // Diff modal close (rules list page) — no backdrop-click; check pending-reload flag
  function _closeDiffAndMaybeReload() {
    var dm = document.getElementById('diffModal');
    var reload = dm && dm.dataset.pendingReload === '1';
    if (dm) delete dm.dataset.pendingReload;
    closeModal('diffModal');
    if (reload) location.reload();
  }
  var diffCloseBtn = document.getElementById('diffModalClose');
  if (diffCloseBtn) diffCloseBtn.addEventListener('click', _closeDiffAndMaybeReload);
  var diffOkBtn = document.getElementById('diffModalOk');
  if (diffOkBtn) diffOkBtn.addEventListener('click', _closeDiffAndMaybeReload);
});
