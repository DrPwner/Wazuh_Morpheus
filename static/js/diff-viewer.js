/**
 * diff-viewer.js — Renders unified diff output as a side-by-side two-pane view
 */

function renderDiff(diff, container) {
  if (!container || !diff) {
    if (container) container.innerHTML = '<span class="text-muted">No changes.</span>';
    return;
  }

  var lines = diff.split('\n');

  // Extract filenames from --- / +++ header lines
  var beforeFile = '';
  var afterFile  = '';
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('--- '))      beforeFile = lines[i].slice(4).replace(/^a\//, '').trim();
    else if (lines[i].startsWith('+++ ')) { afterFile = lines[i].slice(4).replace(/^b\//, '').trim(); break; }
  }

  // Parse unified diff into row descriptors
  var rows = [];
  var minusBuf = [];
  var plusBuf  = [];

  function flush() {
    var max = Math.max(minusBuf.length, plusBuf.length);
    for (var j = 0; j < max; j++) {
      rows.push({
        t:     'change',
        left:  j < minusBuf.length ? minusBuf[j] : null,
        right: j < plusBuf.length  ? plusBuf[j]  : null,
      });
    }
    minusBuf = [];
    plusBuf  = [];
  }

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (line.startsWith('---') || line.startsWith('+++')) {
      continue;
    } else if (line.startsWith('@@')) {
      flush();
      rows.push({ t: 'hunk', text: line });
    } else if (line.startsWith('-')) {
      minusBuf.push(line.slice(1));
    } else if (line.startsWith('+')) {
      plusBuf.push(line.slice(1));
    } else {
      flush();
      // context line — leading space belongs to unified format, strip it
      var ctx = line.length > 0 ? line.slice(1) : '';
      rows.push({ t: 'ctx', text: ctx });
    }
  }
  flush();

  // Build HTML
  var e = escapeHtml;
  var html =
    '<table class="diff-split">' +
    '<thead><tr>' +
    '<th class="diff-split-th">Before: ' + e(beforeFile || 'original') + '</th>' +
    '<th class="diff-split-th">After: '  + e(afterFile  || 'modified') + '</th>' +
    '</tr></thead><tbody>';

  rows.forEach(function (row) {
    if (row.t === 'hunk') {
      html += '<tr class="diff-hunk-row"><td colspan="2">' + e(row.text) + '</td></tr>';
    } else if (row.t === 'ctx') {
      var t = e(row.text) || '&nbsp;';
      html += '<tr class="diff-ctx-row"><td class="diff-cell">' + t +
              '</td><td class="diff-cell">' + t + '</td></tr>';
    } else {
      var lCls = row.left  !== null ? 'diff-cell diff-cell-remove' : 'diff-cell diff-cell-empty';
      var rCls = row.right !== null ? 'diff-cell diff-cell-add'    : 'diff-cell diff-cell-empty';
      var lMark = row.left  !== null ? '<span class="diff-mark diff-mark-r">-</span>' : '';
      var rMark = row.right !== null ? '<span class="diff-mark diff-mark-a">+</span>' : '';
      html += '<tr>' +
        '<td class="' + lCls + '">' + lMark + e(row.left  !== null ? row.left  : '') + '</td>' +
        '<td class="' + rCls + '">' + rMark + e(row.right !== null ? row.right : '') + '</td>' +
        '</tr>';
    }
  });

  html += '</tbody></table>';
  container.innerHTML = html;
}

// Attach to diff-btn clicks
document.addEventListener('DOMContentLoaded', function () {
  document.addEventListener('click', function (e) {
    const btn = e.target.closest('.diff-btn');
    if (!btn) return;

    const diff = btn.dataset.diff || '';
    const content = document.getElementById('diffContent');
    const modal = document.getElementById('diffModal');
    if (!modal || !content) return;

    renderDiff(diff, content);
    openModal('diffModal');
  });

  // Setup diff modal close
  const closeBtn = document.getElementById('diffModalClose');
  if (closeBtn) {
    closeBtn.addEventListener('click', function () { closeModal('diffModal'); });
  }
  // diffModal has no backdrop-click close — only OK / X dismisses it
});
