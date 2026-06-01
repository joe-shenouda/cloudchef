/* ============================================================
   CloudChef — main UI thread
   Engines: structured query parser • chronological sort •
            export • Web Worker pipeline • activity histogram
   ============================================================ */

(() => {
  'use strict';

  /* ---------- STATE ---------- */
  window.allLogs        = [];
  window.filteredLogs   = [];
  window.currentIndex   = 0;
  window.pageSize       = 200;
  window.currentProvider = null;
  window.selectedRow    = null;
  window.sortOrder      = 'asc';     // 'asc' | 'desc'
  window.timeWindow     = null;      // { from, to } in ms — from histogram click
  window.metrics        = null;

  /* ---------- CONSTANTS ---------- */
  const HIGH_RISK = [
    'delete','remove','terminate','destroy','putbucketpolicy','putbucketacl','putuserpolicy',
    'attachrolepolicy','createaccesskey','deactivatemfa','updateassumerolepolicy','consolelogin',
    'stoplogging','disable','revoke','password','createuser','deleteuser',
  ];
  const WARN_KEYWORDS = ['update','modify','put','change','create'];

  const STRUCTURED_KEYS = {
    actor:    '__actor',
    user:     '__actor',
    ip:       '__ip',
    src:      '__ip',
    action:   '__action',
    event:    '__action',
    time:     '__time',
  };

  /* ---------- DOM REFS ---------- */
  const $ = (id) => document.getElementById(id);
  const els = {
    dropZone:        $('drop-zone'),
    fileInput:       $('file-input'),
    dragOverlay:     $('drag-overlay'),
    loadingOverlay:  $('loading-overlay'),
    loadingText:     null, // resolved below
    search:          $('master-search'),
    searchMeta:      $('search-meta'),
    providerBadge:   $('provider-badge'),
    resetBtn:        $('reset-btn'),
    exportBtn:       $('export-btn'),
    exportMenu:      $('export-menu'),
    sortToggle:      $('sort-toggle'),
    histogram:       $('histogram-canvas'),
    histogramWrap:   $('histogram-wrap'),
    histogramHint:   $('histogram-hint'),
    histogramClear:  $('histogram-clear'),
    timelineFeed:    $('timeline-feed'),
    timelineStatus:  $('timeline-status'),
    inspectorBody:   $('inspector-body'),
    copyRawBtn:      $('copy-raw'),
    statTotal:       $('stat-total'),
    statActors:      $('stat-actors'),
    statIps:         $('stat-ips'),
    statRisk:        $('stat-risk'),
    statSpan:        $('stat-span'),
    totalCount:      $('total-count'),
    topIps:          $('top-ips'),
    topActors:       $('top-actors'),
    topRisk:         $('top-risk'),
  };
  els.loadingText = els.loadingOverlay.querySelector('.loading-text');

  /* ---------- HELPERS ---------- */
  const fmtN = (n) => Number(n).toLocaleString('en-US');
  function isHighRisk(a) {
    if (!a) return false;
    const s = String(a).toLowerCase();
    return HIGH_RISK.some(k => s.includes(k));
  }
  function isWarn(a) {
    if (!a) return false;
    const s = String(a).toLowerCase();
    return WARN_KEYWORDS.some(k => s.includes(k));
  }
  function formatTimestamp(t) {
    if (!t) return '—';
    try {
      const d = new Date(t);
      if (isNaN(d.getTime())) return String(t).slice(0, 19);
      const pad = (n) => String(n).padStart(2, '0');
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    } catch (e) { return String(t); }
  }
  function escapeHtml(s) {
    if (s === undefined || s === null) return '';
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }
  function humanDuration(ms) {
    const sec = ms / 1000;
    if (sec < 60)    return `${sec.toFixed(0)}s`;
    if (sec < 3600)  return `${(sec/60).toFixed(1)}m`;
    if (sec < 86400) return `${(sec/3600).toFixed(1)}h`;
    return `${(sec/86400).toFixed(1)}d`;
  }
  function showLoading(show, text) {
    if (text) els.loadingText.textContent = text;
    els.loadingOverlay.classList.toggle('hidden', !show);
  }

  /* ============================================================
     1.  FILE INGESTION  →  Web Worker pipeline
     ============================================================ */
  let worker = null;
  function getWorker() {
    if (worker) return worker;
    try {
      worker = new Worker('parser.worker.js');
      worker.onmessage = onWorkerMessage;
      worker.onerror = (e) => {
        console.warn('Worker error:', e.message);
        worker = null;
        showLoading(false);
        alert(`Worker error: ${e.message}`);
      };
      return worker;
    } catch (e) {
      console.warn('Web Worker unavailable, falling back to main thread.', e);
      return null;
    }
  }

  function onWorkerMessage(e) {
    const msg = e.data || {};
    if (msg.type === 'progress') {
      const phases = { parsing: 'Parsing JSON…', detecting: 'Detecting provider…',
                       normalizing: 'Normalizing records…', sorting: 'Sorting chronologically…',
                       metrics: 'Computing metrics…' };
      els.loadingText.textContent = phases[msg.stage] || 'Working…';
    } else if (msg.type === 'done') {
      acceptParsedResult(msg);
    } else if (msg.type === 'error') {
      showLoading(false);
      alert(`Error parsing file: ${msg.message}\n\nEnsure it is valid JSON or NDJSON.`);
    }
  }

  function handleFile(file) {
    if (!file) return;
    showLoading(true, `Reading ${file.name} (${(file.size/1024/1024).toFixed(1)} MB)…`);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target.result;
      const w = getWorker();
      if (w) {
        els.loadingText.textContent = 'Parsing in background…';
        w.postMessage({ text });
      } else {
        // Inline fallback — yields to repaint loading state first.
        setTimeout(() => parseInline(text), 50);
      }
    };
    reader.onerror = () => { showLoading(false); alert('Failed to read file.'); };
    reader.readAsText(file);
  }

  /* Inline fallback (mirrors worker pipeline) */
  function parseInline(text) {
    try {
      let rawData;
      try { rawData = JSON.parse(text); }
      catch (_) {
        // Cursor-based NDJSON walk — avoids the giant array .split() creates
        // on ~100 MB strings.
        rawData = [];
        const lineRe = /[^\r\n]+/g;
        let mLine;
        while ((mLine = lineRe.exec(text)) !== null) {
          const t = mLine[0].trim();
          if (!t) continue;
          try { rawData.push(JSON.parse(t)); } catch (_) { /* skip bad line */ }
        }
        if (!rawData.length) throw new Error('Not valid JSON or NDJSON.');
      }
      const logs = Array.isArray(rawData)
        ? rawData
        : (rawData.Records || rawData.records || rawData.events || rawData.value || []);
      if (!Array.isArray(logs) || !logs.length) throw new Error('No log records found.');

      const provider = detectProviderInline(logs);
      for (const r of logs) {
        r.__time   = provider.time(r) || '';
        r.__action = provider.action(r) || '—';
        r.__actor  = provider.actor(r) || '—';
        r.__ip     = provider.ip(r) || '—';
        const ms = r.__time ? Date.parse(r.__time) : NaN;
        r.__ts = isNaN(ms) ? 0 : ms;
        // Match the worker's footprint so filtering is uniformly O(1) per record.
        r.__searchSpace = JSON.stringify(r).toLowerCase();
      }
      logs.sort((a, b) => a.__ts - b.__ts);

      acceptParsedResult({
        providerLabel: provider.label,
        logs,
        metrics: computeMetricsInline(logs),
      });
    } catch (e) {
      showLoading(false);
      alert(`Error parsing file: ${e.message}`);
    }
  }
  function detectProviderInline(records) {
    // Inline fallback signatures kept in 1:1 parity with parser.worker.js so
    // CSP-restricted environments without Web Workers still get accurate
    // provider detection for Okta variants (actor+displayMessage), CloudTrail
    // bare exports (eventVersion+eventName), and Azure trails carrying only
    // correlationId+resourceId.
    const sample = records[0] || {};
    const P = {
      aws: {
        label: 'AWS CloudTrail',
        detect: () => ('eventSource' in sample) || ('userIdentity' in sample) || ('eventVersion' in sample && 'eventName' in sample),
        time:(r)=>r.eventTime, action:(r)=>r.eventName,
        actor:(r)=>{const u=r.userIdentity||{};return u.userName||u.arn||u.principalId||u.type||'—';},
        ip:(r)=>r.sourceIPAddress||'—',
      },
      okta: {
        label: 'Okta System Log',
        detect: () => ('published' in sample && 'eventType' in sample) || ('actor' in sample && 'displayMessage' in sample),
        time:(r)=>r.published, action:(r)=>r.eventType||r.displayMessage,
        actor:(r)=>(r.actor&&(r.actor.displayName||r.actor.alternateId))||'—',
        ip:(r)=>(r.client&&r.client.ipAddress)||'—',
      },
      az: {
        label: 'Azure Activity',
        detect: () => ('operationName' in sample) || ('callerIpAddress' in sample) || ('correlationId' in sample && 'resourceId' in sample),
        time:(r)=>r.time||r.eventTimestamp,
        action:(r)=>(r.operationName&&typeof r.operationName==='object'?r.operationName.value:r.operationName)||r.operationNameValue,
        actor:(r)=>{
          if (r.caller) return r.caller;
          if (!r.identity) return '—';
          if (typeof r.identity === 'object') {
            return r.identity.id
                || (r.identity.claims && r.identity.claims.name)
                || JSON.stringify(r.identity);
          }
          return r.identity;
        }, ip:(r)=>r.callerIpAddress||'—',
      },
      gen: {
        label: 'Generic JSON', detect: () => true,
        time:(r)=>r.timestamp||r.time||r.date||r['@timestamp']||'',
        action:(r)=>r.action||r.event||r.message||r.type||JSON.stringify(r).slice(0,60),
        actor:(r)=>r.user||r.actor||r.username||r.principal||'—',
        ip:(r)=>r.ip||r.sourceIp||r.source_ip||r.client_ip||'—',
      },
    };
    if (P.aws.detect()) return P.aws;
    if (P.okta.detect()) return P.okta;
    if (P.az.detect()) return P.az;
    return P.gen;
  }
  function computeMetricsInline(logs) {
    const ipCount=new Map(), actorCount=new Map(), riskCount=new Map();
    let riskTotal=0, minT=Infinity, maxT=-Infinity;
    for (const r of logs) {
      if (r.__ip&&r.__ip!=='—') ipCount.set(r.__ip,(ipCount.get(r.__ip)||0)+1);
      if (r.__actor&&r.__actor!=='—') actorCount.set(r.__actor,(actorCount.get(r.__actor)||0)+1);
      if (isHighRisk(r.__action)) { riskTotal++; riskCount.set(String(r.__action),(riskCount.get(String(r.__action))||0)+1); }
      if (r.__ts) { if(r.__ts<minT)minT=r.__ts; if(r.__ts>maxT)maxT=r.__ts; }
    }
    const topN = (m,n) => [...m.entries()].sort((a,b)=>b[1]-a[1]).slice(0,n);
    return {
      total:logs.length, actors:actorCount.size, ips:ipCount.size, risk:riskTotal,
      minT:isFinite(minT)?minT:null, maxT:isFinite(maxT)?maxT:null,
      topIps:topN(ipCount,5), topActors:topN(actorCount,5), topRisk:topN(riskCount,5),
    };
  }

  /* Shared post-worker handler */
  function acceptParsedResult({ providerLabel, logs, metrics }) {
    window.allLogs       = logs;
    window.currentProvider = { label: providerLabel };
    window.metrics       = metrics;
    window.timeWindow    = null;

    els.providerBadge.textContent = providerLabel;
    els.providerBadge.classList.add('active');

    renderSidebarMetrics(metrics);
    renderHistogram(logs);
    applyFilter(els.search.value || '');
    showLoading(false);
    // Belt-and-braces: ensure the histogram has a non-zero layout before its
    // final paint. The first paint inside renderHistogram is correct in the
    // common path, but if the user loaded the file while the wrap was
    // mid-transition we re-paint after the next frame.
    requestAnimationFrame(() => requestAnimationFrame(paintHistogram));
  }

  /* ============================================================
     2.  SIDEBAR METRICS RENDERING
     ============================================================ */
  function renderSidebarMetrics(m) {
    els.totalCount.textContent = fmtN(m.total);
    els.statTotal.textContent  = fmtN(m.total);
    els.statActors.textContent = fmtN(m.actors);
    els.statIps.textContent    = fmtN(m.ips);
    els.statRisk.textContent   = fmtN(m.risk);
    els.statSpan.textContent   = (m.minT && m.maxT && m.maxT !== m.minT) ? humanDuration(m.maxT - m.minT) : '—';
    renderMetricList(els.topIps,    m.topIps,    'ip');
    renderMetricList(els.topActors, m.topActors, 'actor');
    renderMetricList(els.topRisk,   m.topRisk,   'risk');
  }
  function renderMetricList(el, entries, kind) {
    if (!entries.length) { el.innerHTML = '<li class="muted">—</li>'; return; }
    // Compute the escaped key once per entry: avoids three repeat escape calls
    // per row and guarantees the same sanitized string is used in every slot
    // (data-filter, title, and visible text), eliminating any chance of one
    // slot getting a raw value through a refactor mistake.
    el.innerHTML = entries.map(([k, v]) => {
      const escapedKey = escapeHtml(k);
      return `
      <li class="${kind === 'risk' ? 'risk' : ''}" data-key="${kind}" data-filter="${escapedKey}">
        <span class="m-key" title="${escapedKey}">${escapedKey}</span>
        <span class="m-val">${fmtN(v)}</span>
      </li>`;
    }).join('');
  }

  /* ============================================================
     3.  STRUCTURED QUERY ENGINE (Lucene-lite)
         Supports:  actor:alice ip:10.0.0.5 action:Delete
         Quoted:    actor:"Alice Admin"
         Bare:      bare words → fuzzy global search (AND across tokens)
     ============================================================ */
  function parseQuery(input) {
    const q = String(input || '').trim();
    if (!q) return { structured: [], free: [] };

    const tokens = [];
    // Match either key:"quoted value", key:bareword, "quoted free", or bare word
    const regex = /(\w+):"([^"]+)"|(\w+):(\S+)|"([^"]+)"|(\S+)/g;
    let m;
    while ((m = regex.exec(q)) !== null) {
      if      (m[1]) tokens.push({ key: m[1].toLowerCase(), value: m[2] });
      else if (m[3]) tokens.push({ key: m[3].toLowerCase(), value: m[4] });
      else if (m[5]) tokens.push({ key: null, value: m[5] });
      else if (m[6]) tokens.push({ key: null, value: m[6] });
    }
    return {
      structured: tokens.filter(t => t.key && STRUCTURED_KEYS[t.key]),
      free:       tokens.filter(t => !t.key).map(t => t.value.toLowerCase()),
      unknown:    tokens.filter(t => t.key && !STRUCTURED_KEYS[t.key]),
    };
  }

  function matches(log, plan) {
    // Structured: every key:value must match against its mapped normalized field
    for (const tok of plan.structured) {
      const field = STRUCTURED_KEYS[tok.key];
      const v = log[field];
      if (v === undefined || v === null) return false;
      if (!String(v).toLowerCase().includes(tok.value.toLowerCase())) return false;
    }
    // Unknown structured keys (e.g. region:eu-west-1) → search the pre-built
    // lowercase footprint cached on the record. No per-keystroke stringify cost.
    if (plan.unknown && plan.unknown.length) {
      const raw = log.__searchSpace || '';
      for (const tok of plan.unknown) {
        // Require BOTH the JSON-serialized key signature ("region":)
        // AND the value substring to appear in the record's footprint.
        // Prevents foo:Success from matching every record containing the
        // word "Success" regardless of which field carried it.
        const keySig = '"' + tok.key.toLowerCase() + '":';
        if (!raw.includes(keySig) || !raw.includes(tok.value.toLowerCase())) {
          return false;
        }
      }
    }
    // Free text: full fuzzy match (AND across tokens) using the same cached footprint.
    if (plan.free.length) {
      const raw = log.__searchSpace || '';
      for (const term of plan.free) if (!raw.includes(term)) return false;
    }
    return true;
  }

  function applyFilter(input) {
    const plan = parseQuery(input);

    let out;
    const noTextFilter = (!plan.structured.length && !plan.free.length && !(plan.unknown && plan.unknown.length));

    if (noTextFilter && !window.timeWindow) {
      out = window.allLogs;
    } else {
      out = window.allLogs.filter(log => {
        if (window.timeWindow) {
          const ts = log.__ts || 0;
          if (ts < window.timeWindow.from || ts > window.timeWindow.to) return false;
        }
        return matches(log, plan);
      });
    }

    // Apply sort order
    if (window.sortOrder === 'desc') {
      window.filteredLogs = out.slice().reverse();
    } else {
      window.filteredLogs = out;
    }

    window.currentIndex = 0;
    renderTimeline(window.filteredLogs);
    updateSearchMeta();
    updateHistogramSelection();
  }

  function updateSearchMeta() {
    const total = window.allLogs.length;
    const shown = window.filteredLogs.length;
    if (!total) { els.searchMeta.textContent = ''; els.exportBtn.classList.add('hidden'); return; }
    els.searchMeta.textContent = (shown === total) ? `${fmtN(total)} events` : `${fmtN(shown)} / ${fmtN(total)} match`;
    els.exportBtn.classList.remove('hidden');
  }

  /* ============================================================
     4.  TIMELINE — incremental render + sort toggle
     ============================================================ */
  function renderTimeline(logs) {
    els.timelineFeed.innerHTML = '';
    window.currentIndex = 0;
    if (!logs.length) {
      els.timelineFeed.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">⌗</div>
          <div class="empty-title">No matching events</div>
          <div class="empty-sub">Try a different query or clear the filter.</div>
        </div>`;
      els.timelineStatus.textContent = '0 events';
      return;
    }
    renderChunk(logs);
  }
  function renderChunk(logs) {
    const start = window.currentIndex;
    const end   = Math.min(start + window.pageSize, logs.length);
    const frag  = document.createDocumentFragment();

    for (let i = start; i < end; i++) {
      const r = logs[i];
      const action = r.__action;
      const row = document.createElement('div');
      row.className = 'log-row';
      if (isHighRisk(action))   row.classList.add('critical');
      else if (isWarn(action))  row.classList.add('warn');
      else                      row.classList.add('success');
      row.innerHTML = `
        <span class="cell-time" title="${escapeHtml(r.__time)}">${escapeHtml(formatTimestamp(r.__time))}</span>
        <span class="cell-actor" title="${escapeHtml(r.__actor)}">${escapeHtml(r.__actor)}</span>
        <span class="cell-action" title="${escapeHtml(action)}">${escapeHtml(action)}</span>
        <span class="cell-ip" title="${escapeHtml(r.__ip)}">${escapeHtml(r.__ip)}</span>`;
      row.addEventListener('click', () => openInspector(r, row));
      frag.appendChild(row);
    }
    const existingBtn = els.timelineFeed.querySelector('.load-more');
    if (existingBtn) existingBtn.remove();
    els.timelineFeed.appendChild(frag);
    window.currentIndex = end;
    if (end < logs.length) {
      const btn = document.createElement('button');
      btn.className = 'load-more';
      btn.textContent = `Load more events (${fmtN(logs.length - end)} remaining)`;
      btn.addEventListener('click', () => renderChunk(logs));
      els.timelineFeed.appendChild(btn);
    }
    els.timelineStatus.textContent = `${fmtN(end)} of ${fmtN(logs.length)} events`;
  }

  els.sortToggle.addEventListener('click', () => {
    window.sortOrder = window.sortOrder === 'asc' ? 'desc' : 'asc';
    els.sortToggle.querySelector('.sort-arrow').textContent = window.sortOrder === 'asc' ? '↑' : '↓';
    els.sortToggle.querySelector('.sort-label').textContent = window.sortOrder === 'asc' ? 'oldest first' : 'newest first';
    applyFilter(els.search.value || '');
  });

  /* ============================================================
     5.  INSPECTOR
     ============================================================ */
  function openInspector(record, rowEl) {
    if (window.selectedRow) window.selectedRow.classList.remove('selected');
    if (rowEl) { rowEl.classList.add('selected'); window.selectedRow = rowEl; }

    const clean = {};
    for (const k in record) if (!k.startsWith('__')) clean[k] = record[k];
    const rawJson = JSON.stringify(clean, null, 2);
    const highlighted = highlightJson(rawJson);

    els.inspectorBody.innerHTML = `
      <div class="inspect-meta">
        <div class="m"><span class="m-label">Time</span><span class="m-value">${escapeHtml(formatTimestamp(record.__time))}</span></div>
        <div class="m"><span class="m-label">Actor</span><span class="m-value">${escapeHtml(record.__actor)}</span></div>
        <div class="m"><span class="m-label">Action</span><span class="m-value">${escapeHtml(record.__action)}</span></div>
        <div class="m"><span class="m-label">Source IP</span><span class="m-value">${escapeHtml(record.__ip)}</span></div>
      </div>
      <pre><code>${highlighted}</code></pre>`;
    els.copyRawBtn.classList.remove('hidden');
    els.copyRawBtn.onclick = async () => {
      // navigator.clipboard is undefined on plain HTTP (non-localhost) origins.
      // Bail out gracefully instead of throwing a TypeError on .writeText.
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        alert('Clipboard actions require an HTTPS secure context or localhost.\n\nSelect the JSON text and copy manually (⌘/Ctrl + C).');
        return;
      }
      try {
        await navigator.clipboard.writeText(rawJson);
        const old = els.copyRawBtn.textContent;
        els.copyRawBtn.textContent = '✓ Copied';
        setTimeout(() => els.copyRawBtn.textContent = old, 1200);
      } catch (e) {
        alert('Clipboard access denied by the browser.');
      }
    };
  }
  function highlightJson(json) {
    // After escapeHtml, ampersands inside string values become &amp; — using
    // [^&] as the inner-character class breaks at every URL query string or
    // escaped-quote boundary. Switch to a lazy .*? that stops precisely at the
    // next &quot; terminator.
    return escapeHtml(json)
      .replace(/(&quot;.*?&quot;)(\s*:)/g, '<span class="tok-key">$1</span>$2')
      .replace(/: (&quot;.*?&quot;)/g, ': <span class="tok-str">$1</span>')
      .replace(/\b(-?\d+\.?\d*(?:[eE][+-]?\d+)?)\b/g, '<span class="tok-num">$1</span>')
      .replace(/\b(true|false)\b/g, '<span class="tok-bool">$1</span>')
      .replace(/\b(null)\b/g, '<span class="tok-null">$1</span>');
  }

  /* ============================================================
     6.  EXPORT — JSON / NDJSON / CSV of current filtered view
     ============================================================ */
  function downloadBlob(content, mime, filename) {
    const blob = new Blob([content], { type: mime });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function stripInternals(r) {
    const o = {};
    for (const k in r) if (!k.startsWith('__')) o[k] = r[k];
    return o;
  }
  function exportFiltered(format) {
    const data = window.filteredLogs;
    if (!data.length) { alert('Nothing to export.'); return; }
    const stamp = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
    const base  = `cloudchef-export-${stamp}`;

    if (format === 'json') {
      const out = data.map(stripInternals);
      downloadBlob(JSON.stringify(out, null, 2), 'application/json', `${base}.json`);
    } else if (format === 'ndjson') {
      const out = data.map(r => JSON.stringify(stripInternals(r))).join('\n');
      downloadBlob(out, 'application/x-ndjson', `${base}.ndjson`);
    } else if (format === 'csv') {
      const header = ['time','actor','action','ip','raw'];
      const esc = (v) => {
        const s = (v == null) ? '' : String(v);
        return /[",\n\r]/.test(s) ? `"${s.replace(/"/g,'""')}"` : s;
      };
      const rows = [header.join(',')];
      for (const r of data) {
        rows.push([
          esc(r.__time), esc(r.__actor), esc(r.__action), esc(r.__ip),
          esc(JSON.stringify(stripInternals(r))),
        ].join(','));
      }
      downloadBlob(rows.join('\n'), 'text/csv', `${base}.csv`);
    }
  }

  els.exportBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    els.exportMenu.classList.toggle('hidden');
  });
  els.exportMenu.querySelectorAll('[data-format]').forEach(btn => {
    btn.addEventListener('click', () => {
      const fmt = btn.getAttribute('data-format');
      exportFiltered(fmt);
      els.exportMenu.classList.add('hidden');
    });
  });
  document.addEventListener('click', () => els.exportMenu.classList.add('hidden'));

  /* ============================================================
     7.  ACTIVITY HISTOGRAM (pure canvas, click-to-filter)
     ============================================================ */
  const HIST_BUCKETS = 50;
  let histBuckets = null;
  let histRange   = null;

  function renderHistogram(logs) {
    const canvas = els.histogram;
    if (!canvas) return;
    const wrap = els.histogramWrap;
    wrap.classList.remove('empty');

    // Determine time range
    let minT = Infinity, maxT = -Infinity;
    for (const r of logs) {
      if (r.__ts) { if (r.__ts < minT) minT = r.__ts; if (r.__ts > maxT) maxT = r.__ts; }
    }
    if (!isFinite(minT) || !isFinite(maxT) || minT === maxT) {
      wrap.classList.add('empty');
      els.histogramHint.textContent = 'Not enough timestamped events to build a histogram.';
      return;
    }
    const span = maxT - minT;
    const bucketSize = span / HIST_BUCKETS;
    const buckets = new Array(HIST_BUCKETS).fill(0);
    for (const r of logs) {
      if (!r.__ts) continue;
      let idx = Math.floor((r.__ts - minT) / bucketSize);
      if (idx >= HIST_BUCKETS) idx = HIST_BUCKETS - 1;
      if (idx < 0) idx = 0;
      buckets[idx]++;
    }
    histBuckets = buckets;
    histRange   = { minT, maxT, span, bucketSize };
    paintHistogram();
    els.histogramHint.innerHTML =
      `<span class="hint-range"><strong>${fmtN(logs.length)}</strong> events · ${humanDuration(span)} span · ${HIST_BUCKETS} buckets</span>
       <span class="hint-help">click a column to zoom timeline · click again to clear</span>`;
  }

  function paintHistogram() {
    const canvas = els.histogram;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const W = rect.width, H = rect.height;
    // Layout may not be ready on the very first call (rect can be 0×0); retry
    // once on the next frame instead of painting into the void.
    if (W <= 0 || H <= 0) {
      requestAnimationFrame(paintHistogram);
      return;
    }
    const needW = Math.floor(W * dpr);
    const needH = Math.floor(H * dpr);
    // Assigning canvas.width/height clears the entire backing store and resets
    // the transform matrix — skip the assignment when dimensions are unchanged
    // (e.g. histogram-bucket reselection during search) and just clear+re-scale
    // a fresh transform manually.
    if (canvas.width !== needW || canvas.height !== needH) {
      canvas.width  = needW;
      canvas.height = needH;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    if (!histBuckets || !histRange) return;
    const max = Math.max(...histBuckets) || 1;
    const barGap = 2;
    const barW = (W - (HIST_BUCKETS + 1) * barGap) / HIST_BUCKETS;

    // axis grid
    ctx.strokeStyle = '#21262d'; ctx.lineWidth = 1;
    for (let i = 1; i < 4; i++) {
      const y = (H / 4) * i;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }

    for (let i = 0; i < HIST_BUCKETS; i++) {
      const v = histBuckets[i];
      const h = v ? Math.max(2, (v / max) * (H - 14)) : 0;
      const x = barGap + i * (barW + barGap);
      const y = H - h - 4;

      const bucketFrom = histRange.minT + i * histRange.bucketSize;
      const bucketTo   = bucketFrom + histRange.bucketSize;
      let isSelected = false;
      if (window.timeWindow) {
        isSelected = bucketFrom >= window.timeWindow.from - 1 && bucketTo <= window.timeWindow.to + 1;
      }
      // Color: red if high-risk-dominant? Keep simple — accent normal, danger selected.
      let color = '#1f6feb';
      if (v > max * 0.7) color = '#db6d28';
      if (isSelected) color = '#f85149';
      ctx.fillStyle = color;
      ctx.fillRect(x, y, barW, h);

      if (isSelected) {
        ctx.strokeStyle = '#f85149';
        ctx.lineWidth = 1.5;
        ctx.strokeRect(x - 0.5, 0, barW + 1, H - 4);
      }
    }
    // axis labels
    ctx.fillStyle = '#6e7681'; ctx.font = '10px ui-monospace, monospace';
    ctx.fillText(new Date(histRange.minT).toISOString().slice(0,16).replace('T',' '), 2, 10);
    const rt = new Date(histRange.maxT).toISOString().slice(0,16).replace('T',' ');
    ctx.fillText(rt, W - ctx.measureText(rt).width - 4, 10);
  }

  function updateHistogramSelection() { paintHistogram(); }

  els.histogram.addEventListener('click', (e) => {
    if (!histBuckets || !histRange) return;
    const rect = els.histogram.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const W = rect.width;
    const barGap = 2;
    const barW = (W - (HIST_BUCKETS + 1) * barGap) / HIST_BUCKETS;
    const idx = Math.min(HIST_BUCKETS - 1, Math.max(0, Math.floor((x - barGap) / (barW + barGap))));
    const from = histRange.minT + idx * histRange.bucketSize;
    const to   = from + histRange.bucketSize;

    // Click same bucket again clears
    if (window.timeWindow && Math.abs(window.timeWindow.from - from) < 1) {
      window.timeWindow = null;
      els.histogramClear.classList.add('hidden');
    } else {
      window.timeWindow = { from, to };
      els.histogramClear.classList.remove('hidden');
      els.histogramClear.querySelector('.clear-label').textContent =
        `${formatTimestamp(from)}  →  ${formatTimestamp(to)}`;
    }
    applyFilter(els.search.value || '');
  });

  els.histogramClear.addEventListener('click', () => {
    window.timeWindow = null;
    els.histogramClear.classList.add('hidden');
    applyFilter(els.search.value || '');
  });

  // Resize fires dozens of times per second while dragging — coalesce
  // every burst into a single repaint on the next animation frame.
  let resizeRaf = null;
  window.addEventListener('resize', () => {
    if (resizeRaf) cancelAnimationFrame(resizeRaf);
    resizeRaf = requestAnimationFrame(() => { resizeRaf = null; paintHistogram(); });
  });

  /* ============================================================
     8.  SEARCH BINDINGS & SIDEBAR CLICK ROUTING
     ============================================================ */
  let searchTimer = null;
  els.search.addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    const v = e.target.value;
    searchTimer = setTimeout(() => applyFilter(v), 120);
  });
  function bindMetricClicks(listEl) {
    listEl.addEventListener('click', (e) => {
      const li = e.target.closest('li[data-filter]');
      if (!li) return;
      const val = li.getAttribute('data-filter');
      const kind = li.getAttribute('data-key');
      let query;
      if (kind === 'ip')          query = `ip:${val.includes(' ') ? `"${val}"` : val}`;
      else if (kind === 'actor')  query = `actor:${val.includes(' ') ? `"${val}"` : val}`;
      else if (kind === 'risk')   query = `action:${val.includes(' ') ? `"${val}"` : val}`;
      else                        query = val;
      els.search.value = query;
      applyFilter(query);
      els.search.focus();
    });
  }
  bindMetricClicks(els.topIps);
  bindMetricClicks(els.topActors);
  bindMetricClicks(els.topRisk);

  /* ============================================================
     9.  DRAG & DROP, FILE INPUT, RESET, SHORTCUTS
     ============================================================ */
  els.dropZone.addEventListener('click', () => els.fileInput.click());
  els.fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) handleFile(e.target.files[0]);
    e.target.value = '';
  });

  let dragDepth = 0;
  window.addEventListener('dragenter', (e) => { e.preventDefault(); dragDepth++; els.dragOverlay.classList.remove('hidden'); });
  window.addEventListener('dragover',  (e) => e.preventDefault());
  window.addEventListener('dragleave', (e) => { e.preventDefault(); dragDepth--; if (dragDepth<=0) { dragDepth=0; els.dragOverlay.classList.add('hidden'); } });
  window.addEventListener('drop', (e) => {
    e.preventDefault(); dragDepth = 0;
    els.dragOverlay.classList.add('hidden');
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  ['dragenter','dragover'].forEach(ev => els.dropZone.addEventListener(ev, (e) => { e.preventDefault(); els.dropZone.classList.add('dragging'); }));
  ['dragleave','drop'].forEach(ev => els.dropZone.addEventListener(ev, () => els.dropZone.classList.remove('dragging')));

  els.resetBtn.addEventListener('click', () => {
    if (!window.allLogs.length) return;
    if (!confirm('Clear all loaded logs from memory?')) return;
    window.allLogs = []; window.filteredLogs = []; window.currentIndex = 0;
    window.currentProvider = null; window.selectedRow = null;
    window.timeWindow = null; window.metrics = null;
    els.search.value = '';
    els.providerBadge.textContent = 'no log loaded';
    els.providerBadge.classList.remove('active');
    els.totalCount.textContent = '0';
    els.statTotal.textContent = els.statActors.textContent = els.statIps.textContent
      = els.statRisk.textContent = els.statSpan.textContent = '—';
    els.topIps.innerHTML = els.topActors.innerHTML = els.topRisk.innerHTML = '<li class="muted">—</li>';
    els.timelineStatus.textContent = 'no events';
    els.searchMeta.textContent = '';
    els.copyRawBtn.classList.add('hidden');
    els.exportBtn.classList.add('hidden');
    els.histogramWrap.classList.add('empty');
    els.histogramClear.classList.add('hidden');
    // Use innerHTML so renderHistogram's rich hint markup (left when populated)
    // is fully replaced — textContent would leave residual child <span> nodes
    // intact and only swap the text on the first one.
    els.histogramHint.innerHTML = 'Activity histogram will appear after a log file is ingested.';
    histBuckets = null; histRange = null;
    paintHistogram();
    els.timelineFeed.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">⌗</div>
        <div class="empty-title">No logs ingested</div>
        <div class="empty-sub">Drop a CloudTrail, Okta System Log, or Azure Activity JSON file into the sidebar,<br/>or click an <strong>Example Log</strong> on the left to explore the engine.<br/><br/>Everything stays on your machine — nothing is uploaded.</div>
      </div>`;
    els.inspectorBody.innerHTML = `
      <div class="empty-state small">
        <div class="empty-icon">{ }</div>
        <div class="empty-title">No event selected</div>
        <div class="empty-sub">Click any timeline row to inspect the raw log record.</div>
      </div>`;
  });

  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); els.search.focus(); els.search.select(); }
    if (e.key === 'Escape' && document.activeElement === els.search) { els.search.value = ''; applyFilter(''); els.search.blur(); }
  });

  /* ============================================================
     10.  EXAMPLE LOADER
     ============================================================ */
  document.querySelectorAll('.example-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const path  = btn.getAttribute('data-example');
      const label = btn.getAttribute('data-label') || 'example';
      showLoading(true, `Loading ${label} sample…`);
      try {
        const res = await fetch(path, { cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        const w = getWorker();
        if (w) { els.loadingText.textContent = 'Parsing in background…'; w.postMessage({ text }); }
        else   { setTimeout(() => parseInline(text), 50); }
      } catch (e) {
        showLoading(false);
        alert(`Could not load example: ${e.message}`);
      }
    });
  });

  // Initial paint of empty histogram surface (so the layout is stable).
  paintHistogram();
})();
