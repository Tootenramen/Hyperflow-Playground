/* Hyperflow Playground UI. Wires the pure engine in ioc.js to the page. No network access, no storage. */
(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var esc = function (s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  var st = {
    analysis: null, iocs: [], email: null, decoded: [],
    verdicts: {},              // "type|value" -> verdict, survives re-analysis
    filter: 'all', defang: true, hideInternal: false,
    title: '', severity: 'auto', verdict: 'undecided', notes: '',
    decodeMode: 'auto', decodeInput: '', sample: false, includeReserved: false, exported: false, open: {},
    steps: { parse: 'idle', extract: 'idle', enrich: 'idle', verdict: 'idle', report: 'idle' },
    stepText: { parse: 'waiting for input', extract: '-', enrich: '-', verdict: '-', report: '-' }
  };

  var STEPS = [
    { id: 'parse', t: 'Parse' }, { id: 'extract', t: 'Extract' }, { id: 'enrich', t: 'Pivot links' },
    { id: 'verdict', t: 'Verdict' }, { id: 'report', t: 'Report' }
  ];

  /* ---------------------------------------------------------------- helpers */
  var toastTimer;
  function toast(msg) {
    var t = $('#toast'); t.textContent = msg; t.classList.add('show');
    clearTimeout(toastTimer); toastTimer = setTimeout(function () { t.classList.remove('show'); }, 1600);
  }
  function copy(text, msg) {
    function fallback() {
      var ta = document.createElement('textarea'); ta.value = text; ta.style.cssText = 'position:fixed;opacity:0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); toast(msg || 'Copied'); } catch (e) { toast('Copy blocked by the browser'); }
      ta.remove();
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(function () { toast(msg || 'Copied'); }, fallback);
    else fallback();
  }
  function download(name, text, type) {
    var url = URL.createObjectURL(new Blob([text], { type: type || 'text/plain' }));
    var a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function key(i) { return i.type + '|' + i.value; }
  function shown(i) { return st.defang ? IOC.defang(i.value, i.type) : i.value; }
  function current() {
    return st.iocs.map(function (i) { return Object.assign({}, i, { verdict: st.verdicts[key(i)] || 'unknown' }); });
  }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, reduce ? 0 : ms); }); }

  /* ---------------------------------------------------------------- playbook strip */
  function renderPlaybook() {
    var html = '';
    STEPS.forEach(function (s, i) {
      var state = st.steps[s.id];
      html += '<div class="node ' + state + '" data-step="' + s.id + '"><span class="dot"></span><div class="n">STEP 0' + (i + 1) + '</div><h3>' + s.t + '</h3><div class="st">' + esc(st.stepText[s.id]) + '</div></div>';
      if (i < STEPS.length - 1) {
        var next = st.steps[STEPS[i + 1].id];
        html += '<div class="wire ' + (state === 'done' && next !== 'idle' ? 'done' : state === 'active' ? 'live' : '') + '"></div>';
      }
    });
    $('#playbook').innerHTML = html;
  }
  function setStep(id, state, text) {
    st.steps[id] = state; if (text != null) st.stepText[id] = text; renderPlaybook();
  }
  function verdictStepText() {
    var v = st.verdict !== 'undecided' ? st.verdict : '';
    var marked = Object.keys(st.verdicts).filter(function (k) { return st.verdicts[k]; }).length;
    if (v) return 'verdict: ' + v;
    if (marked) return marked + ' indicator' + (marked > 1 ? 's' : '') + ' marked';
    return 'waiting on you';
  }
  function refreshVerdictStep() {
    if (!st.analysis) return;
    var decided = st.verdict !== 'undecided' || Object.keys(st.verdicts).some(function (k) { return st.verdicts[k]; }) || st.notes.trim();
    st.steps.verdict = decided ? 'done' : 'active';
    st.stepText.verdict = decided ? (verdictStepText() === 'waiting on you' ? 'notes added' : verdictStepText()) : 'waiting on you';
    if (st.steps.report !== 'done') {
      st.steps.report = decided ? 'active' : 'idle';
      st.stepText.report = decided ? 'draft ready: export it' : '-';
    }
    renderPlaybook();
  }
  function markExported() {
    st.exported = true; st.steps.report = 'done'; st.stepText.report = 'exported'; renderPlaybook();
  }

  var runId = 0;
  async function runPlaybook() {
    var id = ++runId, a = st.analysis;
    st.steps = { parse: 'idle', extract: 'idle', enrich: 'idle', verdict: 'idle', report: 'idle' };
    st.stepText = { parse: '-', extract: '-', enrich: '-', verdict: '-', report: '-' }; st.exported = false;
    renderPlaybook();
    var pv = st.iocs.reduce(function (n, i) { return n + IOC.pivots(i).length; }, 0);
    var plan = [
      ['parse', a.email ? 'email headers + ' + a.email.hops.length + ' hops' : 'plain text, ' + $('#input').value.split('\n').length + ' lines'],
      ['extract', st.iocs.length + ' indicators' + (a.decoded.length ? ' (+' + a.decoded.length + ' decoded)' : '')],
      ['enrich', pv + ' links ready, none opened']
    ];
    for (var i = 0; i < plan.length; i++) {
      if (id !== runId) return;
      setStep(plan[i][0], 'active', 'running...'); await sleep(300);
      if (id !== runId) return;
      setStep(plan[i][0], 'done', plan[i][1]);
    }
    refreshVerdictStep();
  }

  /* ---------------------------------------------------------------- analysis */
  function analyze() {
    var raw = $('#input').value;
    if (!raw.trim()) { toast('Paste something first'); return; }
    st.analysis = IOC.analyze(raw, { refang: $('#opt-refang').checked });
    st.iocs = st.analysis.iocs; st.email = st.analysis.email; st.decoded = st.analysis.decoded;
    st.filter = 'all'; st.open = {};
    $('#input-meta').textContent = raw.length.toLocaleString() + ' chars, ' + raw.split('\n').length + ' lines';
    renderAll(); runPlaybook();
  }

  function renderAll() {
    renderIocs(); renderEmail(); renderDecode(); renderReport(); renderSigma(); badges();
  }
  function badges() {
    $('#b-iocs').textContent = st.iocs.length;
    $('#b-email').textContent = st.email ? st.email.findings.filter(function (f) { return f.level !== 'info'; }).length + '!' : '-';
    $('#b-decode').textContent = st.decoded.length;
  }

  /* ---------------------------------------------------------------- indicators tab */
  function flagClass(f) {
    if (/ip-host|credentials|risky|punycode|shortener|cleartext|non-standard|empty-file/.test(f)) return 'fl warn';
    if (/from-decoded/.test(f)) return 'fl info';
    return 'fl';
  }
  function renderIocs() {
    var pane = $('#pane-iocs');
    if (!st.iocs.length) {
      pane.innerHTML = '<div class="empty"><b>' + (st.analysis ? 'No indicators found' : 'No indicators yet') + '</b>' +
        (st.analysis ? 'Nothing in that text looked like an IP, domain, URL, email, hash, CVE, path or registry key.' : 'Load a sample on the left or paste your own text, then run the playbook.') + '</div>';
      return;
    }
    var counts = {}; st.iocs.forEach(function (i) { counts[i.type] = (counts[i.type] || 0) + 1; });
    var list = current().filter(function (i) {
      if (st.filter !== 'all' && i.type !== st.filter) return false;
      if (st.hideInternal && i.flags.indexOf('internal') >= 0) return false;
      return true;
    });
    var h = '<div class="toolbar">';
    h += '<button class="chip ' + (st.filter === 'all' ? 'on' : '') + '" data-filter="all">All ' + st.iocs.length + '</button>';
    IOC.TYPE_ORDER.forEach(function (t) { if (counts[t]) h += '<button class="chip ' + (st.filter === t ? 'on' : '') + '" data-filter="' + t + '">' + IOC.TYPE_LABEL[t] + ' ' + counts[t] + '</button>'; });
    h += '<span class="sp"></span>';
    h += '<button class="btn sm ' + (st.defang ? 'on' : '') + '" id="t-defang" title="Show indicators defanged so they cannot be clicked by accident">Defanged</button>';
    h += '<button class="btn sm ' + (st.hideInternal ? 'on' : '') + '" id="t-internal">Hide internal IPs</button>';
    h += '<button class="btn sm" data-export="list">Copy list</button><button class="btn sm" data-export="csv">CSV</button><button class="btn sm" data-export="json">JSON</button>';
    h += '</div>';
    list.forEach(function (i) {
      var k = key(i), gi = st.iocs.map(key).indexOf(k);
      var flags = i.flags.slice(); if (i.scope && i.scope !== 'public' && flags.indexOf('internal') < 0 && flags.indexOf('documentation-range') < 0) flags.push(i.scope);
      var vd = st.verdicts[k] || '';
      h += '<div class="ioc" data-i="' + gi + '"><span class="t t-' + i.type + '">' + IOC.TYPE_LABEL[i.type].toUpperCase() + '</span>' +
        '<code class="v">' + esc(shown(i)) + '</code>' +
        '<span class="flags">' + flags.map(function (f) { return '<span class="' + flagClass(f) + '">' + esc(f) + '</span>'; }).join('') + '</span>' +
        '<span class="cnt">' + (i.count > 1 ? '&times;' + i.count : '') + '</span>' +
        '<select class="vd ' + vd + '" data-verdict aria-label="Verdict"><option value="">verdict</option>' +
        ['benign', 'suspicious', 'malicious'].map(function (o) { return '<option ' + (vd === o ? 'selected' : '') + '>' + o + '</option>'; }).join('') + '</select>' +
        '<span><button class="mini" data-copy>Copy</button> <button class="mini" data-pivot>Pivot &#9662;</button></span>';
      if (st.open[k]) {
        var pl = IOC.pivots(i);
        h += '<div class="pivots">' + (pl.length ? pl.map(function (p) { return '<a href="' + esc(p.url) + '" target="_blank" rel="noopener noreferrer">' + esc(p.name) + ' &#8599;</a>'; }).join('') : '<span class="note">No lookup sites for this type.</span>') +
          '<span class="note">Opens a third-party site in a new tab and sends it this ' + (i.type === 'path' || i.type === 'regkey' ? 'name' : 'indicator') + '. Nothing is sent until you click.</span></div>';
      }
      h += '</div>';
    });
    if (!list.length) h += '<div class="empty">Nothing matches this filter.</div>';
    h += '<p class="hint">Dedupe is automatic. Internal addresses are flagged so you do not paste them into public lookup sites. Verdicts you set here flow into the Report and Sigma tabs.</p>';
    pane.innerHTML = h;
  }

  function listText(kind) {
    var rows = current();
    if (kind === 'list') return rows.map(shown).join('\n');
    if (kind === 'csv') return 'type,value,count,flags,verdict\n' + rows.map(function (i) {
      return [i.type, '"' + shown(i).replace(/"/g, '""') + '"', i.count, '"' + i.flags.join(' ') + '"', i.verdict].join(',');
    }).join('\n');
    return JSON.stringify(rows.map(function (i) { return { type: i.type, value: shown(i), count: i.count, flags: i.flags, verdict: i.verdict }; }), null, 2);
  }

  /* ---------------------------------------------------------------- email tab */
  function authPill(label, val, goodSet) {
    var cls = !val ? 'unk' : goodSet.indexOf(val) >= 0 ? 'pass' : 'bad';
    return '<div class="auth ' + cls + '"><small>' + label + '</small><b>' + esc(val || 'not found') + '</b></div>';
  }
  function renderEmail() {
    var pane = $('#pane-email'), e = st.email;
    if (!e) {
      pane.innerHTML = '<div class="empty"><b>No email headers detected</b>Paste the full headers of a message (in Gmail: Show original; in Outlook: Message options). The sample on the left has a complete set. SPF, DKIM, DMARC, the Received chain and spoofing tells show up here.</div>';
      return;
    }
    var h = '<div class="auths">' + authPill('SPF', e.auth.spf, ['pass']) + authPill('DKIM', e.auth.dkim, ['pass']) + authPill('DMARC', e.auth.dmarc, ['pass', 'bestguesspass']) + '</div>';
    h += '<dl class="kv">';
    function row(k, v) { h += '<dt>' + k + '</dt><dd>' + (v ? esc(v) : '<span style="color:var(--dim)">-</span>') + '</dd>'; }
    row('Subject', e.subject); row('From', e.from && e.from.raw); row('Return-Path', e.returnPath && e.returnPath.addr);
    row('Reply-To', e.replyTo && e.replyTo.addr); row('To', e.to); row('Date', e.date); row('Message-ID', e.messageId);
    h += '</dl><h4 class="sec">Findings</h4>';
    var order = { high: 0, med: 1, info: 2 };
    e.findings.slice().sort(function (a, b) { return order[a.level] - order[b.level]; }).forEach(function (f) {
      h += '<div class="finding ' + f.level + '"><i>' + (f.level === 'med' ? 'MEDIUM' : f.level.toUpperCase()) + '</i><span>' + esc(f.text) + '</span></div>';
    });
    if (!e.findings.length) h += '<div class="finding info"><i>OK</i><span>Nothing suspicious in these headers.</span></div>';
    h += '<h4 class="sec">Received chain (origin first)</h4><ul class="hops">';
    e.hops.forEach(function (hp) {
      var isOrigin = e.origin && e.origin.hop === hp.n;
      h += '<li class="' + (isOrigin ? 'origin' : '') + '"><b>Hop ' + hp.n + '</b> ' + (isOrigin ? '<span class="fl warn">first external</span> ' : '') +
        '<code>' + esc(hp.from || '?') + '</code> &rarr; <code>' + esc(hp.by || '?') + '</code>' +
        (hp.ips.length ? ' <span class="d">[' + hp.ips.map(function (ip) { return esc(st.defang ? IOC.defang(ip, 'ipv4') : ip); }).join(', ') + ']</span>' : '') +
        '<div class="d">' + esc(hp.date || '') + (hp.delay != null ? ' &middot; +' + hp.delay + 's' : '') + (hp.with ? ' &middot; ' + esc(hp.with) : '') + '</div></li>';
    });
    h += '</ul>';
    pane.innerHTML = h;
  }

  /* ---------------------------------------------------------------- decode tab */
  var MODES = [['auto', 'Auto'], ['base64', 'Base64'], ['hex', 'Hex'], ['url', 'URL'], ['rot13', 'ROT13'], ['powershell', 'PowerShell -enc'], ['refang', 'Refang'], ['defang', 'Defang']];
  function renderDecode() {
    var pane = $('#pane-decode'), h = '';
    if (st.decoded.length) {
      h += '<h4 class="sec" style="margin-top:0">Found inside your input (' + st.decoded.length + ')</h4>';
      st.decoded.forEach(function (d, i) {
        h += '<div class="found"><span class="k">' + (d.kind === 'powershell' ? 'POWERSHELL -ENCODEDCOMMAND' : 'BASE64') + ' &rarr; ' + d.iocs.length + ' indicator' + (d.iocs.length === 1 ? '' : 's') + ' added</span>' +
          '<pre>' + esc(d.decoded.length > 600 ? d.decoded.slice(0, 600) + '...' : d.decoded) + '</pre><div class="src">' + esc(d.source.slice(0, 90)) + (d.source.length > 90 ? '...' : '') + '</div>' +
          '<button class="mini" data-load-decoded="' + i + '">Open in decoder</button></div>';
      });
    }
    h += '<h4 class="sec" ' + (st.decoded.length ? '' : 'style="margin-top:0"') + '>Decoder</h4>';
    h += '<textarea class="io" id="dec-in" spellcheck="false" placeholder="Paste something encoded: base64, hex, %-encoding, ROT13, a PowerShell -enc command, or defanged text...">' + esc(st.decodeInput) + '</textarea>';
    h += '<div class="modes">' + MODES.map(function (m) { return '<button class="chip ' + (st.decodeMode === m[0] ? 'on' : '') + '" data-mode="' + m[0] + '">' + m[1] + '</button>'; }).join('') + '</div>';
    h += '<pre class="out" id="dec-out"></pre><div class="note" id="dec-note"></div>';
    h += '<div class="btnrow"><button class="btn sm" id="dec-copy">Copy output</button><button class="btn sm" id="dec-append">Append to input and analyze</button></div>';
    pane.innerHTML = h;
    runDecode();
  }
  function runDecode() {
    var out = $('#dec-out'); if (!out) return;
    var input = $('#dec-in').value; st.decodeInput = input;
    if (!input.trim()) { out.textContent = ''; out.className = 'out'; $('#dec-note').textContent = 'Output appears here as you type.'; return; }
    var r = IOC.decode(st.decodeMode, input);
    out.textContent = r.ok ? r.output : ''; out.className = 'out' + (r.ok ? '' : ' err');
    $('#dec-note').textContent = r.ok ? (st.decodeMode === 'auto' ? 'auto-detected: ' : '') + r.note : 'Could not decode: ' + r.note;
  }

  /* ---------------------------------------------------------------- report tab */
  function buildReportNow() {
    return IOC.buildReport({ iocs: current(), email: st.email, title: st.title, severity: st.severity, verdict: st.verdict, notes: st.notes, now: new Date().toISOString() });
  }
  function renderReport() {
    var pane = $('#pane-report');
    if (!st.analysis) { pane.innerHTML = '<div class="empty"><b>No report yet</b>Run the playbook first. The summary, ticket draft and JSON are generated from what it finds, plus your verdicts and notes.</div>'; return; }
    var r = buildReportNow();
    pane.innerHTML = '<div class="rgrid"><div>' +
      '<label class="field"><span>Ticket title</span><input id="r-title" value="' + esc(st.title) + '" placeholder="' + esc(r.title) + '"></label>' +
      '<label class="field"><span>Severity</span><select id="r-sev">' + ['auto', 'low', 'medium', 'high', 'critical'].map(function (o) { return '<option ' + (st.severity === o ? 'selected' : '') + '>' + o + '</option>'; }).join('') + '</select></label>' +
      '<label class="field"><span>Your verdict</span><select id="r-verdict">' + ['undecided', 'benign', 'suspicious', 'malicious', 'needs more info'].map(function (o) { return '<option ' + (st.verdict === o ? 'selected' : '') + '>' + o + '</option>'; }).join('') + '</select></label>' +
      '<label class="field"><span>Analyst notes</span><textarea id="r-notes" placeholder="What you checked, what you decided, what is left...">' + esc(st.notes) + '</textarea></label>' +
      '<p class="hint">Suggested: <span class="sev ' + r.severity + '">' + r.severity + '</span> &middot; ' + esc(r.priority) + '<br>' + esc(r.category) + '</p>' +
      '</div><div><div class="btnrow"><button class="btn sm primary" data-rexp="copy-md">Copy Markdown</button><button class="btn sm" data-rexp="dl-md">Download .md</button><button class="btn sm" data-rexp="copy-json">Copy JSON</button><button class="btn sm" data-rexp="dl-json">Download .json</button></div>' +
      '<pre class="preview" id="r-prev">' + esc(r.markdown) + '</pre></div></div>';
  }
  function refreshPreviewOnly() {
    var p = $('#r-prev'); if (!p) return;
    var r = buildReportNow(); p.textContent = r.markdown;
    var title = $('#r-title'); if (title) title.placeholder = r.title;
  }

  /* ---------------------------------------------------------------- sigma tab */
  function renderSigma() {
    var pane = $('#pane-sigma');
    if (!st.analysis) { pane.innerHTML = '<div class="empty"><b>No rule yet</b>Run the playbook and Sigma stubs are drafted from the indicators that are not internal or marked benign.</div>'; return; }
    var y = IOC.buildSigma(current(), { includeReserved: st.includeReserved, title: st.title || undefined });
    pane.innerHTML = '<div class="btnrow"><button class="btn sm primary" data-sig="copy">Copy YAML</button><button class="btn sm" data-sig="dl">Download .yml</button>' +
      '<label class="check"><input type="checkbox" id="sig-res" ' + (st.includeReserved ? 'checked' : '') + '> include example / reserved values (for demos)</label></div>' +
      '<pre class="preview" id="sig-prev">' + esc(y) + '</pre>' +
      '<p class="hint">A starting point, not a finished detection. Mark indicators benign on the Indicators tab to drop them from the rules. Review field names against your own log source before deploying.</p>';
  }

  /* ---------------------------------------------------------------- events */
  document.addEventListener('click', function (ev) {
    var el = ev.target.closest('button, a, .node'); if (!el) return;
    var d = el.dataset;
    if (el.id === 'analyze') return analyze();
    if (el.id === 'clear') {
      $('#input').value = ''; st.analysis = null; st.iocs = []; st.email = null; st.decoded = []; st.verdicts = {}; st.sample = false; st.includeReserved = false;
      st.title = ''; st.severity = 'auto'; st.verdict = 'undecided'; st.notes = ''; $('#input-meta').textContent = ''; runId++;
      st.steps = { parse: 'idle', extract: 'idle', enrich: 'idle', verdict: 'idle', report: 'idle' };
      st.stepText = { parse: 'waiting for input', extract: '-', enrich: '-', verdict: '-', report: '-' };
      renderPlaybook(); renderAll(); return;
    }
    if (d.sample != null) {
      var s = SAMPLES.filter(function (x) { return x.id === d.sample; })[0];
      $('#input').value = s.text; st.sample = true; st.includeReserved = true; st.verdicts = {}; st.verdict = 'undecided'; st.notes = ''; st.title = '';
      $$('#samples .chip').forEach(function (c) { c.classList.toggle('on', c === el); });
      return analyze();
    }
    if (d.tab) {
      $$('.tab').forEach(function (t) { var on = t === el; t.classList.toggle('on', on); t.setAttribute('aria-selected', on); });
      $$('.pane').forEach(function (p) { p.classList.toggle('on', p.id === 'pane-' + d.tab); });
      if (d.tab === 'report') renderReport(); if (d.tab === 'sigma') renderSigma();
      return;
    }
    if (d.filter) { st.filter = d.filter; return renderIocs(); }
    if (el.id === 't-defang') { st.defang = !st.defang; renderIocs(); renderEmail(); return; }
    if (el.id === 't-internal') { st.hideInternal = !st.hideInternal; return renderIocs(); }
    if (d.export) { copy(listText(d.export), 'Copied ' + (d.export === 'list' ? 'list' : d.export.toUpperCase())); return; }
    var row = el.closest('.ioc');
    if (row && el.hasAttribute('data-copy')) { copy(shown(st.iocs[row.dataset.i]), 'Copied'); return; }
    if (row && el.hasAttribute('data-pivot')) { var k = key(st.iocs[row.dataset.i]); st.open[k] = !st.open[k]; return renderIocs(); }
    if (d.mode) { st.decodeMode = d.mode; $$('[data-mode]').forEach(function (c) { c.classList.toggle('on', c === el); }); return runDecode(); }
    if (d.loadDecoded != null) { var dd = st.decoded[+d.loadDecoded]; $('#dec-in').value = dd.source; st.decodeMode = dd.kind === 'powershell' ? 'powershell' : 'base64'; $$('[data-mode]').forEach(function (c) { c.classList.toggle('on', c.dataset.mode === st.decodeMode); }); runDecode(); return; }
    if (el.id === 'dec-copy') { copy($('#dec-out').textContent, 'Copied output'); return; }
    if (el.id === 'dec-append') {
      var out = $('#dec-out').textContent; if (!out) return toast('Nothing to append');
      var box = $('#input'); box.value = box.value.replace(/\s+$/, '') + (box.value ? '\n\n' : '') + '# decoded\n' + out; analyze(); return;
    }
    if (d.rexp) {
      var r = buildReportNow(), slug = (r.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'triage').slice(0, 50);
      if (d.rexp === 'copy-md') copy(r.markdown, 'Copied Markdown');
      if (d.rexp === 'copy-json') copy(JSON.stringify(r.json, null, 2), 'Copied JSON');
      if (d.rexp === 'dl-md') download(slug + '.md', r.markdown, 'text/markdown');
      if (d.rexp === 'dl-json') download(slug + '.json', JSON.stringify(r.json, null, 2), 'application/json');
      markExported(); return;
    }
    if (d.sig) {
      var y = IOC.buildSigma(current(), { includeReserved: st.includeReserved, title: st.title || undefined });
      if (d.sig === 'copy') copy(y, 'Copied Sigma YAML'); else download('hyperflow-triage.yml', y, 'text/yaml');
      markExported(); return;
    }
  });

  document.addEventListener('change', function (ev) {
    var el = ev.target;
    if (el.hasAttribute && el.hasAttribute('data-verdict')) {
      var row = el.closest('.ioc'), k = key(st.iocs[row.dataset.i]);
      if (el.value && el.value !== 'verdict') st.verdicts[k] = el.value; else delete st.verdicts[k];
      el.className = 'vd ' + (st.verdicts[k] || '');
      refreshVerdictStep(); renderSigma(); refreshPreviewOnly(); return;
    }
    if (el.id === 'r-sev') { st.severity = el.value; refreshPreviewOnly(); }
    if (el.id === 'r-verdict') { st.verdict = el.value; refreshVerdictStep(); refreshPreviewOnly(); }
    if (el.id === 'sig-res') { st.includeReserved = el.checked; renderSigma(); }
  });
  document.addEventListener('input', function (ev) {
    var id = ev.target.id;
    if (id === 'r-title') { st.title = ev.target.value; refreshPreviewOnly(); }
    if (id === 'r-notes') { st.notes = ev.target.value; refreshVerdictStep(); refreshPreviewOnly(); }
    if (id === 'dec-in') runDecode();
  });
  $('#input').addEventListener('keydown', function (e) { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); analyze(); } });
  $('#input').addEventListener('paste', function () { st.sample = false; setTimeout(function () { if ($('#input').value.trim()) analyze(); }, 30); });
  $('#opt-refang').addEventListener('change', function () { if (st.analysis) analyze(); });

  /* ---------------------------------------------------------------- boot */
  $('#samples').innerHTML = '<span style="font:11px var(--mono);color:var(--dim);align-self:center">try a sample</span>' +
    SAMPLES.map(function (s) { return '<button class="chip" data-sample="' + s.id + '" title="' + esc(s.note) + '">' + esc(s.label) + '</button>'; }).join('');
  st.stepText.parse = 'waiting for input';
  renderPlaybook(); renderAll();
  // Deep links: index.html#sample=edr&tab=report  (hash only, nothing is requested)
  (function deepLink() {
    var p = {}; location.hash.replace(/^#/, '').split('&').forEach(function (kv) { var a = kv.split('='); if (a[0]) p[a[0]] = decodeURIComponent(a[1] || ''); });
    if (p.sample) { var b = document.querySelector('[data-sample="' + p.sample.replace(/[^a-z]/g, '') + '"]'); if (b) b.click(); }
    if (p.tab) { var t = document.querySelector('[data-tab="' + p.tab.replace(/[^a-z]/g, '') + '"]'); if (t) t.click(); }
  }());
  window.__hyperflow = { state: st };
}());
