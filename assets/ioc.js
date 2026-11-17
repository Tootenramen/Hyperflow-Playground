/*  Hyperflow Playground - core triage engine.
 *  Pure functions, no DOM, no network. Works in the browser (window.IOC) and in Node (require).
 *  Everything the page does with your text happens in here, on your machine.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.IOC = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ------------------------------------------------------------------ constants */

  var TYPE_ORDER = ['ipv4', 'ipv6', 'domain', 'url', 'email', 'sha256', 'sha1', 'md5', 'cve', 'path', 'regkey'];
  var TYPE_LABEL = {
    ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL', email: 'Email',
    sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5', cve: 'CVE', path: 'File path', regkey: 'Registry key'
  };

  // Allow-list of TLDs. Deliberately excludes ones that collide with file extensions
  // (py sh pl rs md so cc ps pm mk zip mov) so "update.zip" or "main.cc" are not called domains.
  var TLDS = new Set(('com net org edu gov mil int info biz name pro mobi io co ai me tv us uk ca au de fr nl be ch at es it se no dk fi ie pt gr cz sk hu ro bg ua by ru kz tr il ae sa ir iq in pk bd lk cn hk tw jp kr sg my th vn ph id nz br ar mx cl pe ve za ng ke eg ma tn is lt lv ee lu li mt cy si hr ba al ge am az uz ' +
    'xyz top site online shop store club live app dev cloud tech link click work rest fun icu vip win bid loan xin pw tk ml ga cf gq su to ws cfd sbs lol one page host space website digital agency network systems solutions support services email world today zone ' +
    'test invalid example').split(/\s+/));

  var RISKY_TLDS = new Set('tk ml ga cf gq top xyz icu click work rest fun vip win bid loan xin pw su cfd sbs lol'.split(' '));
  var SHORTENERS = new Set('bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at tiny.cc rb.gy'.split(' '));
  var EMPTY_HASHES = {
    'd41d8cd98f00b204e9800998ecf8427e': 'MD5 of an empty file',
    'da39a3ee5e6b4b0d3255bfef95601890afd80709': 'SHA-1 of an empty file',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': 'SHA-256 of an empty file'
  };
  var RESERVED_DOMAIN = /(^|\.)(example\.(com|net|org)|[^.]+\.(test|invalid|example))$/;

  /* ------------------------------------------------------------------ refang / defang */

  function refang(text) {
    return String(text == null ? '' : text)
      .replace(/\bhxxp(s?)/gi, 'http$1')
      .replace(/\bfxp(s?)\b/gi, 'ftp$1')
      .replace(/\[\s*:\s*\/\/\s*\]/g, '://')
      .replace(/\[\s*:\s*\]/g, ':')
      .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)/gi, '.')
      .replace(/\[\s*@\s*\]|\(\s*@\s*\)|\[at\]|\(at\)/gi, '@');
  }

  function defang(value, type) {
    var s = String(value);
    if (type === 'url') {
      s = s.replace(/^http/i, 'hxxp').replace(/^ftp/i, 'fxp').replace('://', '[://]');
    }
    if (type === 'email') s = s.replace('@', '[@]');
    if (type === 'ipv6') return s.replace(/:/g, '[:]');
    if (type === 'ipv4' || type === 'domain' || type === 'url' || type === 'email') s = s.replace(/\./g, '[.]');
    return s;
  }

  /* ------------------------------------------------------------------ IP helpers */

  function isIPv4(s) {
    return /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s);
  }

  function ipv4Scope(ip) {
    var p = ip.split('.').map(Number), a = p[0], b = p[1], c = p[2];
    if (a === 10) return 'private';
    if (a === 172 && b >= 16 && b <= 31) return 'private';
    if (a === 192 && b === 168) return 'private';
    if (a === 127) return 'loopback';
    if (a === 169 && b === 254) return 'link-local';
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
    if (a === 0) return 'unspecified';
    if (a >= 224 && a <= 239) return 'multicast';
    if (a >= 240) return 'reserved';
    if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return 'documentation';
    return 'public';
  }

  function validIPv6(s) {
    if (!/^[0-9a-f:]+$/i.test(s) || s.indexOf(':') < 0 || s.indexOf(':::') >= 0) return false;
    var dbl = s.split('::');
    if (dbl.length > 2) return false;
    var parse = function (p) { return p === '' ? [] : p.split(':'); };
    var all = parse(dbl[0]).concat(dbl.length === 2 ? parse(dbl[1]) : []);
    if (!all.length) return false;
    if (!all.every(function (g) { return /^[0-9a-f]{1,4}$/i.test(g); })) return false;
    return dbl.length === 2 ? all.length <= 7 : all.length === 8;
  }

  function ipv6Scope(ip) {
    var s = ip.toLowerCase();
    if (s === '::1') return 'loopback';
    if (/^fe[89ab]/.test(s)) return 'link-local';
    if (/^f[cd]/.test(s)) return 'private';
    if (/^2001:0?db8:/.test(s)) return 'documentation';
    if (/^ff/.test(s)) return 'multicast';
    return 'public';
  }

  var INTERNAL = { private: 1, loopback: 1, 'link-local': 1, cgnat: 1, unspecified: 1 };
  function isInternalScope(scope) { return !!INTERNAL[scope]; }

  /* ------------------------------------------------------------------ domain helpers */

  function domainFrom(candidate) {
    var labels = String(candidate).toLowerCase().replace(/\.$/, '').split('.');
    while (labels.length >= 2 && !TLDS.has(labels[labels.length - 1]) && !/^xn--/.test(labels[labels.length - 1])) labels.pop();
    if (labels.length < 2) return null;
    if (labels.some(function (l) { return !l || l.length > 63 || l[0] === '-' || l[l.length - 1] === '-'; })) return null;
    var d = labels.join('.');
    if (/^system\.(io|net|com)$/.test(d)) return null;     // .NET namespaces, not hosts
    return d;
  }

  function domainFlags(d) {
    var f = [], tld = d.split('.').pop();
    if (RESERVED_DOMAIN.test(d)) f.push('reserved');
    if (RISKY_TLDS.has(tld)) f.push('risky-tld');
    if (/(^|\.)xn--/.test(d)) f.push('punycode');
    if (SHORTENERS.has(d)) f.push('shortener');
    return f;
  }

  /* ------------------------------------------------------------------ IOC extraction */

  function trimTail(s) { return s.replace(/[.,;:!?'"`)\]}>]+$/, ''); }

  function extract(input, opts) {
    opts = opts || {};
    var text = String(input == null ? '' : input);
    if (opts.refang !== false) text = refang(text);

    var found = new Map();
    function add(type, value, extra) {
      var key = type + '|' + value;
      var o = found.get(key);
      if (!o) {
        o = { type: type, value: value, count: 0, flags: [] };
        found.set(key, o);
        if (extra) for (var k in extra) if (k === 'flags') o.flags = extra.flags.slice(); else o[k] = extra[k];
      }
      o.count++;
      return o;
    }
    function addFlag(o, f) { if (o.flags.indexOf(f) < 0) o.flags.push(f); }

    var w = text;
    function mask(re) { w = w.replace(re, function (m) { return new Array(m.length + 1).join(' '); }); }
    function scan(re, fn) {
      var m, snapshot = w;
      re.lastIndex = 0;
      while ((m = re.exec(snapshot)) !== null) { fn(m[0], m.index); if (m[0].length === 0) re.lastIndex++; }
    }
    function addDomain(d, extraFlag) {
      var dom = domainFrom(d);
      if (!dom) return null;
      var o = add('domain', dom, { flags: domainFlags(dom) });
      if (extraFlag) addFlag(o, extraFlag);
      return o;
    }
    function addIPv4(ip) {
      var scope = ipv4Scope(ip), o = add('ipv4', ip, { scope: scope });
      if (isInternalScope(scope)) addFlag(o, 'internal');
      if (scope === 'documentation') addFlag(o, 'documentation-range');
      return o;
    }

    /* URLs first; their hosts become domain / IP indicators too */
    var urlRe = /\b(?:https?|ftp|sftp):\/\/[^\s<>"'`\\^{}|]+/gi;
    scan(urlRe, function (raw) {
      var u = trimTail(raw);
      var m = u.match(/^([a-z]+):\/\/(?:([^@\/?#]*)@)?(\[[^\]]+\]|[^:\/?#]*)(?::(\d+))?/i);
      if (!m) return;
      var scheme = m[1].toLowerCase(), host = m[3].toLowerCase(), port = m[4];
      var rest = u.slice(m[0].length);
      var norm = scheme + '://' + (m[2] != null ? m[2] + '@' : '') + host + (port ? ':' + port : '') + rest;
      var flags = [];
      if (isIPv4(host)) flags.push('ip-host');
      if (m[2] != null) flags.push('credentials-in-url');
      if (port && port !== '80' && port !== '443') flags.push('non-standard-port');
      if (SHORTENERS.has(host)) flags.push('shortener');
      if (/(^|\.)xn--/.test(host)) flags.push('punycode');
      if (RESERVED_DOMAIN.test(host)) flags.push('reserved');
      if (scheme !== 'https' && !isInternalScope(isIPv4(host) ? ipv4Scope(host) : 'public')) flags.push('cleartext-' + scheme);
      var o = add('url', norm, { flags: flags });
      if (host && !/^\[/.test(host)) {
        if (isIPv4(host)) addIPv4(host); else addDomain(host);
      }
      return o;
    });
    mask(urlRe);

    /* Emails */
    var emailRe = /\b[a-z0-9][a-z0-9._%+\-]*@(?:[a-z0-9\-]+\.)+[a-z]{2,24}\b/gi;
    scan(emailRe, function (raw) {
      var addr = raw.toLowerCase();
      var dom = domainFrom(addr.split('@')[1]);
      if (!dom) return;
      add('email', addr);
      addDomain(dom);
    });
    mask(emailRe);

    /* Registry keys and file paths (paths contain dots that look like domains, so mask them) */
    var regRe = /\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\[^\s"'<>|]+/g;
    scan(regRe, function (raw) { add('regkey', trimTail(raw).replace(/\\+$/, '')); });
    mask(regRe);

    var wp = /[A-Za-z]:\\\\/.test(w) ? w.replace(/\\\\/g, '\\') : w;   // JSON-escaped paths
    // directory names may contain spaces ("Program Files"); the final file name may not
    var winRe = /[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\s\\\/:*?"<>|]*/g;
    var uncRe = /\\\\[\w.$\-]+\\[^\s"<>|]+/g;
    [winRe, uncRe].forEach(function (re) {
      var m; re.lastIndex = 0;
      while ((m = re.exec(wp)) !== null) {
        var p = trimTail(m[0]);
        if (p.length > 3) add('path', p);
      }
    });
    mask(winRe); mask(uncRe);
    w = w.replace(/\\\\/g, '  ');

    var nixRe = /(?<![\w.:\/\-])\/(?:etc|var|tmp|usr|bin|sbin|home|opt|root|dev|proc|mnt|srv|lib|lib64|Library|Users|Applications|private)(?:\/[\w.\-@%+~=]+)+/g;
    scan(nixRe, function (raw) { add('path', trimTail(raw)); });
    mask(nixRe);

    /* Hashes (exact length, hex-bounded, so they never overlap) */
    [['sha256', 64], ['sha1', 40], ['md5', 32]].forEach(function (h) {
      var re = new RegExp('(?<![0-9a-fA-F])[0-9a-fA-F]{' + h[1] + '}(?![0-9a-fA-F])', 'g');
      scan(re, function (raw) {
        var v = raw.toLowerCase(), o = add(h[0], v);
        if (EMPTY_HASHES[v]) addFlag(o, 'empty-file-hash');
      });
      mask(re);
    });

    /* CVEs */
    scan(/\bCVE-\d{4}-\d{4,7}\b/gi, function (raw) { add('cve', raw.toUpperCase()); });

    /* IPv4 */
    scan(/(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.?\d)/g, function (raw) { addIPv4(raw); });

    /* IPv6 */
    scan(/(?<![\w:.])[0-9a-f:]{2,39}(?![\w:.])/gi, function (raw) {
      if (!validIPv6(raw)) return;
      var v = raw.toLowerCase(), scope = ipv6Scope(v), o = add('ipv6', v, { scope: scope });
      if (isInternalScope(scope)) addFlag(o, 'internal');
      if (scope === 'documentation') addFlag(o, 'documentation-range');
    });

    /* Domains last */
    scan(/(?<![\w@.\-])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9\-]+)(?![\w\-])/gi, function (raw) { addDomain(raw); });

    var out = Array.from(found.values());
    var rank = {}; TYPE_ORDER.forEach(function (t, i) { rank[t] = i; });
    var idx = new Map(out.map(function (o, i) { return [o, i]; }));
    out.sort(function (a, b) { return (rank[a.type] - rank[b.type]) || (idx.get(a) - idx.get(b)); });
    return out;
  }

  /* ------------------------------------------------------------------ pivot links (built only; opened on user click) */

  function pivots(ioc) {
    var v = ioc.value, e = encodeURIComponent(v), t = ioc.type, L = [];
    function l(name, url) { L.push({ name: name, url: url }); }
    if (t === 'ipv4' || t === 'ipv6') {
      l('VirusTotal', 'https://www.virustotal.com/gui/ip-address/' + e);
      l('AbuseIPDB', 'https://www.abuseipdb.com/check/' + e);
      l('Shodan', 'https://www.shodan.io/host/' + e);
      l('GreyNoise', 'https://viz.greynoise.io/ip/' + e);
      l('Censys', 'https://search.censys.io/hosts/' + e);
      l('Hurricane Electric', 'https://bgp.he.net/ip/' + e);
      l('ARIN RDAP', 'https://search.arin.net/rdap/?query=' + e);
    } else if (t === 'domain') {
      l('VirusTotal', 'https://www.virustotal.com/gui/domain/' + e);
      l('urlscan', 'https://urlscan.io/search/#domain%3A' + e);
      l('WHOIS', 'https://who.is/whois/' + e);
      l('MXToolbox', 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3A' + e + '&run=toolpage');
      l('crt.sh', 'https://crt.sh/?q=' + e);
      l('SecurityTrails', 'https://securitytrails.com/domain/' + e + '/dns');
      l('Shodan', 'https://www.shodan.io/search?query=hostname%3A' + e);
    } else if (t === 'url') {
      l('VirusTotal', 'https://www.virustotal.com/gui/search/' + e);
      l('urlscan', 'https://urlscan.io/search/#' + encodeURIComponent('page.url:"' + v + '"'));
      l('Wayback', 'https://web.archive.org/web/*/' + v);
    } else if (t === 'email') {
      var dom = v.split('@')[1];
      l('EmailRep', 'https://emailrep.io/' + e);
      l('Have I Been Pwned', 'https://haveibeenpwned.com/account/' + e);
      l('Domain on VirusTotal', 'https://www.virustotal.com/gui/domain/' + encodeURIComponent(dom));
      l('MXToolbox', 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3A' + encodeURIComponent(dom) + '&run=toolpage');
    } else if (t === 'sha256' || t === 'sha1' || t === 'md5') {
      l('VirusTotal', 'https://www.virustotal.com/gui/file/' + e);
      l('MalwareBazaar', 'https://bazaar.abuse.ch/browse.php?search=' + e);
      l('Hybrid Analysis', 'https://www.hybrid-analysis.com/search?query=' + e);
      l('Triage', 'https://tria.ge/s?q=' + e);
    } else if (t === 'cve') {
      l('NVD', 'https://nvd.nist.gov/vuln/detail/' + e);
      l('CISA KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + e);
      l('MITRE', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + e);
      l('EPSS', 'https://api.first.org/data/v1/epss?cve=' + e);
    } else if (t === 'path') {
      var base = v.split(/[\\/]/).pop();
      if (base) l('LOLBAS / name search', 'https://www.google.com/search?q=' + encodeURIComponent('"' + base + '" malware OR lolbas'));
    } else if (t === 'regkey') {
      l('MITRE ATT&CK persistence search', 'https://www.google.com/search?q=' + encodeURIComponent('"' + v.split('\\').slice(0, 5).join('\\') + '" persistence'));
    }
    return L;
  }

  /* ------------------------------------------------------------------ decoders */

  function b64bytes(s) {
    s = s.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (!/^[A-Za-z0-9+\/]*={0,2}$/.test(s) || s.length < 4) throw new Error('not valid base64');
    while (s.length % 4) s += '=';
    var bin = atob(s), u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function utf8(u) { try { return new TextDecoder('utf-8', { fatal: true }).decode(u); } catch (e) { return null; } }
  function utf16le(u) { try { return new TextDecoder('utf-16le').decode(u); } catch (e) { return null; } }
  function looksUtf16le(u) {
    if (u.length < 4 || u.length % 2) return false;
    var zeros = 0, n = u.length / 2;
    for (var i = 1; i < u.length; i += 2) if (u[i] === 0) zeros++;
    return zeros / n > 0.8;
  }
  function printableRatio(s) {
    if (!s) return 0;
    var ok = 0;
    for (var i = 0; i < s.length; i++) { var c = s.charCodeAt(i); if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c > 159) ok++; }
    return ok / s.length;
  }
  function hexDump(u) { return Array.prototype.map.call(u, function (b) { return ('0' + b.toString(16)).slice(-2); }).join(' '); }
  function bytesToDisplay(u) {
    if (looksUtf16le(u)) return { text: utf16le(u), note: 'UTF-16LE' };
    var t = utf8(u);
    if (t !== null && printableRatio(t) > 0.85) return { text: t, note: 'UTF-8' };
    return { text: hexDump(u), note: 'binary, shown as hex' };
  }

  function rot13(s) {
    return s.replace(/[a-z]/gi, function (c) {
      var b = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b);
    });
  }

  function decode(mode, input) {
    var s = String(input == null ? '' : input);
    try {
      if (mode === 'auto') mode = detectMode(s);
      if (mode === 'powershell') {
        var m = s.match(/(?:^|\s)-e(?:nc(?:odedcommand)?)?\s+['"]?([A-Za-z0-9+\/=]{8,})['"]?/i);
        var blob = m ? m[1] : s;
        var u = b64bytes(blob), t = utf16le(u);
        if (t === null) throw new Error('not UTF-16LE');
        return { ok: true, mode: mode, output: t, note: 'PowerShell -EncodedCommand (base64 of UTF-16LE)' };
      }
      if (mode === 'base64') {
        var d = bytesToDisplay(b64bytes(s));
        return { ok: true, mode: mode, output: d.text, note: 'base64 -> ' + d.note };
      }
      if (mode === 'hex') {
        var h = s.replace(/0x/gi, '').replace(/\\x/gi, '').replace(/[^0-9a-f]/gi, '');
        if (!h || h.length % 2) throw new Error('hex input needs an even number of hex digits');
        var bytes = new Uint8Array(h.length / 2);
        for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.substr(i * 2, 2), 16);
        var dd = bytesToDisplay(bytes);
        return { ok: true, mode: mode, output: dd.text, note: 'hex -> ' + dd.note };
      }
      if (mode === 'url') {
        var out;
        try { out = decodeURIComponent(s); } catch (e) { out = s.replace(/%([0-9a-f]{2})/gi, function (_, x) { return String.fromCharCode(parseInt(x, 16)); }); }
        return { ok: true, mode: mode, output: out, note: 'percent-decoding' };
      }
      if (mode === 'rot13') return { ok: true, mode: mode, output: rot13(s), note: 'ROT13' };
      if (mode === 'refang') return { ok: true, mode: mode, output: refang(s), note: 'defanged text restored' };
      if (mode === 'defang') {
        var df = s.replace(/\bhttp(s?):\/\//gi, 'hxxp$1[://]').replace(/\bftp:\/\//gi, 'fxp[://]')
          .replace(/(\w)\.(?=[a-z0-9])/gi, '$1[.]').replace(/@/g, '[@]');
        return { ok: true, mode: mode, output: df, note: 'dots, schemes and @ neutralised' };
      }
      throw new Error('unknown mode: ' + mode);
    } catch (e) {
      return { ok: false, mode: mode, output: '', note: e.message };
    }
  }

  function detectMode(s) {
    var t = s.trim();
    if (/(?:^|\s)-e(?:nc(?:odedcommand)?)?\s+['"]?[A-Za-z0-9+\/=]{8,}/i.test(t)) return 'powershell';
    if (/%[0-9a-f]{2}/i.test(t)) return 'url';
    if (/^(?:0x|\\x)?(?:[0-9a-f]{2}[\s,]?(?:0x|\\x)?){4,}$/i.test(t) && !/^[A-Za-z0-9+\/]+=*$/.test(t.replace(/\s/g, '')) ) return 'hex';
    if (/^[A-Za-z0-9+\/_\-\s]{12,}={0,2}$/.test(t)) {
      try {
        var d = bytesToDisplay(b64bytes(t));
        if (d.note.indexOf('binary') < 0) return 'base64';
      } catch (e) { /* fall through */ }
    }
    if (/^(?:[0-9a-f]{2})+$/i.test(t.replace(/\s/g, ''))) return 'hex';
    return 'base64';
  }

  // Look through free text for encoded blobs (PowerShell -enc and long base64), decode, keep the readable ones.
  function scanEncoded(text) {
    var out = [], seen = new Set(), s = String(text || '');
    var psRe = /-e(?:nc(?:odedcommand)?)?\s+['"]?([A-Za-z0-9+\/]{16,}={0,2})['"]?/gi, m;
    while ((m = psRe.exec(s)) !== null) {
      var r = decode('powershell', m[0]);
      if (r.ok && printableRatio(r.output) > 0.9 && !seen.has(m[1])) { seen.add(m[1]); out.push({ kind: 'powershell', source: m[1], decoded: r.output }); }
    }
    var bRe = /(?<![A-Za-z0-9+\/=])[A-Za-z0-9+\/]{24,}={0,2}(?![A-Za-z0-9+\/=])/g;
    while ((m = bRe.exec(s)) !== null) {
      if (seen.has(m[0]) || /^[0-9a-fA-F]+$/.test(m[0])) continue;       // hashes are not base64 payloads
      var d = decode('base64', m[0]);
      if (d.ok && d.note.indexOf('binary') < 0 && printableRatio(d.output) > 0.92 && /[ \/:.]/.test(d.output)) {
        seen.add(m[0]); out.push({ kind: 'base64', source: m[0], decoded: d.output });
      }
    }
    return out;
  }

  /* ------------------------------------------------------------------ email headers */

  function looksLikeHeaders(text) {
    var names = {};
    String(text).split(/\r?\n/).slice(0, 80).forEach(function (ln) {
      var m = ln.match(/^(received|from|to|subject|date|message-id|return-path|reply-to|authentication-results|received-spf|dkim-signature|mime-version|x-[a-z\-]+):/i);
      if (m) names[m[1].toLowerCase()] = 1;
    });
    var n = Object.keys(names).length;
    return n >= 3 && (names['from'] || names['received'] || names['return-path']);
  }

  function parseAddr(s) {
    s = String(s || '').trim();
    if (!s) return null;
    var m = s.match(/^(?:"?([^"<]*?)"?\s*)?<([^>]+)>/), name = '', addr;
    if (m) { name = (m[1] || '').trim(); addr = m[2].trim(); } else { addr = s.replace(/[<>]/g, '').trim(); }
    addr = addr.toLowerCase();
    var at = addr.lastIndexOf('@');
    return { raw: s, name: name, addr: addr, domain: at >= 0 ? addr.slice(at + 1) : '' };
  }

  function headerMap(text) {
    var t = String(text).replace(/\r\n?/g, '\n');
    var cut = t.search(/\n[ \t]*\n/);
    var block = cut >= 0 ? t.slice(0, cut) : t, lines = [];
    block.split('\n').forEach(function (ln) {
      if (/^[ \t]+\S/.test(ln) && lines.length) lines[lines.length - 1] += ' ' + ln.trim(); else lines.push(ln);
    });
    var map = {};
    lines.forEach(function (ln) {
      var m = ln.match(/^([A-Za-z][A-Za-z0-9\-]*):\s?(.*)$/);
      if (m) (map[m[1].toLowerCase()] = map[m[1].toLowerCase()] || []).push(m[2].trim());
    });
    return { map: map, bodyStart: cut >= 0 ? cut : t.length, text: t };
  }

  function authResult(joined, name, allowed) {
    var m = joined.match(new RegExp('\\b' + name + '=(' + allowed + ')\\b', 'i'));
    return m ? m[1].toLowerCase() : '';
  }

  function parseHeaders(text) {
    var hm = headerMap(text), h = hm.map;
    var first = function (k) { return (h[k] && h[k][0]) || ''; };
    var res = {
      subject: first('subject'), date: first('date'), messageId: first('message-id'),
      from: parseAddr(first('from')), returnPath: parseAddr(first('return-path')), replyTo: parseAddr(first('reply-to')),
      to: first('to'), xOriginatingIp: first('x-originating-ip').replace(/[\[\]\s]/g, ''),
      auth: { spf: '', dkim: '', dmarc: '', smtpMailfrom: '', headerFrom: '' }, hops: [], findings: []
    };
    var ar = (h['authentication-results'] || []).join(' ; ');
    res.auth.spf = authResult(ar, 'spf', 'pass|fail|softfail|neutral|none|temperror|permerror');
    res.auth.dkim = authResult(ar, 'dkim', 'pass|fail|none|neutral|policy|temperror|permerror');
    res.auth.dmarc = authResult(ar, 'dmarc', 'pass|fail|none|bestguesspass|temperror|permerror');
    if (!res.auth.spf && h['received-spf']) {
      var rs = h['received-spf'][0].match(/^(pass|fail|softfail|neutral|none|temperror|permerror)/i);
      if (rs) res.auth.spf = rs[1].toLowerCase();
    }
    var mf = ar.match(/smtp\.mailfrom=([^\s;]+)/i), hf = ar.match(/header\.from=([^\s;]+)/i);
    res.auth.smtpMailfrom = mf ? mf[1].toLowerCase() : '';
    res.auth.headerFrom = hf ? hf[1].toLowerCase() : '';

    /* Received chain, oldest first */
    var rec = (h['received'] || []).slice().reverse();
    var prev = null;
    rec.forEach(function (r, i) {
      var from = (r.match(/\bfrom\s+(\S+)/i) || [])[1] || '', by = (r.match(/\bby\s+(\S+)/i) || [])[1] || '';
      var withp = (r.match(/\bwith\s+(\S+)/i) || [])[1] || '';
      var ips = [], re = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.?\d)/g, m;
      while ((m = re.exec(r)) !== null) if (ips.indexOf(m[0]) < 0) ips.push(m[0]);
      var date = (r.split(';').pop() || '').trim(), ts = Date.parse(date);
      var hop = { n: i + 1, from: from, by: by, with: withp, ips: ips, date: date, ts: isNaN(ts) ? null : ts, delay: null };
      if (prev && hop.ts != null && prev.ts != null) hop.delay = Math.round((hop.ts - prev.ts) / 1000);
      prev = hop; res.hops.push(hop);
    });
    var origin = null;
    for (var i = 0; i < res.hops.length && !origin; i++) {
      for (var j = 0; j < res.hops[i].ips.length; j++) {
        var sc = ipv4Scope(res.hops[i].ips[j]);
        if (!isInternalScope(sc)) { origin = { hop: res.hops[i].n, ip: res.hops[i].ips[j], scope: sc }; break; }
      }
    }
    res.origin = origin;

    /* Findings */
    var F = res.findings;
    function f(level, text) { F.push({ level: level, text: text }); }
    var a = res.auth;
    if (!ar && !h['received-spf'] && !h['dkim-signature']) f('info', 'No authentication results in these headers. Pull SPF, DKIM and DMARC from the mail gateway.');
    if (a.spf === 'fail' || a.spf === 'softfail') f('high', 'SPF ' + a.spf + ': the sending server is not authorised for the envelope domain.');
    else if (a.spf && a.spf !== 'pass') f('med', 'SPF result is "' + a.spf + '".');
    if (a.dkim === 'fail') f('high', 'DKIM signature failed.');
    else if (a.dkim === 'none') f('med', 'No DKIM signature.');
    if (a.dmarc === 'fail') f('high', 'DMARC failed: SPF/DKIM did not align with the From domain.');
    if (res.from && res.returnPath && res.from.domain && res.returnPath.domain && res.from.domain !== res.returnPath.domain)
      f('med', 'From domain (' + res.from.domain + ') differs from Return-Path domain (' + res.returnPath.domain + ').');
    if (res.from && res.replyTo && res.replyTo.domain && res.from.domain !== res.replyTo.domain)
      f('med', 'Reply-To domain (' + res.replyTo.domain + ') differs from From domain (' + res.from.domain + '): replies go somewhere else.');
    if (res.from && res.from.name) {
      var inName = res.from.name.match(/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i);
      if (inName && inName[0].toLowerCase() !== res.from.addr) f('high', 'Display name contains a different address (' + inName[0].toLowerCase() + '): classic display-name spoofing.');
      else if (!inName) {
        var dn = res.from.name.match(/\b[a-z0-9\-]+\.(?:com|net|org|io|co)\b/i);
        if (dn && res.from.domain && res.from.domain.indexOf(dn[0].toLowerCase()) < 0) f('med', 'Display name mentions ' + dn[0].toLowerCase() + ' but the address is on ' + res.from.domain + '.');
      }
    }
    if (res.messageId && res.from && res.from.domain) {
      var mid = res.messageId.match(/@([^>\s]+)/);
      if (mid && mid[1].toLowerCase() !== res.from.domain && mid[1].toLowerCase().indexOf(res.from.domain) < 0 && res.from.domain.indexOf(mid[1].toLowerCase()) < 0)
        f('info', 'Message-ID domain (' + mid[1].toLowerCase() + ') differs from the From domain.');
    }
    if (origin) f('info', 'First non-internal hop: ' + origin.ip + ' (hop ' + origin.hop + ', ' + origin.scope + ').');
    res.hops.forEach(function (hop) { if (hop.delay != null && hop.delay >= 3600) f('info', 'Hop ' + hop.n + ' took ' + hop.delay + 's: a long queue delay.'); if (hop.delay != null && hop.delay < 0) f('med', 'Hop ' + hop.n + ' timestamp is earlier than the previous hop: clock skew or forged Received header.'); });
    return res;
  }

  /* ------------------------------------------------------------------ report / ticket / sigma */

  function bump(o, k) { o[k] = (o[k] || 0) + 1; }

  function suggestSeverity(iocs, email) {
    var rank = 0;
    iocs.forEach(function (i) { if (i.verdict === 'malicious') rank = Math.max(rank, 3); else if (i.verdict === 'suspicious') rank = Math.max(rank, 2); });
    if (email && email.findings.some(function (x) { return x.level === 'high'; })) rank = Math.max(rank, 2);
    if (iocs.some(function (i) { return i.decoded || i.type === 'cve'; })) rank = Math.max(rank, 2);   // hidden payload or a named exploit is never "low"
    if (!rank && iocs.some(function (i) { return i.flags.indexOf('ip-host') >= 0 || i.flags.indexOf('credentials-in-url') >= 0; })) rank = 1;
    return ['low', 'low', 'medium', 'high'][rank];
  }

  function categoryOf(iocs, email) {
    var has = function (t) { return iocs.some(function (i) { return t.indexOf(i.type) >= 0; }); };
    if (email) return 'Phishing / email security';
    if (has(['sha256', 'sha1', 'md5', 'path', 'regkey'])) return 'Malware / endpoint';
    if (has(['ipv4', 'ipv6', 'domain', 'url'])) return 'Network / suspicious activity';
    return 'Security event';
  }

  function recommendedActions(iocs, email) {
    var A = [], by = {};
    iocs.forEach(function (i) { if (i.verdict !== 'benign' && !(i.flags.indexOf('internal') >= 0) && i.flags.indexOf('reserved') < 0) (by[i.type] = by[i.type] || []).push(i); });
    if (by.ipv4 || by.ipv6) A.push('Search firewall, proxy and VPN logs for the external IPs; block confirmed malicious ones at the perimeter.');
    if (by.domain || by.url) A.push('Search DNS and web proxy logs for the domains and URLs; add confirmed malicious ones to the DNS / proxy blocklist.');
    if (by.sha256 || by.sha1 || by.md5) A.push('Hunt for the file hashes in EDR; quarantine matches and collect the samples for analysis.');
    if (by.email || email) A.push('Search the mail gateway for the same sender, subject and URLs; purge matching messages from recipient mailboxes.');
    if (email && email.findings.some(function (x) { return x.level === 'high'; })) A.push('Treat the message as spoofed or malicious: confirm with the apparent sender out-of-band, and check whether any recipient clicked or replied.');
    if (by.cve) A.push('Check asset inventory and scanner results for exposure to the referenced CVEs; verify patch status.');
    if (by.regkey || by.path) A.push('Review persistence on affected hosts (run keys, scheduled tasks, services) and the listed file paths; isolate the host if execution is confirmed.');
    if (iocs.some(function (i) { return i.decoded; })) A.push('Decoded payloads were found inside the input: detonate or review them in a sandbox before closing.');
    A.push('Preserve evidence (original message or log, hashes, timestamps) and record the timeline in the ticket.');
    return A;
  }

  function priorityOf(sev) { return { low: 'P4 - Low', medium: 'P3 - Moderate', high: 'P2 - High', critical: 'P1 - Critical' }[sev] || 'P4 - Low'; }

  function buildReport(st) {
    var iocs = st.iocs || [], email = st.email || null, now = st.now || new Date().toISOString();
    var sev = st.severity && st.severity !== 'auto' ? st.severity : suggestSeverity(iocs, email);
    var verdict = st.verdict && st.verdict !== 'undecided' ? st.verdict : 'undecided';
    var title = (st.title || '').trim() || (email && email.subject ? 'Suspicious email: ' + email.subject : 'Security triage: ' + iocs.length + ' indicators');
    var counts = {}; iocs.forEach(function (i) { bump(counts, i.type); });
    var external = iocs.filter(function (i) { return (i.type === 'ipv4' || i.type === 'ipv6') && !isInternalScope(i.scope); }).length;
    var internal = iocs.filter(function (i) { return (i.type === 'ipv4' || i.type === 'ipv6') && isInternalScope(i.scope); }).length;
    var NOUN = { ipv4: ['IPv4 address', 'IPv4 addresses'], ipv6: ['IPv6 address', 'IPv6 addresses'], domain: ['domain', 'domains'], url: ['URL', 'URLs'], email: ['email address', 'email addresses'],
      sha256: ['SHA-256 hash', 'SHA-256 hashes'], sha1: ['SHA-1 hash', 'SHA-1 hashes'], md5: ['MD5 hash', 'MD5 hashes'], cve: ['CVE', 'CVEs'], path: ['file path', 'file paths'], regkey: ['registry key', 'registry keys'] };
    var parts = TYPE_ORDER.filter(function (t) { return counts[t]; }).map(function (t) { return counts[t] + ' ' + NOUN[t][counts[t] > 1 ? 1 : 0]; });
    var summary = iocs.length
      ? 'Automated extraction found ' + iocs.length + ' unique indicator' + (iocs.length > 1 ? 's' : '') + ' (' + parts.join(', ') + ').' + (external || internal ? ' IP addresses: ' + external + ' external, ' + internal + ' internal.' : '')
      : 'No indicators were extracted from the submitted text.';

    var key = [];
    iocs.forEach(function (i) {
      if (i.flags.indexOf('ip-host') >= 0) key.push('URL uses a raw IP address as its host: ' + defang(i.value, 'url'));
      if (i.flags.indexOf('credentials-in-url') >= 0) key.push('URL embeds credentials: ' + defang(i.value, 'url'));
      if (i.flags.indexOf('punycode') >= 0 && i.type === 'domain') key.push('Punycode domain (possible look-alike): ' + defang(i.value, 'domain'));
      if (i.flags.indexOf('risky-tld') >= 0 && i.type === 'domain') key.push('Domain on a TLD that is frequently abused: ' + defang(i.value, 'domain'));
      if (i.flags.indexOf('shortener') >= 0 && i.type === 'url') key.push('Shortened URL hides its destination: ' + defang(i.value, 'url'));
      if (i.flags.indexOf('empty-file-hash') >= 0) key.push('Hash ' + i.value.slice(0, 12) + '... is the hash of an empty file: not a real sample.');
      if (i.decoded) key.push('Indicator recovered from an encoded payload: ' + defang(i.value, i.type));
    });
    if (email) email.findings.forEach(function (x) { if (x.level !== 'info') key.push('Email: ' + x.text); });

    var obs = iocs.map(function (i) {
      return { type: i.type, value: i.value, defanged: defang(i.value, i.type), count: i.count, scope: i.scope || '', flags: i.flags, verdict: i.verdict || 'unknown' };
    });
    var actions = recommendedActions(iocs, email);
    var category = categoryOf(iocs, email), priority = priorityOf(sev);
    var notes = (st.notes || '').trim();

    var md = [];
    md.push('# ' + title, '');
    md.push('- **Generated:** ' + now + ' by Hyperflow Playground (all analysis done locally in the browser)');
    md.push('- **Suggested category:** ' + category);
    md.push('- **Severity / priority:** ' + sev + ' / ' + priority);
    md.push('- **Analyst verdict:** ' + verdict, '');
    md.push('## Summary', '', summary, '');
    if (key.length) { md.push('## Key findings', ''); key.forEach(function (k) { md.push('- ' + k); }); md.push(''); }
    if (email) {
      md.push('## Email analysis', '');
      md.push('| Field | Value |', '|---|---|');
      md.push('| Subject | ' + (email.subject || '-') + ' |');
      md.push('| From | ' + (email.from ? defang(email.from.raw, 'email').replace(/\|/g, '/') : '-') + ' |');
      md.push('| Return-Path | ' + (email.returnPath ? defang(email.returnPath.addr, 'email') : '-') + ' |');
      md.push('| Reply-To | ' + (email.replyTo ? defang(email.replyTo.addr, 'email') : '-') + ' |');
      md.push('| SPF / DKIM / DMARC | ' + [email.auth.spf || '?', email.auth.dkim || '?', email.auth.dmarc || '?'].join(' / ') + ' |');
      md.push('| First external hop | ' + (email.origin ? defang(email.origin.ip, 'ipv4') + ' (hop ' + email.origin.hop + ')' : '-') + ' |', '');
    }
    if (obs.length) {
      md.push('## Observables (defanged)', '', '| Type | Value | Seen | Flags | Verdict |', '|---|---|---|---|---|');
      obs.forEach(function (o) { md.push('| ' + TYPE_LABEL[o.type] + ' | `' + o.defanged.replace(/\|/g, '\\|') + '` | ' + o.count + ' | ' + (o.flags.concat(o.scope && o.flags.indexOf('internal') < 0 && o.scope !== 'public' && o.scope !== 'documentation' ? [o.scope] : []).join(', ') || '-') + ' | ' + o.verdict + ' |'); });
      md.push('');
    }
    md.push('## Analyst notes', '', notes || '_none yet_', '');
    md.push('## Recommended actions', ''); actions.forEach(function (a) { md.push('- [ ] ' + a); }); md.push('');
    md.push('## Incident ticket draft', '');
    md.push('- **Short description:** ' + title);
    md.push('- **Category:** ' + category);
    md.push('- **Priority:** ' + priority);
    md.push('- **Assignment group:** _fill in_');
    md.push('- **Description:** ' + summary + (notes ? ' Analyst notes: ' + notes.replace(/\s+/g, ' ') : ''));
    md.push('- **Observables:** ' + (obs.length ? obs.map(function (o) { return o.defanged; }).join(', ') : 'none'));
    md.push('');

    var json = {
      schema: 'hyperflow.triage/1', generated: now, title: title, category: category, severity: sev, priority: priority, verdict: verdict,
      summary: summary, key_findings: key, analyst_notes: notes, recommended_actions: actions, observables: obs,
      email: email ? { subject: email.subject, from: email.from && email.from.addr, return_path: email.returnPath && email.returnPath.addr, reply_to: email.replyTo && email.replyTo.addr, spf: email.auth.spf, dkim: email.auth.dkim, dmarc: email.auth.dmarc, first_external_hop: email.origin || null, hops: email.hops.map(function (h) { return { n: h.n, from: h.from, by: h.by, ips: h.ips, date: h.date }; }), findings: email.findings } : null
    };
    return { title: title, severity: sev, category: category, priority: priority, summary: summary, key: key, actions: actions, markdown: md.join('\n'), json: json };
  }

  function yq(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }
  function ylist(arr, pad) { return arr.map(function (v) { return pad + '- ' + yq(v); }).join('\n'); }
  function uuidish(seed) {
    var h = 2166136261 >>> 0, s = String(seed), out = '';
    for (var i = 0; i < 32; i++) { h ^= s.charCodeAt(i % Math.max(1, s.length)) + i; h = Math.imul(h, 16777619) >>> 0; out += (h >>> 24 & 15).toString(16); }
    return out.slice(0, 8) + '-' + out.slice(8, 12) + '-4' + out.slice(13, 16) + '-a' + out.slice(17, 20) + '-' + out.slice(20, 32);
  }

  function buildSigma(iocs, opts) {
    opts = opts || {};
    var date = (opts.date || new Date().toISOString().slice(0, 10)).replace(/-/g, '/');
    var live = iocs.filter(function (i) {
      return i.verdict !== 'benign' && i.flags.indexOf('internal') < 0 && (opts.includeReserved || i.flags.indexOf('reserved') < 0) && i.flags.indexOf('empty-file-hash') < 0;
    });
    var ofType = function () { var t = Array.prototype.slice.call(arguments); return live.filter(function (i) { return t.indexOf(i.type) >= 0; }).map(function (i) { return i.value; }); };
    var rules = [];
    var title = opts.title || 'Hyperflow triage';
    function rule(name, desc, logsource, detection, level) {
      var id = opts.id ? opts.id + '-' + rules.length : uuidish(name + date + live.length);
      rules.push([
        'title: ' + yq(title + ' - ' + name), 'id: ' + id, 'status: experimental', 'description: ' + yq(desc),
        'author: Hyperflow Playground', 'date: ' + date, 'logsource:', logsource, 'detection:', detection,
        'falsepositives:', "    - 'Review before deploying: indicators come from one triage and may be shared infrastructure.'", 'level: ' + (level || 'medium')
      ].join('\n'));
    }
    var hashes = ofType('sha256', 'sha1', 'md5');
    if (hashes.length) {
      var hv = live.filter(function (i) { return i.type === 'sha256' || i.type === 'sha1' || i.type === 'md5'; }).map(function (i) { return { sha256: 'SHA256=', sha1: 'SHA1=', md5: 'MD5=' }[i.type] + i.value.toUpperCase(); });
      rule('known file hashes', 'Process image matching a hash seen in triage.', '    category: process_creation\n    product: windows',
        '    selection:\n        Hashes|contains:\n' + ylist(hv, '            ') + '\n    condition: selection', 'high');
    }
    var ips = ofType('ipv4', 'ipv6'), doms = ofType('domain');
    if (ips.length || doms.length) {
      var det = [], cond = [];
      if (ips.length) { det.push('    selection_ip:\n        DestinationIp:\n' + ylist(ips, '            ')); cond.push('selection_ip'); }
      if (doms.length) {
        det.push('    selection_host:\n        DestinationHostname|endswith:\n' + ylist(doms.map(function (d) { return d; }), '            ')); cond.push('selection_host');
      }
      rule('network connections', 'Outbound connection to infrastructure seen in triage.', '    category: network_connection\n    product: windows',
        det.join('\n') + '\n    condition: 1 of selection_*', 'medium');
    }
    if (doms.length) {
      rule('DNS lookups', 'DNS query for a domain seen in triage.', '    category: dns_query\n    product: windows',
        '    selection:\n        QueryName|endswith:\n' + ylist(doms, '            ') + '\n    condition: selection', 'medium');
    }
    var urls = ofType('url');
    if (urls.length) {
      rule('proxy requests', 'Web request to a URL seen in triage.', '    category: proxy',
        '    selection:\n        c-uri|contains:\n' + ylist(urls.map(function (u) { return u.replace(/^[a-z]+:\/\//i, ''); }), '            ') + '\n    condition: selection', 'medium');
    }
    var regs = ofType('regkey');
    if (regs.length) {
      rule('registry persistence', 'Registry write to a key seen in triage.', '    category: registry_set\n    product: windows',
        '    selection:\n        TargetObject|contains:\n' + ylist(regs.map(function (r) { return r.replace(/^HKLM\\/i, 'HKLM\\').replace(/^HKCU\\/i, 'HKU\\'); }), '            ') + '\n    condition: selection', 'high');
    }
    var paths = ofType('path').filter(function (p) { return /^[A-Za-z]:\\|^\\\\/.test(p); });
    if (paths.length) {
      rule('file activity', 'File creation or process image at a path seen in triage.', '    category: file_event\n    product: windows',
        '    selection:\n        TargetFilename|contains:\n' + ylist(paths, '            ') + '\n    condition: selection', 'medium');
    }
    if (!rules.length) return '# No indicators suitable for a rule yet (internal, reserved and benign-marked values are skipped).\n';
    return '# Sigma stub generated locally by Hyperflow Playground. Review, tune and test before deploying.\n' + rules.join('\n---\n') + '\n';
  }

  /* ------------------------------------------------------------------ top-level analyse */

  function analyze(text, opts) {
    opts = opts || {};
    var raw = String(text == null ? '' : text);
    var iocs = extract(raw, opts), email = null, decoded = [];
    if (looksLikeHeaders(raw)) email = parseHeaders(raw);
    scanEncoded(raw).forEach(function (blob) {
      var inner = extract(blob.decoded, opts);
      decoded.push({ kind: blob.kind, source: blob.source, decoded: blob.decoded, iocs: inner });
      inner.forEach(function (n) {
        var existing = iocs.filter(function (o) { return o.type === n.type && o.value === n.value; })[0];
        if (existing) { existing.decoded = true; if (existing.flags.indexOf('from-decoded') < 0) existing.flags.push('from-decoded'); }
        else { n.decoded = true; n.flags.push('from-decoded'); iocs.push(n); }
      });
    });
    var rank = {}; TYPE_ORDER.forEach(function (t, i) { rank[t] = i; });
    var idx = new Map(iocs.map(function (o, i) { return [o, i]; }));
    iocs.sort(function (a, b) { return (rank[a.type] - rank[b.type]) || (idx.get(a) - idx.get(b)); });
    return { iocs: iocs, email: email, decoded: decoded };
  }

  return {
    TYPE_ORDER: TYPE_ORDER, TYPE_LABEL: TYPE_LABEL,
    refang: refang, defang: defang, extract: extract, analyze: analyze, pivots: pivots,
    ipv4Scope: ipv4Scope, ipv6Scope: ipv6Scope, isInternalScope: isInternalScope, validIPv6: validIPv6, isIPv4: isIPv4, domainFrom: domainFrom,
    decode: decode, detectMode: detectMode, scanEncoded: scanEncoded, rot13: rot13,
    looksLikeHeaders: looksLikeHeaders, parseHeaders: parseHeaders, parseAddr: parseAddr,
    buildReport: buildReport, buildSigma: buildSigma, suggestSeverity: suggestSeverity
  };
}));
