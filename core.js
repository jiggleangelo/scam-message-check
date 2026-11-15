(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.ScamCore = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var MAX_CHARS = 8000;

  var SIGNALS = [
    ['safe_account', 0.40, String.raw`safe account|transfer to protect|安全账户`],
    ['police_impersonation', 0.35, String.raw`\bspf\b|police officer|warrant|money laundering|警察|洗钱`],
    ['bank_otp', 0.35, String.raw`\botp\b|one[- ]time password|verify your account|card blocked|验证码`],
    ['gov_impersonation', 0.30, String.raw`(?:from|contact|officer|notice)[ :,-]{0,3}(?:the )?(?:mom|ica|moh)\b|cpf board|\biras\b|移民局|公积金`],
    ['investment', 0.30, String.raw`guaranteed return|guaranteed \d|% daily|crypto|usdt|trading group|保证回报`],
    ['job_task', 0.30, String.raw`like videos earn|part-time task|commission per task|刷单`],
    ['family_in_trouble', 0.30, String.raw`new number|it.?s me,? ma|accident.{0,20}need money|换号码了|出事了`],
    ['remote_access', 0.30, String.raw`anydesk|teamviewer|download this app|\bapk\b`],
    ['parcel', 0.25, String.raw`parcel held|customs fee|redelivery|包裹`],
    ['payment_method', 0.20, String.raw`gift card|paynow to|western union|bitcoin atm`]
  ];
  var URGENCY_SRC = String.raw`within 24 hours|don.?t tell anyone|immediately|\burgent\b|马上|不要告诉`;
  var URGENCY_WEIGHT = 0.15;
  var LINK_WEIGHT = 0.20;
  var URL_SRC = String.raw`https?://[^\s<>]{1,2048}`;

  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co'];
  var TRUSTED = ['gov.sg', 'dbs.com.sg', 'ocbc.com', 'uob.com.sg', 'singpass.gov.sg'];
  var BOOST_WORDS = ['otp', 'safe account', 'guaranteed', '验证码', '安全账户', '保证回报'];

  var CHECKLIST_KEYS = ['check.pause', 'check.codeword', 'check.callback', 'check.help'];

  function normalise(text) {
    return String(text == null ? '' : text).normalize('NFKC').replace(/\s+/g, ' ').trim();
  }

  function labelForScore(score) {
    if (score >= 0.70) return 'likely_scam';
    if (score >= 0.35) return 'suspicious';
    return 'no_strong_signs';
  }

  function suspiciousUrl(raw) {
    var s = String(raw).replace(/[.,);\]}'"]+$/, '');
    var u;
    try {
      u = new URL(s);
    } catch (e) {
      return true;
    }
    var host = String(u.hostname || '').toLowerCase().replace(/\.+$/, '');
    if (!host) return true;
    if (u.username || u.password) return true;
    if (u.protocol !== 'https:') return true;
    if (u.port && u.port !== '443') return true;
    if (SHORTENERS.indexOf(host) !== -1) return true;
    for (var i = 0; i < TRUSTED.length; i++) {
      var t = TRUSTED[i];
      if (host === t || host.slice(-(t.length + 1)) === '.' + t) return false;
    }
    return true;
  }

  // Port of the app's logsafe.redact: masks emails, SG IDs/phones and long digit runs before the phrase rule runs.
  var SENSITIVE = new RegExp('[\\p{L}\\p{N}_.+-]+@[\\p{L}\\p{N}_.-]+|\\b[STFG]\\s*\\d(?:[ -]?\\d){6}[A-Z]\\b|(?<!\\d)(?:\\+?65[ -]?)?(?:[689](?:[ -]?\\d){7})(?!\\d)|(?<!\\d)\\d(?:[ -]?\\d){5,}(?!\\d)', 'giu');
  function redact(v) { return String(v).replace(SENSITIVE, '[redacted]'); }

  function classify(text) {
    var original = String(text == null ? '' : text);
    var truncated = original.length > MAX_CHARS;
    var clean = normalise(original.slice(0, MAX_CHARS));
    if (clean === '') {
      return { label: 'no_strong_signs', score: 0, categories: [], reasons: [], topReasons: [], truncated: truncated, empty: true, adjustment: 0 };
    }
    var found = [];
    var i;
    for (i = 0; i < SIGNALS.length; i++) {
      if (new RegExp(SIGNALS[i][2], 'i').test(clean)) found.push([SIGNALS[i][0], SIGNALS[i][1]]);
    }
    if (new RegExp(URGENCY_SRC, 'i').test(clean)) found.push(['urgency_secrecy', URGENCY_WEIGHT]);
    var urls = clean.match(new RegExp(URL_SRC, 'gi')) || [];
    var bad = false;
    for (i = 0; i < urls.length; i++) {
      if (suspiciousUrl(urls[i])) { bad = true; break; }
    }
    if (bad) found.push(['link', LINK_WEIGHT]);

    var rest = 1;
    for (i = 0; i < found.length; i++) rest *= (1 - found[i][1]);
    var score = 1 - rest;

    var lower = redact(clean).toLowerCase(); // as the app: the phrase rule sees the normalised, redacted text
    var adjustment = 0;
    var boosted = false;
    for (i = 0; i < BOOST_WORDS.length; i++) {
      if (lower.indexOf(BOOST_WORDS[i]) !== -1) { boosted = true; break; }
    }
    if (boosted) adjustment = 0.15;
    else adjustment = 0.05; // clean is non-empty here
    score = Math.min(1, Math.max(0, score + adjustment));

    var categories = [];
    for (i = 0; i < found.length; i++) {
      if (categories.indexOf(found[i][0]) === -1) categories.push(found[i][0]);
    }
    var sorted = found.map(function (f, idx) { return { k: f[0], w: f[1], idx: idx }; })
      .sort(function (a, b) { return (b.w - a.w) || (a.idx - b.idx); })
      .map(function (f) { return f.k; });
    var reasons = [];
    for (i = 0; i < sorted.length && reasons.length < 3; i++) {
      if (reasons.indexOf(sorted[i]) === -1) reasons.push(sorted[i]);
    }
    return {
      label: labelForScore(score),
      score: score,
      categories: categories,
      reasons: reasons,
      topReasons: reasons.slice(),
      truncated: truncated,
      empty: false,
      adjustment: adjustment
    };
  }

  var STRINGS = {
    en: {
      'verdict.likely_scam': 'This looks like a scam. Do not reply, pay, or share codes.',
      'verdict.suspicious': 'Suspicious: pause and verify. Do not act on this message yet.',
      'verdict.no_strong_signs': 'No strong signs found. That does not mean it is safe. Still pause and verify.',
      'reason.police_impersonation': 'It uses police or criminal-case language often used by impersonators.',
      'reason.gov_impersonation': 'It claims to be from a government agency.',
      'reason.bank_otp': 'Banks never ask you to reveal an OTP or password.',
      'reason.safe_account': "Real police and banks never ask you to move money to a 'safe account'.",
      'reason.investment': 'Guaranteed or unusually fast investment returns are a common scam sign.',
      'reason.job_task': 'Paying money to unlock tasks or commission is a common scam pattern.',
      'reason.parcel': 'Unexpected parcel fees and redelivery links can be phishing.',
      'reason.family_in_trouble': 'A new number and urgent request for money may be impersonation.',
      'reason.urgency_secrecy': 'Pressure to act quickly or secretly is a warning sign.',
      'reason.payment_method': 'The requested payment method is commonly used by scammers.',
      'reason.link': 'The link is shortened, unfamiliar, or resembles a trusted organisation.',
      'reason.remote_access': 'Remote-access apps can give a stranger control of your device.',
      'check.pause': 'Pause. Do not reply, pay, click links, or share codes.',
      'check.codeword': 'Ask for your family code word. Do not reveal it first.',
      'check.callback': 'Hang up. Call back using the number already saved in your phone, not the number that called you.',
      'check.help': 'If money may be at risk, contact the bank using its official number.',
      'rules.note': 'Checked by fixed pattern rules written from public scam advisories, not by AI. Rules miss new tricks.',
      'cat.safe_account': 'Safe-account request',
      'cat.police_impersonation': 'Police impersonation',
      'cat.bank_otp': 'OTP or bank-login request',
      'cat.gov_impersonation': 'Government impersonation',
      'cat.investment': 'Investment promise',
      'cat.job_task': 'Task or commission job',
      'cat.family_in_trouble': 'Family in trouble',
      'cat.remote_access': 'Remote access',
      'cat.parcel': 'Parcel or delivery',
      'cat.payment_method': 'Payment method',
      'cat.urgency_secrecy': 'Urgency or secrecy',
      'cat.link': 'Suspicious link',
      'ui.title': 'Scam message check',
      'ui.subtitle': 'Paste a message you received (SMS, chat, email text or call note). We look for common scam patterns.',
      'ui.privacy': 'Your text is never stored, sent or logged.',
      'ui.examples': 'Try an example',
      'ui.exampleTag': 'Made-up example',
      'ui.input': 'Message to check',
      'ui.label': 'Paste the message here (max 8000 characters)',
      'ui.placeholder': 'Paste the message here (max 8000 characters)',
      'ui.check': 'Check message',
      'ui.clear': 'Clear',
      'ui.result': 'Result',
      'ui.empty': 'Enter some text to check.',
      'ui.truncated': 'Your text was longer than 8000 characters. Only the first 8000 were checked.',
      'ui.why': 'Why',
      'ui.also': 'Also matched',
      'ui.checklist': 'Pause and verify',
      'ui.disclaimer': 'General information only, not legal or financial advice.',
      'ex.police': 'Police safe-account',
      'ex.bank': 'Bank OTP',
      'ex.invest': 'Investment',
      'ex.clinic': 'Clinic reminder'
    },
    zh: {
      'verdict.likely_scam': '这很可能是诈骗。不要回复、付款或提供验证码。',
      'verdict.suspicious': '这则信息可疑。请暂停并自行核实，先不要照做。',
      'verdict.no_strong_signs': '我们没有发现明显的诈骗迹象，但这不代表安全。仍请暂停并核实。',
      'reason.police_impersonation': '信息使用了冒充警察时常见的刑事案件说法。',
      'reason.gov_impersonation': '对方声称来自政府机构。',
      'reason.bank_otp': '银行绝不会要求您提供验证码或密码。',
      'reason.safe_account': '真正的警察和银行绝不会要求您把钱转到“安全账户”。',
      'reason.investment': '保证回报或异常快速的回报是常见诈骗迹象。',
      'reason.job_task': '要求先付款才能做任务或拿佣金是常见诈骗方式。',
      'reason.parcel': '意外的包裹费用和重新派送链接可能是钓鱼信息。',
      'reason.family_in_trouble': '新号码加上紧急要钱可能是假冒家人。',
      'reason.urgency_secrecy': '催促您马上或秘密行动是警告迹象。',
      'reason.payment_method': '对方要求的付款方式常被骗子使用。',
      'reason.link': '链接经过缩短、来源陌生，或冒充可信机构。',
      'reason.remote_access': '远程控制软件可能让陌生人控制您的设备。',
      'check.pause': '先暂停。不要回复、付款、点击链接或提供验证码。',
      'check.codeword': '请对方说出家庭暗语，不要先告诉对方。',
      'check.callback': '先挂断。用手机里原本保存的号码回拨，不要用来电号码。',
      'check.help': '如果钱款可能有风险，请使用银行官方号码联系银行。',
      'rules.note': '本工具使用根据公共诈骗警示编写的固定规则，并非人工智能。规则可能无法识别新骗术。',
      'cat.safe_account': '安全账户',
      'cat.police_impersonation': '冒充警察',
      'cat.bank_otp': '验证码或银行登录',
      'cat.gov_impersonation': '冒充政府机构',
      'cat.investment': '投资承诺',
      'cat.job_task': '刷单兼职',
      'cat.family_in_trouble': '家人出事',
      'cat.remote_access': '远程控制',
      'cat.parcel': '包裹派送',
      'cat.payment_method': '付款方式',
      'cat.urgency_secrecy': '催促或保密',
      'cat.link': '可疑链接',
      'ui.title': '诈骗信息检查',
      'ui.subtitle': '粘贴您收到的信息（短信、聊天、邮件文字或通话记录），我们会查找常见的诈骗特征。',
      'ui.privacy': '您的文字不会被保存、发送或记录。',
      'ui.examples': '试试示例',
      'ui.exampleTag': '虚构示例',
      'ui.input': '要检查的信息',
      'ui.label': '请在此粘贴信息（最多 8000 个字符）',
      'ui.placeholder': '请在此粘贴信息（最多 8000 个字符）',
      'ui.check': '检查信息',
      'ui.clear': '清除',
      'ui.result': '结果',
      'ui.empty': '请先输入要检查的文字。',
      'ui.truncated': '您的文字超过 8000 个字符，只检查了前 8000 个字符。',
      'ui.why': '原因',
      'ui.also': '其他匹配项',
      'ui.checklist': '暂停并核实',
      'ui.disclaimer': '仅为一般信息，不构成法律或财务建议。',
      'ex.police': '警察安全账户',
      'ex.bank': '银行验证码',
      'ex.invest': '投资',
      'ex.clinic': '诊所提醒'
    }
  };

  return {
    normalise: normalise,
    labelForScore: labelForScore,
    suspiciousUrl: suspiciousUrl,
    classify: classify,
    STRINGS: STRINGS,
    CHECKLIST_KEYS: CHECKLIST_KEYS
  };
});
