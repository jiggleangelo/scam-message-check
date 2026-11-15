import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const C = require('../core.js');

const near = (a, b) => Math.abs(a - b) < 1e-9;

test('normalise', () => {
  assert.equal(C.normalise('  a \n\t b  '), 'a b');
  assert.equal(C.normalise('ＡＢＣ'), 'ABC');
});

const CASES = [
  ['safe_account', 'Please transfer to protect your funds', '请转入安全账户'],
  ['police_impersonation', 'SPF is investigating you', '警察打电话给您'],
  ['bank_otp', 'Send me the OTP now', '请提供验证码'],
  ['gov_impersonation', 'Notice from MOM about your pass', '移民局通知您'],
  ['investment', 'Join our crypto group', '保证回报很高'],
  ['job_task', 'Easy part-time task for you', '做刷单赚钱'],
  ['family_in_trouble', "Hi it's me, ma. new number", '妈，我换号码了'],
  ['remote_access', 'Please install AnyDesk', null],
  ['parcel', 'Your parcel held at depot', '您的包裹被扣'],
  ['payment_method', 'Pay with a gift card', null],
  ['urgency_secrecy', 'Do it immediately', '请马上办理']
];

for (const [key, en, zh] of CASES) {
  test('signal fires (en): ' + key, () => {
    assert.ok(C.classify(en).categories.includes(key), key);
  });
  if (zh) {
    test('signal fires (zh): ' + key, () => {
      assert.ok(C.classify(zh).categories.includes(key), key);
    });
  }
}

test('link fires on http and shortener, not on trusted https', () => {
  assert.ok(C.classify('visit http://example.com now').categories.includes('link'));
  assert.ok(!C.classify('see https://www.dbs.com.sg/login').categories.includes('link'));
});

test('weights multiply and phrase adjustment applies', () => {
  const r = C.classify('safe account, police officer');
  assert.deepEqual(r.categories, ['safe_account', 'police_impersonation']);
  assert.ok(near(r.score, 1 - 0.6 * 0.65 + 0.15), String(r.score));
  assert.equal(r.label, 'likely_scam');
});

test('labelForScore boundaries', () => {
  assert.equal(C.labelForScore(0.7), 'likely_scam');
  assert.equal(C.labelForScore(0.6999), 'suspicious');
  assert.equal(C.labelForScore(0.35), 'suspicious');
  assert.equal(C.labelForScore(0.3499), 'no_strong_signs');
});

test('thresholds via constructed inputs', () => {
  const low = C.classify('pay with a gift card');
  assert.ok(near(low.score, 0.25));
  assert.equal(low.label, 'no_strong_signs');
  const mid = C.classify('please install anydesk');
  assert.ok(Math.abs(mid.score - 0.35) < 1e-9);
  assert.equal(mid.label, 'suspicious');
  const just = C.classify('otp crypto');
  assert.ok(near(just.score, 1 - 0.65 * 0.7 + 0.15));
  assert.equal(just.label, 'suspicious');
  assert.equal(C.classify('otp crypto immediately').label, 'likely_scam');
});

test('phrase adjustment .05 / .15 / 0', () => {
  assert.ok(near(C.classify('hello there').score, 0.05));
  assert.ok(near(C.classify('hotpot').score, 0.15));
  assert.ok(near(C.classify('guaranteed').score, 0.15));
  assert.ok(near(C.classify('保证回报').score, 1 - 0.7 + 0.15));
  assert.equal(C.classify('').score, 0);
});

test('phrase rule sees the truncated, normalised, redacted text (as the app)', () => {
  assert.ok(near(C.classify('ＯＴＰ　ｃｏｄｅ').score, 0.5));
  assert.ok(near(C.classify('x'.repeat(9000) + ' otp').score, 0.05));
  // bank_otp still matches the raw text (.35), but the email is redacted before the phrase rule, so +.05 not +.15
  const r = C.classify('otp@mail.example');
  assert.ok(r.categories.includes('bank_otp'));
  assert.ok(near(r.score, 0.35 + 0.05), String(r.score));
});

test('suspiciousUrl', () => {
  assert.equal(C.suspiciousUrl('https://dbs.com.sg/x'), false);
  assert.equal(C.suspiciousUrl('https://dbs.com.sg.evil/'), true);
  assert.equal(C.suspiciousUrl('https://dbs-sg-secure.com'), true);
  assert.equal(C.suspiciousUrl('http://dbs.com.sg'), true);
  assert.equal(C.suspiciousUrl('https://bit.ly/x'), true);
  assert.equal(C.suspiciousUrl('https://x@dbs.com.sg'), true);
  assert.equal(C.suspiciousUrl('https://dbs.com.sg:8443'), true);
  assert.equal(C.suspiciousUrl('https://www.singpass.gov.sg/'), false);
  assert.equal(C.suspiciousUrl('https://www.singpass.gov.sg/).'), false);
  assert.equal(C.suspiciousUrl('not a url'), true);
});

test('reasons capped at 3 and ordered by weight', () => {
  const r = C.classify('safe account police officer otp crypto urgent');
  assert.equal(r.categories.length, 5);
  assert.deepEqual(r.reasons, ['safe_account', 'police_impersonation', 'bank_otp']);
  assert.deepEqual(r.topReasons, r.reasons);
});

test('benign clinic reminder', () => {
  const r = C.classify('Reminder: your clinic appointment is Tuesday at 10:00. Call the clinic if you need to reschedule.');
  assert.equal(r.label, 'no_strong_signs');
  assert.deepEqual(r.categories, []);
});

test('app samples', () => {
  assert.equal(C.classify('SPF police officer: your name is in a money laundering case. Transfer to a safe account immediately.').label, 'likely_scam');
  assert.equal(C.classify('您的银行卡已被冻结，请马上提供验证码 OTP，并到 https://dbs-sg-secure.com 验证。').label, 'likely_scam');
  assert.equal(C.classify('Guaranteed 3% daily in our crypto trading group. PayNow to join immediately: https://bit.ly/demo-invest').label, 'likely_scam');
});

test('empty and whitespace input', () => {
  for (const s of ['', '   \n ']) {
    const r = C.classify(s);
    assert.equal(r.label, 'no_strong_signs');
    assert.equal(r.score, 0);
    assert.equal(r.empty, true);
  }
  assert.equal(C.classify(undefined).label, 'no_strong_signs');
});

test('9000-char input does not throw and is flagged truncated', () => {
  const r = C.classify('a'.repeat(9000));
  assert.equal(r.truncated, true);
  assert.equal(r.label, 'no_strong_signs');
});

test('STRINGS complete in both languages', () => {
  const en = Object.keys(C.STRINGS.en);
  const zh = Object.keys(C.STRINGS.zh);
  assert.deepEqual([...en].sort(), [...zh].sort());
  const cats = ['safe_account', 'police_impersonation', 'bank_otp', 'gov_impersonation', 'investment', 'job_task',
    'family_in_trouble', 'remote_access', 'parcel', 'payment_method', 'urgency_secrecy', 'link'];
  const need = ['verdict.likely_scam', 'verdict.suspicious', 'verdict.no_strong_signs', 'rules.note', ...C.CHECKLIST_KEYS];
  for (const c of cats) need.push('reason.' + c, 'cat.' + c);
  for (const lang of ['en', 'zh']) {
    for (const k of need) {
      assert.ok(typeof C.STRINGS[lang][k] === 'string' && C.STRINGS[lang][k].length > 0, lang + ' ' + k);
    }
  }
  assert.equal(C.CHECKLIST_KEYS.length, 4);
  assert.match(C.STRINGS.en['verdict.no_strong_signs'], /That does not mean it is safe\. Still pause and verify\./);
});
