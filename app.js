(function () {
  'use strict';
  var C = globalThis.ScamCore;
  var S = C.STRINGS;
  var lang = 'en';
  var checked = false;

  var EXAMPLES = [
    { id: 'police', text: 'SPF police officer: your name is in a money laundering case. Transfer to a safe account immediately.' },
    { id: 'bank', text: '您的银行卡已被冻结，请马上提供验证码 OTP，并到 https://dbs-sg-secure.com 验证。' },
    { id: 'invest', text: 'Guaranteed 3% daily in our crypto trading group. PayNow to join immediately: https://bit.ly/demo-invest' },
    { id: 'clinic', text: 'Reminder: your clinic appointment is Tuesday at 10:00. Call the clinic if you need to reschedule.' }
  ];

  function $(id) { return document.getElementById(id); }
  function t(k) { return (S[lang] && S[lang][k]) || S.en[k] || k; }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function applyI18n() {
    var nodes = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < nodes.length; i++) nodes[i].textContent = t(nodes[i].getAttribute('data-i18n'));
    var ph = document.querySelectorAll('[data-i18n-placeholder]');
    for (var j = 0; j < ph.length; j++) ph[j].setAttribute('placeholder', t(ph[j].getAttribute('data-i18n-placeholder')));
    document.documentElement.lang = lang === 'zh' ? 'zh-Hans' : 'en';
    document.title = t('ui.title');
    var btns = document.querySelectorAll('[data-lang]');
    for (var k = 0; k < btns.length; k++) {
      btns[k].setAttribute('aria-pressed', btns[k].getAttribute('data-lang') === lang ? 'true' : 'false');
    }
  }

  function buildExamples() {
    var ul = $('examples');
    EXAMPLES.forEach(function (ex) {
      var li = document.createElement('li');
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'example';
      var tag = el('span', 'tag');
      tag.setAttribute('data-i18n', 'ui.exampleTag');
      var name = el('span', 'name');
      name.setAttribute('data-i18n', 'ex.' + ex.id);
      b.appendChild(tag);
      b.appendChild(name);
      b.addEventListener('click', function () {
        $('msg').value = ex.text;
        run();
      });
      li.appendChild(b);
      ul.appendChild(li);
    });
  }

  function reasonItem(key) {
    var li = document.createElement('li');
    li.appendChild(el('strong', null, t('cat.' + key)));
    li.appendChild(document.createTextNode(': ' + t('reason.' + key)));
    return li;
  }

  function render() {
    var body = $('result-body');
    body.replaceChildren();
    if (!checked) return;
    var r = C.classify($('msg').value);
    if (r.empty) {
      body.appendChild(el('p', 'prompt', t('ui.empty')));
      return;
    }
    var v = el('div', 'verdict ' + r.label);
    v.appendChild(el('h3', null, t('verdict.' + r.label)));
    v.appendChild(el('p', 'note', t('rules.note')));
    body.appendChild(v);
    if (r.truncated) body.appendChild(el('p', 'warn', t('ui.truncated')));

    if (r.reasons.length) {
      body.appendChild(el('h3', null, t('ui.why')));
      var ul = el('ul', 'reasons');
      r.reasons.forEach(function (k) { ul.appendChild(reasonItem(k)); });
      body.appendChild(ul);
      var more = r.categories.filter(function (k) { return r.reasons.indexOf(k) === -1; });
      if (more.length) {
        body.appendChild(el('h3', null, t('ui.also')));
        var ul2 = el('ul', 'reasons');
        more.forEach(function (k) { ul2.appendChild(reasonItem(k)); });
        body.appendChild(ul2);
      }
    }
    body.appendChild(el('h3', null, t('ui.checklist')));
    var ol = el('ol', 'checklist');
    C.CHECKLIST_KEYS.forEach(function (k) { ol.appendChild(el('li', null, t(k))); });
    body.appendChild(ol);
  }

  function run() {
    checked = true;
    render();
  }

  function init() {
    buildExamples();
    applyI18n();
    $('check').addEventListener('click', run);
    $('clear').addEventListener('click', function () {
      $('msg').value = '';
      checked = false;
      render();
      $('msg').focus();
    });
    var btns = document.querySelectorAll('[data-lang]');
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener('click', function (e) {
        lang = e.currentTarget.getAttribute('data-lang') === 'zh' ? 'zh' : 'en';
        applyI18n();
        render();
      });
    }
  }

  init();
})();
