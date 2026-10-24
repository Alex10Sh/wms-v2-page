// Собрано scripts/build-page.mjs из src/page/index.html — не править руками. Версия 81497ef.
// sha256 разрешённых адресов сервера: страница принимает ссылку #api= только с ними.
var WMS_API_SHA256 = ["b4b0e994e43162f24ab0c2b759ff6f55439f29861271d2db3ec79633c5f298c4"];
    // Перевод раскладки — первым, до любого скана (находка v1.2 #28). Тот же, что src/core/scan.js.
    var RU = 'йцукенгшщзхъфывапролджэячсмитьбюЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ';
    var EN = "qwertyuiop[]asdfghjkl;'zxcvbnm,.QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>";
    function toEn(s) {
      return String(s).split('').map(function (ch) { var i = RU.indexOf(ch); return i === -1 ? ch : EN.charAt(i); }).join('');
    }
  
    // Страница пишет данные только через textContent: имена, тексты «Контроля» и ответы сервера
    // не попадают в HTML (модель угроз 04, XSS).
    var $ = function (id) { return document.getElementById(id); };
    var KEY_SESSION = 'wms2.session';
    var KEY_QUEUE = 'wms2.queue';

    var mem = {};
    function load(k, dflt) {
      try { var v = window.localStorage.getItem(k); return v ? JSON.parse(v) : dflt; } catch (e) { return mem[k] || dflt; }
    }
    function save(k, v) {
      mem[k] = v;
      try { if (v === null) window.localStorage.removeItem(k); else window.localStorage.setItem(k, JSON.stringify(v)); } catch (e) { mem[k] = v; }
    }

    // Адрес сервера (веб-приложение Apps Script, …/exec) на своей странице — не в коде: в публичном
    // репозитории его нет (проверка 24.10). Владелец даёт ссылку …/#api=<адрес>, страница
    // запоминает адрес на этом телефоне и убирает его из адресной строки. Часть после # на
    // сервер GitHub не уходит. Принимается только адрес, чей sha256 зашит при сборке
    // (WMS_API_SHA256, src/page/api-sha256.txt): чужая ссылка не подменит сервер.
    var KEY_API = 'wms2.api';
    var API_RE = /^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]{20,120}\/exec$/;
    var IN_APPS_SCRIPT = !!(window.google && google.script && google.script.run);
    var apiRejected = false;
    window.WMS_EXEC = '';
    function sha256hex(text) {
      return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(function (buf) {
        return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
      });
    }
    function apiAllowed(url) {
      if (!url || !API_RE.test(url) || !(window.crypto && crypto.subtle)) return Promise.resolve(false);
      return sha256hex(url).then(function (h) { return (window.WMS_API_SHA256 || []).indexOf(h) !== -1; });
    }
    var apiReady = IN_APPS_SCRIPT ? Promise.resolve() : (function () {
      var m = /(?:^#|&)api=([^&]+)/.exec(location.hash || '');
      var fromLink = '';
      if (m) {
        try { fromLink = decodeURIComponent(m[1]); } catch (e) { fromLink = '-'; }
        if (window.history && history.replaceState) history.replaceState(null, '', location.pathname + location.search);
      }
      var stored = load(KEY_API, '');
      return apiAllowed(fromLink).then(function (ok) {
        if (ok) { save(KEY_API, fromLink); window.WMS_EXEC = fromLink; return; }
        apiRejected = !!fromLink;
        return apiAllowed(stored).then(function (okStored) {
          if (okStored) window.WMS_EXEC = stored;
          else if (stored) save(KEY_API, null);
        });
      });
    })();
    // Ссылку открыли во вкладке, где страница уже открыта, — перечитать её с новым адресом.
    window.addEventListener('hashchange', function () { if (/(?:^#|&)api=/.test(location.hash)) location.reload(); });

    var session = load(KEY_SESSION, null);
    var queue = load(KEY_QUEUE, []);
    var sending = false;
    var retryMs = 0;
    var retryTimer = null;

    function newKey() {
      if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
      return 'k-' + Date.now() + '-' + Math.random().toString(16).slice(2);
    }
    function device() {
      return (navigator.userAgent || '').slice(0, 200);
    }

    // Вызов функции сервера → Promise. Отказ — только сбой связи или сервера (ответы — объектом).
    // Внутри Apps Script — google.script.run. На своей странице (GitHub Pages, где работает
    // камера) — POST на адрес веб-приложения WMS_EXEC, его подставляет scripts/build-page.mjs.
    // Тело — текст: простой запрос, без предварительного запроса CORS.
    function call(fn) {
      var args = Array.prototype.slice.call(arguments, 1);
      if (IN_APPS_SCRIPT) {
        return new Promise(function (resolve, reject) {
          var runner = google.script.run.withSuccessHandler(resolve).withFailureHandler(reject);
          runner[fn].apply(runner, args);
        });
      }
      return fetch(window.WMS_EXEC, {
        method: 'POST', redirect: 'follow', credentials: 'omit', cache: 'no-store',
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        body: JSON.stringify({ fn: fn, args: args }),
      }).then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      });
    }

    function el(tag, text, cls) {
      var n = document.createElement(tag);
      if (text !== undefined) n.textContent = text;
      if (cls) n.className = cls;
      return n;
    }
    function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
    function note(text, cls) {
      var li = el('li', new Date().toLocaleTimeString('ru-RU') + ' · ' + text, cls);
      var list = $('results');
      list.insertBefore(li, list.firstChild);
      while (list.children.length > 10) list.removeChild(list.lastChild);
    }

    function show(name) {
      ['framed', 'noapi', 'login', 'pin', 'main'].forEach(function (s) { $('screen-' + s).hidden = s !== name; });
      if (name === 'login') $('login-name').focus();
      if (name === 'pin') {
        $('pin-hint').textContent = 'Первый вход: придумайте свой PIN, ' + ((session && session.pinMin) || 6) + '–8 цифр. Выданный PIN больше не подойдёт.';
        $('pin-new').focus();
      }
      if (name === 'main') $('scan').focus();
    }

    function needLogin(reason) {
      session = null;
      save(KEY_SESSION, null);
      $('login-msg').textContent = reason || '';
      show('login');
    }

    function renderQueue() {
      var mine = queue.filter(function (q) { return session && q.by === session.name; }).length;
      $('queue').textContent = 'Не отправлено: ' + mine;
      $('queue').className = mine ? 'warn' : 'good';
      var others = queue.length - mine;
      $('net').textContent = others ? 'Ещё ' + others + ' операций другого сотрудника — дошлются после его входа.' : '';
    }

    // Очередь: операции с ключом досылаются по порядку. Обрыв, «занято», сбой — повтор, а не
    // удаление. Отказ по делу и конфликт снимают операцию с причиной.
    function enqueue(type, data, label) {
      queue.push({ key: newKey(), type: type, data: data, by: session.name, deviceAt: new Date().toISOString(), device: device(), label: label });
      save(KEY_QUEUE, queue);
      renderQueue();
      pump();
    }

    function later(why) {
      retryMs = Math.min(retryMs ? retryMs * 2 : 2000, 30000);
      $('net').textContent = why + ' Повтор через ' + Math.round(retryMs / 1000) + ' с.';
      clearTimeout(retryTimer);
      retryTimer = setTimeout(pump, retryMs);
    }

    function pump() {
      if (sending || !session || session.mustChangePin) return;
      var item = queue.filter(function (q) { return q.by === session.name; })[0];
      if (!item) { renderQueue(); return; }
      sending = true;
      call('submit', session.token, { key: item.key, type: item.type, data: item.data, by: item.by, deviceAt: item.deviceAt, device: item.device })
        .then(function (r) {
          sending = false;
          if (r.status === 'busy') { retryMs = 0; later('Склад занят.'); return; }
          if (r.status === 'auth') { needLogin(r.reason); return; }
          if (r.status === 'error') { reportError(item.key, r.reason); later('Сервер не ответил.'); return; }
          retryMs = 0;
          queue = queue.filter(function (q) { return q.key !== item.key; });
          save(KEY_QUEUE, queue);
          renderQueue();
          if (r.status === 'ok') note((item.label || item.type) + ' — записано' + (r.replay ? ' (повтор)' : ''), 'good');
          else if (r.status === 'conflict') note((item.label || item.type) + ' — конфликт: ' + r.reason, 'warn');
          else note((item.label || item.type) + ' — не принято: ' + r.reason + '. Операция снята, проверьте и сделайте заново.', 'bad');
          if (item.after) item.after();
          if (item.type === 'контроль.решить') loadControl();
          pump();
        })
        .catch(function () {
          sending = false;
          later('Нет связи.');
        });
    }

    function reportError(opKey, text) {
      if (!session) return;
      call('reportError', session.token, { key: newKey(), opKey: opKey || '', error: String(text).slice(0, 500), device: device(), deviceAt: new Date().toISOString() })
        .catch(function () {});
    }
    window.addEventListener('error', function (e) { reportError('', (e.message || 'ошибка') + ' @' + (e.lineno || '')); });
    window.addEventListener('online', function () { retryMs = 0; pump(); });

    // Вход
    $('login-form').addEventListener('submit', function (e) {
      e.preventDefault();
      $('login-go').disabled = true;
      $('login-msg').textContent = '';
      call('login', $('login-name').value, $('login-pin').value).then(function (r) {
        $('login-go').disabled = false;
        $('login-pin').value = '';
        if (r.status !== 'ok') { $('login-msg').textContent = r.reason; return; }
        session = { token: r.token, name: r.name, role: r.role, exp: r.exp, mustChangePin: r.mustChangePin, pinMin: r.pinMin };
        save(KEY_SESSION, session);
        start();
      }).catch(function () {
        $('login-go').disabled = false;
        $('login-msg').textContent = 'Нет связи с сервером — повторить.';
      });
    });

    $('pin-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var a = $('pin-new').value;
      if (a !== $('pin-again').value) { $('pin-msg').textContent = 'PIN не совпали'; return; }
      $('pin-go').disabled = true;
      call('changePin', session.token, a).then(function (r) {
        $('pin-go').disabled = false;
        $('pin-new').value = '';
        $('pin-again').value = '';
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { $('pin-msg').textContent = r.reason; return; }
        session.mustChangePin = false;
        save(KEY_SESSION, session);
        start();
      }).catch(function () {
        $('pin-go').disabled = false;
        $('pin-msg').textContent = 'Нет связи с сервером — повторить.';
      });
    });

    $('logout').addEventListener('click', function () {
      camStop();
      var t = session && session.token;
      needLogin('');
      if (t) call('logout', t).catch(function () {});
    });

    // Скан: поле держит фокус, Enter — код. Перевод раскладки — до запроса к серверу.
    // Камера отдаёт код в тот же разбор.
    $('scan-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var raw = $('scan').value;
      $('scan').value = '';
      scanCode(raw);
    });
    function scanCode(raw) {
      if (!raw.trim()) return;
      var code = toEn(raw.trim());
      var li = el('li', code + (code !== raw.trim() ? ' (из русской раскладки: ' + raw.trim() + ')' : '') + ' — ищу…');
      var log = $('scan-log');
      log.insertBefore(li, log.firstChild);
      call('scanLookup', session.token, raw).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { li.textContent = code + ' — ' + r.reason; li.className = 'bad'; return; }
        var from = r.russianLayout ? ' (из русской раскладки: ' + raw.trim() + ')' : '';
        li.textContent = r.location
          ? r.code + from + ' — адрес ' + r.location.code + (r.location.zone ? ', зона ' + r.location.zone : '') + (r.location.blocked ? ', заблокирован' : '')
          : r.code + from + ' — такого адреса нет';
        li.className = r.location ? 'good' : 'warn';
      }).catch(function () { li.textContent = code + ' — нет связи, отсканировать ещё раз'; li.className = 'bad'; });
    }
    document.addEventListener('click', function (e) {
      if (!$('screen-main').hidden && !cam && e.target.tagName !== 'INPUT' && e.target.tagName !== 'SELECT' && e.target.tagName !== 'BUTTON') $('scan').focus();
    });

    // Камера телефона. Кадр раз в 150 мс — в распознаватель: BarcodeDetector браузера, если есть
    // (Chrome на Android); иначе библиотека ZXing (Safari на iPhone), её кладёт рядом
    // scripts/build-page.mjs. Видео ведёт страница сама, ZXing только читает кадр.
    // Внутри Apps Script камеру не пускает рамка Google (проба 02 п. 1) — кнопки там нет.
    // Один и тот же код подряд принимается раз в 2 с: камера видит его много кадров.
    var CAM_FORMATS = ['code_128', 'ean_13', 'ean_8', 'code_39', 'qr_code', 'data_matrix'];
    var cam = null;
    var camLast = { code: '', at: 0 };
    function camAvailable() {
      return !IN_APPS_SCRIPT && !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia) && !!(window.BarcodeDetector || window.ZXing);
    }
    function camFound(text) {
      var now = Date.now();
      if (text === camLast.code && now - camLast.at < 2000) return;
      camLast = { code: text, at: now };
      if (navigator.vibrate) navigator.vibrate(60);
      $('cam-msg').textContent = 'Считано: ' + text;
      scanCode(text);
    }
    function camStop() {
      if (!cam) return;
      if (cam.timer) clearInterval(cam.timer);
      if (cam.stream) cam.stream.getTracks().forEach(function (t) { t.stop(); });
      $('cam-video').srcObject = null;
      cam = null;
      $('cam-box').hidden = true;
      $('cam-open').hidden = !camAvailable();
    }
    function camFail(e) {
      camStop();
      var name = e && e.name ? e.name : String(e);
      $('cam-msg').textContent = name === 'NotAllowedError'
        ? 'Нет доступа к камере. Разрешите камеру для этой страницы в настройках браузера и нажмите ещё раз.'
        : 'Камера не включилась: ' + name;
      $('cam-msg').className = 'bad';
    }
    // Распознаватель кадра: Promise с текстом кода или ''.
    function camDetector() {
      if (window.BarcodeDetector) {
        var supported = BarcodeDetector.getSupportedFormats ? BarcodeDetector.getSupportedFormats() : Promise.resolve(CAM_FORMATS);
        return supported.then(function (list) {
          var detector = new BarcodeDetector({ formats: CAM_FORMATS.filter(function (f) { return list.indexOf(f) !== -1; }) });
          return function (video) {
            return detector.detect(video).then(function (codes) { return codes.length ? codes[0].rawValue : ''; });
          };
        });
      }
      var F = ZXing.BarcodeFormat;
      var hints = new Map();
      hints.set(ZXing.DecodeHintType.POSSIBLE_FORMATS, [F.CODE_128, F.EAN_13, F.EAN_8, F.CODE_39, F.QR_CODE, F.DATA_MATRIX]);
      hints.set(ZXing.DecodeHintType.TRY_HARDER, true);
      var reader = new ZXing.MultiFormatReader();
      reader.setHints(hints);
      var canvas = document.createElement('canvas');
      var ctx = canvas.getContext('2d', { willReadFrequently: true });
      return Promise.resolve(function (video) {
        var scale = Math.min(1, 960 / video.videoWidth);
        canvas.width = Math.round(video.videoWidth * scale);
        canvas.height = Math.round(video.videoHeight * scale);
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        try {
          var bitmap = new ZXing.BinaryBitmap(new ZXing.HybridBinarizer(new ZXing.HTMLCanvasElementLuminanceSource(canvas)));
          return Promise.resolve(reader.decodeWithState(bitmap).getText());
        } catch (e) {
          return Promise.resolve(''); // в кадре нет кода — следующий кадр
        }
      });
    }
    function camStart() {
      $('cam-msg').textContent = 'Включаю камеру…';
      $('cam-msg').className = 'muted';
      $('cam-open').hidden = true;
      $('cam-box').hidden = false;
      var video = $('cam-video');
      cam = {};
      var constraints = { video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false };
      navigator.mediaDevices.getUserMedia(constraints).then(function (stream) {
        if (!cam) { stream.getTracks().forEach(function (t) { t.stop(); }); return; }
        cam.stream = stream;
        video.srcObject = stream;
        return video.play().then(camDetector).then(function (detect) {
          if (!cam) return;
          $('cam-msg').textContent = 'Наведите рамку на штрихкод';
          var busy = false;
          cam.timer = setInterval(function () {
            if (busy || !cam || video.readyState < 2) return;
            busy = true;
            detect(video).then(function (text) {
              busy = false;
              if (text && cam) camFound(text);
            }, function () { busy = false; });
          }, 150);
        });
      }).catch(camFail);
    }
    $('cam-open').addEventListener('click', camStart);
    $('cam-close').addEventListener('click', function () { camStop(); $('cam-msg').textContent = ''; $('scan').focus(); });
    document.addEventListener('visibilitychange', function () { if (document.hidden) camStop(); });

    // «Контроль»
    function loadControl() {
      if (!session || (session.role !== 'старшая' && session.role !== 'владелец')) return;
      call('controlList', session.token).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        var list = $('control-list');
        clear(list);
        if (r.status !== 'ok') { list.appendChild(el('p', r.reason, 'bad')); return; }
        $('control-empty').hidden = r.groups.length > 0;
        r.groups.forEach(function (g) { list.appendChild(controlCard(g)); });
      }).catch(function () { $('control-list').textContent = 'Нет связи — нажмите «Обновить».'; });
    }

    function controlCard(g) {
      var card = el('div', undefined, 'card');
      card.appendChild(el('p', g.type + (g.client ? ' · ' + g.client : '') + (g.ids.length > 1 ? ' · записей: ' + g.ids.length : '')));
      card.appendChild(el('p', g.text));
      g.details.forEach(function (d) { card.appendChild(el('p', d, 'muted')); });
      if (!g.canDecide) { card.appendChild(el('p', 'Решает владелец', 'muted')); return card; }
      var sel = el('select');
      g.decisions.forEach(function (d) { sel.appendChild(el('option', d)); });
      var reason = el('input');
      reason.placeholder = 'Причина решения';
      reason.maxLength = 500;
      var btn = el('button', 'Решить');
      btn.type = 'button';
      btn.addEventListener('click', function () {
        if (!reason.value.trim()) { reason.focus(); return; }
        btn.disabled = true;
        enqueue('контроль.решить', { ids: g.ids, decision: sel.value, reason: reason.value }, 'Контроль: ' + sel.value);
      });
      card.appendChild(sel);
      card.appendChild(reason);
      var p = el('p');
      p.appendChild(btn);
      card.appendChild(p);
      return card;
    }
    $('control-refresh').addEventListener('click', loadControl);

    // Сотрудники — только владелец
    function loadWorkers() {
      if (!session || session.role !== 'владелец') return;
      call('workersList', session.token).then(function (r) {
        var list = $('workers-list');
        clear(list);
        if (r.status !== 'ok') { list.appendChild(el('p', r.reason, 'bad')); return; }
        r.workers.forEach(function (w) {
          var card = el('div', undefined, 'card');
          card.appendChild(el('p', w.name + ' · ' + w.role + (w.active ? '' : ' · отключён') + (w.mustChangePin ? ' · ждёт смены PIN' : '')));
          var row = el('div', undefined, 'row');
          if (w.blocked) {
            card.appendChild(el('p', 'Вход ' + w.blocked + ': много неверных PIN', 'warn'));
            var unblock = el('button', 'Снять блок', 'secondary');
            unblock.type = 'button';
            unblock.addEventListener('click', function () { workerCall('workerUnblock', [w.name]); });
            row.appendChild(unblock);
          }
          if (w.name !== session.name) {
            var access = el('button', w.active ? 'Отключить' : 'Включить', 'secondary');
            access.type = 'button';
            access.addEventListener('click', function () { workerCall('workerAccess', [w.name, !w.active]); });
            row.appendChild(access);
          }
          var pin = el('input');
          pin.type = 'password';
          pin.inputMode = 'numeric';
          pin.maxLength = 8;
          pin.placeholder = 'Новый временный PIN';
          var give = el('button', 'Выдать PIN', 'secondary');
          give.type = 'button';
          give.addEventListener('click', function () { if (pin.value) workerCall('workerTempPin', [w.name, pin.value]); });
          row.appendChild(pin);
          row.appendChild(give);
          card.appendChild(row);
          list.appendChild(card);
        });
      });
    }
    function workerCall(fn, args) {
      $('worker-msg').textContent = '';
      call.apply(null, [fn, session.token].concat(args)).then(function (r) {
        $('worker-msg').textContent = r.status === 'ok' ? 'Готово' : r.reason;
        $('worker-msg').className = r.status === 'ok' ? 'good' : 'bad';
        if (r.status === 'auth') { needLogin(r.reason); return; }
        loadWorkers();
      }).catch(function () { $('worker-msg').textContent = 'Нет связи — повторить'; $('worker-msg').className = 'bad'; });
    }
    $('worker-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var pin = $('worker-pin').value;
      $('worker-pin').value = '';
      workerCall('workerAdd', [$('worker-name').value, $('worker-role').value, pin]);
      $('worker-name').value = '';
    });

    $('share-copy').addEventListener('click', function () {
      var input = $('share-link');
      input.select();
      var done = function () { $('share-copy').textContent = 'Скопировано'; };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(input.value).then(done, function () {});
      else if (document.execCommand && document.execCommand('copy')) done();
    });

    // Клиенты, кабинеты, токены WB, каталог (05): старшая обновляет каталог, владелец — всё.
    function dateRu(iso) {
      return iso ? iso.slice(8, 10) + '.' + iso.slice(5, 7) + '.' + iso.slice(0, 4) : '';
    }
    function settingsMsg(text, cls) {
      $('settings-msg').textContent = text || '';
      $('settings-msg').className = cls || '';
    }
    function settingsAnswer(r, okText) {
      if (r.status === 'auth') { needLogin(r.reason); return false; }
      if (r.status === 'ok') { settingsMsg(okText || 'Готово', 'good'); return true; }
      settingsMsg(r.reason || 'Не получилось', 'bad');
      return false;
    }
    function loadSettings() {
      if (!session || (session.role !== 'старшая' && session.role !== 'владелец')) return;
      var owner = session.role === 'владелец';
      $('client-form').hidden = !owner;
      $('cabinet-form').hidden = !owner;
      call('settingsList', session.token).then(function (r) {
        var list = $('cabinets-list');
        clear(list);
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { list.appendChild(el('p', r.reason, 'bad')); return; }
        var sel = $('cabinet-client');
        clear(sel);
        r.clients.forEach(function (c) { sel.appendChild(el('option', c.name)); });
        if (!r.clients.length) list.appendChild(el('p', 'Клиентов пока нет.', 'muted'));
        r.clients.forEach(function (c) {
          if (!r.cabinets.some(function (k) { return k.client === c.name; })) {
            list.appendChild(el('p', c.name + ' · тарифы: ' + c.tariffRow + ' · кабинетов нет', 'muted'));
          }
        });
        r.cabinets.forEach(function (k) { list.appendChild(cabinetCard(k, owner)); });
      }).catch(function () { $('cabinets-list').textContent = 'Нет связи — обновите страницу.'; });
    }
    function cabinetCard(k, owner) {
      var card = el('div', undefined, 'card');
      card.appendChild(el('p', k.name + ' (' + k.code + ') · клиент ' + k.client));
      card.appendChild(el('p', 'Товаров в каталоге: ' + k.items + ' · поставки WB через v2: ' + (k.ownSupplies ? 'да' : 'нет'), 'muted'));
      k.tokens.forEach(function (t) {
        var left = t.until ? (Date.parse(t.until) - Date.now()) / 86400000 : -1;
        var text = 'Токен «' + t.title + '»: ' + (!t.has ? 'нет' : t.until ? 'до ' + dateRu(t.until) : 'срок неизвестен');
        card.appendChild(el('p', text, !t.has || left < 0 ? 'bad' : left <= 14 ? 'warn' : ''));
      });
      var res = el('p', '', 'muted');
      var refresh = el('button', 'Обновить каталог', 'secondary');
      refresh.type = 'button';
      refresh.addEventListener('click', function () {
        refresh.disabled = true;
        res.textContent = 'Читаю карточки WB…';
        call('catalogRefresh', session.token, k.code).then(function (r) {
          refresh.disabled = false;
          if (r.status === 'auth') { needLogin(r.reason); return; }
          if (r.status !== 'ok') { res.textContent = r.reason; res.className = 'bad'; return; }
          var x = r.result;
          res.className = 'good';
          res.textContent = 'Размеров ' + x.sizes + ', баркодов ' + x.barcodes + ': новых ' + x.added + ', изменено ' + x.changed +
            ', без изменений ' + x.same + (x.markRequired ? ', нужен код ЧЗ — ' + x.markRequired : '') +
            (x.missing ? ', нет в WB — ' + x.missing : '') + (x.duplicates ? ', один баркод у двух размеров — ' + x.duplicates + ' (в «Контроле»)' : '');
        }).catch(function () { refresh.disabled = false; res.textContent = 'Нет связи — повторить'; res.className = 'bad'; });
      });
      card.appendChild(el('p')).appendChild(refresh);
      card.appendChild(res);
      if (owner) {
        var kind = el('select');
        k.tokens.forEach(function (t) { var o = el('option', t.title); o.value = t.kind; kind.appendChild(o); });
        var value = el('input');
        value.type = 'password';
        value.autocomplete = 'off';
        value.spellcheck = false;
        value.placeholder = 'Вставить токен из кабинета WB';
        var save = el('button', 'Сохранить токен', 'secondary');
        save.type = 'button';
        save.addEventListener('click', function () {
          var v = value.value;
          value.value = '';
          if (!v) return;
          settingsMsg('Проверяю токен в WB…');
          call('tokenSave', session.token, k.code, kind.value, v).then(function (r) {
            if (settingsAnswer(r, 'Токен сохранён, действует до ' + dateRu(r.until))) loadSettings();
          }).catch(function () { settingsMsg('Нет связи — повторить', 'bad'); });
        });
        var row = el('div', undefined, 'row');
        row.appendChild(kind);
        row.appendChild(value);
        row.appendChild(save);
        card.appendChild(row);
      }
      return card;
    }
    $('client-form').addEventListener('submit', function (e) {
      e.preventDefault();
      call('clientAdd', session.token, { name: $('client-name').value, tariffRow: $('client-tariff').value }).then(function (r) {
        if (settingsAnswer(r, 'Клиент заведён')) { $('client-name').value = ''; $('client-tariff').value = ''; loadSettings(); }
      }).catch(function () { settingsMsg('Нет связи — повторить', 'bad'); });
    });
    $('cabinet-form').addEventListener('submit', function (e) {
      e.preventDefault();
      call('cabinetAdd', session.token, {
        client: $('cabinet-client').value, code: $('cabinet-code').value.trim(), name: $('cabinet-name').value,
        ownSupplies: $('cabinet-supplies').value === 'да',
      }).then(function (r) {
        if (settingsAnswer(r, 'Кабинет заведён — теперь вставьте его токены')) { $('cabinet-code').value = ''; $('cabinet-name').value = ''; loadSettings(); }
      }).catch(function () { settingsMsg('Нет связи — повторить', 'bad'); });
    });

    function start() {
      // Во фрейме чужой страницы не работать: кнопки можно подсунуть под чужой текст.
      // Внутри Apps Script страница всегда во фрейме Google — там проверки нет.
      if (!IN_APPS_SCRIPT && window.top !== window.self) { show('framed'); return; }
      if (!IN_APPS_SCRIPT && !window.WMS_EXEC) { $('noapi-bad').hidden = !apiRejected; show('noapi'); return; }
      if (!session) { show('login'); return; }
      if (Date.parse(session.exp) <= Date.now()) { needLogin('Вход истёк — войти заново'); return; }
      if (session.mustChangePin) { show('pin'); return; }
      $('who').textContent = session.name + ' · ' + session.role;
      $('control-box').hidden = !(session.role === 'старшая' || session.role === 'владелец');
      $('workers-box').hidden = session.role !== 'владелец';
      $('settings-box').hidden = !(session.role === 'старшая' || session.role === 'владелец');
      $('share-box').hidden = IN_APPS_SCRIPT || session.role !== 'владелец';
      $('share-link').value = IN_APPS_SCRIPT ? '' : location.origin + location.pathname + '#api=' + encodeURIComponent(window.WMS_EXEC);
      show('main');
      $('cam-open').hidden = !camAvailable() || !!cam;
      renderQueue();
      loadControl();
      loadWorkers();
      loadSettings();
      pump();
    }
    apiReady.then(start, start);
  