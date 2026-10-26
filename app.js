// Собрано scripts/build-page.mjs из src/page/index.html — не править руками. Версия 0e5adf1.
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
    // Место упаковки — случайный номер этого компьютера, живёт в браузере: недоделанный заказ
    // продолжает тот же компьютер, второй компьютер с тем же входом берёт следующий заказ.
    var KEY_STATION = 'wms2.station';
    function station() {
      var s = load(KEY_STATION, '');
      if (!s) { s = newKey(); save(KEY_STATION, s); }
      return String(s).slice(0, 64);
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

    // Переполнение после «принять факт»: решение по нескольким записям приходит списком.
    function overfullOf(result) {
      var a = result && result.applied;
      if (!a) return '';
      return [].concat(a).filter(function (x) { return x && x.overfull; }).map(function (x) { return x.overfull; }).join('; ');
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
          if (r.status === 'ok' && item.type.indexOf('приёмка.') === 0) receiptAnswer(item, r);
          else if (r.status === 'ok' && item.type === 'размещение') {
            note('Размещено ' + r.result.qty + ' шт на ' + r.result.location + (r.result.left ? ', осталось разместить ' + r.result.left : ''), 'good');
          } else if (r.status === 'ok' && item.type === 'перемещение') {
            note('Перемещено ' + r.result.qty + ' шт: ' + r.result.from + ' → ' + r.result.to, 'good');
          } else if (r.status === 'ok' && item.type === 'адрес.пересчёт') {
            if (r.result.match) note('Пересчёт ' + r.result.location + ' совпал с учётом', 'good');
            else note('Пересчёт ' + r.result.location + ': расхождений ' + r.result.diffs.length + ' — запись в «Контроль», остаток прежний до решения', 'warn');
          } else if (r.status === 'ok' && item.type === 'корректировка') {
            note('Корректировка ' + r.result.location + ': ' + (r.result.qty > 0 ? '+' : '') + r.result.qty + ' шт (' + r.result.reason + '), на адресе ' + r.result.left, 'good');
          } else if (r.status === 'ok' && item.type === 'отмена.вернуть') {
            note('Заказ ' + r.result.wbId + ': товар возвращён на ' + r.result.location + ', там ' + r.result.onLocation + ' шт', 'good');
          } else if (r.status === 'ok' && item.type === 'упаковка.освободить') {
            note('Заказ ' + r.result.wbId + ' освобождён: следующий скан этого товара его доупакует', 'good');
          } else if (r.status === 'ok' && item.type === 'поставка.отгрузить') {
            var held = r.result.held || [];
            note('Поставка ' + r.result.supply + ' отгружена: заказов ' + r.result.shipped +
              (r.result.cancelled.length ? '; отменены, не отгружать: ' + r.result.cancelled.join(', ') : '') +
              (held.length ? '; не отгружены до сверки состава в ЛК WB: ' + held.join(', ') + ' — решение в «Контроле»' : ''),
              r.result.cancelled.length || held.length ? 'warn' : 'good');
          } else if (r.status === 'ok' && item.type === 'адрес.паллеты') {
            note('Паллет ' + r.result.client + ' на ' + r.result.location + ': ' + r.result.pallets + ' · занято ' + r.result.used + ' из ' + r.result.capacity, 'good');
          } else if (r.status === 'ok' && overfullOf(r.result)) {
            note((item.label || item.type) + ' — записано. ' + overfullOf(r.result), 'warn');
          } else if (r.status === 'ok' && item.type === 'отбор.лист') {
            note('Лист отбора ' + r.result.list + ': заказов ' + r.result.orders + ', адресов ' + r.result.addresses, 'good');
          } else if (r.status === 'ok' && item.type === 'отбор.взять') {
            var x = r.result;
            if (!x.shortage) note('Отбор ' + x.location + ': взято ' + x.taken + ' шт' + (r.replay ? ' (повтор)' : ''), 'good');
            else {
              note('Отбор ' + x.location + ': взято ' + x.taken + ', не хватило ' + x.shortage + ' — запись в «Контроль», остаток адреса заморожен' +
                (x.offered.length ? '; добрать: ' + x.offered.map(function (o) { return o.code + ' — ' + o.qty + ' шт'; }).join(', ') : '') +
                (x.noStock ? '; без товара заказов: ' + x.noStock : ''), 'warn');
            }
          } else if (r.status === 'ok') note((item.label || item.type) + ' — записано' + (r.replay ? ' (повтор)' : ''), 'good');
          else if (r.status === 'conflict') note((item.label || item.type) + ' — конфликт: ' + r.reason, 'warn');
          else note((item.label || item.type) + ' — не принято: ' + r.reason + '. Операция снята, проверьте и сделайте заново.', 'bad');
          if (item.after) item.after();
          if (item.type === 'контроль.решить') loadControl();
          if (item.type.indexOf('адрес.') === 0) loadLocations();
          if (item.type.indexOf('приёмка.') === 0) { loadReceipts(); if (item.type === 'приёмка.закрыть') loadPlacement(); }
          if (item.type === 'размещение' || item.type === 'перемещение' || item.type === 'корректировка') { loadPlacement(); loadStock(); }
          if (item.type === 'адрес.пересчёт') loadControl();
          if (item.type === 'контроль.решить') { loadStock(); loadOrders(); }
          if (item.type === 'размещение' || item.type === 'корректировка') loadOrders();
          if (item.type === 'отмена.вернуть') { loadPacks(); loadStock(); loadControl(); }
          if (item.type === 'упаковка.освободить') loadPacks();
          if (item.type === 'поставка.отгрузить') { loadPacks(); loadStock(); loadOrders(); }
          if (item.type.indexOf('отбор.') === 0) { loadPicks(); loadOrders(); if (item.type === 'отбор.взять') { loadStock(); loadControl(); } }
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
      if (pickStep) { pickScan(raw); return; }
      if (placeTask) { placeScan(raw); return; }
      if (recountTask) { recountScan(raw); return; }
      if (activeReceipt) { receiptScan(raw); return; }
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
        if (r.contents) showContents(li, r.contents);
        else if (r.items && r.items.length) {
          li.textContent = r.code + from + ' — товар: ' + r.items.map(function (x) { return x.title + ' (' + x.client + ')'; }).join('; ');
          li.className = 'good';
        }
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
    var camLast = { code: '', gone: true, missFrom: 0 };
    function camAvailable() {
      return !IN_APPS_SCRIPT && !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia) && !!(window.BarcodeDetector || window.ZXing);
    }
    // Тот же код считывается снова, только когда кадры без него шли хотя бы 0,5 с: камера видит его
    // много кадров подряд, а держать телефон над товаром — не второй скан. Не от таймера: медленное
    // распознавание не даёт повтора (Р3-4 п. 5 вехи Г). text пустой — в кадре кода нет.
    function camFound(text) {
      var now = Date.now();
      if (!text) {
        if (!camLast.missFrom) camLast.missFrom = now;
        if (now - camLast.missFrom >= 500) camLast.gone = true;
        return;
      }
      var same = text === camLast.code && !camLast.gone;
      camLast = { code: text, gone: false, missFrom: 0 };
      if (same) return;
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
      camLast = { code: '', gone: true, missFrom: 0 };
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
              if (cam) camFound(text || '');
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
        clear($('control-poll'));
        if (r.poll) $('control-poll').appendChild(pollLine(r.poll));
        $('control-empty').hidden = r.groups.length > 0;
        r.groups.forEach(function (g) { list.appendChild(controlCard(g)); });
      }).catch(function () { $('control-list').textContent = 'Нет связи — нажмите «Обновить».'; });
    }

    // Опрос заказов WB: сигнал без триггеров — при кончившейся квоте Google заказы перестают приходить молча.
    function pollLine(p) {
      if (p.paused) return el('p', 'Опрос заказов WB на паузе (тестовый проект).', 'muted');
      var when = p.ageMin === null ? 'ещё не проходил' : 'был ' + p.ageMin + ' мин назад';
      if (!p.late) return el('p', 'Опрос заказов WB ' + when + '.', 'muted');
      var box = el('div');
      box.appendChild(el('p', 'Опрос заказов WB ' + when + ': новые заказы не приходят.', 'bad'));
      box.appendChild(el('p', 'Сообщите владельцу: возможно, кончилась суточная квота автозапусков Google.'));
      return box;
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

    // Итог дня (16): старшая переносит A–E в «Производство» руками; нет тарифа — сумма неполная.
    function mskToday() {
      return new Date(Date.now() + 3 * 3600 * 1000).toISOString().slice(0, 10);
    }
    function loadDay() {
      if (!session || (session.role !== 'старшая' && session.role !== 'владелец')) return;
      var day = $('day-date').value || mskToday();
      $('day-date').value = day;
      var msg = $('day-msg');
      var box = $('day-table');
      // Прежний итог убрать сразу: пока идёт ответ, на экране не должно быть старых чисел.
      clear(box);
      $('day-copy-box').hidden = true;
      msg.textContent = 'Загружаю…';
      msg.className = 'muted';
      call('daySummary', session.token, day).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        clear(box);
        $('day-copy-box').hidden = true;
        if (r.status !== 'ok') { msg.textContent = r.reason; msg.className = 'bad'; return; }
        msg.className = 'muted';
        msg.textContent = r.rows.length ? '' : 'За этот день упаковок, приёмок и начислений нет.';
        var short = {};
        r.noTariff.forEach(function (n) { short[n.client] = true; });
        Object.keys(short).forEach(function (c) { box.appendChild(el('p', 'Сумма неполная: ' + c + ' — нет тарифа, запись в «Контроле»', 'warn')); });
        (r.waitingShip || []).forEach(function (w) { box.appendChild(el('p', w.client + ': ждут отгрузки ' + w.count + ' — их ФБС начислит «Отгружено», «ФБС ₽» пока меньше', 'warn')); });
        if (!r.rows.length) return;
        var table = el('table', undefined, 'day-table');
        var head = el('tr');
        r.headers.forEach(function (h) { head.appendChild(el('th', h)); });
        table.appendChild(head);
        r.rows.forEach(function (row) {
          var tr = el('tr');
          row.forEach(function (v) { tr.appendChild(el('td', String(v))); });
          table.appendChild(tr);
        });
        box.appendChild(table);
        r.tariffs.forEach(function (x) {
          box.appendChild(el('p', x.client + ' · ' + x.service + ' → «' + x.column + '» · ' + x.price + ' ₽' + (x.priceFrom ? ' с ' + x.priceFrom : ' по «Справочникам»'), 'muted'));
        });
        $('day-tsv').value = r.rows.map(function (row) { return row.slice(0, 5).join('\t'); }).join('\n');
        $('day-copy').textContent = 'Скопировать A–E';
        $('day-copy-box').hidden = false;
      }).catch(function () { msg.textContent = 'Нет связи — нажмите «Показать».'; msg.className = 'bad'; });
    }
    $('day-show').addEventListener('click', loadDay);
    $('day-copy').addEventListener('click', function () {
      var input = $('day-tsv');
      input.select();
      var done = function () { $('day-copy').textContent = 'Скопировано'; };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(input.value).then(done, function () {});
      else if (document.execCommand && document.execCommand('copy')) done();
    });

    // Заказы ФБС (11): сводка по клиентам и ждущие товара — по сроку.
    function loadOrders() {
      if (!session || (session.role !== 'старшая' && session.role !== 'владелец')) return;
      call('ordersList', session.token).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        var sum = $('orders-summary');
        var wait = $('orders-waiting');
        clear(sum);
        clear(wait);
        if (r.status !== 'ok') { $('orders-msg').textContent = r.reason; $('orders-msg').className = 'bad'; return; }
        $('orders-msg').textContent = r.clients.length ? '' : 'Заказов в работе нет.';
        $('orders-msg').className = 'muted';
        r.clients.forEach(function (c) {
          var card = el('div', undefined, 'card');
          card.appendChild(el('p', c.client + ' · в работе: ' + c.total));
          card.appendChild(el('p', r.statuses.filter(function (st) { return c.counts[st]; })
            .map(function (st) { return st + ' ' + c.counts[st]; }).join(' · '), 'muted'));
          sum.appendChild(card);
        });
        if (r.waiting.length) {
          wait.appendChild(el('p', 'Ждут товара или каталога, по сроку:'));
          var ul = el('ul', undefined, 'log');
          r.waiting.forEach(function (o) {
            ul.appendChild(el('li', o.wbId + ' · ' + o.status + ' · ' + o.title + ' · ' + o.client + ' · ' + shortTime(o.deadline), o.status === 'новый' ? 'warn' : ''));
          });
          wait.appendChild(ul);
        }
        var sel = $('orders-xlsx-cabinet');
        var was = sel.value;
        clear(sel);
        r.cabinets.forEach(function (c) { var o = el('option', c.name + ' (' + c.client + ')'); o.value = c.code; sel.appendChild(o); });
        if (was) sel.value = was;
      }).catch(function () { $('orders-msg').textContent = 'Нет связи — нажмите «Обновить».'; $('orders-msg').className = 'bad'; });
    }
    function shortTime(iso) {
      var d = new Date(iso);
      return isNaN(d) ? String(iso) : d.toLocaleString('ru-RU', { timeZone: 'Europe/Moscow', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    }
    $('orders-refresh').addEventListener('click', loadOrders);

    // xlsx в браузере: zip (DecompressionStream) → XML листа; из ячеек берутся только колонки
    // XLSX_COLUMNS (как COLUMNS в src/core/orders-xlsx.js), остальные — ФИО, телефон, адрес — не читаются.
    var XLSX_COLUMNS = ['№ задания', 'Дата создания', 'Наименование', 'Размер', 'Баркод', 'Артикул Wildberries', 'Артикул продавца', 'Склад продавца', 'Статус задания'];
    var xlsxTable = null;
    function zipEntries(buf) {
      var v = new DataView(buf);
      var end = -1;
      for (var i = buf.byteLength - 22; i >= Math.max(0, buf.byteLength - 65557); i--) { if (v.getUint32(i, true) === 0x06054b50) { end = i; break; } }
      if (end < 0) throw new Error('это не xlsx');
      var count = v.getUint16(end + 10, true);
      var p = v.getUint32(end + 16, true);
      var out = {};
      for (var k = 0; k < count; k++) {
        if (v.getUint32(p, true) !== 0x02014b50) throw new Error('файл повреждён');
        var method = v.getUint16(p + 10, true);
        var size = v.getUint32(p + 20, true);
        var nameLen = v.getUint16(p + 28, true);
        var extra = v.getUint16(p + 30, true);
        var comment = v.getUint16(p + 32, true);
        var local = v.getUint32(p + 42, true);
        var name = new TextDecoder().decode(new Uint8Array(buf, p + 46, nameLen));
        var start = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true);
        out[name] = { method: method, data: new Uint8Array(buf, start, size) };
        p += 46 + nameLen + extra + comment;
      }
      return out;
    }
    function zipText(entry) {
      if (!entry) return Promise.resolve('');
      if (entry.method === 0) return Promise.resolve(new TextDecoder().decode(entry.data));
      if (entry.method !== 8 || !window.DecompressionStream) return Promise.reject(new Error('браузер не умеет распаковать xlsx'));
      return new Response(new Blob([entry.data]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).text();
    }
    function colIndex(ref) {
      var m = /^([A-Z]+)/.exec(ref || '');
      if (!m) return -1;
      return m[1].split('').reduce(function (n, ch) { return n * 26 + ch.charCodeAt(0) - 64; }, 0) - 1;
    }
    function readXlsx(file) {
      return file.arrayBuffer().then(function (buf) {
        var z = zipEntries(buf);
        var sheetName = z['xl/worksheets/sheet1.xml'] ? 'xl/worksheets/sheet1.xml'
          : Object.keys(z).filter(function (n) { return /^xl\/worksheets\/sheet\d+\.xml$/.test(n); }).sort()[0];
        if (!sheetName) throw new Error('в файле нет листа');
        return Promise.all([zipText(z['xl/sharedStrings.xml']), zipText(z[sheetName])]);
      }).then(function (xml) {
        var parser = new DOMParser();
        var shared = [];
        if (xml[0]) {
          var si = parser.parseFromString(xml[0], 'application/xml').getElementsByTagNameNS('*', 'si');
          for (var i = 0; i < si.length; i++) {
            var ts = si[i].getElementsByTagNameNS('*', 't');
            var t = '';
            for (var j = 0; j < ts.length; j++) t += ts[j].textContent;
            shared.push(t);
          }
        }
        var rows = parser.parseFromString(xml[1], 'application/xml').getElementsByTagNameNS('*', 'row');
        var want = null;
        var headers = [];
        var out = [];
        for (var r = 0; r < rows.length; r++) {
          var cells = rows[r].getElementsByTagNameNS('*', 'c');
          var line = {};
          for (var c = 0; c < cells.length; c++) {
            var idx = colIndex(cells[c].getAttribute('r'));
            if (want && want.indexOf(idx) === -1) continue; // колонка не из списка — не читается
            var type = cells[c].getAttribute('t');
            var vEl = cells[c].getElementsByTagNameNS('*', 'v')[0];
            var value = type === 'inlineStr' ? (cells[c].getElementsByTagNameNS('*', 't')[0] || { textContent: '' }).textContent
              : type === 's' ? shared[Number(vEl ? vEl.textContent : -1)] || '' : vEl ? vEl.textContent : '';
            line[idx] = value;
          }
          if (!want) {
            want = [];
            Object.keys(line).forEach(function (k) {
              if (XLSX_COLUMNS.indexOf(String(line[k]).trim()) !== -1) { want.push(Number(k)); headers.push(String(line[k]).trim()); }
            });
            continue;
          }
          out.push(want.map(function (k) { return line[k] === undefined ? '' : line[k]; }));
        }
        return { headers: headers, rows: out };
      });
    }
    $('orders-xlsx-file').addEventListener('change', function () {
      var f = $('orders-xlsx-file').files[0];
      xlsxTable = null;
      $('orders-xlsx-load').disabled = true;
      clear($('orders-xlsx-wh'));
      $('orders-xlsx-msg').textContent = '';
      if (!f) return;
      readXlsx(f).then(function (t) {
        var wi = t.headers.indexOf('Склад продавца');
        if (wi === -1) { $('orders-xlsx-msg').textContent = 'В файле нет колонки «Склад продавца» — нужна выгрузка вкладки «Новые»'; $('orders-xlsx-msg').className = 'bad'; return; }
        var whs = [];
        t.rows.forEach(function (row) { if (row[wi] && whs.indexOf(row[wi]) === -1) whs.push(row[wi]); });
        whs.forEach(function (w) { $('orders-xlsx-wh').appendChild(el('option', w)); });
        xlsxTable = t;
        $('orders-xlsx-load').disabled = !whs.length;
        $('orders-xlsx-msg').textContent = 'В файле заданий: ' + t.rows.length + '. Выберите склад продавца и нажмите «Загрузить заказы».';
        $('orders-xlsx-msg').className = 'muted';
      }).catch(function (e) { $('orders-xlsx-msg').textContent = 'Файл не прочитан: ' + (e && e.message ? e.message : e); $('orders-xlsx-msg').className = 'bad'; });
    });
    var XLSX_PART = 150;
    $('orders-xlsx-load').addEventListener('click', function () {
      if (!xlsxTable) return;
      var btn = $('orders-xlsx-load');
      btn.disabled = true;
      var total = { added: 0, already: 0, otherWarehouse: 0, notInCatalog: 0 };
      var replays = 0;
      var parts = [];
      for (var i = 0; i < xlsxTable.rows.length; i += XLSX_PART) parts.push(xlsxTable.rows.slice(i, i + XLSX_PART));
      var cab = $('orders-xlsx-cabinet').value;
      var wh = $('orders-xlsx-wh').value;
      var next = function (k) {
        if (k >= parts.length) {
          btn.disabled = false;
          $('orders-xlsx-msg').textContent = replays === parts.length ? 'Этот файл уже загружен — повтор, заказы не задвоены.'
            : 'Загружено. Новых заказов: ' + total.added + ', уже были: ' + total.already +
            ', другой склад: ' + total.otherWarehouse + ', нет в каталоге: ' + total.notInCatalog + '.';
          $('orders-xlsx-msg').className = total.notInCatalog ? 'warn' : 'good';
          loadOrders();
          loadControl();
          return;
        }
        call('ordersXlsxLoad', session.token, cab, wh, { headers: xlsxTable.headers, rows: parts[k] }).then(function (r) {
          if (r.status === 'auth') { needLogin(r.reason); return; }
          if (r.status !== 'ok') {
            btn.disabled = false;
            $('orders-xlsx-msg').textContent = (k ? 'Часть ' + (k + 1) + ' из ' + parts.length + ' не загружена: ' : '') + r.reason;
            $('orders-xlsx-msg').className = 'bad';
            return;
          }
          if (r.replay) replays += 1;
          else ['added', 'already', 'otherWarehouse', 'notInCatalog'].forEach(function (x) { total[x] += r.result[x] || 0; });
          next(k + 1);
        }).catch(function () { btn.disabled = false; $('orders-xlsx-msg').textContent = 'Нет связи — нажмите ещё раз: загруженное не задвоится.'; $('orders-xlsx-msg').className = 'bad'; });
      };
      next(0);
    });

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
      if (owner) card.appendChild(el('p', k.seller ? 'ID продавца ' + k.seller + ' — сверьте с кабинетом WB клиента' : 'ID продавца — с первого токена', 'muted'));
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
            if (settingsAnswer(r, 'Токен сохранён, действует до ' + dateRu(r.until) + ' · ID продавца ' + r.seller + ' — сверьте с кабинетом WB')) loadSettings();
          }).catch(function () { settingsMsg('Нет связи — повторить', 'bad'); });
        });
        var row = el('div', undefined, 'row');
        row.appendChild(kind);
        row.appendChild(value);
        row.appendChild(save);
        card.appendChild(row);
        // Первым сохранили токен не того кабинета — ID продавца сбросить, следующий токен задаст новый.
        if (k.seller) {
          var why = el('input');
          why.placeholder = 'Причина сброса ID продавца';
          why.maxLength = 300;
          var reset = el('button', 'Сбросить ID продавца', 'secondary');
          reset.type = 'button';
          reset.addEventListener('click', function () {
            if (!why.value.trim()) { why.focus(); return; }
            call('cabinetSeller', session.token, k.code, '', why.value).then(function (r) {
              if (settingsAnswer(r, 'ID продавца сброшен — сохраните токен из кабинета WB клиента, ID возьмётся из него')) loadSettings();
            }).catch(function () { settingsMsg('Нет связи — повторить', 'bad'); });
          });
          var row2 = el('div', undefined, 'row');
          row2.appendChild(why);
          row2.appendChild(reset);
          card.appendChild(row2);
        }
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

    // Упаковка (14). Упаковщик за компьютером сканирует отобранный товар: сервер берёт заказ с
    // самым ранним сроком, кладёт в открытую поставку WB и отдаёт стикер 58×40 — он сразу уходит на
    // печать. Ответа нет — «Повторить» шлёт тот же ключ: заказ не задвоится. Отменённый после отбора
    // товар возвращается на адрес сканом этикетки.
    var packPending = null;
    var packReturn = null;
    function packMsg(text, cls) {
      $('pack-msg').textContent = text || '';
      $('pack-msg').className = cls || '';
    }
    function printSticker(s) {
      return s ? printPng(s.file, 'Стикер ' + (s.partA || '') + ' ' + (s.partB || '')) : false;
    }
    // PNG 58×40 из WB (стикер заказа, QR поставки) — на принтер этикеток.
    function printPng(file, alt) {
      if (!/^[A-Za-z0-9+\/=]+$/.test(file || '')) return false;
      var area = $('print-area');
      clear(area);
      var label = el('div', undefined, 'label sticker');
      var img = document.createElement('img');
      img.alt = alt;
      img.src = 'data:image/png;base64,' + file;
      label.appendChild(img);
      area.appendChild(label);
      if (img.complete) window.print();
      else { img.onload = function () { window.print(); }; img.onerror = function () { window.print(); }; }
      return true;
    }
    function sendPack() {
      var p = packPending;
      if (!p) return;
      $('pack-retry').hidden = true;
      $('pack-go').disabled = true;
      packMsg('Упаковываю…');
      call('pack', session.token, { key: p.key, barcode: p.barcode, station: station() }).then(function (r) {
        $('pack-go').disabled = false;
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status === 'busy' || r.status === 'error' || r.status === 'wb-error') {
          packMsg(r.reason + ' — «Повторить» доупакует тот же заказ.', 'warn');
          $('pack-retry').hidden = false;
          return;
        }
        packPending = null;
        if (r.status !== 'ok') {
          packMsg(r.reason, 'bad');
          if (/отменён/.test(r.reason || '')) loadPacks();
          return;
        }
        var x = r.result;
        var printed = printSticker(x.sticker);
        packMsg('Заказ ' + x.wbId + ' · ' + x.title + ' → поставка ' + x.supply + ' · стикер ' + x.sticker.partA + ' ' + x.sticker.partB +
          (printed ? ' — на печать' : ' — стикер не пришёл, «Печать» в списке ниже'), 'good');
        note('Упакован заказ ' + x.wbId + (r.replay ? ' (повтор)' : ''), 'good');
        loadPacks();
        loadOrders();
      }).catch(function () {
        $('pack-go').disabled = false;
        packMsg('Нет связи — «Повторить» доупакует тот же заказ.', 'bad');
        $('pack-retry').hidden = false;
      });
    }
    $('pack-form').addEventListener('submit', function (e) {
      e.preventDefault();
      if (packPending) { packMsg('Сначала доупакуйте заказ: «Повторить».', 'warn'); return; }
      var code = toEn($('pack-scan').value.trim());
      $('pack-scan').value = '';
      if (!code) return;
      packPending = { key: newKey(), barcode: code };
      sendPack();
    });
    $('pack-retry').addEventListener('click', sendPack);
    $('pack-refresh').addEventListener('click', function () { loadPacks(); });
    function loadPacks() {
      if (!session) return;
      call('packState', session.token).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { packMsg(r.reason, 'bad'); return; }
        $('pack-ready').textContent = 'Отобрано к упаковке: ' + r.ready;
        var back = $('pack-back');
        clear(back);
        r.toReturn.forEach(function (x) {
          var card = el('div', undefined, 'card');
          card.appendChild(el('p', 'Отменён после отбора: заказ ' + x.wbId + ' · ' + x.title + ' — стикер не клеить, вернуть на адрес', 'warn'));
          card.appendChild(locRow([locButton('Вернуть на адрес', function () { openReturn(x); })]));
          back.appendChild(card);
        });
        (r.unfinished || []).forEach(function (x) {
          var card = el('div', undefined, 'card');
          if (!x.worker) {
            card.appendChild(el('p', 'Освобождён: заказ ' + x.wbId + ' · ' + x.title + ' — отсканируйте товар, и он доупакуется', 'warn'));
            back.appendChild(card);
            return;
          }
          card.appendChild(el('p', 'Не доупакован: заказ ' + x.wbId + ' · ' + x.title + ' · ' + x.worker + ' с ' + String(x.at).slice(11, 16) + ' · ' + x.status));
          if (senior()) {
            card.appendChild(el('p', 'Освободить — только если упаковщик ушёл и стикер не наклеен: следующий скан товара доупакует заказ', 'muted'));
            card.appendChild(locRow([locButton('Освободить', function () { enqueue('упаковка.освободить', { order: x.order }, 'Освободить заказ ' + x.wbId); })]));
          }
          back.appendChild(card);
        });
        var sup = $('pack-supplies');
        clear(sup);
        r.shipping.forEach(function (x) { sup.appendChild(supplyCard(x)); });
        var list = $('pack-list');
        clear(list);
        r.packed.forEach(function (x) {
          var card = el('div', undefined, 'card');
          card.appendChild(el('p', 'Заказ ' + x.wbId + ' · ' + x.title + ' · стикер ' + x.sticker + ' · ' + x.worker));
          card.appendChild(locRow([locButton('Печать', function () { reprintSticker(x.order); })]));
          list.appendChild(card);
        });
      }).catch(function () { packMsg('Нет связи — нажмите «Обновить».', 'bad'); });
    }
    // Поставки (15): старшая закрывает (WB «передать в доставку») и печатает QR, потом отмечает отгрузку.
    var supplyKeys = {};
    function supplyCard(x) {
      var card = el('div', undefined, 'card');
      card.appendChild(el('p', 'Поставка ' + x.wbId + ' (' + x.cabinet + ') · ' + x.status + ' · заказов ' + x.orders));
      if (x.waiting.length) card.appendChild(el('p', 'Без стикера: ' + x.waiting.join(', ') + ' — допаковать сканом товара', 'warn'));
      if (x.cancelled.length) card.appendChild(el('p', 'Отменены, не отгружать: ' + x.cancelled.join(', '), 'warn'));
      if (!senior()) return card;
      if (x.status === 'закрыта') {
        var buttons = locRow([
          locButton('QR ещё раз', function () { reprintQr(x.wbId); }),
          locButton('Отгружено', function () { buttons.hidden = true; sure.hidden = false; }),
        ]);
        // Отгрузка начисляет ФБС и не отменяется — второй шаг на той же карточке (Р1-4 п. 9).
        var sure = el('div');
        sure.hidden = true;
        sure.appendChild(el('p', 'Отгрузить поставку ' + x.wbId + ', заказов: ' + x.orders + '? Нажимайте после передачи курьеру', 'warn'));
        sure.appendChild(locRow([
          locButton('Да, отгружено', function () { sure.hidden = true; enqueue('поставка.отгрузить', { supply: x.wbId }, 'Отгрузка поставки ' + x.wbId); }),
          locButton('Отмена', function () { sure.hidden = true; buttons.hidden = false; }),
        ]));
        card.appendChild(buttons);
        card.appendChild(sure);
      } else card.appendChild(locRow([locButton('Закрыть и печатать QR', function () { closeSupply(x.wbId); })]));
      return card;
    }
    function closeSupply(wbId) {
      supplyKeys[wbId] = supplyKeys[wbId] || newKey();
      packMsg('Закрываю поставку ' + wbId + '…');
      call('supplyClose', session.token, { key: supplyKeys[wbId], supply: wbId }).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') {
          packMsg(r.reason + (r.status === 'rejected' ? '' : ' — «Закрыть» ещё раз повторит тот же запрос.'), r.status === 'rejected' ? 'bad' : 'warn');
          if (r.status === 'rejected') delete supplyKeys[wbId];
          return;
        }
        delete supplyKeys[wbId];
        var x = r.result;
        var printed = printPng(x.qr.file, 'QR поставки ' + x.supply);
        var diff = x.onlyWb.length || x.onlyV2.length;
        packMsg('Поставка ' + x.supply + ' закрыта: заказов ' + x.orders + (printed ? ', QR — на печать' : ', QR не пришёл — «QR ещё раз»') +
          (x.waiting.length ? '; без стикера: ' + x.waiting.join(', ') : '') +
          (diff ? '; состав WB ≠ v2 — запись в «Контроль»' : ''), diff || x.waiting.length ? 'warn' : 'good');
        loadPacks();
        if (diff) loadControl();
      }).catch(function () { packMsg('Нет связи — «Закрыть» ещё раз повторит тот же запрос.', 'bad'); });
    }
    function reprintQr(wbId) {
      call('supplyQr', session.token, wbId).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { packMsg(r.reason, 'bad'); return; }
        printPng(r.result.qr.file, 'QR поставки ' + r.result.supply);
        packMsg('QR поставки ' + r.result.supply + ' — на печать.', 'good');
      }).catch(function () { packMsg('Нет связи — повторить', 'bad'); });
    }
    function reprintSticker(order) {
      call('packReprint', session.token, order).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { packMsg(r.reason, 'bad'); return; }
        printSticker(r.result.sticker);
        packMsg('Стикер заказа ' + r.result.wbId + ' — повторно на печать, без списания.', 'good');
      }).catch(function () { packMsg('Нет связи — повторить', 'bad'); });
    }
    function openReturn(x) {
      packReturn = x;
      $('pack-return').hidden = false;
      $('pack-return-title').textContent = 'Заказ ' + x.wbId + ' · ' + x.title + ': отсканируйте этикетку адреса, куда кладёте товар';
      $('pack-return-loc').value = '';
      $('pack-return-loc').focus();
    }
    function sendReturn() {
      var loc = $('pack-return-loc').value.trim();
      if (!packReturn || !loc) return;
      enqueue('отмена.вернуть', { order: packReturn.order, location: loc }, 'Возврат заказа ' + packReturn.wbId + ' на адрес');
      packReturn = null;
      $('pack-return').hidden = true;
    }
    $('pack-return-go').addEventListener('click', sendReturn);
    $('pack-return-loc').addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); sendReturn(); } });
    $('pack-return-stop').addEventListener('click', function () { packReturn = null; $('pack-return').hidden = true; });

    // Отбор (13). Старшая формирует лист; сборщик идёт по шагам листа в порядке обхода: скан
    // этикетки адреса, скан товара, «сколько нашли» → «Взял». Следующий шаг — после ответа сервера.
    var pickStep = null;
    var pickOpen = null;
    function pickMsg(text, cls) {
      $('pick-msg').textContent = text || '';
      $('pick-msg').className = cls || '';
    }
    function loadPicks() {
      if (!session) return;
      call('pickLists', session.token).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { pickMsg(r.reason, 'bad'); return; }
        $('pick-make').hidden = !senior() || !r.ready;
        if (senior()) $('pick-make').textContent = 'Сформировать лист отбора (готово заказов: ' + (r.ready || 0) + ')';
        var box = $('pick-lists');
        clear(box);
        if (!r.open.length) box.appendChild(el('p', 'Открытых листов нет.', 'muted'));
        r.open.forEach(function (l) {
          var card = el('div', undefined, 'card');
          card.appendChild(el('p', 'Лист ' + l.list + ' · заказов ' + l.orders + ' · ' + l.worker));
          card.appendChild(locRow([locButton('Отбирать', function () { openPick(l.list); })]));
          box.appendChild(card);
        });
        if (pickOpen) openPick(pickOpen);
      }).catch(function () { pickMsg('Нет связи — нажмите «Обновить».', 'bad'); });
    }
    function openPick(list) {
      call('pickList', session.token, list).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { pickMsg(r.reason, 'bad'); return; }
        var next = r.steps.filter(function (s) { return s.need > 0; })[0];
        if (!next) {
          pickOpen = null;
          setPickStep(null);
          pickMsg('Лист ' + r.list + ' собран.', 'good');
          return;
        }
        pickOpen = r.list;
        var left = r.steps.reduce(function (n, s) { return n + s.need; }, 0);
        setPickStep({ list: r.list, code: next.code, barcode: next.barcode, item: next.item, title: next.title, client: next.client,
          barcodes: next.barcodes, need: next.need, left: left, addrOk: false, scanned: '' });
      }).catch(function () { pickMsg('Нет связи — нажмите «Обновить».', 'bad'); });
    }
    function setPickStep(step) {
      pickStep = step;
      $('pick-step').hidden = !step;
      if (!step) return;
      $('pick-step-title').textContent = 'Лист ' + step.list + ' · ' + step.code + ' → ' + step.title + ' · ' + step.client + ' — взять ' + step.need + ' шт';
      $('pick-found').value = String(step.need);
      $('pick-found').max = String(step.need);
      $('pick-take').disabled = true;
      pickHint();
      $('scan').focus();
    }
    function pickHint() {
      var s = pickStep;
      $('pick-step-hint').textContent = !s.addrOk ? 'Отсканируйте этикетку адреса ' + s.code + '. Всего в листе осталось ' + s.left + ' шт.'
        : !s.scanned ? 'Адрес верный. Отсканируйте товар.' : 'Товар верный. Сколько нашли — и «Взял».';
    }
    function pickScan(raw) {
      var s = pickStep;
      var code = toEn(raw.trim()).toUpperCase();
      if (!s.addrOk) {
        if (code === String(s.barcode).toUpperCase() || raw.trim().toUpperCase() === String(s.code).toUpperCase()) { s.addrOk = true; pickMsg(''); }
        else pickMsg('Это не адрес ' + s.code + ' — отсканируйте этикетку ' + s.code, 'bad');
        pickHint();
        return;
      }
      if (s.barcodes.map(function (b) { return String(b).toUpperCase(); }).indexOf(code) === -1) {
        pickMsg('Не тот товар: нужен ' + s.title, 'bad');
        return;
      }
      s.scanned = code;
      pickMsg('');
      $('pick-take').disabled = false;
      pickHint();
      $('pick-found').focus();
    }
    $('pick-take').addEventListener('click', function () {
      var s = pickStep;
      var found = Number($('pick-found').value);
      if ($('pick-found').value === '' || Math.round(found) !== found || found < 0 || found > s.need) { pickMsg('Сколько нашли — от 0 до ' + s.need, 'bad'); return; }
      enqueue('отбор.взять', { list: s.list, location: s.barcode, item: s.scanned, client: s.client, product: s.item, found: found }, 'Отбор ' + s.code + ' · ' + s.title);
      setPickStep(null);
      pickMsg('Отправлено, жду следующий шаг…', 'muted');
    });
    $('pick-stop').addEventListener('click', function () { pickOpen = null; setPickStep(null); pickMsg(''); });
    $('pick-make').addEventListener('click', function () { $('pick-make').hidden = true; enqueue('отбор.лист', {}, 'Лист отбора'); });
    $('pick-refresh').addEventListener('click', loadPicks);

    // Размещение и перемещение (08). Задание: что, сколько и куда; адрес подтверждается сканом
    // этикетки — следующий скан уходит в задание, а не в поиск.
    var placeTask = null;
    function placeMsg(text, cls) {
      $('place-msg').textContent = text || '';
      $('place-msg').className = cls || '';
    }
    function senior() {
      return session && (session.role === 'старшая' || session.role === 'владелец');
    }
    function setPlaceTask(task) {
      placeTask = task;
      $('place-task').hidden = !task;
      if (!task) return;
      $('place-task-title').textContent = (task.move ? 'Переместить с ' + task.from + ': ' : 'Разместить: ') + task.title + ' · ' + task.client;
      $('place-qty').value = String(task.max);
      $('place-qty').max = String(task.max);
      $('place-pallets').value = '';
      // Поле паллет — когда адрес на N > 1 или ещё не выбран (по скану может оказаться таким).
      $('place-pallets-box').hidden = !!task.expected && !(task.capacity > 1);
      $('place-task-hint').textContent = (task.expected ? 'Отсканируйте этикетку адреса ' + task.expected : 'Отсканируйте этикетку адреса, куда кладёте') +
        ' (не больше ' + task.max + ' шт).';
      $('scan').focus();
    }
    function placeScan(raw) {
      var t = placeTask;
      var qty = Number($('place-qty').value);
      if (!qty || Math.round(qty) !== qty || qty < 1 || qty > t.max) { placeMsg('Количество — от 1 до ' + t.max, 'bad'); $('place-qty').focus(); return; }
      var data = { client: t.client, item: t.item, qty: qty };
      if ($('place-pallets').value) data.pallets = Number($('place-pallets').value);
      if (t.move) {
        data.from = t.from;
        data.to = raw.trim();
        enqueue('перемещение', data, 'Перемещение ' + t.title + ' с ' + t.from);
      } else {
        data.scan = raw.trim();
        if (t.expected) data.expected = t.expected;
        enqueue('размещение', data, 'Размещение ' + t.title);
      }
      placeMsg('');
      setPlaceTask(null);
    }
    $('place-cancel').addEventListener('click', function () { setPlaceTask(null); });
    function loadPlacement() {
      if (!session) return;
      call('placementList', session.token).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { placeMsg(r.reason, 'bad'); return; }
        var list = $('place-list');
        clear(list);
        if (!r.unplaced.length) list.appendChild(el('p', 'Всё размещено: в зоне приёмки ничего нет.', 'muted'));
        r.unplaced.forEach(function (u) {
          var card = el('div', undefined, 'card');
          card.appendChild(el('p', u.title + ' · ' + u.client + ' — не размещено ' + u.qty + ' шт'));
          var task = function (s) {
            return { client: u.client, item: u.item, title: u.title, max: u.qty, expected: s ? s.code : '', capacity: s ? s.capacity : 1 };
          };
          u.suggestions.forEach(function (s) {
            card.appendChild(locRow([locButton(s.code + ' · ' + s.why + (s.capacity > 1 ? ' · мест ' + s.capacity : ''), function () { setPlaceTask(task(s)); })]));
          });
          card.appendChild(locRow([locButton('Другой адрес — по скану', function () { setPlaceTask(task(null)); })]));
          list.appendChild(card);
        });
      }).catch(function () { placeMsg('Нет связи — обновите страницу.', 'bad'); });
    }
    // Скан адреса в обычном режиме: что лежит и чьё; старшей — «Переместить» по строке.
    function showContents(li, c) {
      var head = 'адрес ' + c.code + (c.blocked ? ' — заблокирован: ' + c.blockReason : '') +
        (c.capacity > 1 ? ' · паллетомест занято ' + c.palletsUsed + ' из ' + c.capacity : '');
      li.textContent = li.textContent.replace(/ — адрес .*$/, ' — ' + head);
      if (senior()) li.appendChild(locButton('Пересчитать адрес', function () { setRecount(c); }));
      if (!c.stock.length) { li.appendChild(el('div', 'Пусто', 'muted')); return; }
      // Адрес на N > 1: паллеты клиента по факту — после перемещения части, пересчёта, смены N.
      if (senior() && c.capacity > 1) {
        Object.keys(c.pallets).forEach(function (client) {
          var n = numberInput(c.pallets[client], 1, c.capacity, 'паллет');
          n.setAttribute('aria-label', 'Паллет клиента ' + client);
          li.appendChild(locRow([el('span', client + ': паллет'), n, locButton('Записать паллеты', function () {
            enqueue('адрес.паллеты', { location: c.code, client: client, pallets: Number(n.value) }, 'Паллеты ' + client + ' на ' + c.code + ': ' + n.value);
          })]));
        });
      }
      c.stock.forEach(function (x) {
        li.appendChild(el('div', x.title + ' · ' + x.client + ' — ' + x.qty + ' шт'));
        if (senior()) {
          li.appendChild(locButton('Переместить', function () {
            setPlaceTask({ move: true, client: x.client, item: x.item, title: x.title, max: x.qty, from: c.code, capacity: 1 });
          }));
        }
      });
    }
    function loadStock(client) {
      if (!senior()) return;
      call('stockList', session.token, client || $('stock-client').value || '').then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { $('stock-msg').textContent = r.reason; return; }
        var sel = $('stock-client');
        clear(sel);
        r.clients.forEach(function (c) { sel.appendChild(el('option', c)); });
        sel.value = r.client;
        var list = $('stock-list');
        clear(list);
        if (!r.items.length) list.appendChild(el('p', 'Остатка нет.', 'muted'));
        r.items.forEach(function (x) {
          var card = el('div', undefined, 'card');
          card.appendChild(el('p', x.title));
          card.appendChild(el('p', 'Всего ' + x.total + ': на адресах ' + x.onAddresses + ' · в зоне приёмки ' + x.receiving + ' · отобрано ' + x.picked));
          card.appendChild(el('p', 'В резерве ' + x.reserved + (x.frozen ? ' · заморожено ' + x.frozen : '') + ' · свободно ' + x.free, 'muted'));
          x.addresses.forEach(function (a) {
            var row = [el('span', a.code + ' — ' + a.qty + ' шт'), locButton('Переместить', function () {
              setPlaceTask({ move: true, client: r.client, item: x.item, title: x.title, max: a.qty, from: a.code, capacity: 1 });
            })];
            if (session.role === 'владелец') row.push(locButton('Корректировка', function () { setFix({ client: r.client, item: x.item, title: x.title, code: a.code, qty: a.qty }); }));
            card.appendChild(locRow(row));
          });
          list.appendChild(card);
        });
      }).catch(function () { $('stock-msg').textContent = 'Нет связи — обновите страницу.'; });
    }
    $('stock-client').addEventListener('change', function () { loadStock($('stock-client').value); });

    // Пересчёт адреса (09): факт по каждой строке адреса; лишний товар — сканом баркода. Пока
    // пересчёт открыт, скан уходит в него. Расхождение — запись в «Контроль», решает старшая.
    var recountTask = null;
    function setRecount(c) {
      recountTask = c ? { code: c.code, version: c.version, lines: c.stock.map(function (x) { return { client: x.client, item: x.item, title: x.title, input: null }; }) } : null;
      $('recount').hidden = !recountTask;
      clear($('recount-choices'));
      if (!recountTask) return;
      $('recount-title').textContent = 'Пересчёт адреса ' + c.code;
      renderRecount();
      $('scan').focus();
    }
    function renderRecount() {
      var box = $('recount-lines');
      clear(box);
      recountTask.lines.forEach(function (l) {
        if (!l.input) l.input = numberInput('', 0, 100000, 'факт');
        box.appendChild(el('p', l.title + ' · ' + l.client));
        box.appendChild(l.input);
      });
      if (!recountTask.lines.length) box.appendChild(el('p', 'По учёту адрес пуст. Нашли товар — отсканируйте его.', 'muted'));
    }
    function addRecountLine(x) {
      if (recountTask.lines.some(function (l) { return l.client === x.client && l.item === x.item; })) { note(x.title + ' уже в пересчёте', 'warn'); return; }
      recountTask.lines.push({ client: x.client, item: x.item, title: x.title, input: null });
      clear($('recount-choices'));
      renderRecount();
    }
    function recountScan(raw) {
      call('scanLookup', session.token, raw).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { note(r.reason, 'bad'); return; }
        if (r.location) { note('Это адрес ' + r.location.code + ' — в пересчёт сканируйте товар', 'warn'); return; }
        if (!r.items || !r.items.length) { note('Баркода ' + r.code + ' нет в каталоге', 'bad'); return; }
        if (r.items.length === 1) { addRecountLine(r.items[0]); return; }
        var box = $('recount-choices');
        clear(box);
        r.items.forEach(function (x) { box.appendChild(locRow([locButton(x.title + ' · ' + x.client, function () { addRecountLine(x); })])); });
      }).catch(function () { note('Нет связи — отсканировать ещё раз', 'bad'); });
    }
    $('recount-send').addEventListener('click', function () {
      var t = recountTask;
      var lines = [];
      for (var i = 0; i < t.lines.length; i++) {
        var v = t.lines[i].input.value;
        var q = Number(v);
        if (v === '' || Math.round(q) !== q || q < 0) { note('Впишите факт по строке: ' + t.lines[i].title + ' (нет товара — 0)', 'bad'); t.lines[i].input.focus(); return; }
        lines.push({ client: t.lines[i].client, item: t.lines[i].item, qty: q });
      }
      enqueue('адрес.пересчёт', { location: t.code, lines: lines, version: t.version }, 'Пересчёт ' + t.code);
      setRecount(null);
    });
    $('recount-cancel').addEventListener('click', function () { setRecount(null); });

    // Корректировка «вне первой версии» (09, А4): только владелец, причина из списка.
    // Записать — вторым нажатием (без окна confirm).
    var fixTask = null;
    function setFix(t) {
      fixTask = t;
      $('fix').hidden = !t;
      $('fix-send').textContent = 'Записать';
      delete $('fix-send').dataset.sure;
      if (!t) return;
      $('fix-title').textContent = 'Корректировка: ' + t.title + ' · ' + t.client + ' · ' + t.code + ' (сейчас ' + t.qty + ' шт)';
      $('fix-qty').value = '';
      $('fix-reason').value = '';
      $('fix-note').value = '';
      $('fix-qty').focus();
    }
    $('fix-send').addEventListener('click', function () {
      var t = fixTask;
      var q = Number($('fix-qty').value);
      if (!q || Math.round(q) !== q) { note('Изменение — целое, не ноль', 'bad'); return; }
      if (q < 0 && -q > t.qty) { note('На адресе ' + t.qty + ' шт — нельзя списать ' + (-q), 'bad'); return; }
      if (!$('fix-reason').value) { note('Выберите причину', 'bad'); return; }
      var b = $('fix-send');
      if (!b.dataset.sure) { b.dataset.sure = '1'; b.textContent = 'Точно? ' + (q > 0 ? '+' : '') + q + ' шт, ' + $('fix-reason').value; return; }
      enqueue('корректировка', { client: t.client, item: t.item, location: t.code, qty: q, reason: $('fix-reason').value, note: $('fix-note').value },
        'Корректировка ' + t.title + ' на ' + t.code);
      setFix(null);
    });
    $('fix-cancel').addEventListener('click', function () { setFix(null); });

    // Начальные остатки (09): весь список — одна операция, не через очередь (нужна связь).
    // Повтор того же списка не удваивает: ключ — хеш содержимого.
    $('initial-load').addEventListener('click', function () {
      var text = $('initial-list').value;
      var client = $('stock-client').value;
      var errs = $('initial-errors');
      clear(errs);
      if (!client) { $('initial-msg').textContent = 'Сначала клиент — выше'; return; }
      if (!text.trim()) { $('initial-msg').textContent = 'Список пуст'; return; }
      $('initial-msg').textContent = 'Загружаю…';
      $('initial-load').disabled = true;
      call('initialStockLoad', session.token, client, text).then(function (r) {
        $('initial-load').disabled = false;
        if (r.status === 'auth') { needLogin(r.reason); return; }
        var head = r.header ? 'Строка ' + r.header + ' — шапка, пропущена. ' : '';
        if (r.status !== 'ok') {
          $('initial-msg').textContent = head + r.reason;
          ((r.details && r.details.errors) || []).forEach(function (e) { errs.appendChild(el('li', 'Строка ' + e.line + ': ' + e.text, 'bad')); });
          return;
        }
        var x = r.result;
        $('initial-msg').textContent = head + (x.already ? 'Этот список уже загружен (' + x.at + '), ничего не добавлено. Строк: ' + x.rows + ', штук: ' + x.total
          : 'Загружено. Строк: ' + x.rows + ', штук: ' + x.total + ', адресов: ' + x.addresses + (r.replay ? ' (повтор — не удвоено)' : ''));
        loadStock(client);
      }).catch(function () { $('initial-load').disabled = false; $('initial-msg').textContent = 'Нет связи — загрузить ещё раз: повтор не удвоит.'; });
    });

    // Приёмка (07): пока выбрана приёмка, скан и камера считают товар в неё. Операции — через
    // очередь: без связи скан не теряется. Создать и закрыть — старшая или владелец.
    var KEY_RECEIPT = 'wms2.receipt';
    var activeReceipt = null;
    var receiptsData = { open: [], closed: [], canManage: false };
    function receiptMsg(text, cls) {
      $('receipt-msg').textContent = text || '';
      $('receipt-msg').className = cls || '';
    }
    function setActiveReceipt(r) {
      activeReceipt = r ? { id: r.id, number: r.number, client: r.client } : null;
      save(KEY_RECEIPT, activeReceipt && session ? { by: session.name, receipt: activeReceipt } : null);
      clear($('receipt-choices'));
      renderReceipts();
    }
    function loadReceipts() {
      if (!session) return;
      call('receiptsList', session.token).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { receiptMsg(r.reason, 'bad'); return; }
        receiptsData = r;
        var sel = $('receipt-client');
        var was = sel.value;
        clear(sel);
        r.clients.forEach(function (c) { sel.appendChild(el('option', c)); });
        if (was) sel.value = was;
        // Приёмку закрыли (здесь или с другого телефона) — скан возвращается в поиск адреса.
        if (activeReceipt && !r.open.some(function (x) { return x.id === activeReceipt.id; })) activeReceipt = null;
        renderReceipts();
      }).catch(function () { receiptMsg('Нет связи — обновите страницу.', 'bad'); });
    }
    function receiptTitle(r) {
      return 'Приёмка № ' + r.number + ' · ' + r.client;
    }
    function renderReceipts() {
      $('receipt-form').hidden = !receiptsData.canManage;
      $('receipt-active').hidden = !activeReceipt;
      if (activeReceipt) $('receipt-active-title').textContent = 'Скан идёт в приёмку № ' + activeReceipt.number + ' · ' + activeReceipt.client;
      var open = $('receipts-open');
      clear(open);
      if (!receiptsData.open.length) open.appendChild(el('p', 'Открытых приёмок нет.', 'muted'));
      receiptsData.open.forEach(function (r) { open.appendChild(receiptCard(r)); });
      var closed = $('receipts-closed');
      clear(closed);
      if (receiptsData.closed.length) closed.appendChild(el('p', 'Последние закрытые:', 'muted'));
      receiptsData.closed.forEach(function (r) {
        closed.appendChild(el('p', receiptTitle(r) + ' · ' + r.total + ' шт · закрыта ' + r.closedAt, 'muted'));
      });
    }
    function receiptCard(r) {
      var card = el('div', undefined, 'card');
      var mine = activeReceipt && activeReceipt.id === r.id;
      card.appendChild(el('p', receiptTitle(r) + (mine ? ' · скан сюда' : ''), mine ? 'good' : ''));
      card.appendChild(el('p', 'Создала: ' + r.openedBy + ' · ' + r.openedAt + ' · всего ' + r.total + ' шт', 'muted'));
      r.lines.forEach(function (l) {
        var qty = numberInput(undefined, -10000, 10000, '±шт');
        card.appendChild(el('p', l.title + ' — ' + l.qty + ' шт'));
        card.appendChild(locRow([qty, locButton('Добавить', function () {
          var n = Number(qty.value);
          if (!n || Math.round(n) !== n) { qty.focus(); return; }
          enqueue('приёмка.добавить', { receipt: r.id, item: l.item, qty: n }, receiptTitle(r) + ': ' + l.title + ' ' + (n > 0 ? '+' : '') + n);
        })]));
      });
      var buttons = [];
      if (!mine) buttons.push(locButton('Принимать сюда', function () { setActiveReceipt(r); $('scan').focus(); }));
      if (receiptsData.canManage) {
        // Закрытие не отменить: второе нажатие подтверждает (без окна confirm).
        var close = locButton('Закрыть приёмку', function () {
          if (!close.dataset.sure) { close.dataset.sure = '1'; close.textContent = 'Точно закрыть? ' + r.total + ' шт'; return; }
          close.disabled = true;
          enqueue('приёмка.закрыть', { receipt: r.id }, receiptTitle(r) + ': закрыть');
        });
        buttons.push(close);
      }
      if (buttons.length) card.appendChild(locRow(buttons));
      return card;
    }
    function receiptScan(raw) {
      var qty = Number($('receipt-qty').value) || 1;
      $('receipt-qty').value = '';
      var code = toEn(raw.trim());
      enqueue('приёмка.добавить', { receipt: activeReceipt.id, barcode: raw.trim(), qty: qty },
        receiptTitle(activeReceipt) + ': ' + code + (qty !== 1 ? ' × ' + qty : ''));
    }
    // Ответ сервера на операцию приёмки из очереди.
    function receiptAnswer(item, r) {
      var x = r.result || {};
      var label = item.label || item.type;
      if (item.type === 'приёмка.создать') {
        note('Приёмка № ' + x.number + ' создана · ' + x.client, 'good');
        setActiveReceipt({ id: x.id, number: x.number, client: x.client });
      } else if (item.type === 'приёмка.закрыть') {
        if (x.already) note('Приёмка № ' + x.number + ' уже закрыта', 'muted');
        else {
          note('Приёмка № ' + x.number + ' закрыта: ' + x.total + ' шт — в зоне приёмки, на адреса не разложено', 'good');
          if (x.chargeProblem) note('Начисление приёмки не записано: ' + x.chargeProblem + '. Запись в «Контроле».', 'warn');
        }
      } else if (x.unknown) {
        note('Баркода ' + x.unknown + ' нет в каталоге клиента — не посчитан, запись в «Контроле». Отложите товар.', 'warn');
      } else if (x.choices) {
        note('Баркод ' + x.barcode + ' у нескольких размеров — выберите размер', 'warn');
        var box = $('receipt-choices');
        clear(box);
        x.choices.forEach(function (c) {
          box.appendChild(el('p')).appendChild(locButton(c.title, function () {
            clear(box);
            enqueue('приёмка.добавить', { receipt: x.receipt, item: c.item, qty: item.data.qty || 1 }, label + ' → ' + c.title);
          }));
        });
      } else {
        note(label + ' — записано, в строке ' + x.qty + ' шт' + (r.replay ? ' (повтор)' : ''), 'good');
      }
    }
    $('receipt-leave').addEventListener('click', function () { setActiveReceipt(null); });
    $('receipt-form').addEventListener('submit', function (e) {
      e.preventDefault();
      if (!$('receipt-client').value) return;
      enqueue('приёмка.создать', { client: $('receipt-client').value }, 'Новая приёмка · ' + $('receipt-client').value);
    });

    // Адреса (06): старшая и владелец правят через очередь; этикетки рисуются полосами SVG.
    var LOC_SHOW = 30;
    var locations = { list: [], zones: [] };
    function locationsMsg(text, cls) {
      $('locations-msg').textContent = text || '';
      $('locations-msg').className = cls || '';
    }
    function zoneTitle(key) {
      var z = locations.zones.filter(function (x) { return x.key === key; })[0];
      return z ? z.title : key;
    }
    function loadLocations() {
      if (!session || (session.role !== 'старшая' && session.role !== 'владелец')) return;
      call('locationsList', session.token).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { locationsMsg(r.reason, 'bad'); return; }
        locations = { list: r.locations, zones: r.zones };
        var sel = $('location-zone');
        if (!sel.options.length) {
          r.zones.forEach(function (z) { var o = el('option', z.title); o.value = z.key; sel.appendChild(o); });
        }
        renderLocations();
      }).catch(function () { locationsMsg('Нет связи — обновите страницу.', 'bad'); });
    }
    function foundLocations() {
      var q = $('locations-filter').value.trim().toUpperCase();
      return locations.list.filter(function (l) {
        return !q || l.code.toUpperCase().indexOf(q) !== -1 || l.barcode.indexOf(q) !== -1 || l.barcode.indexOf(toEn(q)) !== -1;
      });
    }
    function renderLocations() {
      var found = foundLocations();
      var blocked = locations.list.filter(function (l) { return l.blocked; }).length;
      $('locations-count').textContent = 'Адресов: ' + locations.list.length + ', заблокировано: ' + blocked +
        (found.length > LOC_SHOW ? '. Показаны первые ' + LOC_SHOW + ' из ' + found.length + ' — уточните поиск.' : '');
      var list = $('locations-list');
      clear(list);
      if (!locations.list.length) list.appendChild(el('p', 'Адресов пока нет — владелец запускает мастер setupLocations.', 'muted'));
      found.slice(0, LOC_SHOW).forEach(function (l) { list.appendChild(locationCard(l)); });
    }
    function locButton(text, fn) {
      var b = el('button', text, 'secondary');
      b.type = 'button';
      b.addEventListener('click', fn);
      return b;
    }
    function locRow(nodes) {
      var row = el('div', undefined, 'row');
      nodes.forEach(function (n) { row.appendChild(n); });
      return row;
    }
    function numberInput(value, min, max, placeholder) {
      var x = el('input');
      x.type = 'number';
      x.inputMode = 'numeric';
      x.min = String(min);
      x.max = String(max);
      x.value = value === undefined ? '' : String(value);
      x.placeholder = placeholder;
      return x;
    }
    function locationCard(l) {
      var card = el('div', undefined, 'card');
      card.appendChild(el('p', l.code + ' · ' + zoneTitle(l.zone)));
      card.appendChild(el('p', 'Штрихкод ' + l.barcode + ' · вместимость ' + l.capacity + ' · порядок ' + l.order +
        (l.stockRows ? ' · строк остатка: ' + l.stockRows : ''), 'muted'));
      if (l.blocked) card.appendChild(el('p', 'Заблокирован: ' + (l.blockReason || 'без причины'), 'warn'));
      var edit = el('div');
      edit.hidden = true;
      card.appendChild(locRow([
        locButton('Изменить', function () { edit.hidden = !edit.hidden; }),
        locButton('Этикетка', function () { printLabels([l.code]); }),
      ]));
      var newCode = el('input');
      newCode.maxLength = 20;
      newCode.autocapitalize = 'characters';
      newCode.spellcheck = false;
      newCode.placeholder = 'Новый код';
      edit.appendChild(locRow([newCode, locButton('Переименовать', function () {
        if (!newCode.value.trim()) { newCode.focus(); return; }
        enqueue('адрес.переименовать', { code: l.code, newCode: newCode.value.trim() }, 'Адрес ' + l.code + ' → ' + newCode.value.trim());
      })]));
      var cap = numberInput(l.capacity, 1, 20, 'Паллет');
      edit.appendChild(locRow([cap, locButton('Вместимость', function () {
        enqueue('адрес.вместимость', { code: l.code, capacity: Number(cap.value) }, 'Адрес ' + l.code + ': вместимость ' + cap.value);
      })]));
      var order = numberInput(l.order, 1, 999999, 'Порядок');
      edit.appendChild(locRow([order, locButton('Порядок', function () {
        enqueue('адрес.порядок', { code: l.code, order: Number(order.value) }, 'Адрес ' + l.code + ': порядок ' + order.value);
      })]));
      if (l.blocked) {
        edit.appendChild(locRow([locButton('Снять блок', function () {
          enqueue('адрес.блок', { code: l.code, blocked: false }, 'Адрес ' + l.code + ': блок снят');
        })]));
      } else {
        var reason = el('input');
        reason.maxLength = 200;
        reason.placeholder = 'Причина блокировки';
        edit.appendChild(locRow([reason, locButton('Заблокировать', function () {
          if (!reason.value.trim()) { reason.focus(); return; }
          enqueue('адрес.блок', { code: l.code, blocked: true, reason: reason.value.trim() }, 'Адрес ' + l.code + ': заблокирован');
        })]));
      }
      card.appendChild(edit);
      return card;
    }
    $('locations-filter').addEventListener('input', renderLocations);
    $('location-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var code = $('location-code').value.trim();
      var data = { code: code, zone: $('location-zone').value, capacity: Number($('location-capacity').value || 1) };
      if ($('location-order').value) data.order = Number($('location-order').value);
      enqueue('адрес.добавить', data, 'Новый адрес ' + code);
      $('location-code').value = '';
      $('location-order').value = '';
    });

    var SVG_NS = 'http://www.w3.org/2000/svg';
    // Полосы Code 128 с сервера: «1» — чёрный модуль. Подряд идущие «1» — один прямоугольник.
    function barsSvg(bits) {
      var svg = document.createElementNS(SVG_NS, 'svg');
      svg.setAttribute('viewBox', '0 0 ' + bits.length + ' 40');
      svg.setAttribute('preserveAspectRatio', 'none');
      svg.setAttribute('shape-rendering', 'crispEdges');
      var rect = function (x, w, fill) {
        var r = document.createElementNS(SVG_NS, 'rect');
        r.setAttribute('x', String(x));
        r.setAttribute('y', '0');
        r.setAttribute('width', String(w));
        r.setAttribute('height', '40');
        r.setAttribute('fill', fill);
        svg.appendChild(r);
      };
      rect(0, bits.length, '#fff');
      for (var i = 0; i < bits.length;) {
        if (bits.charAt(i) !== '1') { i++; continue; }
        var j = i;
        while (bits.charAt(j) === '1') j++;
        rect(i, j - i, '#000');
        i = j;
      }
      return svg;
    }
    function printLabels(codes) {
      locationsMsg('Готовлю этикетки…');
      call('locationLabels', session.token, codes).then(function (r) {
        if (r.status === 'auth') { needLogin(r.reason); return; }
        if (r.status !== 'ok') { locationsMsg(r.reason, 'bad'); return; }
        var area = $('print-area');
        clear(area);
        r.labels.forEach(function (x) {
          if (!/^[01]+$/.test(x.bits)) return;
          var label = el('div', undefined, 'label');
          label.appendChild(barsSvg(x.bits));
          label.appendChild(el('div', x.code, 'cap'));
          label.appendChild(el('div', x.barcode, 'sub'));
          area.appendChild(label);
        });
        var n = area.childNodes.length;
        locationsMsg('Этикеток: ' + n + (r.missing.length ? '. Нет адресов: ' + r.missing.join(', ') : ''), r.missing.length ? 'warn' : 'good');
        if (n) window.print();
      }).catch(function () { locationsMsg('Нет связи — повторить', 'bad'); });
    }
    $('labels-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var typed = $('labels-codes').value.split(/[\s,;]+/).filter(Boolean);
      var codes = typed.length ? typed : foundLocations().map(function (l) { return l.code; });
      if (codes.length) printLabels(codes);
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
      $('orders-box').hidden = !(session.role === 'старшая' || session.role === 'владелец');
      $('day-box').hidden = !(session.role === 'старшая' || session.role === 'владелец');
      $('workers-box').hidden = session.role !== 'владелец';
      $('settings-box').hidden = !(session.role === 'старшая' || session.role === 'владелец');
      $('locations-box').hidden = !(session.role === 'старшая' || session.role === 'владелец');
      $('receipt-box').hidden = false;
      $('place-box').hidden = false;
      $('pick-box').hidden = false;
      $('pack-box').hidden = false;
      $('stock-box').hidden = !(session.role === 'старшая' || session.role === 'владелец');
      var savedReceipt = load(KEY_RECEIPT, null);
      activeReceipt = savedReceipt && savedReceipt.by === session.name ? savedReceipt.receipt : null;
      $('share-box').hidden = IN_APPS_SCRIPT || session.role !== 'владелец';
      $('share-link').value = IN_APPS_SCRIPT ? '' : location.origin + location.pathname + '#api=' + encodeURIComponent(window.WMS_EXEC);
      show('main');
      $('cam-open').hidden = !camAvailable() || !!cam;
      renderQueue();
      loadControl();
      loadDay();
      loadWorkers();
      loadSettings();
      loadLocations();
      loadReceipts();
      loadPlacement();
      loadStock();
      loadOrders();
      loadPicks();
      loadPacks();
      pump();
    }
    apiReady.then(start, start);
  