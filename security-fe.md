# Безопасность фронтенд-приложения

Правила для браузерной части React-приложения: SPA на Vite / webpack или Next.js. Что выполняется в браузере
пользователя, что оно хранит, что отдаёт сервер статики и кому утекают данные. Универсальные, без привязки к
конкретному репозиторию. Зависимости, CI и машина разработчика — [dependency-hygiene.md](dependency-hygiene.md);
производительность — [optimizations.md](optimizations.md). Источники и как применять — [README.md](README.md).

## Как читать

- **обязательно** — для любого проекта своего типа; нарушение — находка аудита;
- **по ситуации** — только при условии из правила;
- **Найти:** — как обнаружить нарушение; *(авто)* — проверяет инструмент.

Ссылки вида *ASVS 3.4.1* — требования OWASP ASVS 5.0 (уровень L1–L3 в скобках), *RFC 10017 §6.1* — OAuth 2.0 for
Browser-Based Applications (BCP 212, август 2026).

## Главное правило

**Любой скрипт, выполнившийся на вашем origin, имеет все права приложения**: читает хранилища, шлёт запросы с
сессией пользователя, меняет страницу (RFC 10017 §5). Защита фронтенда поэтому держится на трёх вещах, по порядку
важности:

1. **Не дать чужому коду выполниться** — вывод данных без XSS (раздел 1), строгая CSP (3), контроль сторонних
   скриптов (4).
2. **Уменьшить, что он унесёт** — токены вне досягаемости JS (2), минимум данных в браузере и в отчётах об ошибках (6).
3. **Граница доверия — сервер.** Проверка на клиенте — это UX, а не защита: права, оплата, лимиты и видимость данных
   решает API (2.6).

Против уже выполняющегося XSS прикладных средств почти нет: проксирование запросов через браузер жертвы «не может
быть остановлено мерами на уровне приложения» (RFC 10017 §5.1.4). Поэтому вес — на пункте 1.

## 1. Вывод данных (XSS)

**1.1. HTML из данных — только через санитайзер и в одном месте.** *обязательно*
JSX экранирует всё, что выводится как текст. `dangerouslySetInnerHTML` — единственный штатный обход: только с
`DOMPurify.sanitize()` (или Sanitizer API, где он есть), внутри одного компонента-обёртки, без правки результата после
санитайзера. DOMPurify обновлять сразу: обходы в нём находят регулярно (OWASP XSS Cheat Sheet).
**Найти:** *(авто)* `react/no-danger` (eslint-plugin-react); поиск `dangerouslySetInnerHTML` без `sanitize` рядом.

**1.2. Мимо React в DOM — только текстовые синки.** *обязательно*
`ref.current.innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `DOMParser.parseFromString`, `srcdoc`
с данными — XSS в обход экранирования JSX. Для текста — `textContent` / `createTextNode` (ASVS 3.2.2, L1); имя тега
в `createElement` и атрибута в `setAttribute` — из константы, не из данных; обработчики — `addEventListener` с
функцией, не строкой в `on*`.
**Найти:** *(авто)* `eslint-plugin-no-unsanitized`; поиск `innerHTML` / `insertAdjacentHTML` / `.write(`.

**1.3. URL из данных — по белому списку схем.** *обязательно*
React 19 подменяет `javascript:` в `href` / `src` на ошибку (проверено, включая `' JaVaScRiPt:'`), но **`data:`
пропускает**, а ссылки, собранные вне JSX (`location.href = …`, `window.open(…)`), не трогает вовсе. Проверка —
разбором, а не регуляркой: `new URL(value, location.origin)` и `protocol` из списка (`https:`, `http:`, при
необходимости `mailto:` / `tel:`).
**Найти:** `href={` / `src={` / `location.href =` / `window.open(` со значением из API, профиля, URL-параметров.

**1.4. Никакого кода из строки.** *обязательно*
`eval`, `new Function`, `setTimeout` / `setInterval` со строкой — исполнение данных. JSON — только `JSON.parse`.
Строгая CSP (3.2) без `'unsafe-eval'` превращает это из правила в ограничение браузера.
**Найти:** *(авто)* ESLint `no-eval`, `no-implied-eval`, `no-new-func`; в бандле — `new Function` из зависимостей
(тогда CSP требует `'unsafe-eval'` — это решение записывается).

**1.5. Источники XSS — не только API.** *обязательно*
`location.hash` / `search`, `postMessage` (5.1), сообщения сокета (5.4), `localStorage` / `sessionStorage` (их мог
записать прошлый XSS), имя файла при загрузке, буфер обмена — недоверенные при каждом чтении, как ответ API.
**Найти:** чтение URL-параметров и хранилищ, которое уходит в синки из 1.1–1.3.

## 2. Сессия, токены, доступ

**2.1. Приложение с личными данными — токены не в JS.** *по ситуации: личные данные, платежи*
RFC 10017 располагает архитектуры по убыванию защищённости: **BFF** (сервер держит токены, браузер — только
HttpOnly-cookie сессии), **token-mediating backend** (сервер получает токены, отдаёт браузеру только access token),
**браузерный OAuth-клиент** (все токены в JS). BFF — «strongly recommended for business applications, sensitive
applications, and applications that handle personal data»; браузерный клиент для них — «not recommended» (§6.1.4.3,
§6.3.4.3). Причина: из BFF атакующий с XSS не уносит токены и не может запустить новый OAuth-flow — BFF
конфиденциальный клиент. Это архитектурное решение бэкенда; находка аудита — токены в JS при личных данных без
записанного решения.
**Найти:** `accessToken` / `refreshToken` в `localStorage`, `sessionStorage`, IndexedDB, Redux; заголовок
`Authorization: Bearer`, собираемый в клиентском коде.

**2.2. Если токены всё же в браузере — минимизировать ущерб.** *по ситуации: токены доступны JS*
- место хранения от XSS не спасает: «none of these options can fully mitigate token exfiltration» (RFC 10017 §8.5);
  но память — лучше постоянного хранилища (токен живёт только в текущей вкладке, §8.4); refresh token — в
  HttpOnly-cookie, которую ставит сервер, а не в JS;
- **не класть токены в cookie из JS** (`document.cookie`) — «NOT RECOMMENDED» (§8.1);
- access token живёт минуты; refresh token **ротируется при каждом использовании**, имеет максимальный срок, ротация
  этот срок не продлевает, срок привязан к сессии пользователя (§6.3.2.3 — требования к серверу авторизации);
- DPoP с неэкспортируемым ключом WebCrypto делает украденный токен бесполезным вне браузера жертвы (§9.2), но не
  мешает атакующему получить новые токены (§5.1.3).
**Найти:** время жизни access / refresh в ответе логина; повторное использование старого refresh token проходит.

**2.3. Cookie сессии — с полным набором атрибутов.** *по ситуации: сессия или refresh token в cookie*
`Secure`, `HttpOnly`, `SameSite` (Strict или Lax по назначению), имя с префиксом `__Host-`, `Path=/`, без `Domain`
(ASVS 3.3.1–3.3.4, RFC 10017 §6.1.3.2). При аутентификации по cookie нужна защита от CSRF: изменяющие запросы — только
не-GET (ASVS 3.5.3), и либо anti-CSRF токен, либо обязательный нестандартный заголовок (`X-Requested-With`), который
форсирует CORS preflight (ASVS 3.5.1–3.5.2, RFC 10017 §6.1.3.3.2). `SameSite` сам по себе не защищает от соседних
поддоменов того же сайта.
**Найти:** DevTools → Application → Cookies; `Set-Cookie` в ответе логина / refresh; GET-эндпоинты, меняющие данные.

**2.4. Выход и истечение — сессия мертва на сервере, клиент чист.** *обязательно*
Logout аннулирует сессию / refresh token на сервере (ASVS 7.4.1, L1), а клиент очищает всё своё: хранилища, кэш
React Query, store, кэши service worker, соединение сокета. Смена пароля или почты — с возможностью завершить другие
сессии (ASVS 7.4.3), смена email / телефона — с повторным вводом пароля (ASVS 7.5.1). Сбой обновления токена — выход,
а не работа на старом состоянии (fail closed).
**Найти:** после выхода — старый refresh token принимается сервером; данные прошлого пользователя видны после входа
другого в той же вкладке; в хранилищах остались ключи.

**2.5. Вход через OAuth / OIDC — Authorization Code + PKCE.** *по ситуации: вход через внешнего провайдера*
Если приложение само ведёт Authorization Code flow как публичный клиент — **PKCE обязателен** (RFC 10017 §6.3.2.1,
MUST), и сервер авторизации его требует. Implicit grant запрещён (§7.2), пароль провайдера в форму приложения — тоже
(§7.3). `state` / `nonce` проверяются (§6.3.2.2); redirect URI — точное совпадение у провайдера (§6.3.3.2.1).
ID token провайдера (Google, Facebook) проверяется **на бэкенде** — подпись, `aud`, `exp` (ASVS 9.1.1, 9.2.1,
9.2.3); фронт передаёт его, но решений по нему не принимает. Кнопка входа, отдающая ID token в callback (Google
Identity Services), — не code flow: PKCE к ней не относится, проверка на бэкенде — да. Popup-flow: у `postMessage`
проверяются оба origin (§6.3.3.3).
**Найти:** `response_type=token` в URL авторизации; `response_type=code` без `code_challenge`; токен в
`location.hash` после редиректа; решение «вошёл» по расшифрованному на клиенте JWT.

**2.6. Скрытое в UI не должно приходить в ответе.** *обязательно*
Роль, подписка, баланс, «премиум», закрытый контент — решает API. Размытие CSS-фильтром, `display: none`, заглушка
поверх контента не защищают, если оригинал есть в JSON или его URL угадывается. Проверка прав по каждому ресурсу —
на сервере (OWASP A01:2025 Broken Access Control, IDOR).
**Найти:** DevTools → Network: ответы на экранах с платным / закрытым контентом — нет ли там полных данных и прямых
URL; ID в URL заменить на чужой.

## 3. Заголовки ответа и CSP

**3.1. Базовые заголовки на каждом ответе.** *обязательно*

| Заголовок | Значение | Зачем |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` (+ `preload` после проверки на hstspreload.org) | только HTTPS (ASVS 3.4.1: ≥ 1 год) |
| `X-Content-Type-Options` | `nosniff` | браузер не угадывает тип (ASVS 3.4.4) |
| `Content-Security-Policy` | минимум `frame-ancestors 'none'` (или список своих доменов); полная — 3.2 | clickjacking (ASVS 3.4.6: `X-Frame-Options` устарел) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | путь и query не уходят третьим сторонам (ASVS 3.4.5) |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` — всё, что не используется | чужой iframe / скрипт не получит API |
| `Cross-Origin-Opener-Policy` | `same-origin`; при OAuth / платёжных popup — `same-origin-allow-popups` | изоляция окна (ASVS 3.4.8) |

Не отправлять: `X-XSS-Protection` (не ставить или `0`), `Expect-CT`, `Public-Key-Pins`, версию в `Server`,
`X-Powered-By` (OWASP HTTP Headers Cheat Sheet). **nginx:** `add_header … always`, иначе заголовка нет на ошибках;
**любой `add_header` внутри `location` молча отменяет все заголовки уровня `server`** — их повторяют через `include`
в каждом `location` (или `add_header_inherit merge;` в nginx 1.29.3+). Заголовки на CDN / в бакете — там же, где
отдаётся `index.html`.
**Найти:** *(авто)* Mozilla HTTP Observatory; `curl -sI https://<домен>/` и `curl -sI https://<домен>/<чанк>.js`.

**3.2. CSP — строгая, через хэши, сначала в report-only.** *обязательно*
CSP со списком доменов (`script-src https://cdn.example.com …`) обходится «in most configurations» (web.dev) — через
JSONP и гаджеты на разрешённых доменах. Строгая CSP разрешает скрипты по nonce / хэшу, а `'strict-dynamic'` передаёт
доверие скриптам, которые они загрузили. Статическому SPA nonce недоступен (ответ один на всех) — вариант с хэшами:

```http
Content-Security-Policy: script-src 'sha256-<хэш inline-скрипта>' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp; report-uri https://<сборщик>/csp
Reporting-Endpoints: csp="https://<сборщик>/csp"
```

- хэш считается **после сборки** по точным байтам каждого inline-скрипта в `index.html`, включая вставленные
  плагинами (plugin-legacy, GTM-сниппет); внешние бандлы грузит inline-загрузчик через `createElement('script')` —
  их пропускает `'strict-dynamic'`, либо `<script src>` с `integrity` и тем же хэшем в `script-src` (Chrome 59+,
  Firefox 116+, Safari 15.6+ — caniuse; в `script-src` должны быть все хэши из `integrity`);
- `https:` и `'unsafe-inline'` — только для старых браузеров: при хэше / nonce современные их игнорируют;
- `report-uri` устарел, но пока `report-to` поддержан не везде — оба;
- `<meta http-equiv>` не умеет report-only и `frame-ancestors` — только заголовок;
- выкатка: `Content-Security-Policy-Report-Only` → разбор отчётов → enforce (ASVS 3.4.3, 3.4.7).
Политика ограничивает только скрипты: `img-src`, `connect-src`, `style-src` она не задаёт, и, если их добавить (или
`default-src`), домены аналитики придётся перечислить. **GTM:** гайд Google (developers.google.com/tag-platform/
security/guides/csp) рекомендует nonce, хэш сниппета допускает, `'strict-dynamic'` не разбирает. По механике
`'strict-dynamic'` контейнер, загруженный хэшированным сниппетом, получает доверие; Custom HTML теги с inline-кодом —
вывод, а не факт из источника: проверяется по отчётам report-only. **Custom JavaScript variables в GTM без
`'unsafe-eval'` возвращают `undefined`** — их заменяют Custom Templates, а не добавляют `'unsafe-eval'`.
**Найти:** заголовок CSP в ответе `index.html`; `unsafe-inline` без хэша / nonce рядом; *(авто)* Lighthouse (Best
Practices → «CSP effective against XSS»), CSP Evaluator.

**3.3. Trusted Types — когда есть DOM-синки, которые не убрать.** *по ситуации: HTML из данных, сторонние виджеты*
`require-trusted-types-for 'script'` запрещает передавать строку в `innerHTML`, `eval`, `script.src` и другие синки —
только объект из именованной политики (`trustedTypes.createPolicy('sanitize', {createHTML: (s) => DOMPurify.sanitize(s)})`);
`trusted-types sanitize` ограничивает имена политик; политика `default` — крайняя мера. Поддержка — Chrome / Edge 83,
Firefox 148, Safari 26 — Baseline (newly available) с 24.02.2026. Выкатка — тоже через report-only. React 19.3
передаёт `TrustedHTML` в `dangerouslySetInnerHTML` без приведения к строке.
**Найти:** `require-trusted-types-for` в CSP; отчёты о нарушениях.

**3.4. Ответы с личными данными не кэшируются.** *обязательно*
API с личными данными — `Cache-Control: no-store` (`no-cache` разрешает хранение). В Cache API service worker —
только статика: `Cache-Control` на него не действует (OWASP HTML5 / HTTP Headers).
**Найти:** заголовки ответов API в DevTools; что кладёт в `caches` service worker.

## 4. Сторонние скрипты и платёжная страница

**4.1. Каждый сторонний скрипт — в списке, с владельцем и причиной.** *обязательно*
Аналитика, пиксели, чаты поддержки, SDK входа и оплаты, капча, антифрод выполняются с правами приложения (главное
правило). Список: что, кто владелец, зачем, на каких страницах, что читает. Tag manager — это возможность
выкатывать код без релиза: публикация — у узкого круга с 2FA, изменения контейнера читаются как код. Data layer «is
not a sandbox»: в него не попадают токены и личные данные, а правила маркетинга не берут значения из URL в
исполняемые места (OWASP Third Party JavaScript Management).
**Найти:** DevTools → Network по типу `script` с чужих доменов; сравнить со списком; права на публикацию в GTM.

**4.2. Статичный чужой файл — с SRI.** *по ситуации: скрипт / стиль с чужого домена с версией в URL*
`integrity="sha384-…"` + `crossorigin="anonymous"` (CDN должен отдавать CORS). Загрузчики, чей файл меняется
без смены URL (`gtm.js` — при каждой публикации контейнера, SDK без версии в пути), с закреплённым хэшем сломаются —
для них решение без SRI записывается в список из 4.1 (ASVS 3.6.1, L3).
**Найти:** `<script src="https://…">` без `integrity` в `index.html`.

**4.3. Платёжная страница — минимум скриптов и контроль их изменений.** *по ситуации: встроенная форма оплаты*
Данные карты вводятся только в iframe / поле платёжного провайдера, не в свою разметку. PCI DSS (SAQ A, с февраля
2025): мерчант, встраивающий форму провайдера, подтверждает, что его страница «not susceptible to attacks from
scripts» — техниками требований 6.4.3 (инвентарь скриптов страницы оплаты, их авторизация и целостность) и 11.6.1
(обнаружение несанкционированных изменений заголовков и скриптов) или письменным подтверждением провайдера (PCI SSC
FAQ 1588). Редирект на страницу провайдера под этот критерий не попадает. Практика: на странице оплаты не грузить
GTM, пиксели и чаты; CSP-отчёты (3.2) служат сигналом изменений.
**Найти:** скрипты, загруженные на экране оплаты; есть ли инвентарь и процедура уведомления о новых.

**4.4. Чужой контент — в `sandbox`-iframe.** *по ситуации: виджеты, превью, пользовательский HTML*
`sandbox` с минимумом разрешений; `allow-scripts` вместе с `allow-same-origin` для того же origin снимает изоляцию.
**Найти:** `<iframe` без `sandbox` с внешним или пользовательским содержимым.

## 5. Окна, переходы, соединения

**5.1. `postMessage` — с точным origin в обе стороны.** *обязательно*
Отправка — с конкретным `targetOrigin`, не `'*'`. Приём — `event.origin` сравнивается **на точное равенство** со
списком: `indexOf('.example.com')` пропускает `example.com.attacker.net`. Схема сообщения проверяется, данные идут в
`textContent`, не в HTML (OWASP HTML5, ASVS 3.5.5, RFC 10017 §6.3.3.3).
**Найти:** `addEventListener('message'` без проверки `origin` в первых строках обработчика; `postMessage(…, '*')`;
`includes` / `indexOf` / `endsWith` по origin.

**5.2. Переходы по URL из параметров — только на свои адреса.** *обязательно*
`?redirect=`, `returnUrl`, `next` после входа или оплаты — открытый редирект для фишинга. Разрешать только
относительные пути своего origin: `new URL(v, location.origin).origin === location.origin` (строка `//evil.com` и
`/\evil.com` — это чужой хост); внешние — по списку (ASVS 3.7.2).
**Найти:** чтение `redirect` / `return` / `next` / `url` из query с последующим `navigate` / `location.href`.

**5.3. Новые окна — без доступа к `opener`.** *обязательно*
`target="_blank"` в современных браузерах уже подразумевает `noopener`, а `window.open` — нет: третий аргумент
`'noopener,noreferrer'` (OWASP HTML5, tabnabbing). Если `opener` нужен (OAuth / платёжный popup) — только для своих
доменов, с COOP `same-origin-allow-popups` (3.1).
**Найти:** `window.open(` без `noopener`.

**5.4. WebSocket — `wss`, токен не в URL, данные недоверенные.** *обязательно*
Только `wss://`; токен — первым сообщением или в поле аутентификации handshake (в Socket.io — `auth`), не в query
string: он попадёт в логи прокси (OWASP WebSocket Security). Сервер проверяет `Origin` по списку (Cross-Site
WebSocket Hijacking), авторизацию — на каждое действие, а не один раз при подключении. Входящие сообщения
валидируются как ответ API (1.5); при выходе соединение закрывается (2.4).
**Найти:** URL сокета с `token=`; `ws://` в продовом конфиге; рукопожатие с чужим `Origin` принимается.

**5.5. Service worker — узкий scope и выключатель.** *по ситуации: есть service worker*
Файл — с фиксированного пути по HTTPS, `scope` — минимальный; в Cache API — не ответы API с личными данными (3.4);
если воркер держит токены — не в хранилище, общем с окном, например IndexedDB (RFC 10017 §8.2, MUST NOT);
есть путь аварийно снять воркер (`unregister` + очистка кэшей) с новым деплоем. Параметры, переданные воркеру через
query при регистрации, проверяются им по списку значений.
**Найти:** `navigator.serviceWorker.register` — scope; что воркер кэширует; есть ли код снятия.

## 6. Данные в браузере и утечки

**6.1. Публичные переменные сборки — публичны.** *обязательно*
Всё, что сборщик вшивает в клиентский код (`VITE_*`, `NEXT_PUBLIC_*`), попадает в JS и видно любому. Ключи API — на
сервере / edge; в клиенте — только публичные идентификаторы (ключ сайта капчи, DSN Sentry, id GTM). Секрет,
нужный только в разработке, — под `import.meta.env.DEV`, и сборка проверяется на его отсутствие. `.env.*.local` — в
`.gitignore`.
**Найти:** `VITE_` / `NEXT_PUBLIC_` с `KEY`, `SECRET`, `TOKEN` в имени; поиск строк ключей и заголовков в `dist/`.

**6.2. Один артефакт на несколько окружений — только с конфигом в рантайме.** *по ситуации: build once, deploy
many*
Публичные переменные замораживаются при сборке: образ, выкаченный на stage и production, получит значения окружения
сборки. Либо сборка на каждое окружение, либо конфиг читается при запуске (`config.json`, ответ сервера).
**Найти:** один артефакт для нескольких окружений + `import.meta.env` в клиентском коде.

**6.3. В хранилищах браузера — минимум и ничего навсегда.** *обязательно*
`localStorage` живёт без срока и читается любым скриптом origin; в нём нет токенов (2.1), паролей, документов,
переписки. Что нужно между перезагрузками — `sessionStorage` или с явным сроком; при выходе — очистка (2.4). Одно
приложение — один origin: соседние приложения на том же хосте делят хранилища и cookie (ASVS 3.5.4, RFC 10017 §9.4).
**Найти:** DevTools → Application: ключи `localStorage` / IndexedDB у залогиненного пользователя и после выхода.

**6.4. Мониторинг ошибок не собирает токены и личные данные.** *обязательно*
SDK мониторинга по умолчанию собирают много; настройка — до первого продового события:
- Sentry + Redux: `createReduxEnhancer` по умолчанию прикладывает **весь state** к каждой ошибке (`attachReduxState`)
  и отправляет все actions в breadcrumbs — `stateTransformer` вырезает токены и личные данные, `actionTransformer`
  — поля actions;
- заголовки, cookie, query string, тела запросов — по умолчанию собираются (`dataCollection` с SDK 10.57); встроенный
  список чувствительных ключей (`auth`, `token`, `secret`, `session`, `jwt` и др.) ловит только **имена** ключей — не
  значения в URL и не поля вроде `email`, `phone`, `birthDate`;
- пользователь — `Sentry.setUser({id})`, без email;
- Session Replay — маскирование по умолчанию (`maskAllText`, `maskAllInputs`, `blockAllMedia`) не отключать;
- серверный скраббинг в проекте Sentry — включён, свои поля — в «Additional Sensitive Fields».
**Найти:** открыть событие ошибки в Sentry: вложение `redux_state.json`, breadcrumbs, заголовки запросов — есть ли
токены, email, переписка.

**6.5. Секреты не в URL.** *обязательно*
Токен в query string оседает в истории браузера, логах прокси и CDN, breadcrumbs мониторинга, а при переходе на чужой
сайт — в `Referer` (если Referrer-Policy слабее 3.1). Ссылки с одноразовым токеном (подтверждение почты, вход по
ссылке): обменять токен на сессию и сразу убрать из адреса (`history.replaceState`).
**Найти:** `token=` / `code=` / `key=` в URL приложения и в breadcrumbs мониторинга.

**6.6. Сторонним сервисам — без личных данных.** *обязательно*
В события аналитики, пиксели, `dataLayer`, URL, уходящие трекерам, не попадают email, телефон, имя, текст сообщений.
Идентификатор пользователя — внутренний id или его хэш, если провайдер требует.
**Найти:** DevTools → Network: запросы к доменам аналитики и их параметры на экранах с профилем и чатом.

**6.7. Source maps — не публичны.** *обязательно*
Source map открывает исходники с комментариями и внутренними адресами. Сборка — `sourcemap: 'hidden'` (без ссылки в
бандле), загрузка в мониторинг, затем удаление файлов или запрет `*.map` на сервере. В плагине Sentry удаление
задаётся явно (`sourcemaps.filesToDeleteAfterUpload: ['dist/**/*.map']`): значения по умолчанию у опции нет, и карты,
включённые самим проектом (`'hidden'`), без неё остаются в `dist/`.
**Найти:** `curl -sI https://<домен>/assets/<чанк>.js.map` — должен быть 404; `sourceMappingURL` в продовых чанках.

**6.8. В консоль продакшена — без данных.** *обязательно*
`console.log` с ответами API, токенами, state видит любое расширение браузера и любой, кто открыл DevTools на чужом
компьютере. В продовой сборке логирование — через мониторинг (6.4) или вырезается.
**Найти:** *(авто)* ESLint `no-console`; в продовой консоли после входа и открытия чата — нет данных.

**6.9. Ошибка — пользователю без внутренностей.** *обязательно*
UI показывает понятное сообщение, а не текст исключения, стек, SQL или ответ сервера целиком; детали — в мониторинг
(OWASP A10:2025 Mishandling of Exceptional Conditions).
**Найти:** экраны ошибок и тосты: что показывается при 500 от API.

## 7. Окружение разработки

**7.1. Dev-сервер — не в сети без надобности, и с явным списком хостов.** *обязательно*
По умолчанию Vite слушает только `localhost`. `server.host: true` открывает dev-сервер в LAN и публичные адреса;
**`allowedHosts: true` позволяет любому сайту читать исходники через DNS rebinding** (предупреждение «DANGER» в
документации Vite), `cors: true` — тоже. Если сервер должен быть доступен (Docker, обратный прокси, телефон в сети) —
в `allowedHosts` явный список своих dev-хостов (`['app.test', …]`), `cors` по умолчанию, `server.fs.deny` не
переопределять (по умолчанию закрывает `.env*`, ключи, `.npmrc`, `.git`). Большинство уязвимостей Vite 2025–2026
(обходы `fs.deny`, чтение файлов через WebSocket, RCE через `__vite-browser-external` — critical, ноябрь 2026)
срабатывают только на открытом в сеть dev-сервере — поэтому при `host: true` Vite обновляется по advisories так же
срочно, как продовая зависимость.
**Найти:** `host` / `allowedHosts` / `cors` в `vite.config.*`; версия Vite против
github.com/vitejs/vite/security/advisories.

**7.2. Секреты dev-окружения — вне бандла.** *обязательно*
Ключи и заголовки доступа к закрытому dev / stage API (Zero Trust-прокси, basic auth, сервисные токены) — только в
ветке кода, которую сборка выкидывает статически (`if (import.meta.env.DEV)`), и только из `.env.*.local`. После
изменения — проверка `dist/` на значения.
**Найти:** поиск имён секретов и их значений в `dist/` после продовой сборки.

## 8. Next.js

**8.1. Данные и Server Actions.** *обязательно для Next.js*
- один подход к данным на проект; для нового — **Data Access Layer**: только сервер (`import 'server-only'`),
  проверка авторизации, возвращает минимальный DTO; `process.env` и пакеты БД — только внутри DAL;
- Server Action доступна прямым POST: в каждой — валидация аргументов, аутентификация и **авторизация** (владеет ли
  пользователь ресурсом — защита от IDOR); проверка на странице на action не распространяется; возвращать только
  нужное UI; дорогие операции — rate limiting;
- папки `[param]` — пользовательский ввод, валидировать;
- `proxy.ts` (до Next.js 16 — `middleware.ts`) и `route.ts` — самые мощные точки входа, аудитировать отдельно;
- мутации — никогда в рендере;
- Taint API (`experimental.taint`) — дополнительный слой, не замена фильтрации в DAL.
**Найти:** импорт пакетов БД и `process.env` вне DAL; `'use server'` без проверки сессии и прав; props клиентских
компонентов с целыми сущностями.

**8.2. CSP с nonce.** *обязательно для Next.js с динамическим рендером*
В отличие от статического SPA (3.2), сервер может выдавать nonce на каждый ответ: `script-src 'nonce-…'
'strict-dynamic'` из `proxy.ts`. Цена — страницы с nonce не кэшируются статически.
**Найти:** CSP в ответах; `unsafe-inline` вместо nonce.

## 9. Процесс

**9.1. Защитные lint-правила — в CI.** *обязательно*
`react/no-danger` (или `no-danger-with-children` + ревью), `no-unsanitized/method`, `no-unsanitized/property`,
`no-eval`, `no-implied-eval`, `no-new-func`, `no-console` для продовой сборки. Исключение — `eslint-disable` с
причиной в той же строке.
**Найти:** *(авто)* эти правила в конфиге ESLint; `eslint-disable` для них без причины.

**9.2. Изменения в чувствительных местах — с отдельным ревью.** *обязательно*
Вход и токены, оплата, вывод HTML, редиректы, `postMessage`, заголовки сервера, CSP, подключение сторонних скриптов —
`CODEOWNERS` или чек-лист PR с этими пунктами; для AI-агента — те же правила в инструкциях проекта.
**Найти:** PR, менявшие эти места без ревьюера по безопасности.

**9.3. Проверка снаружи — регулярно.** *обязательно*
Раз в релиз или по расписанию: заголовки (HTTP Observatory), CSP-отчёты (их кто-то читает), `.map` недоступны,
ключи не в бандле, `npm audit` по продовым зависимостям ([dependency-hygiene.md](dependency-hygiene.md) 3.1).
Для статического анализа JS / TS — CodeQL или Semgrep в CI.
**Найти:** нет ни одной автоматической проверки из списка.

## 10. Минимальный набор

**Заголовки (nginx, `security-headers.conf`, подключается `include` в каждый `location` с `add_header`):**

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
# при входе / оплате через popup (Google, PayPal) — "same-origin-allow-popups"
add_header Cross-Origin-Opener-Policy "same-origin" always;
# действует сразу: report-only не блокирует, в том числе frame-ancestors
add_header Content-Security-Policy "frame-ancestors 'none'; object-src 'none'; base-uri 'none'" always;
# строгая script-src — сначала в report-only (3.2)
add_header Content-Security-Policy-Report-Only "script-src 'sha256-…' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp; report-uri https://…/csp" always;
add_header Reporting-Endpoints 'csp="https://…/csp"' always;
server_tokens off;
```

**ESLint:**

```js
// eslint.config.mjs — пакеты eslint-plugin-react, eslint-plugin-no-unsanitized, globals
import react from 'eslint-plugin-react'
import noUnsanitized from 'eslint-plugin-no-unsanitized'
import globals from 'globals'

const files = ['**/*.{js,jsx,ts,tsx}']

export default [
  {files, ...noUnsanitized.configs.recommended},
  {
    files,
    plugins: {react},
    // без globals.browser no-implied-eval не видит setTimeout('…') — проверено
    languageOptions: {globals: globals.browser},
    rules: {'react/no-danger': 'error', 'no-eval': 'error', 'no-implied-eval': 'error', 'no-new-func': 'error'}
  }
]
```

Проверено на ESLint 9.39, eslint-plugin-react 7.37, eslint-plugin-no-unsanitized 4.1: ловит `innerHTML =`, `eval`,
`setTimeout` со строкой, `new Function`, `dangerouslySetInnerHTML`. Для `.ts` / `.tsx` нужен парсер проекта
(typescript-eslint) — в существующем конфиге эти правила добавляются к нему.

**Sentry:**

```ts
// белый список: в событие уходит только перечисленное, новый слайс сам не утечёт
Sentry.createReduxEnhancer({
  stateTransformer: (state) => ({userId: state.user?.id, route: state.router?.pathname}),
  actionTransformer: (action) => ({type: action.type})
})
```

**Проверки:**

| Проверка | Как | Когда |
|---|---|---|
| Заголовки и CSP | Mozilla HTTP Observatory, `curl -sI` | каждый релиз |
| CSP-нарушения | отчёты `report-to` / `report-uri` | постоянно |
| Опасные синки и eval | ESLint (9.1), CodeQL / Semgrep | каждый PR |
| Source maps закрыты | `curl -sI …/*.js.map` → 404 | каждый релиз |
| Ключи не в бандле | поиск по `dist/` | каждая сборка |
| Сторонние скрипты | Network по чужим доменам против списка 4.1 | раз в квартал, перед изменениями оплаты |
| Данные в Sentry | открыть свежее событие ошибки | после изменений store / SDK |
| Токены и выход | DevTools → Application до и после logout | при изменениях авторизации |
| Vite dev-сервер | версия против advisories, `host` / `allowedHosts` | при каждом advisory |

## Знать, применять по поводу

| Что | Когда вспомнить |
|---|---|
| DOM clobbering (ASVS 3.2.3) | `id` / `name` из пользовательского HTML совпадают с глобальными переменными |
| `Integrity-Policy` (MDN) | требовать SRI для всех скриптов и стилей; начинать с `-Report-Only` |
| COEP `require-corp`, CORP | нужен `SharedArrayBuffer` / кросс-оригинная изоляция; ломает чужие ресурсы без CORS / CORP |
| Fetch Metadata (`Sec-Fetch-*`) | серверная защита от CSRF и XSSI (ASVS 3.5.3, 3.5.8) |
| `Clear-Site-Data` | серверный способ очистить хранилища и кэш при выходе |
| JSONP, данные в ответах-скриптах (ASVS 3.5.6–3.5.7) | API отдаёт `text/javascript` или `callback=` |
| DPoP (RFC 9449) | токены остаются в браузере, и нужен шаг дальше 2.2 |
| Mix-up атаки (RFC 10017 §9.3) | приложение работает с двумя и более серверами авторизации |
