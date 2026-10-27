'use strict';

// Run with node --test tests/authentication.test.cjs. Platform services are mocked; no network is used.
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const root = join(__dirname, '..');
const backend = readFileSync(join(root, 'src/code-resources/sql-studio-backend.html'), 'utf8');
const page = readFileSync(join(root, 'src/cloud-page/sql-studio.html'), 'utf8');
const pageURL = 'https://sqlstudio.example.invalid/app';
const backendURL = 'https://sqlstudio.example.invalid/backend';
const storeKey = 'ss.session.' + backendURL;
const userId = 'test-user';
const secret = 'test-client-secret';
const hash = value => createHash('sha256').update(value).digest('hex');
const serverScript = html => html.match(/^<script runat="server">([\s\S]*)<\/script>/)[1];

function runtime(configuration = {}) {
    const cookies = new Map();
    const rows = new Map();
    const encrypted = new Map();
    const requests = [];
    let cipherIndex = 0;
    let authLogPresent = !configuration.missingAuthLog;

    function render(html, options = {}) {
        const headers = {};
        const output = [];
        const variables = new Map();
        const requestCookies = new Map(options.cookies || cookies);
        const url = new URL(options.url || (html === backend ? backendURL : pageURL));
        let redirect;
        const redirected = {};
        const lookupCalls = [];
        const context = {
            Stringify: JSON.stringify, GUID: randomUUID, Write: value => output.push(String(value)),
            Platform: {
                Load() {},
                Request: {
                    Method: () => options.method || 'GET',
                    RequestURL: url.href,
                    GetQueryStringParameter: name => url.searchParams.get(name),
                    GetFormField: name => (options.form || {})[name],
                    GetRequestHeader: () => Object.hasOwn(options, 'origin') ? options.origin : new URL(backendURL).origin,
                    GetCookieValue(name) {
                        if (options.cookieReadError) throw new Error('Cookie unavailable');
                        return requestCookies.get(name) || null;
                    }
                },
                Response: {
                    SetResponseHeader(name, value) { headers[name] = value; },
                    Redirect(value) { redirect = value; throw redirected; }
                },
                Variable: { SetValue: (name, value) => variables.set(name, value) },
                Function: {
                    ParseJSON: JSON.parse,
                    Now: () => new Date(),
                    SystemDateToLocalDate: value => value,
                    Lookup(de, field, keys, values) {
                        if (!authLogPresent) throw new Error('Data Extension does not exist');
                        lookupCalls.push({ field, keys, values });
                        return (rows.get(values[keys.indexOf('session')]) || {})[field] ?? null;
                    },
                    UpsertData(de, keys, values, fields, data) {
                        if (!authLogPresent) throw new Error('Data Extension does not exist');
                        rows.set(values[0], Object.fromEntries(fields.map((field, i) => [field, data[i]])));
                        return 1;
                    },
                    InsertData() { return 1; },
                    TreatAsContent(content) {
                        if (content.includes('SHA256(')) return hash(variables.get('@ssHashInput'));
                        const text = variables.get('@ssCryptText');
                        if (content.includes('EncryptSymmetric(')) {
                            const cipher = Buffer.from('opaque-ciphertext-' + (++cipherIndex)).toString('base64');
                            encrypted.set(cipher, text);
                            return cipher;
                        }
                        if (content.includes('DecryptSymmetric(')) return encrypted.get(text) || '';
                        throw new Error('Unexpected AMPscript');
                    }
                }
            },
            Script: { Util: { WSProxy: class {
                createItem(type, data) {
                    assert.equal(type, 'DataExtension');
                    assert.equal(data.CustomerKey, 'SQL Studio Auth Log');
                    authLogPresent = true;
                    return { Results: [{ StatusCode: 'OK' }] };
                }
            }, HttpRequest: class {
                constructor(address) { this.url = address; }
                setHeader() {}
                send() {
                    requests.push({ url: this.url, method: this.method, body: this.postData });
                    if (this.url.endsWith('/v2/token')) {
                        return { statusCode: options.tokenFailure ? 400 : 200, content: JSON.stringify(
                            options.tokenFailure ? { error: 'invalid_grant' } : { access_token: 'test-access-token', expires_in: 1200 }
                        ) };
                    }
                    assert.ok(this.url.endsWith('/v2/userinfo'));
                    return { statusCode: 200, content: JSON.stringify({ user: { sub: userId, name: 'Test User', email: 'user@example.invalid' } }) };
                }
            } } }
        };
        const source = serverScript(html)
            .replace("'SQL_STUDIO_PAGE_URL'", JSON.stringify(options.pageURL || pageURL))
            .replace("'SQL_STUDIO_BACKEND_URL'", JSON.stringify(backendURL))
            .replace("'SQL_STUDIO_FRONTEND_URL'", "'https://sqlstudio.example.invalid/frontend'")
            .replace("'CLIENT_ID'", "'test-client-id'")
            .replace("'CLIENT_SECRET'", JSON.stringify(secret))
            .replace("'API_BASE_URI'", "'mcaaaaaaaaaaaaaaaaaaaaaaaaaa'");
        try { vm.runInNewContext(source, context, { timeout: 1000 }); }
        catch (error) { if (error !== redirected) throw error; }
        if (headers['Set-Cookie'] && options.acceptCookies !== false) {
            const [pair] = headers['Set-Cookie'].split(';');
            const separator = pair.indexOf('=');
            const name = pair.slice(0, separator);
            if (headers['Set-Cookie'].includes('Max-Age=0;')) cookies.delete(name);
            else cookies.set(name, pair.slice(separator + 1));
        }
        return { html: output.join(''), headers, redirect, lookupCalls };
    }

    function start(options) {
        const result = render(backend, options);
        return { ...result, state: result.redirect ? new URL(result.redirect).searchParams.get('state') : null };
    }

    function finish(state, options = {}) {
        return render(backend, { url: backendURL + '?code=test-code&state=' + encodeURIComponent(state), ...options });
    }

    return { cookies, rows, requests, render, start, finish };
}

function sessionFrom(result) {
    const match = result.html.match(/name="s" value="([0-9a-f-]{36})"/i);
    assert.ok(match, result.html);
    return match[1];
}

test('all server and frontend JavaScript parses', () => {
    new vm.Script(serverScript(backend));
    new vm.Script(serverScript(page));
    for (const file of ['sql-studio-frontend.js', 'sql-studio-frontend.min.js']) {
        new vm.Script(readFileSync(join(root, 'src/code-resources', file), 'utf8'));
    }
});

test('a fresh sign-in sets a short-lived, host-only, secure HttpOnly state cookie', () => {
    const app = runtime();
    const initial = app.start();
    assert.match(initial.state, /^[0-9a-f-]{36}\.[0-9]{13}$/i);
    assert.match(initial.headers['Set-Cookie'], /^__Host-SQLStudioOAuth-/);
    for (const flag of ['Path=/', 'Max-Age=300', 'Secure', 'HttpOnly', 'SameSite=None']) {
        assert.ok(initial.headers['Set-Cookie'].includes(flag));
    }
    assert.ok(!initial.headers['Set-Cookie'].includes('Domain='));
    assert.equal(initial.headers['Cache-Control'], 'no-store');
    assert.equal(initial.headers['Referrer-Policy'], 'strict-origin');
    assert.equal(app.requests.length, 0);
});

test('a matching callback consumes its cookie and POSTs a fresh session without a credential URL', () => {
    const app = runtime();
    const initial = app.start();
    const result = app.finish(initial.state);
    const session = sessionFrom(result);
    assert.notEqual(session, initial.state.split('.')[0]);
    assert.equal(result.redirect, undefined);
    assert.match(result.html, new RegExp('method="post" action="' + pageURL + '"'));
    assert.ok(!result.html.includes('?s='));
    assert.ok(!result.html.includes('test-access-token'));
    assert.equal(result.headers['Content-Type'], 'text/html; charset=utf-8');
    assert.equal(result.headers['Cache-Control'], 'no-store');
    assert.equal(result.headers['Referrer-Policy'], 'strict-origin');
    assert.match(result.headers['Set-Cookie'], /Max-Age=0;/);
    assert.equal(app.cookies.size, 0);
    assert.equal(app.requests.length, 2);
    assert.equal(app.rows.get(hash(session)).userId, userId);
    const replay = app.finish(initial.state);
    assert.equal(new URL(replay.redirect).searchParams.get('error'), 'invalid_state');
    assert.equal(app.requests.length, 2);
});

test('missing, malformed, expired, future and browser-mismatched states never exchange a code', () => {
    const cases = ['missing', 'malformed', 'expired', 'future', 'different-browser', 'wrong-cookie', 'blocked-cookie', 'cookie-read-error'];
    for (const scenario of cases) {
        const app = runtime();
        const initial = app.start({ acceptCookies: scenario !== 'blocked-cookie' });
        let state = initial.state;
        const options = {};
        if (scenario === 'missing') state = '';
        if (scenario === 'malformed') state = randomUUID();
        if (scenario === 'different-browser') options.cookies = new Map();
        if (scenario === 'wrong-cookie') app.cookies.set([...app.cookies.keys()][0], 'forged-proof');
        if (scenario === 'cookie-read-error') options.cookieReadError = true;
        if (scenario === 'expired' || scenario === 'future') {
            state = state.split('.')[0] + '.' + (Date.now() + (scenario === 'expired' ? -301000 : 60000));
            app.cookies.set([...app.cookies.keys()][0], hash('SQLStudio.oauth-state.v1|' + state + '|' + secret));
        }
        const result = app.finish(state, options);
        assert.equal(new URL(result.redirect).searchParams.get('error'), 'invalid_state', scenario);
        assert.equal(app.requests.length, 0, scenario);
        assert.equal(app.rows.size, 0, scenario);
    }
});

test('concurrent sign-ins keep separate browser proofs', () => {
    const app = runtime();
    const first = app.start();
    const second = app.start();
    assert.equal(app.cookies.size, 2);
    const firstSession = sessionFrom(app.finish(first.state));
    assert.equal(app.cookies.size, 1);
    const secondSession = sessionFrom(app.finish(second.state));
    assert.notEqual(firstSession, secondSession);
    assert.equal(app.cookies.size, 0);
});

test('first sign-in still creates Auth Log and carries the pending setup flag in the POST', () => {
    const app = runtime({ missingAuthLog: true });
    const result = app.finish(app.start().state);
    const session = sessionFrom(result);
    assert.match(result.html, /name="setup" value="pending"/);
    assert.equal(app.rows.get(hash(session)).userId, userId);
    const opened = app.render(page, { method: 'POST', form: { s: session, setup: 'pending' } });
    assert.ok(opened.html.includes('setupPending: true'));
});

test('OAuth errors must match browser state and consume it too', () => {
    const app = runtime();
    const initial = app.start();
    const forged = app.render(backend, { url: backendURL + '?error=access_denied&state=' + randomUUID() });
    assert.equal(new URL(forged.redirect).searchParams.get('error'), 'invalid_state');
    assert.equal(app.cookies.size, 1);
    const actual = app.render(backend, { url: backendURL + '?error=access_denied&state=' + initial.state });
    assert.equal(new URL(actual.redirect).searchParams.get('error'), 'access_denied');
    assert.equal(app.cookies.size, 0);
    assert.equal(app.requests.length, 0);
});

test('bad authorization codes or failed exchanges never hand over a session', () => {
    for (const failure of ['missing-code', 'long-code', 'exchange-failed']) {
        const app = runtime();
        const initial = app.start();
        const url = backendURL + '?state=' + initial.state +
            (failure === 'missing-code' ? '' : '&code=' + (failure === 'long-code' ? 'a'.repeat(513) : 'test-code'));
        const result = app.render(backend, { url, tokenFailure: failure === 'exchange-failed' });
        assert.equal(new URL(result.redirect).searchParams.get('error'),
            failure === 'exchange-failed' ? 'token_exchange_failed' : 'invalid_request');
        assert.ok(!result.html.includes('name="s"'));
        assert.equal(app.rows.size, 0);
        assert.equal(app.cookies.size, 0);
    }
});

test('HTTP and cross-origin handoff destinations are rejected before OAuth starts', () => {
    for (const pageURL of ['http://sqlstudio.example.invalid/app', 'https://other.example.invalid/app']) {
        const app = runtime();
        const result = app.start({ pageURL });
        assert.equal(new URL(result.redirect).searchParams.get('error'), 'signin_failed');
        assert.equal(app.cookies.size, 0);
        assert.equal(app.requests.length, 0);
    }
});

test('the Cloud Page accepts the POST handoff and rejects session-bearing GETs and malformed POSTs', () => {
    const app = runtime();
    const session = sessionFrom(app.finish(app.start().state));
    const result = app.render(page, { method: 'POST', form: { s: session, setup: 'pending' } });
    assert.ok(result.html.includes("session: '" + session + "'"));
    assert.ok(result.html.includes('sessionStorage.setItem('));
    assert.ok(result.html.includes('setupPending: true'));
    assert.equal(result.headers['Cache-Control'], 'no-store');
    assert.equal(result.headers['Referrer-Policy'], 'strict-origin');
    for (const options of [
        { url: pageURL + '?s=' + session },
        { url: pageURL + '?s=' + session, method: 'POST', form: { s: session } },
        { method: 'POST', form: { s: '<script>' } }
    ]) {
        const denied = app.render(page, options);
        assert.ok(!denied.html.includes('window.SQLStudioConfig ='));
        assert.equal(denied.lookupCalls.length, 0);
    }
});

test('even a valid session cannot be injected by an external, missing or opaque POST origin', () => {
    const app = runtime();
    const session = sessionFrom(app.finish(app.start().state));
    for (const origin of [
        null, '', 'null', 'https://external.example.invalid',
        'https://sqlstudio.example.invalid.evil.invalid', 'http://sqlstudio.example.invalid',
        'https://sqlstudio.example.invalid:444'
    ]) {
        const result = app.render(page, { method: 'POST', form: { s: session }, origin });
        assert.ok(!result.html.includes('window.SQLStudioConfig ='), String(origin));
        assert.equal(result.lookupCalls.length, 0, String(origin));
    }
});

function bootstrap(html, saved, blocked = false) {
    const forms = [];
    const error = { hidden: true };
    let redirect;
    const context = {
        sessionStorage: { getItem() { if (blocked) throw new Error('Blocked'); return saved; } },
        location: { origin: new URL(pageURL).origin, pathname: '/app', replace(value) { redirect = value; } },
        document: {
            getElementById: () => error,
            body: { appendChild() {} },
            createElement(tag) {
                return { tag, fields: [], appendChild(input) { this.fields.push(input); }, submit() { forms.push(this); } };
            }
        }
    };
    const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].find(match => match[1].includes('sessionStorage.getItem'))[1];
    vm.runInNewContext(script, context);
    return { forms, error, redirect };
}

test('a clean reload restores the tab session in a POST body, never a URL', () => {
    const app = runtime();
    const html = app.render(page).html;
    const session = randomUUID();
    const restored = bootstrap(html, session);
    assert.equal(restored.forms.length, 1);
    assert.equal(restored.forms[0].method, 'post');
    assert.equal(restored.forms[0].action, pageURL);
    assert.equal(restored.forms[0].fields[0].name, 's');
    assert.equal(restored.forms[0].fields[0].value, session);
    assert.equal(bootstrap(html, null).redirect, backendURL);
    assert.equal(bootstrap(html, '<script>').redirect, backendURL);
    const blocked = bootstrap(html, session, true);
    assert.equal(blocked.forms.length, 0);
    assert.equal(blocked.redirect, undefined);
    assert.equal(blocked.error.hidden, false);
});

for (const file of ['sql-studio-frontend.js', 'sql-studio-frontend.min.js']) {
    test(file + ': renewal reads the expected Cloud Page config and remembers sessions outside URLs', async () => {
        const source = readFileSync(join(root, 'src/code-resources', file), 'utf8');
        const section = source.slice(source.indexOf('var RENEW_FRAME_NAME ='), source.indexOf('var Session ='));
        assert.ok(section.length > 0);
        const stored = new Map();
        let frame;
        let replaced;
        let timeout;
        const global = {
            location: new URL(pageURL),
            history: { replaceState(state, title, url) { replaced = url; } },
            sessionStorage: { setItem: (key, value) => stored.set(key, value) }
        };
        const body = { appendChild(value) { frame = value; frame.parentNode = body; }, removeChild() {} };
        const context = {
            global, URL, Config: { data: { backendUrl: backendURL } },
            SESSION_ID_RE: /^[0-9a-fA-F-]{36}$/, SILENT_RENEW_TIMEOUT_MS: 30000,
            Api: { makeError: (code, message) => Object.assign(new Error(message), { code }) },
            setTimeout(callback) { timeout = callback; return 1; }, clearTimeout() {},
            document: { body, createElement: () => ({ setAttribute() {}, style: {}, contentWindow: {} }) }
        };
        vm.createContext(context);
        vm.runInContext(section, context);
        const session = randomUUID();
        const renewed = context.SilentRenew.run();
        frame.contentWindow.location = new URL(pageURL);
        frame.contentWindow.SQLStudioConfig = { session };
        context.SilentRenew.frameArrived();
        assert.equal(await renewed, session);
        context.rememberSession(session);
        assert.equal(stored.get(storeKey), session);
        assert.equal(replaced, pageURL);
        assert.ok(!replaced.includes(session));
        global.location = new URL(pageURL + '?s=legacy&keep=1');
        context.rememberSession(session);
        assert.equal(replaced, pageURL + '?keep=1');
        global.location = new URL(pageURL);

        const forged = context.SilentRenew.run();
        frame.contentWindow.location = new URL(pageURL + '?s=' + session);
        frame.contentWindow.SQLStudioConfig = {};
        context.SilentRenew.frameArrived();
        await assert.rejects(forged, { code: 'RENEW_FAILED' });

        const wrongPath = context.SilentRenew.run();
        frame.contentWindow.location = new URL('https://sqlstudio.example.invalid/other');
        frame.contentWindow.SQLStudioConfig = { session };
        context.SilentRenew.frameArrived();
        await assert.rejects(wrongPath, { code: 'RENEW_FAILED' });

        const wrongOrigin = context.SilentRenew.run();
        let configRead = false;
        frame.contentWindow.location = new URL('https://other.example.invalid/app');
        Object.defineProperty(frame.contentWindow, 'SQLStudioConfig', { get() { configRead = true; return { session }; } });
        context.SilentRenew.frameArrived();
        assert.equal(configRead, false);
        timeout();
        await assert.rejects(wrongOrigin, { code: 'RENEW_FAILED' });
    });
}
