'use strict';

// Run with node --test tests/permanent-writes.test.cjs. No MCE credentials or network required.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const html = readFileSync(join(__dirname, '../src/code-resources/sql-studio-backend.html'), 'utf8');
const source = html.match(/^<script runat="server">([\s\S]*)<\/script>/)[1];
const session = '12345678-1234-4234-8234-123456789abc';
const sessionKey = createHash('sha256').update(session).digest('hex');
const userId = 'test-user';
const permanentActions = [
    'createDataExtension', 'moveToDataExtension', 'saveQueryActivity', 'updateQueryActivity'
];

function request(action, options = {}) {
    const handlerCalls = [];
    const externalCalls = [];
    const variables = new Map();
    const now = new Date();
    const auth = {
        token: 'encrypted-test-token', userId, userName: 'Test User',
        userEmail: 'test@example.invalid',
        tokenExpire: new Date(now.getTime() + (options.expired ? -60000 : 60000))
    };
    const payload = options.payload || {};
    const sandbox = {
        __handlerCalls: handlerCalls,
        __stubHandlers: options.stubHandlers !== false,
        Stringify: JSON.stringify,
        GUID: () => session,
        Platform: {
            Load() {},
            Request: {
                Method: () => 'POST',
                GetPostData: () => JSON.stringify({ action, session, payload })
            },
            Response: { SetResponseHeader() {} },
            Variable: { SetValue: (key, value) => variables.set(key, value) },
            Function: {
                ParseJSON: JSON.parse,
                Now: () => now,
                SystemDateToLocalDate: value => value,
                Lookup(de, field, keys, values) {
                    assert.equal(values[1], sessionKey);
                    return options.sessionExists === false ? null : auth[field];
                },
                TreatAsContent(content) {
                    if (content.includes('SHA256(')) {
                        return createHash('sha256').update(variables.get('@ssHashInput')).digest('hex');
                    }
                    // Mock the platform's decryption, keeping the real session lookup and binding checks.
                    assert.ok(content.includes('DecryptSymmetric('));
                    assert.equal(variables.get('@ssCryptText'), auth.token);
                    return 'ss2:' + sessionKey + '|' + userId + '|test-access-token';
                },
                InsertData() { externalCalls.push({ method: 'InsertData' }); }
            }
        },
        Script: { Util: {
            HttpRequest: class {
                constructor(url) { this.url = url; this.headers = {}; }
                setHeader(name, value) { this.headers[name] = value; }
                send() {
                    externalCalls.push({ url: this.url, method: this.method, body: this.postData, headers: this.headers });
                    return { statusCode: 200, content: JSON.stringify({ queryDefinitionId: session }) };
                }
            },
            WSProxy: class {
                constructor() { throw new Error('Unexpected WSProxy access'); }
            }
        } }
    };
    // Optional settings are globals in the Backend's configuration section.
    for (const setting of ['permanentWrites', 'existingTargets']) {
        if (Object.hasOwn(options, setting)) sandbox[setting] = options[setting];
    }
    let configured = source
        .replace("'SQL_STUDIO_PAGE_URL'", "'https://sqlstudio.example.invalid/app'")
        .replace("'SQL_STUDIO_BACKEND_URL'", "'https://sqlstudio.example.invalid/backend'")
        .replace("'CLIENT_ID'", "'test-client-id'")
        .replace("'CLIENT_SECRET'", "'test-client-secret'")
        .replace("'API_BASE_URI'", "'mcaaaaaaaaaaaaaaaaaaaaaaaaaa'");

    // Observe dispatch without replacing the authentication, policy, or response code. Most cases
    // stub only the selected handler's work; integration cases below run the real save handlers.
    const dispatch = 'var data = handler(payload, authRow);';
    assert.ok(configured.includes(dispatch));
    configured = configured.replace(dispatch,
        '__handlerCalls.push(action);\n' +
        'var data = __stubHandlers ? { action: action } : handler(payload, authRow);');
    vm.runInNewContext(configured, sandbox, { timeout: 1000 });
    return { response: JSON.parse(sandbox.stringifiedResponse), handlerCalls, externalCalls };
}

test('the complete Backend JavaScript parses', () => {
    new vm.Script(source);
});

test('missing, disabled, and malformed settings block every permanent-write action', async t => {
    const settings = [
        ['absent', {}], ['false', { permanentWrites: false }],
        ['string true', { permanentWrites: 'true' }], ['number', { permanentWrites: 1 }],
        ['null', { permanentWrites: null }], ['object', { permanentWrites: {} }],
        ['array', { permanentWrites: [] }]
    ];
    for (const [label, config] of settings) {
        for (const action of permanentActions) {
            await t.test(label + ': ' + action, () => {
                const result = request(action, {
                    ...config, existingTargets: true,
                    payload: { permanentWrites: true, existingTargets: true, confirmOverwrite: true }
                });
                assert.equal(result.response.ok, false);
                assert.equal(result.response.error.code, 'PERMANENT_WRITES_DISABLED');
                assert.match(result.response.error.message, /permanentWrites = true/);
                assert.equal(result.response.error.details, null);
                assert.equal(result.response.meta.apiCalls, 0);
                assert.equal(result.response.meta.wsproxyCalls, 0);
                assert.deepEqual(result.handlerCalls, []);
                assert.deepEqual(result.externalCalls, []);
            });
        }
    }
});

test('only explicit boolean true permits every permanent-write handler', () => {
    for (const action of permanentActions) {
        const result = request(action, { permanentWrites: true });
        assert.equal(result.response.ok, true);
        assert.deepEqual(result.handlerCalls, [action]);
    }
});

test('session validity and expiry are checked before the write policy', () => {
    for (const action of permanentActions) {
        for (const permanentWrites of [false, true]) {
            for (const [config, expected] of [
                [{ sessionExists: false }, 'SESSION_INVALID'],
                [{ expired: true }, 'SESSION_EXPIRED']
            ]) {
                const result = request(action, { ...config, permanentWrites });
                assert.equal(result.response.error.code, expected);
                assert.deepEqual(result.handlerCalls, []);
                assert.deepEqual(result.externalCalls, []);
            }
        }
    }
});

test('all other current actions remain dispatchable without a permanent-write opt-in', () => {
    const actions = [
        'whoami', 'finishSetup', 'getWorkspace', 'listFolders', 'listDataExtensions',
        'listParentDataExtensions', 'getDataExtensionFields', 'getDataExtensionDetails',
        'validateQuery', 'runQuery', 'getRunStatus', 'getRunOutcome', 'getResults',
        'exportRows', 'deleteRun', 'listRuns', 'listQueryActivities', 'getQueryActivity',
        'addHistory', 'listHistory', 'clearHistory', 'listSnippets', 'saveSnippet', 'deleteSnippet'
    ];
    for (const action of actions) {
        const result = request(action);
        assert.equal(result.response.ok, true, action);
        assert.deepEqual(result.handlerCalls, [action]);
    }
});

test('unknown and inherited action names remain rejected', () => {
    for (const action of ['unknownAction', '__proto__', 'constructor']) {
        const result = request(action);
        assert.equal(result.response.error.code, 'UNKNOWN_ACTION');
        assert.deepEqual(result.handlerCalls, []);
    }
});

test('existingTargets false still rejects existing-target moves after opting in', () => {
    const result = request('moveToDataExtension', {
        permanentWrites: true, existingTargets: false, stubHandlers: false,
        payload: { slot: 1, targetKey: 'ProductionDE', updateType: 'Overwrite' }
    });
    assert.deepEqual(result.handlerCalls, ['moveToDataExtension']);
    assert.equal(result.response.error.code, 'BAD_REQUEST');
    assert.match(result.response.error.message, /existingTargets/);
    assert.deepEqual(result.externalCalls, []);
});

test('opted-in Query Activity saves still use the real handlers and user token API path', () => {
    for (const action of ['saveQueryActivity', 'updateQueryActivity']) {
        const result = request(action, {
            permanentWrites: true, stubHandlers: false,
            payload: {
                id: session, name: 'Saved Query', sql: 'SELECT ContactKey FROM Contacts',
                targetKey: 'TargetDE', targetName: 'Target DE', updateType: 'Append'
            }
        });
        assert.equal(result.response.ok, true);
        assert.equal(result.response.data.queryId, session);
        assert.equal(result.externalCalls.length, 1);
        assert.equal(result.externalCalls[0].method, action === 'saveQueryActivity' ? 'POST' : 'PATCH');
        assert.equal(result.externalCalls[0].headers.Authorization, 'Bearer test-access-token');
        assert.equal(JSON.parse(result.externalCalls[0].body).queryText, 'SELECT ContactKey FROM Contacts');
    }
});
