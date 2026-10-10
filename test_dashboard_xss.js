const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const payload = '<img src=x onerror=alert(1)>';
const templatePath = path.join(__dirname, 'dashboard', 'templates', 'dashboard.html');
const template = fs.readFileSync(templatePath, 'utf8');
const script = [...template.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)?.[1];
assert.ok(script, 'dashboard inline script should exist');

class FakeElement {
    constructor(tagName = 'div') {
        this.tagName = tagName.toUpperCase();
        this.children = [];
        this.style = {};
        this.listeners = {};
        this.attributes = {};
        this.value = '';
        this.classList = { add() {}, remove() {} };
        this._text = '';
        this._innerHTML = '';
    }

    set textContent(value) {
        this._text = String(value ?? '');
        this.children = [];
    }

    get textContent() {
        return this._text + this.children.map(child => child.textContent || '').join('');
    }

    set innerText(value) {
        this.textContent = value;
    }

    get innerText() {
        return this.textContent;
    }

    set innerHTML(value) {
        this._innerHTML = String(value);
        throw new Error('HTML parsing sink was used');
    }

    appendChild(child) {
        this.children.push(child);
        return child;
    }

    append(...children) {
        children.forEach(child => this.appendChild(child));
    }

    replaceChildren(...children) {
        this._text = '';
        this.children = children;
    }

    addEventListener(type, callback) {
        this.listeners[type] = callback;
    }

    setAttribute(name, value) {
        this.attributes[name] = String(value);
    }

    getContext() {
        return {};
    }
}

function makeHarness(apiResponse) {
    const elements = new Map();
    const calls = [];
    const document = {
        addEventListener() {},
        createElement: tag => new FakeElement(tag),
        createTextNode: text => {
            const node = new FakeElement('#text');
            node.textContent = text;
            return node;
        },
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, new FakeElement());
            return elements.get(id);
        },
        querySelectorAll: () => []
    };
    document.getElementById('report-range-select').value = '7d';

    const context = vm.createContext({
        document,
        console,
        encodeURIComponent,
        fetch: async url => {
            calls.push(String(url));
            return { json: async () => apiResponse(String(url)) };
        },
        setInterval: () => 1,
        clearInterval() {},
        setTimeout() {},
        Chart: class { destroy() {} },
        window: { URL: {} },
        alert() {}
    });
    vm.runInContext(script, context, { filename: 'dashboard.html inline script' });
    return { context, document, calls };
}

function allText(node) {
    return node.textContent;
}

function findElement(node, tagName) {
    if (node.tagName === tagName.toUpperCase()) return node;
    for (const child of node.children) {
        const found = findElement(child, tagName);
        if (found) return found;
    }
    return null;
}

function assertTextOnly(element, expected = payload) {
    assert.ok(allText(element).includes(expected), 'the supplied value should remain visible as text');
    assert.equal(findElement(element, 'img'), null, 'the supplied value must not create an image element');
}

test('attack, session, IP, command, and credential values are rendered as text', async () => {
    const harness = makeHarness(url => {
        if (url.startsWith('/api/attacks')) return { events: [{ timestamp: payload, event_type: 'command_input', src_ip: payload, session_id: payload, input: payload }] };
        if (url.startsWith('/api/sessions?')) return { sessions: [{ session_id: payload, src_ip: payload, start_time: payload }] };
        if (url === '/api/ips') return { ips: [{ src_ip: payload, first_seen: payload }] };
        if (url === '/api/commands') return { commands: [{ input: payload, meaning: payload }] };
        if (url === '/api/credentials') return { usernames: [{ username: payload }], passwords: [{ password: payload, count: 1 }] };
        return {};
    });

    await harness.context.fetchAttacks(1);
    assertTextOnly(harness.document.getElementById('tbody-attacks'));
    const inspectButton = findElement(harness.document.getElementById('tbody-attacks'), 'button');
    assert.equal(typeof inspectButton.listeners.click, 'function', 'attack action should use a click listener');
    assert.equal(inspectButton.attributes.onclick, undefined, 'attack action should not use an inline handler');

    await harness.context.fetchSessions(1);
    assertTextOnly(harness.document.getElementById('tbody-sessions'));
    await harness.context.fetchIPs();
    assertTextOnly(harness.document.getElementById('tbody-ips'));
    const analyzeButton = findElement(harness.document.getElementById('tbody-ips'), 'button');
    assert.equal(typeof analyzeButton.listeners.click, 'function', 'IP action should use a click listener');
    await harness.context.fetchCommands();
    assertTextOnly(harness.document.getElementById('tbody-commands'));
    await harness.context.fetchCredentials();
    assertTextOnly(harness.document.getElementById('tbody-usernames'));
    assert.ok(!allText(harness.document.getElementById('tbody-passwords')).includes(payload), 'password values must not be rendered');
});

test('overview sessions, classifier indicators, and intelligence mitigations are rendered as text', async () => {
    const harness = makeHarness(url => {
        if (url === '/api/dashboard/summary') return {
            recent_sessions: [{ start_time: payload, src_ip: payload, session_id: payload, username: payload, success: 1 }],
            bot_assessment: { assessment: payload, indicators: [payload], automation_score: 1 },
            top_ips: [], top_commands: []
        };
        if (url === '/api/timeline') return { timeline: [] };
        if (url === '/api/intelligence') return { summary: payload, mitigations: [{ recommendation: payload, reason: payload }] };
        return {};
    });

    await harness.context.fetchSummaryData();
    await new Promise(resolve => setTimeout(resolve, 0));
    assertTextOnly(harness.document.getElementById('tbody-recent-sessions'));
    assertTextOnly(harness.document.getElementById('classifier-assessment-text'));
    assertTextOnly(harness.document.getElementById('classifier-indicators-list'));
    assertTextOnly(harness.document.getElementById('dashboard-ai-summary-text'));
    assertTextOnly(harness.document.getElementById('dashboard-ai-mitigations-container'));
});

test('session and IP detail values are rendered as text', async () => {
    const harness = makeHarness(url => url.includes('/api/sessions/') ? {
        session: { src_ip: payload, dst_port: 2222, start_time: payload },
        logins: [{ timestamp: payload, username: payload, password: 'SECRET_PASSWORD_XSS', success: 0 }],
        commands: [{ timestamp: payload, input: payload, meaning: payload }]
    } : { sessions: [{ session_id: payload, start_time: payload, dst_port: 22 }] });

    await harness.context.inspectSession('session-id');
    assertTextOnly(harness.document.getElementById('modal-title'), 'session-id');
    assertTextOnly(harness.document.getElementById('modal-body-content'));
    assert.ok(!allText(harness.document.getElementById('modal-body-content')).includes('SECRET_PASSWORD_XSS'), 'password field remains redacted');
    assert.ok(harness.calls[0].includes('/api/sessions/session-id'));

    await harness.context.inspectIP(payload);
    assertTextOnly(harness.document.getElementById('modal-title'));
    assertTextOnly(harness.document.getElementById('modal-body-content'));
    assert.ok(harness.calls[1].includes(encodeURIComponent(payload)), 'IP detail request should safely encode its path value');
});

test('report preview treats AI summary and mitigation values as untrusted text', async () => {
    const harness = makeHarness(() => ({
        summary_obj: { summary: payload },
        bot_info: { assessment: payload, automation_score: 12 },
        mitigations: [{ recommendation: payload, reason: payload }],
        generated_at: payload,
        tot_events: 1,
        unique_ips: 1,
        tot_sessions: 1,
        tot_logins: 1
    }));

    await harness.context.previewReportModal();
    const preview = harness.document.getElementById('report-preview-container');
    assertTextOnly(preview);
    const downloadButton = findElement(preview, 'button');
    assert.equal(typeof downloadButton.listeners.click, 'function', 'preview download action should use a click listener');
    assert.equal(downloadButton.attributes.onclick, undefined);
});
