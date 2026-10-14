/* ModScanOpen — utilità condivise, navigazione e chiamate API. */
/* Versione open source della UI di JarAnalyzer: solo due modalità (File JAR e Cartella mods).
   Nessuna licenza, nessun backend, nessuna rete. */
(function () {
    'use strict';
    const J = window.J = {};
    J.$ = (id) => document.getElementById(id);
    J.RM = !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
    J.sleep = (ms) => new Promise((r) => setTimeout(r, J.RM ? 15 : ms));
    J.esc = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    J.ic = (n, size) => '<svg class="ic" aria-hidden="true"' + (size ? ' style="width:' + size + 'px;height:' + size + 'px"' : '') + '><use href="#i-' + n + '"/></svg>';
    J.base = (p) => { const i = Math.max(String(p).lastIndexOf('/'), String(p).lastIndexOf('\\')); return i >= 0 ? String(p).slice(i + 1) : String(p); };

    J.fmtBytes = function (b) {
        if (b == null || isNaN(b)) return '—';
        if (b === 0) return '0 B';
        const u = ['B', 'KB', 'MB', 'GB'], i = Math.min(3, Math.floor(Math.log(b) / Math.log(1024)));
        return (b / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0).replace('.', ',') + ' ' + u[i];
    };
    J.fmtDur = (ms) => ms == null ? '—' : (ms / 1000 < 0.01 ? '0,01 s' : (ms / 1000).toFixed(2).replace('.', ',') + ' s');

    J.count = function (el, to, dec, dur) {
        if (!el) return;
        const t0 = performance.now(), D = J.RM ? 1 : (dur || 1300);
        (function f(t) {
            const p = Math.min((t - t0) / D, 1), v = to * (1 - Math.pow(1 - p, 3));
            el.textContent = dec ? v.toFixed(dec).replace('.', ',') : Math.round(v).toLocaleString('it-IT');
            if (p < 1) requestAnimationFrame(f);
        })(t0);
    };

    let tt;
    J.toast = function (msg, type) {
        const t = J.$('toast');
        t.textContent = msg;
        t.className = 'toast on' + (type === 'error' ? ' error' : '');
        clearTimeout(tt);
        tt = setTimeout(() => t.classList.remove('on'), type === 'error' ? 5200 : 2200);
    };
    J.error = (m) => J.toast(m, 'error');

    J.copy = function (text, msg) {
        const done = () => J.toast(msg || 'Copiato');
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done, () => fallback());
        } else fallback();
        function fallback() {
            const ta = document.createElement('textarea');
            ta.value = text; ta.style.cssText = 'position:fixed;opacity:0';
            document.body.appendChild(ta); ta.select();
            try { document.execCommand('copy'); } catch (e) { /* ignore */ }
            document.body.removeChild(ta); done();
        }
    };

    /* ---------- chiamate API ---------- */
    /* Trasporto verso Java. Nell'app desktop (WebView) si usa il bridge nativo: nessun server, nessuna porta.
       Fuori dall'app (anteprima nel browser) non c'è un server: le API non funzionano, lo segnala il messaggio. */
    const IS_DESKTOP = /ModScanOpenDesktop/.test(navigator.userAgent);
    let seq = 0;
    const pending = {};
    window.__javaResponse = function (id, status, body) {
        const p = pending[id];
        if (!p) return;
        delete pending[id];
        let data = null;
        try { data = body ? JSON.parse(body) : null; } catch (e) { /* corpo non JSON */ }
        p.resolve({ status: status, data: data });
    };
    async function waitBridge() {
        for (let i = 0; i < 120; i++) {
            if (window.javafxBridge && window.javafxBridge.request) return window.javafxBridge;
            await new Promise((r) => setTimeout(r, 100));
        }
        throw new Error("Il collegamento con l'applicazione non è disponibile. Riavvia ModScanOpen.");
    }
    function bodyToString(body) {
        if (body == null) return '';
        if (typeof body === 'string') return body;
        if (typeof FormData !== 'undefined' && body instanceof FormData) {
            const u = new URLSearchParams();
            body.forEach((v, k) => { if (typeof v === 'string') u.append(k, v); });
            return u.toString();
        }
        return String(body);
    }
    J.transport = async function (method, url, body) {
        if (IS_DESKTOP) {
            const bridge = await waitBridge();
            return new Promise((resolve) => {
                const id = 'r' + (++seq);
                pending[id] = { resolve: resolve };
                bridge.request(id, method, url, bodyToString(body), '');
            });
        }
        throw new Error('Le API sono disponibili solo dentro ModScanOpen. Riavvia la app desktop.');
    };

    J.api = async function (url, opts) {
        opts = opts || {};
        const method = (opts.method || 'GET').toUpperCase();
        const r = await J.transport(method, url, opts.body);
        if (r.status >= 400) {
            throw new Error((r.data && (r.data.message || r.data.error)) || ('Errore (' + r.status + ')'));
        }
        return r.data;
    };

    /* ---------- animazione a passi legata a una richiesta reale ---------- */
    J.runSteps = async function (o) {
        const ul = o.list, steps = o.steps, logEl = o.log, pg = o.progress;
        const before = o.before || [];
        ul.innerHTML = before.map((s) => '<li class="done"><span class="d"></span>' + J.esc(s) + '</li>').join('') + steps.map((s) => '<li><span class="d"></span>' + J.esc(s) + '</li>').join('');
        if (logEl) logEl.innerHTML = '';
        if (pg) pg.style.width = '0';
        let done = false, value, error;
        o.promise.then((v) => { done = true; value = v; }, (e) => { done = true; error = e; });
        const lis = [...ul.children].slice(before.length);
        for (let i = 0; i < steps.length; i++) {
            lis[i].className = 'run';
            if (o.onStep) o.onStep(i, steps.length);
            if (logEl && o.logs && o.logs[i]) {
                const d = document.createElement('div');
                d.innerHTML = '<span class="pr">›</span> ' + J.esc(o.logs[i]);
                logEl.appendChild(d);
                while (logEl.children.length > 5) logEl.removeChild(logEl.firstChild);
            }
            if (i < steps.length - 1) {
                await J.sleep(done ? 40 : (o.stepMs || 420));
            } else {
                while (!done) await J.sleep(80);
                await J.sleep(40);
            }
            if (error && i === steps.length - 1) { lis[i].className = 'fail'; }
            else lis[i].className = 'done';
            if (pg) pg.style.width = ((i + 1) / steps.length * 100) + '%';
            if (error) { for (let k = i + 1; k < steps.length; k++) lis[k].className = ''; break; }
        }
        if (error) throw error;
        return value;
    };

    /* ---------- fasi reali: l'animazione avanza quando avanza l'operazione ---------- */
    J.phaseRunner = function (list, steps, o) {
        o = o || {};
        list.innerHTML = steps.map((s) => '<li><span class="d"></span>' + J.esc(s) + '</li>').join('');
        const lis = [...list.children];
        if (o.log) o.log.innerHTML = '';
        if (o.progress) o.progress.style.width = '0';
        const say = (txt) => {
            if (!o.log || !txt) return;
            const d = document.createElement('div');
            d.innerHTML = '<span class="pr">›</span> ' + J.esc(txt);
            o.log.appendChild(d);
            while (o.log.children.length > 5) o.log.removeChild(o.log.firstChild);
        };
        let at = -1;
        const api = {
            set(i, logLine) {
                for (let k = 0; k < lis.length; k++) lis[k].className = k < i ? 'done' : (k === i ? 'run' : '');
                at = i; say(logLine);
                if (o.progress) o.progress.style.width = (i / steps.length * 100) + '%';
                if (o.phaseLabel) o.phaseLabel.textContent = steps[i] + '…';
            },
            say,
            finish() { lis.forEach((l) => { l.className = 'done'; }); if (o.progress) o.progress.style.width = '100%'; if (o.phaseLabel) o.phaseLabel.textContent = 'Completato'; },
            fail(msg) { if (at >= 0 && lis[at]) lis[at].className = 'fail'; if (o.phaseLabel) o.phaseLabel.textContent = msg || 'Operazione non riuscita'; }
        };
        return api;
    };

    /* ---------- stepper pilotato dalle fasi reali di una pipeline ---------- */
    J.stepper = function (list, steps, o) {
        o = o || {};
        list.innerHTML = steps.map((s) => '<li><span class="d"></span>' + J.esc(s) + '</li>').join('');
        if (o.log) o.log.innerHTML = '';
        if (o.progress) o.progress.style.width = '0';
        const lis = [...list.children];
        let n = 0, tick = null;
        const setPg = (v) => { if (o.progress) o.progress.style.width = v + '%'; };
        const api = {
            start(i, logText) {
                lis[i].className = 'run';
                if (logText && o.log) { const d = document.createElement('div'); d.innerHTML = '<span class="pr">›</span> ' + J.esc(logText); o.log.appendChild(d); while (o.log.children.length > 5) o.log.removeChild(o.log.firstChild); }
                setPg(Math.max(i / steps.length * 100, parseFloat((o.progress && o.progress.style.width) || 0) || 0));
                if (o.label) o.label.textContent = steps[i] + '…';
                clearInterval(tick);
                let w = i / steps.length * 100; const cap = (i + 1) / steps.length * 100 - 4;
                tick = setInterval(() => { w = Math.min(w + 1.2, cap); setPg(w); }, 400);
            },
            done(i) { clearInterval(tick); lis[i].className = 'done'; n = i + 1; setPg(n / steps.length * 100); },
            skip(i) { lis[i].className = 'skip'; },
            fail(i) { clearInterval(tick); lis[i].className = 'fail'; },
            stop() { clearInterval(tick); }
        };
        return api;
    };

    /* ---------- navigazione (solo due modalità) ---------- */
    J.modes = [
        { id: 'jar', n: 'File JAR', tab: 'File JAR', ic: 'jar', d: 'Analisi statica del bytecode: malware, offuscamento, firme note e pattern sospetti.' },
        { id: 'mods', n: 'Cartella mods', tab: 'Mods', ic: 'folder', d: 'Trova la cartella dal gioco in esecuzione e controlla tutte le mod: sospette e da verificare.' }
    ];
    J.onShow = {};
    let cur = 0;
    const tabs = J.$('tabs');
    J.modes.forEach((m, i) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.innerHTML = J.ic(m.ic) + m.tab;
        b.onclick = () => J.pick(m.id);
        tabs.appendChild(b);
    });
    const btns = () => [...tabs.querySelectorAll('button')];
    function thumb() {
        const b = btns()[cur];
        if (!b) return;
        const t = J.$('thumb');
        t.style.width = b.offsetWidth + 'px';
        t.style.transform = 'translateX(' + (b.offsetLeft - 4) + 'px)';
    }
    window.addEventListener('resize', thumb);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(thumb);
    J.pick = function (id) {
        const i = J.modes.findIndex((m) => m.id === id);
        if (i < 0) return;
        cur = i;
        const m = J.modes[i];
        btns().forEach((b, j) => b.setAttribute('aria-current', j === i));
        thumb();
        const h = J.$('head');
        h.classList.remove('sw'); void h.offsetWidth; h.classList.add('sw');
        J.$('t').textContent = m.n; J.$('d').textContent = m.d;
        document.querySelectorAll('.view').forEach((v) => {
            const on = v.dataset.v === id;
            v.hidden = !on;
            v.classList.remove('in');
            if (on) { void v.offsetWidth; v.classList.add('in'); }
        });
        if (J.onShow[id]) J.onShow[id]();
        thumb();
    };
    J.current = () => J.modes[cur].id;
    document.addEventListener('keydown', (e) => {
        if (e.metaKey || e.ctrlKey || e.altKey || /INPUT|TEXTAREA|SELECT/.test((document.activeElement || {}).tagName || '')) return;
        const n = parseInt(e.key, 10);
        if (n >= 1 && n <= J.modes.length) J.pick(J.modes[n - 1].id);
    });

    /* trascinare un file sulla finestra non deve mai aprirlo nel browser */
    ['dragover', 'drop'].forEach((ev) => document.addEventListener(ev, (e) => e.preventDefault()));

    function boot() {
        J.pick('jar');
        if (window.J_boot) window.J_boot.forEach((f) => f());
    }
    J.ready = (f) => { (window.J_boot = window.J_boot || []).push(f); };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => setTimeout(boot, 0));
    else setTimeout(boot, 0);
})();
