/* Modalità "Cartella mods": individuazione automatica dal processo javaw, scansione con animazione, scansione del singolo jar. */
(function () {
    'use strict';
    const J = window.J, $ = J.$, esc = J.esc, ic = J.ic;
    const STT = { new: 'In coda', ok: 'Ufficiale', unk: 'Non riconosciuta', bad: 'Da controllare' };
    const MAP = { VERIFIED: 'ok', UNVERIFIED: 'unk', SUSPICIOUS: 'bad' };
    const STEP_TXT = ['Apro la mod', 'Leggo il codice', 'Cerco cheat e funzioni pericolose', 'Controllo connessioni e codice nascosto'];
    const CK = ['È ufficiale?', 'Comportamento', 'Internet', 'Codice nascosto'];
    const CKS = { 1: ['y', 'ok'], 0: ['n', 'attenzione'], 2: ['w', 'da guardare'] };
    let path = null, entries = [], filter = 'all', busy = false, located = false;

    const list = $('mlist');

    /* Badge "risultati nella lista": journal (righe rosse) e dump memoria (chip per mod).
       Riempiti da journal.js e mem.js dopo i rispettivi controlli. */
    J.modsBadges = J.modsBadges || { journal: {}, mem: {}, gone: [], journalMeta: null };
    const jkey = (m) => String(m.fileName || '').toLowerCase();
    const jinfo = (m) => J.modsBadges.journal[jkey(m)];
    function badges(m) {
        const key = String(m.fileName || '').toLowerCase();
        const mb = J.modsBadges.mem[key];
        let h = '';
        if (mb) {
            h += mb.skipped
                ? '<span class="sb new" title="' + esc('Saltata nel dump: release verificata su ' + (mb.by || 'database pubblico') + ', nessun dato sospetto da leggere') + '">dump ✓</span>'
                : '<span class="sb ' + mb.cls + '" title="' + esc(mb.title || 'Rilevamenti nel dump memoria') + '">mem ' + mb.count + '</span>';
        }
        return h ? '<span class="mchips">' + h + '</span>' : '';
    }
    /* ---------- percorso ---------- */
    function setPath(p, sourceText) {
        path = p;
        $('mods-path').textContent = p || 'Nessuna cartella selezionata';
        $('mods-source').textContent = sourceText || '';
        $('btn-mods-scan').disabled = !p;
    }

    /* La card "Integrità mod" (journal.js) controlla la stessa cartella. */
    J.modsPath = () => path;

    async function locate(auto) {
        const btn = $('btn-mods-locate');
        btn.disabled = true;
        $('mods-source').textContent = 'Cerco il gioco tra i processi Java in esecuzione…';
        try {
            const r = await J.api('/api/mods/locate');
            const cands = [];
            (r.processes || []).forEach((p) => (p.candidates || []).forEach((c) => cands.push({ p, c })));
            const box = $('mods-cands');
            if (r.best) {
                const b = r.best;
                setPath(b.path, 'Trovata dal processo ' + (R_exe(b.processName)) + ' (PID ' + b.pid + ') · ' + b.source + (b.exists ? ' · ' + b.jarCount + ' file .jar' : ' · la cartella non esiste ancora'));
                if (cands.length > 1) {
                    box.hidden = false;
                    box.innerHTML = '<span class="cl">Altre cartelle trovate:</span>' + cands.map((x, i) => '<button type="button" class="fl" data-i="' + i + '" aria-pressed="' + (x.c.path === b.path && x.p.pid === b.pid) + '">PID ' + esc(x.p.pid) + ' · ' + esc(tail(x.c.path)) + ' · ' + x.c.jarCount + ' jar</button>').join('');
                    box.onclick = (e) => {
                        const bt = e.target.closest('button[data-i]'); if (!bt) return;
                        const x = cands[+bt.dataset.i];
                        box.querySelectorAll('button').forEach((q) => q.setAttribute('aria-pressed', q === bt));
                        setPath(x.c.path, 'Dal processo ' + R_exe(x.p.processName) + ' (PID ' + x.p.pid + ') · ' + x.c.source);
                        scan();
                    };
                } else box.hidden = true;
                located = true;
                if (b.exists) { scan(); }
            } else {
                $('mods-cands').hidden = true;
                $('mods-source').textContent = auto ? 'Nessun Minecraft in esecuzione: avvia il gioco e premi «Trova da javaw», oppure scegli la cartella a mano.' : 'Nessun processo Minecraft trovato. Avvia il gioco oppure scegli la cartella a mano.';
                if (!auto) J.toast('Nessun processo Minecraft trovato');
            }
        } catch (e) {
            $('mods-source').textContent = 'Ricerca non riuscita: ' + e.message;
        } finally { btn.disabled = false; }
    }
    function R_exe(s) { return window.J.Report.exeName(s) || 'java'; }
    function tail(p) { const a = String(p).replace(/\\/g, '/').split('/').filter(Boolean); return a.slice(-3).join('/'); }

    function choose() {
        if (window.javafxBridge) {
            if (window.javafxBridge.chooseFolderAt) window.javafxBridge.chooseFolderAt(path || ''); else window.javafxBridge.chooseFolder();
        } else {
            const p = window.prompt('Percorso della cartella mods', path || '');
            if (p) window.handleModsFolderSelection(p.trim());
        }
    }
    /* chiamata da Java (DesktopApp) */
    window.handleModsFolderSelection = function (p) { J.pick('mods'); $('mods-cands').hidden = true; setPath(p, 'Cartella scelta a mano'); scan(); };

    /* ---------- rendering ----------
       Elenco a pagine (40 righe + "Mostra altri"/scorrimento): con centinaia di mod il DOM resta piccolo.
       Stato, filtri e conteggi lavorano sempre sull'intero elenco in memoria. */
    const PAGE = 40, PAGE_MORE = 60;
    let rows = [], shown = 0, io = null;
    function row(m, i) {
        const name = m.modName || m.fileName, sub = m.sha256 ? m.sha256.slice(0, 8) + '…' + m.sha256.slice(-6) + ' · impronta del file' : 'impronta non disponibile';
        const note = (m.s === 'bad' || m.s === 'unk') && m.verificationNote && !m.ui.scanning ? '<small class="note ' + m.s + '">' + esc(m.verificationNote) + '</small>' : '';
        const btnCls = m.s === 'bad' ? '' : ' sec';
        const ji = jinfo(m), jrx = ji && J.jr ? J.jr.flag(ji, m.s === 'ok') : '';
        return '<div class="mrw' + (m.ui.scanning ? ' scn' : '') + (ji ? (ji.state === 'added' ? ' fa' : ' fm') : '') + '" id="mw' + i + '"><div class="mr"><span class="pic">' + ic('jar', 20) + '</span>' +
            '<div><b>' + esc(name) + (m.author ? '<span class="chip">' + esc(String(m.author).slice(0, 28)) + '</span>' : '') + '</b>' + badges(m) + '<small>' + (m.ui.scanning ? '<span class="stp">' + esc(m.ui.step) + '</span>' : esc(m.fileName) + ' · ' + sub) + '</small>' + note + jrx + '</div>' +
            '<span class="sz">' + J.fmtBytes(m.fileSize) + '</span><span class="sb ' + m.s + '" title="' + esc(m.verificationNote || '') + '">' + STT[m.s] + '</span>' +
            '<button class="btn sm' + btnCls + '" data-i="' + i + '" type="button"' + (m.ui.scanning ? ' disabled' : '') + '>' + (m.ui.scanning ? '<span class="sp"></span>Scansione…' : ic('shield') + (m.ui.deep ? 'Ricontrolla' : 'Controlla a fondo')) + '</button></div>' +
            '<span class="mp" id="mp' + i + '" style="width:' + (m.ui.p || 0) + '%"></span>' + (m.ui.deep && !m.ui.scanning ? detail(m, i) : '') + '</div>';
    }
    function detail(m) {
        const d = m.ui.deep;
        return '<div class="mdet"><div class="chk">' + d.ck.map((c, j) => '<div class="' + CKS[c][0] + '"><b>' + CK[j] + '</b>' + CKS[c][1] + '</div>').join('') + '</div><div class="mnote"><span>' + esc(d.note) + '</span><button class="btn sec sm" data-open="' + esc(m.path) + '" type="button">Apri il risultato completo</button></div></div>';
    }
    function setRow(i) { const e = $('mw' + i); if (e) e.outerHTML = row(entries[i], i); }
    function counts() { const c = { ok: 0, unk: 0, bad: 0, new: 0 }; entries.forEach((m) => c[m.s]++); return c; }
    /* Analisi approfondita in sequenza delle mod non verificate (una alla volta: l'analisi completa è pesante). */
    let deepRun = false, deepStop = false;
    async function deepAll() {
        if (deepRun) { deepStop = true; return; }
        const todo = entries.map((m, i) => i).filter((i) => entries[i].s === 'unk' && !entries[i].ui.deep);
        if (!todo.length) { J.toast('Nessuna mod non riconosciuta da controllare'); return; }
        deepRun = true; deepStop = false;
        const btn = $('btn-mods-deep'), label = btn.querySelector('span');
        for (let k = 0; k < todo.length && !deepStop; k++) {
            label.textContent = 'Controllo ' + (k + 1) + '/' + todo.length + ' — interrompi';
            await scanOne(todo[k]);
        }
        deepRun = false;
        const c = counts();
        J.toast(deepStop ? 'Controllo interrotto' : 'Controllo completato: ' + c.bad + ' da controllare, ' + c.unk + ' ancora non riconosciute', c.bad ? 'error' : undefined);
        updateSum(); render();
    }
    function updateSum() {
        const c = counts(), any = entries.length && c.new < entries.length, v = (x) => any ? x : '–';
        $('ms0').textContent = entries.length || '–'; $('fa').textContent = entries.length;
        $('ms1').textContent = v(c.ok); $('ms2').textContent = v(c.unk); $('ms3').textContent = v(c.bad);
        $('fo').textContent = v(c.ok); $('fu').textContent = v(c.unk); $('fb').textContent = v(c.bad);
        const touched = entries.filter((m) => jinfo(m)).length + (J.modsBadges.gone || []).length;
        $('ms4').textContent = $('fj').textContent = J.modsBadges.journalMeta ? touched : '–';
        const w = [c.ok, c.unk, c.bad], n = entries.length || 1;
        document.querySelectorAll('#mbar span').forEach((e, i) => { e.style.width = (any ? w[i] / n * 100 : 0) + '%'; });
        const db = $('btn-mods-deep'), label = db.querySelector('span');
        db.disabled = !(c.unk > 0) && !deepRun;
        if (!deepRun) label.textContent = c.unk ? 'Controlla a fondo le non riconosciute (' + c.unk + ')' : 'Controlla a fondo le non riconosciute';
    }
    let goneList = [];
    function ghostRow(x) {
        const kind = x.kind === 'deleted';
        return '<div class="mrw fg"><div class="mr"><span class="pic">' + ic('jar', 20) + '</span><div><b>' + esc(x.fileName) + '</b><small>non è più nella cartella</small>' +
            '<div class="flag">' + ic('flag') + '<span>' + J.jr.ghostWhy(x) + '</span></div></div><span class="sz">–</span><span class="sb ' + (kind ? 'bad' : 'unk') + '">' + (kind ? 'Eliminato' : 'Rinominato') + '</span><span></span></div></div>';
    }
    function buildRows() {
        const q = $('mq').value.toLowerCase();
        const G = [['bad', 'Da controllare', 'var(--crit)'], ['unk', 'Non riconosciute', 'var(--med)'], ['ok', 'Ufficiali', '#5fd6a0'], ['new', 'In lettura', '#6d645d']];
        rows = [];
        goneList = (J.modsBadges.gone || []).filter((x) => !q || x.fileName.toLowerCase().indexOf(q) >= 0);
        if (goneList.length && (filter === 'all' || filter === 'jr')) {
            rows.push({ h: 'Spariti dopo l\'avvio', c: 'var(--crit)', n: goneList.length });
            goneList.forEach((x, k) => rows.push({ gi: k }));
        }
        G.forEach((g) => {
            const l = [];
            entries.forEach((m, i) => { if (m.s === g[0] && (filter === 'all' || filter === g[0] || (filter === 'jr' && jinfo(m))) && (!q || (m.fileName + ' ' + (m.modName || '')).toLowerCase().indexOf(q) >= 0)) l.push(i); });
            if (!l.length) return;
            l.sort((a, b) => ((jinfo(entries[b]) ? 1 : 0) - (jinfo(entries[a]) ? 1 : 0)) || (a - b));
            rows.push({ h: g[1], c: g[2], n: l.length });
            l.forEach((i) => rows.push({ i: i }));
        });
    }
    function rowHtml(r) { return r.h ? '<div class="mgh"><i style="background:' + r.c + '"></i>' + r.h + ' <span class="n">' + r.n + '</span></div>' : r.gi !== undefined ? ghostRow(goneList[r.gi]) : row(entries[r.i], r.i); }
    function foot() {
        const total = rows.filter((r) => !r.h).length, nowShown = rows.slice(0, shown).filter((r) => !r.h).length;
        return shown >= rows.length ? '' : '<div class="pgap" id="mods-more"><span>Visualizzate ' + nowShown + ' di ' + total + ' mod.</span> <button class="btn sec sm" type="button" data-more>Mostra altre</button></div>';
    }
    function render() {
        buildRows();
        shown = Math.min(rows.length, PAGE);
        list.innerHTML = rows.length ? rows.slice(0, shown).map(rowHtml).join('') + foot() : '<div class="mempty">' + (entries.length ? 'Nessuna mod corrisponde ai filtri.' : 'Nessun file .jar in questa cartella.') + '</div>';
        observe();
    }
    /* Journal e dump memoria ri-chiamano questa quando hanno badge nuovi per le righe. */
    J.modsRefresh = () => { if (entries.length) { updateSum(); render(); } };
    J.modsFilter = (f) => {
        filter = f;
        document.querySelectorAll('#mfil .fl').forEach((x) => x.setAttribute('aria-pressed', x.dataset.f === f));
        render();
        const bar = $('mfil'); if (bar && bar.scrollIntoView) bar.scrollIntoView({ behavior: 'smooth', block: 'center' });
    };
    function more() {
        const f = $('mods-more'); if (!f || shown >= rows.length) return;
        const from = shown; shown = Math.min(rows.length, shown + PAGE_MORE);
        f.remove();
        list.insertAdjacentHTML('beforeend', rows.slice(from, shown).map(rowHtml).join('') + foot());
        observe();
    }
    function observe() {
        const f = $('mods-more'); if (!f || typeof IntersectionObserver === 'undefined') return;
        if (!io) io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) more(); }), { rootMargin: '400px' });
        io.observe(f);
    }

    /* ---------- scansione cartella ---------- */
    async function scan() {
        if (busy || !path) return;
        busy = true;
        $('btn-mods-scan').disabled = true;
        entries = []; filter = 'all'; $('mq').value = '';
        J.modsBadges.journal = {}; J.modsBadges.gone = []; J.modsBadges.journalMeta = null;
        document.querySelectorAll('#mfil .fl').forEach((x) => x.setAttribute('aria-pressed', x.dataset.f === 'all'));
        updateSum();
        list.innerHTML = '<div class="mempty"><span class="sp"></span>Lettura della cartella, calcolo degli hash e verifica dei rilasci…</div>';
        const pg = $('mods-pg'), ph = $('mods-ph');
        pg.style.width = '8%'; ph.textContent = 'Lettura di ' + tail(path) + '…';
        let data;
        try {
            const req = J.api('/api/mods/folder?path=' + encodeURIComponent(path));
            let w = 8; const iv = setInterval(() => { w = Math.min(w + 4, 85); pg.style.width = w + '%'; }, 300);
            try { data = await req; } finally { clearInterval(iv); }
        } catch (e) {
            J.error(e.message); ph.textContent = 'Scansione non riuscita'; pg.style.width = '0'; list.innerHTML = '<div class="mempty">' + esc(e.message) + '</div>';
            busy = false; $('btn-mods-scan').disabled = false; return;
        }
        /* Le righe sono già verificate dal servizio: si mostrano subito (nessuna attesa artificiale per riga). */
        entries = (data.mods || []).map((m) => Object.assign(m, { s: MAP[m.status] || 'unk', ui: { scanning: false, p: 0, step: '', deep: null } }));
        pg.style.width = '100%';
        updateSum(); render();
        const c = counts(), n = entries.length;
        ph.textContent = n ? 'Controllo completato — ' + c.ok + ' ufficiali, ' + c.unk + ' non riconosciute, ' + c.bad + ' da controllare' : 'Nessun file .jar trovato';
        $('btn-mods-scan').disabled = false;
        busy = false;
        if (c.bad) J.toast(c.bad + ' mod da controllare', 'error'); else J.toast('Cartella controllata');
        /* v1.2.0: journal e dump di memoria partono da soli; gli esiti compaiono in questa lista. */
        if (J.journal && J.journal.auto) J.journal.auto();
    }

    /* ---------- scansione del singolo jar ---------- */
    async function scanOne(i) {
        const m = entries[i];
        if (m.ui.scanning) return;
        m.ui.scanning = true; m.ui.deep = null; m.ui.p = 0; m.ui.step = STEP_TXT[0] + '… 1/4';
        setRow(i);
        const fd = new FormData(); fd.append('path', m.path);
        const req = J.api('/api/analyze-local', { method: 'POST', body: fd });
        let done = false, data, err;
        req.then((v) => { done = true; data = v; }, (e) => { done = true; err = e; });
        for (let k = 0; k < 4; k++) {
            const w = $('mw' + i);
            if (w) { const s = w.querySelector('.stp'); if (s) s.textContent = STEP_TXT[k] + '… ' + (k + 1) + '/4'; const p = $('mp' + i); if (p) p.style.width = ((k + 1) * (k === 3 ? 22 : 25)) + '%'; }
            m.ui.step = STEP_TXT[k] + '… ' + (k + 1) + '/4';
            await J.sleep(done ? 40 : 380);
        }
        while (!done) await J.sleep(80);
        m.ui.scanning = false; m.ui.p = 0;
        if (err) { J.error(m.fileName + ': ' + err.message); setRow(i); return; }
        const d = assess(m, data);
        m.ui.deep = d; m.ui.full = data; m.s = d.status;
        setRow(i); updateSum();
        J.toast(m.fileName + ': ' + (d.headline || STT[m.s]).toLowerCase(), m.s === 'bad' ? 'error' : undefined);
    }

    function has(findings, cats, minSev) {
        const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        let worst = null;
        findings.forEach((f) => {
            const c = String(f.category || '').toUpperCase().replace(/ /g, '_');
            if (cats.indexOf(c) >= 0) { const s = String(f.severity || 'INFO').toUpperCase(); if (worst === null || order.indexOf(s) < order.indexOf(worst)) worst = s; }
        });
        if (worst === null) return 1;
        return order.indexOf(worst) <= order.indexOf(minSev || 'HIGH') ? 0 : 2;
    }
    function assess(m, data) {
        const f = data.findings || [], mi = data.modInfo || {};
        const sum = J.Explain.summarize(data);
        const hash = mi.modrinthStatus === 'VERIFIED' || m.real === 'ok' ? 1 : 2;
        const ck = [hash, has(f, ['MALWARE_SIGNATURE', 'SUSPICIOUS_API', 'MALWARE_BEHAVIOR', 'CODE_INJECTION', 'EXECUTION', 'CHEAT']), has(f, ['NETWORK']), has(f, ['OBFUSCATION', 'ENTROPY'], 'MEDIUM')];
        const status = sum.flag ? 'bad' : (hash === 1 ? 'ok' : 'unk');
        return { status, ck, note: sum.headline + (sum.also ? ' ' + sum.also : ''), headline: sum.headline };
    }

    /* ---------- eventi ---------- */
    list.onclick = (e) => {
        const mb = e.target.closest('[data-more]');
        if (mb) { more(); return; }
        const b = e.target.closest('button[data-i]');
        if (b) { scanOne(+b.dataset.i); return; }
        const o = e.target.closest('[data-open]');
        if (o) { const m = entries.find((x) => x.path === o.dataset.open); if (m && m.ui.full) J.jar.show(m.ui.full, m.fileName, m.path); }
    };
    let mqT = null; $('mq').oninput = () => { clearTimeout(mqT); mqT = setTimeout(render, 160); };
    document.querySelectorAll('#mfil .fl').forEach((b) => { b.onclick = () => { filter = b.dataset.f; document.querySelectorAll('#mfil .fl').forEach((x) => x.setAttribute('aria-pressed', x === b)); render(); }; });
    $('btn-mods-scan').onclick = scan;
    $('btn-mods-deep').onclick = deepAll;
    $('btn-mods-choose').onclick = choose;
    $('btn-mods-locate').onclick = () => locate(false);
    J.onShow.mods = () => { if (!located && !path) locate(true); };
})();
