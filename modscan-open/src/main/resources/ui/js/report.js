/* JarAnalyzer — rendering condiviso dei risultati (JAR, processo, scansione remota). */
(function () {
    'use strict';
    const J = window.J, esc = J.esc, ic = J.ic;
    const SEV = { CRITICAL: ['c', 'Critico'], HIGH: ['h', 'Alto'], MEDIUM: ['m', 'Medio'], LOW: ['l', 'Basso'], INFO: ['i', 'Info'] };
    const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const LEVEL = {
        SAFE: ['Nessuna minaccia rilevata', '#5fd6a0'], LOW: ['Rischio basso', 'var(--info)'], MEDIUM: ['Rischio medio', 'var(--med)'],
        HIGH: ['Rischio alto', 'var(--high)'], CRITICAL: ['Rischio critico', 'var(--crit)']
    };
    const R = J.Report = {};

    function sevOf(f) { const s = String(f.severity || 'INFO').toUpperCase(); return SEV[s] ? s : 'INFO'; }
    function sortFindings(list) { return list.map((f, i) => ({ f, i })).sort((a, b) => SEV_ORDER.indexOf(sevOf(a.f)) - SEV_ORDER.indexOf(sevOf(b.f)) || a.i - b.i).map((x) => x.f); }

    /* ================= mappa delle classi (griglia DOM del parser: celle animate) =================
       Stessa UI dell'anteprima v7: celle DOM con onda idle, accensione progressiva (.seen)
       durante l'analisi e perchette finali (.f, pop scalato) per ogni classe con rilevamenti.
       Tooltip col nome della classe e click sulla cella → apre il rilevamento corrispondente. */
    const MAP_MAX = 1024;
    R.Map = {
        el: null, n: 320, cells: [], names: null,
        build(el, n) {
            this.el = el;
            this.n = Math.max(64, Math.min(MAP_MAX, n || 320));
            this.names = {};
            el.classList.remove('idle-map');
            el.innerHTML = '';
            this.cells = [];
            const frag = document.createDocumentFragment();
            for (let i = 0; i < this.n; i++) {
                const c = document.createElement('div');
                c.className = 'cell';
                c.style.setProperty('--d', ((i % 40) + (i / 40 | 0)) * 45 + 'ms');
                frag.appendChild(c);
                this.cells.push(c);
            }
            el.appendChild(frag);
            const tip = J.$('tip');
            if (tip && !el._tipWired) {
                el._tipWired = true;
                el.addEventListener('pointermove', (e) => {
                    const c = e.target.closest && e.target.closest('.cell');
                    if (!c || !c.getAttribute('data-name')) { tip.style.opacity = 0; return; }
                    tip.textContent = c.getAttribute('data-name');
                    tip.style.opacity = 1;
                    tip.style.left = Math.min(e.clientX + 14, innerWidth - 300) + 'px';
                    tip.style.top = (e.clientY + 16) + 'px';
                });
                el.addEventListener('pointerleave', () => { tip.style.opacity = 0; });
            }
        },
        idle() { if (this.el) { this.el.classList.add('idle-map'); this.cells.forEach((c) => { c.className = 'cell'; c.removeAttribute('data-s'); c.removeAttribute('data-name'); c.style.removeProperty('--fd'); }); this.names = {}; } },
        /* Durante l'analisi: accende progressivamente le classi come "esaminate". */
        sweep(frac) {
            if (!this.cells.length) return;
            this.el.classList.remove('idle-map');
            const upto = Math.min(this.n, Math.floor(this.cells.length * frac));
            for (let i = 0; i < upto; i++) {
                if (!this.cells[i].classList.contains('seen') && !this.cells[i].classList.contains('f')) {
                    this.cells[i].style.transitionDelay = (i % 24) * 3 + 'ms';
                    this.cells[i].classList.add('seen');
                }
            }
        },
        /* A fine analisi: colora le classi con rilevamenti (per severità, pop scalato). */
        reveal(findings, classCount, findingsViewId) {
            if (!this.el) return 0;
            const n = Math.max(64, Math.min(MAP_MAX, classCount || this.n));
            if (n !== this.n) this.build(this.el, n);
            this.el.classList.remove('idle-map');
            this.names = {};
            const SN = { c: 'Critico', h: 'Alto', m: 'Medio', l: 'Basso', i: 'Info' };
            const taken = {}, byLoc = {};
            findings.forEach((f) => {
                const loc = locKey(f.location);
                if (!loc) return;
                const s = sevOf(f), o = byLoc[loc] || (byLoc[loc] = { sev: s, count: 0, first: f });
                if (SEV_ORDER.indexOf(s) < SEV_ORDER.indexOf(o.sev)) { o.sev = s; o.first = f; }
                o.count++;
            });
            let k = 0;
            Object.keys(byLoc).forEach((loc) => {
                let i = hash(loc) % this.n, guard = 0;
                while (taken[i] && guard++ < this.n) i = (i + 1) % this.n;
                taken[i] = 1;
                const o = byLoc[loc], c = this.cells[i];
                const code = { c: 'c', h: 'h', m: 'm', l: 'i', i: 'i' }[SEV[o.sev][0]] || 'i';
                c.className = 'cell f';
                c.setAttribute('data-s', code);
                c.setAttribute('data-name', loc);
                c.style.setProperty('--fd', (k++) * 70 + 'ms');
                this.names[i] = loc + ' · ' + SN[SEV[o.sev][0]] + (o.count > 1 ? ' (' + o.count + ' rilevamenti)' : '');
                const self = this;
                c.onclick = () => {
                    const root = findingsViewId ? document.getElementById(findingsViewId) : null;
                    if (!root || !o.first) return;
                    const it = root.querySelector('.item[data-i="' + o.first._i + '"]');
                    if (!it) return;
                    it.setAttribute('aria-expanded', 'true');
                    const body = it.querySelector('.fbody'); if (body) body.hidden = false;
                    it.scrollIntoView({ behavior: J.RM ? 'auto' : 'smooth', block: 'center' });
                    it.classList.add('hl'); setTimeout(() => it.classList.remove('hl'), 1600);
                };
            });
            return k;
        }
    };
    function locKey(loc) {
        if (!loc) return null;
        const m = String(loc).trim().match(/^[^\s:(\[]+/);
        const k = m ? m[0] : '';
        return k.length > 1 ? k : null;
    }
    function hash(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0); }

    /* ================= verdetto + risultati ================= */
    function statsFor(d) {
        const m = d.metadata || {}, p = d.processInfo || {};
        if (d.kind === 'jar') return [[J.fmtBytes(m.fileSize), 'dimensione'], [(m.classCount || 0).toLocaleString('it-IT'), 'classi'], [(m.packages ? m.packages.length : 0).toLocaleString('it-IT'), 'pacchetti'], [(m.totalEntries || 0).toLocaleString('it-IT'), 'entries']];
        const heap = (p.heapMax || p.heapUsed) ? J.fmtBytes(p.heapUsed) + ' / ' + J.fmtBytes(p.heapMax) : 'N/D';
        return [[heap, 'heap'], [(p.threadCount || 0).toLocaleString('it-IT'), 'thread'], [(p.loadedClassCount || 0).toLocaleString('it-IT'), 'classi caricate'], [J.fmtUptime(p.uptimeMs), 'uptime']];
    }

    R.verdictHtml = function (d) {
        const level = LEVEL[d.riskLevel] ? d.riskLevel : 'SAFE', col = LEVEL[level][1], score = Math.max(0, Math.min(100, d.riskScore || 0));
        const n = {}; SEV_ORDER.forEach((s) => n[s] = 0);
        d.findings.forEach((f) => n[sevOf(f)]++);
        const tot = d.findings.length;
        const bar = tot ? SEV_ORDER.filter((s) => n[s]).map((s) => '<span class="' + SEV[s][0] + '" data-w="' + (n[s] / tot * 100) + '"></span>').join('') : '<span class="g" data-w="100"></span>';
        const legend = tot ? SEV_ORDER.filter((s) => n[s]).map((s) => '<span><i class="' + SEV[s][0] + '"></i>' + SEV[s][1] + ' <b>' + n[s] + '</b></span>').join('') : '<span><i class="g"></i>Nessun rilevamento</span>';
        const m = d.metadata || {}, p = d.processInfo || {};
        let meta;
        if (d.kind === 'jar') {
            const sha = m.sha256 || '';
            meta = '<span>' + esc(m.fileName || 'file') + '</span>' + (sha ? '<span>·</span><span title="' + esc(sha) + '">sha256 ' + esc(sha.slice(0, 10)) + '…' + esc(sha.slice(-6)) + '</span><button class="copy" type="button" data-copy="' + esc(sha) + '" data-msg="SHA-256 copiato">' + ic('copy') + ' copia</button>' : '');
        } else {
            meta = '<span>' + esc(exeName(p.processName) || 'java') + '</span><span>·</span><span>PID ' + esc(p.pid || d.pid || '?') + '</span>' + (d.kindLabel ? '<span>·</span><span>' + esc(d.kindLabel) + '</span>' : '');
        }
        meta += '<span>·</span><span>' + J.fmtDur(d.analysisTimeMs) + '</span>';
        const stats = statsFor(d).map((s) => '<div><b>' + esc(s[0]) + '</b>' + esc(s[1]) + '</div>').join('');
        return '<div class="card verdict" data-score="' + score + '"><div class="ring"><svg viewBox="0 0 120 120"><circle class="bg" cx="60" cy="60" r="54"/><circle class="fg" cx="60" cy="60" r="54" style="stroke:' + col + '"/></svg><b>0</b></div>' +
            '<div><h3 style="color:' + col + '">' + esc(LEVEL[level][0]) + '</h3><div class="meta">' + meta + '</div><div class="bar" role="img" aria-label="Distribuzione delle gravità">' + bar + '</div><div class="legend">' + legend + '</div>' +
            '<div class="stats">' + stats + '</div><div class="vactions" id="vactions-' + d.kind + '">' +
            '<button class="btn sec sm" type="button" data-act="export">' + ic('down') + 'Esporta report</button><button class="btn sec sm" type="button" data-act="summary">' + ic('copy') + 'Copia riepilogo</button><button class="btn sec sm" type="button" data-act="again">' + ic('refresh') + 'Nuova analisi</button></div></div></div>';
    };

    R.idleVerdict = function (title, sub) {
        return '<div class="card verdict idle"><div class="ring"><svg viewBox="0 0 120 120"><circle class="bg" cx="60" cy="60" r="54"/><circle class="fg" cx="60" cy="60" r="54"/></svg><b>–</b></div><div><h3>' + esc(title) + '</h3><div class="meta"><span>' + esc(sub) + '</span></div><div class="bar"></div></div></div>';
    };

    /* ================= organizzazione dei rilevamenti =================
       Modello in memoria (ordinato, con testo di ricerca precalcolato) + DOM minimo: si disegna solo la pagina
       visibile, i dettagli di una voce vengono creati quando la si apre. Filtri, ricerca e raggruppamento lavorano
       sempre sull'INTERO set (nessun taglio silenzioso: contatori e "Mostra altri" lo rendono esplicito). */
    const CAT = {
        NETWORK: ['Rete', 'globe'], EXECUTION: ['Esecuzione comandi', 'term'], CODE_INJECTION: ['Iniezione di codice', 'inject'],
        MALWARE_BEHAVIOR: ['Comportamento malware', 'bug'], MALWARE_SIGNATURE: ['Firme note', 'shield'], SUSPICIOUS_API: ['API sospette', 'code'],
        OBFUSCATION: ['Offuscamento', 'eye'], CRYPTO: ['Crittografia', 'lock'], ENTROPY: ['Entropia', 'eye'], STRUCTURE: ['Struttura del file', 'file'],
        MANIFEST: ['Manifest', 'file'], FILE_ACCESS: ['Accesso ai file', 'folder'], CERTIFICATE: ['Certificato', 'key'], VIRUSTOTAL: ['VirusTotal', 'shield'],
        CHEAT: ['Cheat noti', 'alert'], PROCESS: ['Processo', 'cpu'], MEMORY: ['Memoria', 'cpu'], OTHER: ['Altro', 'file']
    };
    function catKey(f) { const k = String(f.category || '').toUpperCase().replace(/[ -]+/g, '_'); return k || 'OTHER'; }
    function catLabel(k) { return (CAT[k] || [k.charAt(0) + k.slice(1).toLowerCase().replace(/_/g, ' ')])[0]; }
    R.PAGE = 40; R.PAGE_MORE = 80;

    /** Costruisce il modello: voci ordinate per gravità, conteggi sull'intero set. */
    R.buildModel = function (findings) {
        const all = (findings || []).map((f, i) => {
            const sev = sevOf(f), sl = SEV[sev][0], cat = catKey(f);
            return { f: f, i: i, sev: sev, sl: sl, cat: cat,
                q: ((f.title || '') + ' ' + (f.ruleName || '') + ' ' + (f.description || '') + ' ' + (f.location || '') + ' ' + (f.family || '') + ' ' + catLabel(cat)).toLowerCase() };
        });
        all.sort((a, b) => SEV_ORDER.indexOf(a.sev) - SEV_ORDER.indexOf(b.sev) || a.i - b.i);
        const bySev = { c: 0, h: 0, m: 0, l: 0, i: 0 }, byCat = {};
        all.forEach((x) => { bySev[x.sl]++; const c = byCat[x.cat] || (byCat[x.cat] = { n: 0, worst: 9 }); c.n++; c.worst = Math.min(c.worst, SEV_ORDER.indexOf(x.sev)); });
        return { all: all, bySev: bySev, byCat: byCat, total: all.length };
    };

    /** Applica filtri/ricerca/raggruppamento. opt: {sev:'all'|'c'|..., cat:'all'|KEY, q:'', group:'sev'|'cat'} → {items, rows} */
    R.query = function (model, opt) {
        const q = (opt.q || '').trim().toLowerCase();
        const items = model.all.filter((x) => (opt.sev === 'all' || x.sl === opt.sev) && (opt.cat === 'all' || x.cat === opt.cat) && (!q || x.q.indexOf(q) >= 0));
        const rows = [];
        if (opt.group === 'cat') {
            const groups = {};
            items.forEach((x) => { (groups[x.cat] || (groups[x.cat] = [])).push(x); });
            Object.keys(groups).sort((a, b) => model.byCat[a].worst - model.byCat[b].worst || groups[b].length - groups[a].length).forEach((k) => {
                rows.push({ h: catLabel(k), n: groups[k].length, sl: SEV[SEV_ORDER[model.byCat[k].worst]][0], icon: (CAT[k] || CAT.OTHER)[1] });
                groups[k].forEach((x) => rows.push(x));
            });
        } else {
            let last = null;
            items.forEach((x) => {
                if (x.sl !== last) { last = x.sl; rows.push({ h: SEV[x.sev][1], n: items.filter((y) => y.sl === x.sl).length, sl: x.sl }); }
                rows.push(x);
            });
        }
        return { items: items, rows: rows };
    };

    function rowHtml(r) {
        if (r.h !== undefined) return '<div class="grp"><i class="' + r.sl + '"></i><b>' + esc(r.h) + '</b><span>' + r.n + '</span></div>';
        const f = r.f, title = f.title || f.ruleName || 'Rilevamento';
        f._i = r.i; /* per il click dalla cella della mappa */
        return '<div class="item' + (r.sl === 'c' ? ' cr' : '') + '" data-i="' + r.i + '" data-s="' + r.sl + '" style="--n:' + r.i + '" role="button" tabindex="0" aria-expanded="false"><span class="sev ' + r.sl + '">' + SEV[r.sev][1] + '</span>' +
            '<span class="ib"><strong>' + esc(title) + '</strong>' + (f.family ? '<small class="fam">' + esc(f.family) + '</small>' : '') + '<small class="cat">' + esc(catLabel(r.cat)) + '</small>' +
            (f.description ? '<small>' + esc(f.description.length > 140 ? f.description.slice(0, 140) + '…' : f.description) + '</small>' : '') + '</span>' +
            '<span class="where">' + esc(f.location ? shortLoc(f.location) : '') + '</span></div>';
    }
    function shortLoc(l) { l = String(l); return l.length > 34 ? '…' + l.slice(-33) : l; }

    const CODE_CAP = 6000;
    function bodyHtml(f, id) {
        let b = '';
        if (f.description) b += '<p>' + esc(f.description) + '</p>';
        if (f.location) b += '<div class="fd"><span>Posizione</span><code>' + esc(f.location) + '</code></div>';
        if (f.evidence) b += '<div class="fd"><span>Evidenza</span><pre>' + esc(String(f.evidence).slice(0, CODE_CAP)) + '</pre></div>';
        if (f.recommendation) b += '<div class="fd"><span>Raccomandazione</span><p>' + esc(f.recommendation) + '</p></div>';
        if (f.decompiledCode) {
            const code = String(f.decompiledCode), cut = code.length > CODE_CAP;
            b += '<div class="fd"><span>' + ic('code') + ' Codice decompilato (CFR)</span><pre class="java">' + esc(cut ? code.slice(0, CODE_CAP) : code) + '</pre>' +
                (cut ? '<button class="btn sec sm" type="button" data-fx-act="fullcode" data-id="' + id + '">Mostra tutto (' + code.length.toLocaleString('it-IT') + ' caratteri)</button>' : '') + '</div>';
        }
        return '<div class="fbody">' + (b || '<p class="mut">Nessun dettaglio aggiuntivo.</p>') + '</div>';
    }

    const EX = {}; let exSeq = 0;
    function exStore(model, title) {
        const id = 'fx' + (++exSeq);
        EX[id] = { id: id, model: model, title: title, opt: { sev: 'all', cat: 'all', q: '', group: 'sev' }, view: null, shown: 0 };
        const keys = Object.keys(EX); if (keys.length > 24) delete EX[keys[0]];
        return EX[id];
    }
    function exRefresh(st) { st.view = R.query(st.model, st.opt); st.shown = Math.min(st.view.rows.length, R.PAGE); }
    function exCountItems(st, upto) { let n = 0; for (let k = 0; k < upto; k++) if (st.view.rows[k].h === undefined) n++; return n; }
    function exPaint(st) {
        const root = document.getElementById(st.id); if (!root) return;
        const list = root.querySelector('.list'), foot = root.querySelector('.pgap');
        list.innerHTML = st.view.rows.length ? st.view.rows.slice(0, st.shown).map(rowHtml).join('') : '<div class="mempty">Nessun rilevamento corrisponde ai filtri.</div>';
        exFoot(st, foot);
        root.querySelectorAll('.fl').forEach((b) => b.setAttribute('aria-pressed', b.dataset.f === st.opt.sev));
        root.querySelectorAll('.cat-chip').forEach((b) => b.setAttribute('aria-pressed', b.dataset.c === st.opt.cat));
        root.querySelectorAll('.seg2 button').forEach((b) => b.setAttribute('aria-pressed', b.dataset.g === st.opt.group));
    }
    function exFoot(st, foot) {
        const total = st.view.items.length, shownItems = exCountItems(st, st.shown);
        if (st.shown >= st.view.rows.length) { foot.hidden = true; return; }
        foot.hidden = false;
        foot.querySelector('span').textContent = 'Visualizzati ' + shownItems + ' di ' + total + ' rilevamenti.';
        exObserve(st, foot);
    }
    function exMore(st) {
        const root = document.getElementById(st.id); if (!root || st.shown >= st.view.rows.length) return;
        const from = st.shown; st.shown = Math.min(st.view.rows.length, st.shown + R.PAGE_MORE);
        root.querySelector('.list').insertAdjacentHTML('beforeend', st.view.rows.slice(from, st.shown).map(rowHtml).join(''));
        exFoot(st, root.querySelector('.pgap'));
    }
    let io = null;
    function exObserve(st, foot) {
        if (typeof IntersectionObserver === 'undefined') return;
        if (!io) io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { const r = e.target.closest('[data-fx]'); if (r && EX[r.id]) exMore(EX[r.id]); } }), { rootMargin: '400px' });
        io.unobserve(foot); io.observe(foot);
    }

    R.findingsHtml = function (d, title) {
        const model = R.buildModel(d.findings), st = exStore(model, title || 'Rilevamenti');
        R.lastId = st.id;
        exRefresh(st);
        const n = model.bySev;
        const chips = [['all', 'Tutti', model.total]].concat(SEV_ORDER.filter((s) => n[SEV[s][0]]).map((s) => [SEV[s][0], SEV[s][1], n[SEV[s][0]]]));
        const head = '<div class="fh"><h3>' + esc(st.title) + ' <span class="chip">' + model.total + '</span></h3><div class="filters">' + chips.map((c, i) => '<button class="fl" data-f="' + c[0] + '" aria-pressed="' + (i === 0) + '">' + c[1] + ' ' + c[2] + '</button>').join('') + '</div></div>';
        if (!model.total) return '<div class="card finds">' + head + '<div class="clean">' + ic('shield', 38) + '<b>Nessuna minaccia rilevata</b><span>In base all\'analisi eseguita il risultato appare pulito.</span></div></div>';
        const cats = Object.keys(model.byCat).sort((a, b) => model.byCat[a].worst - model.byCat[b].worst || model.byCat[b].n - model.byCat[a].n);
        const catRow = cats.length > 1 ? '<div class="cats"><button class="cat-chip" data-c="all" type="button" aria-pressed="true">Tutte le categorie</button>' +
            cats.map((k) => '<button class="cat-chip" data-c="' + k + '" type="button" aria-pressed="false">' + ic((CAT[k] || CAT.OTHER)[1]) + esc(catLabel(k)) + ' <b>' + model.byCat[k].n + '</b></button>').join('') + '</div>' : '';
        const tools = '<div class="ftools"><label class="search"><svg class="ic"><use href="#i-search"/></svg><input class="fsearch" type="search" placeholder="Cerca nei rilevamenti" aria-label="Cerca nei rilevamenti"></label>' +
            '<div class="seg2" role="group" aria-label="Raggruppa per"><span>Raggruppa per</span><button type="button" data-g="sev" aria-pressed="true">Gravità</button><button type="button" data-g="cat" aria-pressed="false">Categoria</button></div></div>';
        const first = st.view.rows.slice(0, st.shown);
        const gap = st.shown < st.view.rows.length ? '<div class="pgap"><span>Visualizzati ' + exCountItems(st, st.shown) + ' di ' + st.view.items.length + ' rilevamenti.</span> <button class="btn sec sm" type="button" data-fx-act="more">Mostra altri</button></div>' : '<div class="pgap" hidden><span></span> <button class="btn sec sm" type="button" data-fx-act="more">Mostra altri</button></div>';
        return '<div class="card finds" id="' + st.id + '" data-fx>' + head + tools + catRow + '<div class="list on">' + first.map(rowHtml).join('') + '</div>' + gap + '</div>';
    };

    /** Card "Da controllare per primi" da voci già raccolte: entries = [{x: riga del modello, fx: id esploratore, label?}]. */
    R.priorityFrom = function (entries, seriousTotal) {
        const top = entries.filter((e) => e.x.sl === 'c' || e.x.sl === 'h').sort((a, b) => SEV_ORDER.indexOf(a.x.sev) - SEV_ORDER.indexOf(b.x.sev)).slice(0, 5);
        if (!top.length) return '';
        return '<div class="card pri"><div class="fh"><h3>Da controllare per primi</h3><span class="chip">' + top.length + ' di ' + (seriousTotal || top.length) + ' gravi</span></div>' +
            top.map((e) => '<button class="prirow" type="button" data-fx-act="jump" data-fx="' + e.fx + '" data-i="' + e.x.i + '"><span class="sev ' + e.x.sl + '">' + SEV[e.x.sev][1] + '</span><span><strong>' + esc(e.x.f.title || e.x.f.ruleName || 'Rilevamento') + '</strong><small>' + esc((e.label ? e.label + ' · ' : '') + (e.x.f.location ? shortLoc(e.x.f.location) : catLabel(e.x.cat))) + '</small></span><span class="go">' + ic('code') + '</span></button>').join('') + '</div>';
    };
    R.priorityHtml = function (d, fxId) {
        const model = R.buildModel(d.findings);
        return R.priorityFrom(model.all.map((x) => ({ x: x, fx: fxId })), model.bySev.c + model.bySev.h);
    };

    /** Riepilogo testuale da incollare in un ticket/chat. */
    R.summaryText = function (d) {
        const m = d.metadata || {}, p = d.processInfo || {}, model = R.buildModel(d.findings), L = LEVEL[d.riskLevel] || LEVEL.SAFE;
        const subject = d.kind === 'jar' ? (m.fileName || 'file') : (exeName(p.processName) || 'processo') + ' (PID ' + (p.pid || d.pid || '?') + ')';
        const lines = ['ModScanOpen — ' + subject, L[0] + ' · punteggio ' + (d.riskScore || 0) + '/100',
            'Rilevamenti: ' + model.total + ' (' + ['c', 'h', 'm', 'l', 'i'].filter((k) => model.bySev[k]).map((k) => model.bySev[k] + ' ' + SEV[SEV_ORDER[['c', 'h', 'm', 'l', 'i'].indexOf(k)]][1].toLowerCase()).join(', ') + ')'];
        if (m.sha256) lines.push('SHA-256: ' + m.sha256);
        model.all.filter((x) => x.sl === 'c' || x.sl === 'h').slice(0, 8).forEach((x, k) => lines.push((k + 1) + '. [' + SEV[x.sev][1] + '] ' + (x.f.title || x.f.ruleName) + (x.f.location ? ' — ' + x.f.location : '')));
        return lines.join('\n');
    };

    document.addEventListener('click', (e) => {
        const t = e.target;
        const root = t.closest && t.closest('[data-fx]');
        if (!root) { const j = t.closest && t.closest('[data-fx-act="jump"]'); if (j) jump(j); return; }
        const st = EX[root.id]; if (!st) return;
        const fl = t.closest('.fl'), cc = t.closest('.cat-chip'), sg = t.closest('.seg2 button'), more = t.closest('[data-fx-act="more"]'), full = t.closest('[data-fx-act="fullcode"]'), it = t.closest('.item');
        if (fl) { st.opt.sev = fl.dataset.f; exRefresh(st); exPaint(st); }
        else if (cc) { st.opt.cat = st.opt.cat === cc.dataset.c ? 'all' : cc.dataset.c; exRefresh(st); exPaint(st); }
        else if (sg) { st.opt.group = sg.dataset.g; exRefresh(st); exPaint(st); }
        else if (more) exMore(st);
        else if (full) { const x = st.model.all.find((y) => String(y.i) === full.closest('.item').dataset.i); if (x) { const pre = full.parentNode.querySelector('pre'); pre.textContent = x.f.decompiledCode; full.remove(); } }
        else if (it) toggle(st, it);
    });
    document.addEventListener('keydown', (e) => { const it = e.target.closest && e.target.closest('[data-fx] .item'); if (it && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); it.click(); } });
    let qT = null;
    document.addEventListener('input', (e) => {
        const inp = e.target.closest && e.target.closest('.fsearch'); if (!inp) return;
        const root = inp.closest('[data-fx]'), st = root && EX[root.id]; if (!st) return;
        clearTimeout(qT); qT = setTimeout(() => { st.opt.q = inp.value; exRefresh(st); exPaint(st); }, 160);
    });
    function toggle(st, it) {
        const open = it.getAttribute('aria-expanded') !== 'true';
        it.setAttribute('aria-expanded', open);
        const ib = it.querySelector('.ib'); let body = ib.querySelector('.fbody');
        if (open && !body) { const x = st.model.all.find((y) => String(y.i) === it.dataset.i); if (x) ib.insertAdjacentHTML('beforeend', bodyHtml(x.f, st.id)); body = ib.querySelector('.fbody'); }
        if (body) body.hidden = !open;
    }
    function jump(btn) {
        const mine = (btn.dataset.fx && document.getElementById(btn.dataset.fx)) || (btn.closest('.view') || document).querySelector('[data-fx]');
        const st = mine && EX[mine.id]; if (!st) return;
        st.opt = { sev: 'all', cat: 'all', q: '', group: 'sev' }; exRefresh(st);
        const idx = st.view.rows.findIndex((r) => r.h === undefined && String(r.i) === btn.dataset.i);
        if (idx >= st.shown) st.shown = Math.min(st.view.rows.length, idx + 10);
        exPaint(st);
        const si = mine.querySelector('.fsearch'); if (si) si.value = '';
        const el = mine.querySelector('.item[data-i="' + btn.dataset.i + '"]');
        if (el) { if (el.getAttribute('aria-expanded') !== 'true') toggle(st, el); el.scrollIntoView({ block: 'center' }); el.classList.add('hl'); setTimeout(() => el.classList.remove('hl'), 1500); }
    }
    R._EX = EX;

    /* verifiche esterne (solo JAR): Modrinth (con Megabase di riserva) + tipologia del file */
    R.certsHtml = function (d) {
        const mi = d.modInfo || {};
        let mod;
        if (!mi.minecraftMod) {
            mod = cert('Tipo file', 'na', 'Non applicabile', 'Il file non sembra una mod Minecraft (Fabric/Forge).');
        } else {
            let det = 'Mod ' + (mi.platform || 'Minecraft') + (mi.modVersion ? ' · v' + mi.modVersion : '') + (mi.mcVersion ? ' · MC ' + mi.mcVersion : '');
            let extra = '';
            if (mi.modrinthProjectUrl) extra = '<span class="clink">' + esc(mi.modrinthProjectUrl) + '</span>';
            const st = mi.modrinthStatus;
            if (st === 'VERIFIED') {
                mod = cert('Modrinth', 'ok', 'Verificato', det + (mi.modrinthVersion ? ' — rilascio ufficiale v' + mi.modrinthVersion : ' — rilascio ufficiale'), extra);
            } else if (st === 'NOT_FOUND') {
                mod = cert('Modrinth', 'warn', 'Non verificato', det + ' — nessuna corrispondenza su Modrinth o Megabase: attenzione a build custom o file modificati.');
            } else if (st === 'ERROR') {
                mod = cert('Modrinth', 'na', 'Verifica non disponibile', det + ' — impossibile contattare i database delle mod.');
            } else {
                mod = cert('Modrinth', 'na', '—', det);
            }
        }
        const vt = cert('Rete', 'na', 'Solo Modrinth e Megabase', 'L\'analisi è locale; le uniche connessioni servono a verificare l\'hash sui database delle mod.');
        return '<div class="certs">' + mod + vt + '</div>';
    };
    function cert(name, kind, status, detail, extra) {
        return '<div class="card cert"><div class="ch"><span>' + esc(name) + '</span><span class="cs ' + kind + '">' + esc(status) + '</span></div><p>' + esc(detail) + '</p>' + (extra || '') + '</div>';
    }

    const SX = {}; let sxSeq = 0; const SPAGE = 200;
    R.stringsHtml = function (d) {
        const ms = d.memoryStrings || {}, keys = Object.keys(ms).filter((k) => (ms[k] || []).length);
        if (!keys.length) return '';
        const id = 'sx' + (++sxSeq);
        SX[id] = { id: id, ms: ms, keys: keys, cur: keys[0], q: '', shown: SPAGE };
        const ks = Object.keys(SX); if (ks.length > 6) delete SX[ks[0]];
        const tabs = keys.map((k, n) => '<button class="cat-chip" type="button" data-sk="' + esc(k) + '" aria-pressed="' + (n === 0) + '">' + esc(k) + ' <b>' + ms[k].length.toLocaleString('it-IT') + '</b></button>').join('');
        return '<div class="card finds" id="' + id + '" data-sx><div class="fh"><h3>Stringhe in memoria <span class="chip">' + keys.reduce((a, k) => a + ms[k].length, 0).toLocaleString('it-IT') + '</span></h3></div>' +
            '<div class="ftools"><label class="search"><svg class="ic"><use href="#i-search"/></svg><input class="ssearch" type="search" placeholder="Cerca nelle stringhe" aria-label="Cerca nelle stringhe"></label></div>' +
            '<div class="cats">' + tabs + '</div><div class="sbody"></div></div>';
    };
    function sxPaint(st) {
        const root = document.getElementById(st.id); if (!root) return;
        const q = st.q.toLowerCase(), all = st.ms[st.cur] || [], list = q ? all.filter((x) => String(x).toLowerCase().indexOf(q) >= 0) : all, shown = list.slice(0, st.shown);
        root.querySelector('.sbody').innerHTML = (list.length ? '<pre class="strs">' + esc(shown.join('\n')) + '</pre>' : '<div class="mempty">Nessuna stringa corrisponde.</div>') +
            '<div class="pgap"' + (shown.length >= list.length ? ' hidden' : '') + '><span>Visualizzate ' + shown.length.toLocaleString('it-IT') + ' di ' + list.length.toLocaleString('it-IT') + ' stringhe.</span> <button class="btn sec sm" type="button" data-sx-more>Mostra altre</button></div>';
        root.querySelectorAll('.cat-chip').forEach((b) => b.setAttribute('aria-pressed', b.dataset.sk === st.cur));
    }
    function sxInit(root) { const st = SX[root.id]; if (st && !root.dataset.ready) { root.dataset.ready = '1'; sxPaint(st); } }
    document.addEventListener('click', (e) => {
        const root = e.target.closest && e.target.closest('[data-sx]'); if (!root) return;
        const st = SX[root.id]; if (!st) return;
        const tab = e.target.closest('[data-sk]'), more = e.target.closest('[data-sx-more]');
        if (tab) { st.cur = tab.dataset.sk; st.shown = SPAGE; sxPaint(st); }
        else if (more) { st.shown += SPAGE; sxPaint(st); }
    });
    document.addEventListener('input', (e) => {
        const inp = e.target.closest && e.target.closest('.ssearch'); if (!inp) return;
        const root = inp.closest('[data-sx]'), st = root && SX[root.id]; if (!st) return;
        clearTimeout(qT); qT = setTimeout(() => { st.q = inp.value; st.shown = SPAGE; sxPaint(st); }, 160);
    });

    /* ================= montaggio ================= */
    /**
     * @param slots {verdict: Element, map?: Element, below: Element}
     * @param d dati normalizzati (vedi R.normalize*)
     */
    R.render = function (slots, d, opts) {
        opts = opts || {};
        slots.verdict.innerHTML = R.verdictHtml(d);
        const parts = [];
        if (d.kind === 'jar') parts.push(R.certsHtml(d));
        const fHtml = R.findingsHtml(d, opts.findingsTitle), fId = R.lastId;
        const pHtml = R.priorityHtml(d, fId);
        if (slots.priority) slots.priority.innerHTML = pHtml; else parts.push(pHtml);
        parts.push(fHtml);
        parts.push(R.stringsHtml(d));
        slots.below.innerHTML = parts.join('');
        const roots = slots.priority ? [slots.verdict, slots.below, slots.priority] : [slots.verdict, slots.below];
        if (slots.verdict === slots.below) { slots.below.innerHTML = R.verdictHtml(d) + parts.join(''); roots.length = 1; }
        roots.forEach((root) => { wire(root, d, opts); root.querySelectorAll('[data-sx]').forEach(sxInit); });
        const v = slots.verdict.querySelector('.verdict'), score = d.riskScore || 0;
        requestAnimationFrame(() => {
            const fg = v.querySelector('.fg'); if (fg) fg.style.strokeDashoffset = 339.3 * (1 - Math.max(0, Math.min(100, score)) / 100);
            v.querySelectorAll('.bar span').forEach((x) => { x.style.width = x.dataset.w + '%'; });
            J.count(v.querySelector('.ring b'), score, 0, 900);
        });
        return v;
    };

    function wire(root, d, opts) {
        root.onclick = function (e) {
            const c = e.target.closest('[data-copy]');
            if (c) { J.copy(c.dataset.copy, c.dataset.msg); return; }
            const a = e.target.closest('[data-act]');
            if (!a) return;
            if (a.dataset.act === 'export') R.exportHtml(d);
            else if (a.dataset.act === 'summary') J.copy(R.summaryText(d), 'Riepilogo copiato');
            else if (opts.onAction) opts.onAction(a.dataset.act, a);
        };
    }

    /* ================= normalizzazione ================= */
    function exeName(s) { if (!s) return ''; const p = String(s).split(/[\\/]/); return p[p.length - 1]; }
    R.exeName = exeName;
    R.fromJar = function (data) {
        return Object.assign({}, data, { kind: 'jar', findings: data.findings || [], riskScore: data.riskScore || 0, riskLevel: data.riskLevel || 'SAFE', metadata: data.metadata || {} });
    };
    R.fromProcess = function (data, label) {
        const p = data.processInfo || {};
        return { kind: 'process', kindLabel: label || '', findings: data.findings || [], riskScore: data.riskScore || 0, riskLevel: data.riskLevel || 'SAFE', analysisTimeMs: data.analysisTimeMs || 0, processInfo: p, pid: data.pid, memoryStrings: data.memoryStrings || {}, timestamp: data.timestamp };
    };
    R.merge = function (scan, dump) {
        if (!dump) return scan;
        if (dump.findings && dump.findings.length) {
            const seen = {}, key = (f) => [f.ruleName, f.title, f.location, f.severity].join('|');
            scan.findings = (scan.findings || []).concat(dump.findings).filter((f) => { const k = key(f); if (seen[k]) return false; seen[k] = 1; return true; });
        }
        if ((dump.riskScore || 0) > (scan.riskScore || 0)) { scan.riskScore = dump.riskScore; scan.riskLevel = dump.riskLevel; }
        if (dump.memoryStrings && Object.keys(dump.memoryStrings).length) scan.memoryStrings = Object.assign(scan.memoryStrings || {}, dump.memoryStrings);
        return scan;
    };

    /* ================= export HTML ================= */
    R.exportHtml = function (d) {
        const when = new Date().toLocaleString('it-IT');
        const m = d.metadata || {}, p = d.processInfo || {};
        const subject = d.kind === 'jar' ? (m.fileName || 'File analizzato') : (exeName(p.processName) || 'Processo') + ' (PID ' + (p.pid || d.pid || '?') + ')';
        const colors = { CRITICAL: '#ff4560', HIGH: '#ff8a3d', MEDIUM: '#f2c14e', LOW: '#5fb4ff', INFO: '#9b928a' };
        const rows = sortFindings(d.findings || []).map((f) => '<tr><td><span class="b" style="background:' + (colors[sevOf(f)]) + '">' + SEV[sevOf(f)][1] + '</span></td><td>' + esc(f.category || '') + '</td><td>' + esc(f.title || f.ruleName || '') + '</td><td>' + esc(f.description || '') + '</td><td><code>' + esc(f.location || '—') + '</code></td></tr>').join('');
        const html = '<!DOCTYPE html><html lang="it"><head><meta charset="UTF-8"><title>Report — ' + esc(subject) + '</title><style>body{font-family:Segoe UI,Arial,sans-serif;background:#0f0e0d;color:#efeae2;padding:32px}h1{margin:0 0 6px}.meta{color:#9b928a;margin-bottom:22px;font-size:14px}table{width:100%;border-collapse:collapse;background:#171513}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #2b2724;font-size:13px;vertical-align:top}th{background:#201d1a;color:#c3a6ff;font-size:12px;text-transform:uppercase}.b{color:#12100e;font-weight:700;padding:2px 9px;border-radius:6px;font-size:12px}code{color:#8aa4ff;word-break:break-all}.s{font-size:44px;font-weight:800}.f{margin-top:18px;color:#6d645d;font-size:12px}</style></head><body><h1>Report di analisi — ' + esc(subject) + '</h1><div class="meta">Generato il ' + esc(when) + (m.sha256 ? ' · SHA-256 ' + esc(m.sha256) : '') + '</div><div class="s">' + (d.riskScore || 0) + '<span style="font-size:16px;color:#9b928a"> / 100 — ' + esc((LEVEL[d.riskLevel] || LEVEL.SAFE)[0]) + '</span></div><h2>Rilevamenti (' + (d.findings || []).length + ')</h2><table><thead><tr><th>Gravità</th><th>Categoria</th><th>Titolo</th><th>Descrizione</th><th>Posizione</th></tr></thead><tbody>' + (rows || '<tr><td colspan="5">Nessun rilevamento.</td></tr>') + '</tbody></table><div class="f">Generato da ModScanOpen (open source, MIT)</div></body></html>';
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        window.ModScanOpenFileSaver.saveTextFile(html, 'report-' + ts + '.html', 'text/html').then((r) => { if (r.success) J.toast('Report salvato'); });
    };
})();
