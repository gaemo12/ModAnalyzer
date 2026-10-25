/* JarAnalyzer — rendering condiviso dei risultati (JAR, processo, scansione remota). */
(function () {
    'use strict';
    const J = window.J, esc = J.esc, ic = J.ic;
    const SEV = { CRITICAL: ['c', 'Grave'], HIGH: ['h', 'Serio'], MEDIUM: ['m', 'Dubbio'], LOW: ['l', 'Lieve'], INFO: ['i', 'Nota'] };
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
                    const parts = c.getAttribute('data-name').split('/'), cls = parts.pop();
                    tip.innerHTML = '<b>' + esc(cls) + '</b>' + (parts.length ? '<small>' + esc(parts.join('/')) + '</small>' : '') + esc(c.getAttribute('data-info') || '') + '<br><em>Clic per vedere i dettagli</em>';
                    tip.style.opacity = 1;
                    tip.style.left = Math.min(e.clientX + 14, innerWidth - 340) + 'px';
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
                c.setAttribute('data-info', SEV[o.sev][1] + ' · ' + o.count + (o.count > 1 ? ' segnalazioni' : ' segnalazione'));
                c.style.setProperty('--fd', (k++) * 70 + 'ms');
                this.names[i] = loc + ' · ' + SN[SEV[o.sev][0]] + (o.count > 1 ? ' (' + o.count + ' rilevamenti)' : '');
                const self = this;
                c.onclick = () => {
                    const root = findingsViewId ? document.getElementById(findingsViewId) : null;
                    if (!root || !o.first) return;
                    const it = root.querySelector('.item[data-i="' + o.first._i + '"]');
                    if (!it) return;
                    const dt = root.closest('details'); if (dt) dt.open = true; /* i dettagli tecnici sono ripiegati */
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

    const RING_COL = { ok: '#5fd6a0', note: '#5fd6a0', warn: 'var(--med)', bad: 'var(--crit)' };
    const RING_ICON = { ok: 'shield', note: 'shield', warn: 'alert', bad: 'x' };
    function ringHtml(state) {
        const col = RING_COL[state] || 'var(--mut)';
        return '<div class="ring"><svg viewBox="0 0 120 120"><circle class="bg" cx="60" cy="60" r="54"/><circle class="fg" cx="60" cy="60" r="54" style="stroke:' + col + '"/></svg><b style="color:' + col + '">' + ic(RING_ICON[state] || 'shield', 52) + '</b></div>';
    }

    R.verdictHtml = function (d) {
        const s = J.Explain.summarize(d), m = d.metadata || {}, mi = d.modInfo || {}, p = d.processInfo || {};
        const subject = d.kind === 'jar' ? (m.fileName || 'File') : (exeName(p.processName) || 'Minecraft') + ' · PID ' + (p.pid || d.pid || '?');
        const chips = [];
        if (d.kind === 'jar') {
            chips.push(J.fmtBytes(m.fileSize));
            if (mi.minecraftMod) chips.push('Mod ' + (mi.platform || 'Minecraft') + (mi.mcVersion ? ' · Minecraft ' + mi.mcVersion : ''));
            else chips.push('Non sembra una mod');
        } else if (d.kindLabel) chips.push(d.kindLabel);
        if (s.verified) chips.push('Ufficiale su Modrinth');
        const chipHtml = chips.map((c) => '<span class="chip">' + esc(c) + '</span>').join('');
        return '<div class="card verdict vd st-' + s.state + '" data-state="' + s.state + '">' + ringHtml(s.state) +
            '<div class="vbody"><span class="vsubj">' + esc(subject) + '</span><h3>' + esc(s.headline) + '</h3><p class="vsub">' + esc(s.sub) + '</p>' +
            (s.also ? '<p class="valso">' + esc(s.also) + '</p>' : '') + '<div class="vchips">' + chipHtml + '</div>' +
            '<div class="vactions" id="vactions-' + d.kind + '"><button class="btn sec sm" type="button" data-act="export">' + ic('down') + 'Salva report</button>' +
            '<button class="btn sec sm" type="button" data-act="summary">' + ic('copy') + 'Copia riepilogo</button>' +
            '<button class="btn sec sm" type="button" data-act="again">' + ic('refresh') + 'Controlla un’altra mod</button></div></div></div>';
    };

    R.idleVerdict = function (title, sub) {
        return '<div class="card verdict vd idle"><div class="ring"><svg viewBox="0 0 120 120"><circle class="bg" cx="60" cy="60" r="54"/></svg><b>–</b></div><div class="vbody"><h3>' + esc(title) + '</h3><p class="vsub">' + esc(sub) + '</p></div></div>';
    };

    /** Card "Cosa fare": passi concreti in base al verdetto. */
    R.adviceHtml = function (sum) {
        return '<div class="card advice st-' + sum.state + '"><div class="fh"><h3>Cosa fare</h3></div><ul>' +
            sum.advice.map((a) => '<li>' + esc(a) + '</li>').join('') + '</ul><p class="caveat">' + esc(J.Explain.CAVEAT) + '</p></div>';
    };

    /** Card "Cosa abbiamo trovato": un blocco per argomento, in parole semplici. */
    R.topicsHtml = function (d, fxId) {
        const sum = J.Explain.summarize(d);
        if (!sum.topics.length) {
            return '<div class="card topics"><div class="fh"><h3>Cosa abbiamo controllato</h3></div><div class="clean">' + ic('shield', 38) + '<b>Non è emerso niente di sospetto</b><span>Abbiamo cercato furto di account e password, controllo remoto, mining, cheat, codice nascosto e connessioni strane.</span></div></div>';
        }
        const T = J.Explain.TIER;
        const rows = sum.topics.map((g) => {
            const t = g.t, tier = T[t.tier], items = g.items.slice().sort((a, b) => a.s - b.s), shown = items.slice(0, 5);
            const lis = shown.map((x) => {
                const sv = SEV[SEV_ORDER[x.s]];
                return '<li><button type="button" class="tpi" data-fx-act="jump" data-fx-target="' + fxId + '" data-i="' + x.i + '"><span class="sev ' + sv[0] + '">' + sv[1] + '</span><span><strong>' + esc(x.f.title || x.f.ruleName || 'Segnalazione') + '</strong>' +
                    (x.f.location ? '<small>' + esc(shortLoc(x.f.location)) + '</small>' : '') + '</span></button></li>';
            }).join('');
            const more = items.length > 5 ? '<p class="tpmore">…e altre ' + (items.length - 5) + ' nei dettagli tecnici.</p>' : '';
            const open = (t.tier === 'grave' || t.tier === 'serio') ? ' open' : '';
            return '<details class="tp t-' + t.tier + '"' + open + '><summary><span class="tpi0">' + ic(t.icon, 22) + '</span><span class="tpt"><b>' + esc(t.label) + '</b><small>' + esc(t.what) + '</small></span>' +
                '<span class="tier ' + tier[1] + '">' + tier[0] + '</span><span class="tpn" title="Segnalazioni in questo gruppo">' + items.length + '</span></summary>' +
                '<div class="tpb"><p>' + esc(t.why) + '</p><ul>' + lis + '</ul>' + more + '</div></details>';
        }).join('');
        return '<div class="card topics"><div class="fh"><h3>Cosa abbiamo trovato</h3></div>' + rows + '</div>';
    };

    /** Sezione ripiegata per chi vuole vedere il codice: elenco completo, stringhe, mappa. */
    R.techHtml = function (d, findingsCard, stringsCard) {
        const n = (d.findings || []).length;
        return '<details class="card tech"><summary><span>Dettagli tecnici</span><small>per chi vuole vedere il codice · punteggio tecnico ' + (d.riskScore || 0) + '/100</small><span class="chip">' + n + '</span></summary>' +
            '<div class="techb">' + findingsCard + stringsCard + '</div></details>';
    };

    /* ================= organizzazione dei rilevamenti =================
       Modello in memoria (ordinato, con testo di ricerca precalcolato) + DOM minimo: si disegna solo la pagina
       visibile, i dettagli di una voce vengono creati quando la si apre. Filtri, ricerca e raggruppamento lavorano
       sempre sull'INTERO set (nessun taglio silenzioso: contatori e "Mostra altri" lo rendono esplicito). */
    const CAT = {
        NETWORK: ['Connessioni a internet', 'globe'], EXECUTION: ['Esegue comandi sul PC', 'code'], CODE_INJECTION: ['Si aggancia ad altri programmi', 'inject'],
        MALWARE_BEHAVIOR: ['Comportamento sospetto', 'bug'], MALWARE_SIGNATURE: ['File pericolosi noti', 'shield'], SUSPICIOUS_API: ['Funzioni delicate di Java', 'code'],
        OBFUSCATION: ['Codice nascosto', 'eye'], CRYPTO: ['Cifratura', 'lock'], ENTROPY: ['Dati compressi o cifrati', 'eye'], STRUCTURE: ['Struttura del file', 'file'],
        MANIFEST: ['Informazioni del file', 'file'], FILE_ACCESS: ['Accesso ai file del PC', 'folder'], CERTIFICATE: ['Firma del file', 'shield'], VIRUSTOTAL: ['VirusTotal', 'shield'],
        CHEAT: ['Funzioni da cheat', 'alert'], PROCESS: ['Gioco in esecuzione', 'cpu'], MEMORY: ['Memoria del gioco', 'cpu'], SYSTEM: ['Sistema', 'cpu'], OTHER: ['Altro', 'file']
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
        const tp = J.Explain.topicOf(f);
        b += '<p class="plain"><b>In parole semplici:</b> ' + esc(tp.what + (tp.why ? ' ' + tp.why : '')) + '</p>';
        if (f.description) b += '<p>' + esc(f.description) + '</p>';
        if (f.location) b += '<div class="fd"><span>Dove nel file</span><code>' + esc(f.location) + '</code></div>';
        if (f.evidence) b += '<div class="fd"><span>Cosa è stato trovato</span><pre>' + esc(String(f.evidence).slice(0, CODE_CAP)) + '</pre></div>';
        if (f.recommendation) b += '<div class="fd"><span>Consiglio</span><p>' + esc(f.recommendation) + '</p></div>';
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
        list.innerHTML = st.view.rows.length ? st.view.rows.slice(0, st.shown).map(rowHtml).join('') : '<div class="mempty">Nessuna segnalazione corrisponde ai filtri.</div>';
        exFoot(st, foot);
        root.querySelectorAll('.fl').forEach((b) => b.setAttribute('aria-pressed', b.dataset.f === st.opt.sev));
        root.querySelectorAll('.cat-chip').forEach((b) => b.setAttribute('aria-pressed', b.dataset.c === st.opt.cat));
        root.querySelectorAll('.seg2 button').forEach((b) => b.setAttribute('aria-pressed', b.dataset.g === st.opt.group));
    }
    function exFoot(st, foot) {
        const total = st.view.items.length, shownItems = exCountItems(st, st.shown);
        if (st.shown >= st.view.rows.length) { foot.hidden = true; return; }
        foot.hidden = false;
        foot.querySelector('span').textContent = 'Visualizzate ' + shownItems + ' di ' + total + ' segnalazioni.';
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
        if (!model.total) return '<div class="card finds">' + head + '<div class="clean">' + ic('shield', 38) + '<b>Nessuna segnalazione</b><span>Il controllo non ha trovato niente da segnalare.</span></div></div>';
        const cats = Object.keys(model.byCat).sort((a, b) => model.byCat[a].worst - model.byCat[b].worst || model.byCat[b].n - model.byCat[a].n);
        const catRow = cats.length > 1 ? '<div class="cats"><button class="cat-chip" data-c="all" type="button" aria-pressed="true">Tutte le categorie</button>' +
            cats.map((k) => '<button class="cat-chip" data-c="' + k + '" type="button" aria-pressed="false">' + ic((CAT[k] || CAT.OTHER)[1]) + esc(catLabel(k)) + ' <b>' + model.byCat[k].n + '</b></button>').join('') + '</div>' : '';
        const tools = '<div class="ftools"><label class="search"><svg class="ic"><use href="#i-search"/></svg><input class="fsearch" type="search" placeholder="Cerca nelle segnalazioni" aria-label="Cerca nelle segnalazioni"></label>' +
            '<div class="seg2" role="group" aria-label="Raggruppa per"><span>Raggruppa per</span><button type="button" data-g="sev" aria-pressed="true">Gravità</button><button type="button" data-g="cat" aria-pressed="false">Categoria</button></div></div>';
        const first = st.view.rows.slice(0, st.shown);
        const gap = st.shown < st.view.rows.length ? '<div class="pgap"><span>Visualizzate ' + exCountItems(st, st.shown) + ' di ' + st.view.items.length + ' segnalazioni.</span> <button class="btn sec sm" type="button" data-fx-act="more">Mostra altri</button></div>' : '<div class="pgap" hidden><span></span> <button class="btn sec sm" type="button" data-fx-act="more">Mostra altri</button></div>';
        return '<div class="card finds" id="' + st.id + '" data-fx>' + head + tools + catRow + '<div class="list on">' + first.map(rowHtml).join('') + '</div>' + gap + '</div>';
    };

    /** Card "Da controllare per primi" da voci già raccolte: entries = [{x: riga del modello, fx: id esploratore, label?}]. */
    R.priorityFrom = function (entries, seriousTotal) {
        const top = entries.filter((e) => e.x.sl === 'c' || e.x.sl === 'h').sort((a, b) => SEV_ORDER.indexOf(a.x.sev) - SEV_ORDER.indexOf(b.x.sev)).slice(0, 5);
        if (!top.length) return '';
        return '<div class="card pri"><div class="fh"><h3>Da controllare per primi</h3><span class="chip">' + top.length + ' di ' + (seriousTotal || top.length) + ' gravi</span></div>' +
            top.map((e) => '<button class="prirow" type="button" data-fx-act="jump" data-fx-target="' + e.fx + '" data-i="' + e.x.i + '"><span class="sev ' + e.x.sl + '">' + SEV[e.x.sev][1] + '</span><span><strong>' + esc(e.x.f.title || e.x.f.ruleName || 'Rilevamento') + '</strong><small>' + esc((e.label ? e.label + ' · ' : '') + (e.x.f.location ? shortLoc(e.x.f.location) : catLabel(e.x.cat))) + '</small></span><span class="go">' + ic('code') + '</span></button>').join('') + '</div>';
    };
    R.priorityHtml = function (d, fxId) {
        const model = R.buildModel(d.findings);
        return R.priorityFrom(model.all.map((x) => ({ x: x, fx: fxId })), model.bySev.c + model.bySev.h);
    };

/** Riepilogo testuale da incollare in una chat o in un ticket. */
    R.summaryText = function (d) {
        const m = d.metadata || {}, p = d.processInfo || {}, sum = J.Explain.summarize(d);
        const subject = d.kind === 'jar' ? (m.fileName || 'file') : (exeName(p.processName) || 'Minecraft') + ' (PID ' + (p.pid || d.pid || '?') + ')';
        const lines = ['ModScanOpen — ' + subject, 'Esito: ' + sum.headline, sum.sub];
        if (sum.also) lines.push(sum.also);
        if (d.kind === 'jar') lines.push('Mod ufficiale su Modrinth: ' + (sum.verified ? 'sì' : 'no / non riconosciuta'));
        if (sum.topics.length) {
            lines.push('', 'Cosa è stato trovato:');
            sum.topics.forEach((g) => lines.push('- ' + g.t.label + ' (' + g.items.length + ')'));
        }
        if (m.sha256) lines.push('', 'SHA-256: ' + m.sha256);
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
        const mine = ((btn.dataset.fxTarget || btn.dataset.fx) && document.getElementById(btn.dataset.fxTarget || btn.dataset.fx)) || (btn.closest('.view') || document).querySelector('[data-fx]');
        const st = mine && EX[mine.id]; if (!st) return;
        const dt = mine.closest('details'); if (dt) dt.open = true;
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
    R.originHtml = function (d) {
        const mi = d.modInfo || {};
        let kind = 'na', status, detail;
        if (!mi.minecraftMod) {
            status = 'Non sembra una mod'; detail = 'Dentro il file non ci sono le informazioni tipiche di una mod Fabric o Forge.';
        } else {
            const det = 'Mod ' + (mi.platform || 'Minecraft') + (mi.modVersion ? ' v' + mi.modVersion : '') + (mi.mcVersion ? ' · Minecraft ' + mi.mcVersion : '');
            const st = mi.modrinthStatus;
            if (st === 'VERIFIED') { kind = 'ok'; status = 'Mod ufficiale'; detail = det + ' — coincide con la versione pubblicata su Modrinth' + (mi.modrinthVersion ? ' (v' + mi.modrinthVersion + ').' : '.'); }
            else if (st === 'NOT_FOUND') { kind = 'warn'; status = 'Non riconosciuta'; detail = det + ' — non è nei siti delle mod (Modrinth, Megabase). Può essere una versione nuova, modificata o fatta in casa.'; }
            else if (st === 'ERROR') { status = 'Controllo non riuscito'; detail = det + ' — impossibile collegarsi ai siti delle mod: controlla la connessione.'; }
            else { status = 'Origine non controllata'; detail = det; }
        }
        const extra = (mi.modrinthProjectUrl ? '<span class="clink">' + esc(mi.modrinthProjectUrl) + '</span>' : '') +
            '<p class="mut" style="margin:6px 0 0;font-size:12.5px">Per il controllo viene inviata solo l’impronta (hash) del file, mai il file.</p>';
        return '<div class="certs one">' + cert('È una mod ufficiale?', kind, status, detail, extra) + '</div>';
    };
    R.certsHtml = R.originHtml;
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
        const sum = J.Explain.summarize(d);
        slots.verdict.innerHTML = R.verdictHtml(d);
        const fHtml = R.findingsHtml(d, 'Tutte le segnalazioni'), fId = R.lastId;
        const advice = R.adviceHtml(sum);
        const parts = [];
        if (d.kind === 'jar') parts.push(R.originHtml(d));
        if (slots.priority) slots.priority.innerHTML = advice; else parts.push(advice);
        parts.push(R.topicsHtml(d, fId));
        parts.push(R.techHtml(d, fHtml, R.stringsHtml(d)));
        slots.below.innerHTML = parts.join('');
        const roots = slots.priority ? [slots.verdict, slots.below, slots.priority] : [slots.verdict, slots.below];
        roots.forEach((root) => { wire(root, d, opts); root.querySelectorAll('[data-sx]').forEach(sxInit); });
        return slots.verdict.querySelector('.verdict');
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
        const m = d.metadata || {}, p = d.processInfo || {}, sum = J.Explain.summarize(d), T = J.Explain.TIER;
        const subject = d.kind === 'jar' ? (m.fileName || 'File analizzato') : (exeName(p.processName) || 'Minecraft') + ' (PID ' + (p.pid || d.pid || '?') + ')';
        const col = { ok: '#5fd6a0', note: '#5fd6a0', warn: '#f2c14e', bad: '#ff4560' }[sum.state];
        const colors = { CRITICAL: '#ff4560', HIGH: '#ff8a3d', MEDIUM: '#f2c14e', LOW: '#5fd6a0', INFO: '#9b928a' };
        const topics = sum.topics.map((g) => '<div class="tp"><h3>' + esc(g.t.label) + ' <span class="t">' + esc(T[g.t.tier][0]) + ' · ' + g.items.length + '</span></h3><p>' + esc(g.t.what + ' ' + g.t.why) + '</p></div>').join('');
        const rows = sortFindings(d.findings || []).map((f) => '<tr><td><span class="b" style="background:' + colors[sevOf(f)] + '">' + SEV[sevOf(f)][1] + '</span></td><td>' + esc(catLabel(catKey(f))) + '</td><td>' + esc(f.title || f.ruleName || '') + '</td><td><code>' + esc(f.location || '—') + '</code></td></tr>').join('');
        const html = '<!DOCTYPE html><html lang="it"><head><meta charset="UTF-8"><title>Report — ' + esc(subject) + '</title><style>body{font-family:Segoe UI,Arial,sans-serif;background:#0f0e0d;color:#efeae2;padding:32px;max-width:980px;margin:0 auto;line-height:1.5}h1{margin:0 0 4px}.meta{color:#9b928a;margin-bottom:22px;font-size:14px}.v{border-left:6px solid ' + col + ';background:#171513;padding:16px 20px;border-radius:10px;margin-bottom:22px}.v h2{margin:0 0 6px;color:' + col + '}.tp{background:#171513;padding:12px 18px;border-radius:10px;margin-bottom:10px}.tp h3{margin:0 0 4px;font-size:16px}.tp p{margin:0;color:#c9c1b8}.t{font-weight:400;font-size:12px;color:#9b928a;margin-left:8px}table{width:100%;border-collapse:collapse;background:#171513}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #2b2724;font-size:13px;vertical-align:top}th{background:#201d1a;color:#c3a6ff;font-size:12px}.b{color:#12100e;font-weight:700;padding:2px 9px;border-radius:6px;font-size:12px}code{color:#8aa4ff;word-break:break-all}.f{margin-top:18px;color:#6d645d;font-size:12px}</style></head><body><h1>' + esc(subject) + '</h1><div class="meta">Controllato il ' + esc(when) + (m.sha256 ? ' · SHA-256 ' + esc(m.sha256) : '') + '</div>' +
            '<div class="v"><h2>' + esc(sum.headline) + '</h2><div>' + esc(sum.sub) + '</div>' + (sum.also ? '<div style="margin-top:6px;color:#c9c1b8">' + esc(sum.also) + '</div>' : '') + '</div>' +
            (topics ? '<h2>Cosa è stato trovato</h2>' + topics : '') +
            '<h2>Cosa fare</h2><ul>' + sum.advice.map((a) => '<li>' + esc(a) + '</li>').join('') + '</ul>' +
            '<h2>Dettagli tecnici (' + (d.findings || []).length + ' segnalazioni · punteggio tecnico ' + (d.riskScore || 0) + '/100)</h2><table><thead><tr><th>Importanza</th><th>Tipo</th><th>Segnalazione</th><th>Dove nel file</th></tr></thead><tbody>' + (rows || '<tr><td colspan="4">Nessuna segnalazione.</td></tr>') + '</tbody></table>' +
            '<div class="f">' + esc(J.Explain.CAVEAT) + ' — Generato da ModScanOpen (open source, MIT)</div></body></html>';
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        window.ModScanOpenFileSaver.saveTextFile(html, 'report-' + ts + '.html', 'text/html').then((r) => { if (r.success) J.toast('Report salvato'); });
    };
})();
