/* Modalita "Memoria JVM": memory-dump opt-in via agent e scansione del dump.
   v1.2.0: il dump salta le mod verificate su Modrinth/Megabase (e i loro jar annidati),
   le librerie del launcher e l'agent theseus; l'avanzamento reale si vede nella card;
   dopo la scansione della cartella l'analisi parte da sola e gli esiti compaiono
   come badge nella lista delle mod. Riaprire la sezione non rifà il dump. */
(function () {
    'use strict';
    const J = window.J, $ = J.$, R = J.Report;
    const STEPS = ['Mi collego al gioco', 'Copio il codice in uso', 'Preparo il pacchetto', 'Lettura del codice', 'Cerco funzioni pericolose o da cheat', 'Preparo il risultato'];
    const LOGS = ['mi collego a Minecraft', 'copio il codice caricato (mod ufficiali saltate)', 'preparo il file da controllare', 'leggo il codice', 'cerco furto di dati, controllo remoto e cheat', 'metto insieme il risultato'];
    const LS = 'modscan.mem.auto';
    let busy = false, current = null, pollTimer = null;

    const verdictSlot = $('mem-verdict-slot'), priSlot = $('mem-pri-slot'),
        mapSlot = $('mem-map-slot'), rep = $('mem-rep'),
        pidInput = $('mem-pid'), scanBtn = $('btn-mem-scan'),
        autoBox = $('mem-auto'), phaseEl = $('mem-phase');

    /* Preferenza "automatico" (default attivo): salvata in locale. */
    if (autoBox) {
        try {
            const v = localStorage.getItem(LS);
            if (v === '0') autoBox.checked = false;
            else if (v === '1') autoBox.checked = true;
        } catch (e) { /* storage non disponibile: resta il default */ }
        autoBox.onchange = () => {
            try { localStorage.setItem(LS, autoBox.checked ? '1' : '0'); } catch (e) { /* preferenza non salvata */ }
        };
    }
    const autoOn = () => !autoBox || autoBox.checked;

    function setPhase(txt) { if (phaseEl) phaseEl.textContent = txt || ''; }
    function fmtSec(ms) { return ms > 0 ? Math.round(ms / 1000) + 's' : '–'; }

    /* Avanzamento reale dal server (progress.txt dell'agent + fasi app). */
    function startPoll() {
        stopPoll();
        pollTimer = setInterval(async () => {
            try {
                const st = await J.api('/api/mem/progress');
                if (!st || (st.state !== 'running' && st.state !== 'done')) return;
                setPhase((st.note || '') + (st.state === 'running' && st.total ? ' — ' + st.pct + '%' : ''));
                if (st.state === 'running' && st.pct > 0) $('mem-pg').style.width = st.pct + '%';
            } catch (e) { /* polling silenzioso */ }
        }, 1500);
    }
    function stopPoll() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

    function mapCard() {
        return '<section class="card map" aria-label="Mappa delle classi"><div class="mh"><h3>Mappa delle classi</h3><div class="leg"><span><i style="background:var(--crit)"></i>Grave</span><span><i style="background:var(--high)"></i>Serio</span><span><i style="background:var(--med)"></i>Dubbio</span><span><i style="background:var(--info)"></i>Nota</span></div></div><div class="grid idle-map" id="mem-grid"></div><p class="mapnote" id="mem-mapnote">Ogni quadratino è una classe in uso; quelli colorati hanno qualcosa da guardare.</p></section>';
    }
    function idle() {
        stopPoll();
        verdictSlot.innerHTML = R.idleVerdict('In attesa di un processo', 'PID di una JVM in esecuzione, o auto per javaw');
        mapSlot.innerHTML = ''; priSlot.innerHTML = '';
        rep.innerHTML = '';
        $('mem-steps').innerHTML = ''; $('mem-log').innerHTML = ''; $('mem-pg').style.width = '0';
        setPhase('');
        $('mem-path').textContent = 'Nessun processo selezionato';
        scanBtn.disabled = false;
        busy = false;
    }

    async function analyze(label, request) {
        if (busy) return null;
        busy = true;
        rep.innerHTML = ''; priSlot.innerHTML = '';
        verdictSlot.innerHTML = R.idleVerdict('Analisi in corso…', label);
        $('mem-path').textContent = label;
        mapSlot.innerHTML = mapCard();
        R.Map.idle();
        R.Map.build($('mem-grid'), 320);
        scanBtn.disabled = true;
        setPhase('Preparazione del dump…');
        startPoll();
        const p = request();
        try {
            const data = await J.runSteps({ list: $('mem-steps'), log: $('mem-log'), steps: STEPS, logs: LOGS, promise: p, stepMs: 900,
                onStep: (i, n) => { R.Map.sweep((i + 1) / n); } });
            show(data, label);
            return data;
        } catch (e) {
            J.error(e.message || 'Memory dump fallito.');
            idle();
            return null;
        } finally {
            stopPoll();
            scanBtn.disabled = false;
            busy = false;
        }
    }

    function show(raw, label) {
        const d = R.fromJar(raw);
        d.kind = 'mem';
        current = d;
        $('mem-path').textContent = 'PID ' + (d.pid || '?') + ' — ' + ((d.processInfo || {}).processName || 'JVM').split(/[\\/]/).pop();
        R.render({ verdict: verdictSlot, priority: priSlot, below: rep }, d, { onAction });
        mapSlot.innerHTML = mapCard();
        R.Map.build($('mem-grid'), 320);
        const flagged = R.Map.reveal(d.findings, (d.metadata || {}).classCount, R.lastId);
        $('mem-mapnote').textContent = ((d.metadata || {}).classCount || 0).toLocaleString('it-IT') + ' parti di codice controllate — ' + flagged + ' con segnalazioni';
        setPhase(raw.cached
            ? 'Risultati già pronti per questa sessione di gioco: nessun nuovo dump.'
            : 'Dump completato — dump ' + fmtSec(raw.dumpMs) + ', analisi ' + fmtSec(raw.analysisMs) + '.');
        publishBadges(raw);
        window.onAnalysisComplete && window.onAnalysisComplete(d);
    }

    /* Esiti nella lista delle mod: un badge per mod (gravità massima e conteggio),
       più il chip "dump ✓" per le mod saltate perché verificate. */
    function publishBadges(raw) {
        const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        const map = {};
        (raw.findings || []).forEach((f) => {
            const name = originName(f.origin);
            if (!name) return;
            let v = map[name];
            if (!v) v = map[name] = { count: 0, worst: 'INFO', rules: [] };
            v.count++;
            const sev = String(f.severity || 'INFO').toUpperCase();
            if ((rank[sev] == null ? 4 : rank[sev]) < (rank[v.worst] == null ? 4 : rank[v.worst])) v.worst = sev;
            if (f.rule && f.rule !== 'unspecified' && v.rules.length < 3 && v.rules.indexOf(f.rule) < 0) v.rules.push(f.rule);
        });
        Object.keys(map).forEach((k) => {
            const v = map[k];
            v.cls = (v.worst === 'CRITICAL' || v.worst === 'HIGH') ? 'bad' : (v.worst === 'MEDIUM' ? 'unk' : 'new');
            v.title = 'Nel dump memoria: ' + v.count + ' rilevament' + (v.count === 1 ? 'o' : 'i') + ' — gravità massima ' + v.worst
                + (v.rules.length ? ' (' + v.rules.join(', ') + ')' : '');
        });
        const skip = (raw.memoryScope || {}).skip || {};
        (skip.verifiedFiles || []).forEach((fn) => {
            const k = String(fn).toLowerCase();
            if (!map[k]) map[k] = { skipped: true, by: 'Modrinth/Megabase' };
        });
        J.modsBadges.mem = map;
        if (J.modsRefresh) J.modsRefresh();
    }
    function originName(o) {
        if (!o) return null;
        let s = String(o);
        try { s = decodeURIComponent(s); } catch (e) { /* origin già decodificata */ }
        s = s.replace(/^file:\/*/i, '');
        const b = J.base(s).toLowerCase();
        return b || null;
    }

    function onAction(act) {
        if (act === 'again') {
            idle();
            current = null;
            window.scrollTo({ top: 0, behavior: J.RM ? 'auto' : 'smooth' });
        }
    }

    function pid() {
        const v = (pidInput.value || '').trim();
        if (/^\d+$/.test(v) || v.toLowerCase() === 'auto') return v.toLowerCase();
        return 'auto';
    }
    async function loadProcs() {
        try {
            const data = await J.api('/api/mem/processes');
            const list = (data && data.processes) || [];
            pidInput.innerHTML = '<option value="auto">auto — primo javaw/java</option>' + list.map((p) =>
                '<option value="' + p.pid + '">' + p.pid + ' — ' + J.esc(p.exe || 'java') +
                (p.minecraftLike ? ' ★' : '') + '</option>').join('');
            $('mem-path').textContent = list.length ? list.length + ' processi Java trovati' : 'Nessun processo Java in esecuzione';
        } catch (e) {
            J.error(e.message || 'Elenco processi fallito.');
        }
    }

    /* Dump manuale o automatico: le mod verificate sono sempre saltate (skip=1). */
    function scan(pidOverride) {
        const p = pidOverride && /^\d+$/.test(String(pidOverride)) ? String(pidOverride) : pid();
        pidInput.value = p;
        J.pick('mods');
        const mp = (J.modsPath && J.modsPath()) || '';
        analyze('PID ' + p, () => J.api('/api/mem/dump', { method: 'POST', body: 'pid=' + encodeURIComponent(p) + '&skip=1' + (mp ? '&mods=' + encodeURIComponent(mp) : '') })
            .catch((e) => {
                // Un dump è già partito (altra finestra o auto-avvio): ci si aggancia.
                if (/già in esecuzione|già in corso/i.test(e.message || '')) return waitExistingDump();
                throw e;
            }));
    }

    /* v1.2.0: avvio automatico (dopo la scansione della cartella e il journal).
       Se un dump è già in corso ci si aggancia al suo progresso; se questa sessione
       di gioco ha già un risultato, il server risponde dalla cache senza rifare nulla. */
    async function auto(pidArg) {
        if (busy || !autoOn()) return;
        try {
            const st = await J.api('/api/mem/progress');
            if (st && st.state === 'running') {
                J.pick('mods');
                await analyze('Dump in corso…', () => waitExistingDump());
                return;
            }
        } catch (e) { /* stato non leggibile: si prova comunque ad avviare */ }
        scan(pidArg);
    }
    function waitExistingDump() {
        return new Promise((resolve, reject) => {
            const iv = setInterval(async () => {
                try {
                    const st = await J.api('/api/mem/progress');
                    if (!st) return;
                    if (st.state === 'done') { clearInterval(iv); resolve(await J.api('/api/mem/result')); }
                    else if (st.state === 'error') { clearInterval(iv); reject(new Error(st.note || 'Dump non riuscito')); }
                } catch (e) { clearInterval(iv); reject(e); }
            }, 2000);
        });
    }

    $('btn-mem-auto').onclick = () => { loadProcs(); };
    scanBtn.onclick = () => scan();

    J.mem = { scan: (p) => scan(p), auto: (p) => auto(p), last: () => current };
    J.ready(idle);
})();
