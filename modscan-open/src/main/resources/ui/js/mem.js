/* Modalita "Memoria JVM": memory-dump opt-in via agent e scansione del dump. */
(function () {
    'use strict';
    const J = window.J, $ = J.$, R = J.Report;
    const STEPS = ['Attach al processo', 'Dump del bytecode', 'Impacchettamento', 'Analisi del bytecode', 'Regole di malware e comportamenti sospetti', 'Calcolo del punteggio'];
    const LOGS = ['connessione alla JVM bersaglio', 'cattura delle classi caricate', 'scrittura di mem-<pid>.jar', 'scansione di chiamate e costanti', 'applicazione delle regole (offline)', 'aggregazione dei rilevamenti'];
    let busy = false, current = null;

    const verdictSlot = $('mem-verdict-slot'), priSlot = $('mem-pri-slot'),
        mapSlot = $('mem-map-slot'), rep = $('mem-rep'),
        pidInput = $('mem-pid'), scanBtn = $('btn-mem-scan');

    function mapCard() {
        return '<section class="card map" aria-label="Mappa delle classi"><div class="mh"><h3>Mappa delle classi</h3><div class="leg"><span><i style="background:var(--crit)"></i>Critico</span><span><i style="background:var(--high)"></i>Alto</span><span><i style="background:var(--med)"></i>Medio</span><span><i style="background:var(--info)"></i>Basso/Info</span></div></div><div class="grid idle-map" id="mem-grid"></div><p class="mapnote" id="mem-mapnote">Ogni cella e una classe dumpata; quelle colorate hanno almeno un rilevamento.</p></section>';
    }
    function idle() {
        verdictSlot.innerHTML = R.idleVerdict('In attesa di un processo', 'PID di una JVM in esecuzione, o auto per javaw');
        mapSlot.innerHTML = ''; priSlot.innerHTML = '';
        rep.innerHTML = '';
        $('mem-steps').innerHTML = ''; $('mem-log').innerHTML = ''; $('mem-pg').style.width = '0';
        $('mem-path').textContent = 'Nessun processo selezionato';
        scanBtn.disabled = false;
        busy = false;
    }

    async function analyze(label, request) {
        if (busy) return;
        busy = true;
        rep.innerHTML = ''; priSlot.innerHTML = '';
        verdictSlot.innerHTML = R.idleVerdict('Analisi in corso…', label);
        $('mem-path').textContent = label;
        mapSlot.innerHTML = mapCard();
        R.Map.idle();
        R.Map.build($('mem-grid'), 320);
        scanBtn.disabled = true;
        const p = request();
        try {
            const data = await J.runSteps({ list: $('mem-steps'), log: $('mem-log'), progress: $('mem-pg'), steps: STEPS, logs: LOGS, promise: p, stepMs: 900,
                onStep: (i, n) => { R.Map.sweep((i + 1) / n); } });
            show(data, label);
        } catch (e) {
            J.error(e.message || 'Memory dump fallito.');
            idle();
        } finally {
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
        $('mem-mapnote').textContent = ((d.metadata || {}).classCount || 0).toLocaleString('it-IT') + ' classi dumpate — ' + flagged + ' con rilevamenti';
        window.onAnalysisComplete && window.onAnalysisComplete(d);
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
    function scan() {
        const p = pid() || 'auto';
        pidInput.value = p;
        J.pick('mods');
        analyze('PID ' + p, () => J.api('/api/mem/dump', { method: 'POST', body: 'pid=' + encodeURIComponent(p) }));
    }

    $('btn-mem-auto').onclick = () => { loadProcs(); };
    scanBtn.onclick = () => scan();

    J.mem = { scan: (p) => { if (p) pidInput.value = p; scan(); }, last: () => current };
    J.ready(idle);
})();
