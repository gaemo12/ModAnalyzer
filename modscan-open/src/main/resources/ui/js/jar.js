/* Modalità "File JAR": scelta/trascinamento, analisi con animazione legata alla richiesta reale, risultati. */
(function () {
    'use strict';
    const J = window.J, $ = J.$, R = J.Report;
    const STEPS = ['Lettura del file', 'Apertura della mod', 'Lettura del codice', 'Cerco funzioni pericolose o da cheat', 'Controllo connessioni e codice nascosto', 'Preparo il risultato'];
    const LOGS = ['apro il file .jar', 'elenco le parti della mod', 'leggo il codice della mod', 'cerco furto di dati, controllo remoto e cheat', 'controllo connessioni a internet e codice nascosto', 'metto insieme il risultato'];
    let busy = false, current = null, currentFile = null, currentPath = null;

    const verdictSlot = $('jar-verdict-slot'), priSlot = $('jar-pri-slot'), mapSlot = $('jar-map-slot'), rep = $('jar-rep'), drop = $('drop');

    function mapCard() {
        return '<section class="card map" aria-label="Mappa delle classi"><div class="mh"><h3>Mappa delle classi</h3><div class="leg"><span><i style="background:var(--crit)"></i>Grave</span><span><i style="background:var(--high)"></i>Serio</span><span><i style="background:var(--med)"></i>Dubbio</span><span><i style="background:var(--info)"></i>Nota</span></div></div><div class="grid idle-map" id="jar-grid"></div><p class="mapnote" id="jar-mapnote">Ogni quadratino è una classe del file; quelli colorati hanno qualcosa da guardare.</p></section>';
    }
    function idle() {
        verdictSlot.innerHTML = R.idleVerdict('In attesa di un file', 'Nessuna analisi in corso');
        mapSlot.innerHTML = ''; priSlot.innerHTML = '';
        rep.innerHTML = '';
        $('jar-steps').innerHTML = ''; $('jar-log').innerHTML = ''; $('jar-pg').style.width = '0';
        $('drop-title').textContent = 'Trascina qui un file .jar';
        $('drop-sub').textContent = 'Il file resta sul tuo PC: l\'analisi è locale.';
        drop.classList.remove('scanning'); setDone(false);
    }

    function setDone(on) { const con = drop.closest && drop.closest('.console'); if (con) con.classList.toggle('done', on); }

    async function analyze(label, request) {
        if (busy) return;
        busy = true;
        rep.innerHTML = ''; priSlot.innerHTML = '';
        verdictSlot.innerHTML = R.idleVerdict('Analisi in corso…', label);
        $('drop-title').textContent = label;
        $('drop-sub').textContent = 'Analisi in corso…';
        drop.classList.add('scanning'); setDone(false);
        $('btn-choose-jar').disabled = true;
        /* Mappa delle classi visibile DURANTE l'analisi: le celle si accendono
           man mano che le classi vengono esaminate (come la vecchia app). */
        mapSlot.innerHTML = mapCard();
        R.Map.idle();
        R.Map.build($('jar-grid'), 320);
        const p = request();
        try {
            const data = await J.runSteps({ list: $('jar-steps'), log: $('jar-log'), progress: $('jar-pg'), steps: STEPS, logs: LOGS, promise: p, stepMs: 450,
                onStep: (i, n) => { R.Map.sweep((i + 1) / n); } });
            show(data, label);
        } catch (e) {
            J.error(e.message || 'Analisi fallita.');
            idle();
        } finally {
            drop.classList.remove('scanning');
            $('btn-choose-jar').disabled = false;
            busy = false;
        }
    }

    function show(raw, label) {
        const d = R.fromJar(raw);
        current = d;
        $('drop-title').textContent = (d.metadata && d.metadata.fileName) || label;
        $('drop-sub').textContent = 'Analisi completata';
        R.render({ verdict: verdictSlot, priority: priSlot, below: rep }, d, { onAction });
        setDone(true);
        mapSlot.innerHTML = mapCard();
        R.Map.build($('jar-grid'), 320);
        const flagged = R.Map.reveal(d.findings, (d.metadata || {}).classCount, R.lastId);
        $('jar-mapnote').textContent = ((d.metadata || {}).classCount || 0).toLocaleString('it-IT') + ' parti di codice controllate · ' + flagged + ' con segnalazioni' + (((d.metadata || {}).classCount || 0) > R.Map.n ? ' (la mappa ne mostra al massimo 1.024)' : '');
        window.onAnalysisComplete && window.onAnalysisComplete(d);
    }

    /* Azioni del verdetto (pulsanti dentro la scheda risultati). */
    function onAction(act) {
        if (act === 'again') {
            idle();
            current = null; currentFile = null; currentPath = null;
            window.scrollTo({ top: 0, behavior: J.RM ? 'auto' : 'smooth' });
        }
        /* 'vt-upload' non esiste nell'edizione open: niente VirusTotal. */
    }

    /* ---- ingressi ----
       Nota: nessun limite di dimensione qui. Nell'app il file non passa mai dal
       browser (percorso nativo, limite Java 512 MB); in anteprima browser il file
       viaggia via FormData e vale il limite del server. */
    function validate(file) {
        if (!file) return 'Nessun file selezionato.';
        if (!/\.jar$/i.test(file.name)) return 'Formato non valido: seleziona un file .jar.';
        if (file.size === 0) return 'Il file è vuoto.';
        return null;
    }
    function analyzeFile(file) {
        const err = validate(file);
        if (err) { J.error(err); return; }
        currentFile = file; currentPath = null;
        const fd = new FormData(); fd.append('file', file);
        J.pick('jar');
        analyze(file.name, () => J.api('/api/analyze', { method: 'POST', body: fd }));
    }
    function analyzePath(path) {
        currentFile = null; currentPath = path;
        const fd = new FormData(); fd.append('path', path);
        J.pick('jar');
        return analyze(J.base(path), () => J.api('/api/analyze-local', { method: 'POST', body: fd }));
    }
    function choose() {
        if (busy) return;
        if (window.javafxBridge) window.javafxBridge.chooseFile(); else $('file-input').click();
    }

    $('btn-choose-jar').onclick = (e) => { e.stopPropagation(); choose(); };
    drop.addEventListener('click', (e) => { if (!e.target.closest('button')) choose(); });
    drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(); } });
    $('file-input').addEventListener('change', (e) => { if (e.target.files.length) analyzeFile(e.target.files[0]); e.target.value = ''; });
    ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, () => drop.classList.add('over')));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove('over')));
    drop.addEventListener('drop', (e) => { if (window.javafxBridge) return; const f = e.dataTransfer.files; if (f.length) analyzeFile(f[0]); });

    /* Chiamata da Java (DesktopApp): drag&drop nativo e file chooser. */
    window.handleLocalFileSelection = function (path) { analyzePath(path); };
    /* Chiamata da Java (DesktopApp): drop nativo scartato prima dell'analisi. */
    window.handleLocalFileError = function (msg) { J.error(msg || 'File non valido.'); };

    /* Il tooltip della mappa è gestito da report.js (la mappa è un canvas). */

    J.jar = { analyzePath, show: (data, label, path) => { J.pick('jar'); currentPath = path || null; currentFile = null; show(data, label); }, last: () => current };
    J.ready(idle);
})();
