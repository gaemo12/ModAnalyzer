/* Confronto runtime (v1.3.0): cosa gira davvero rispetto a cosa c'è su disco.
   1) riga di comando del processo di gioco (javaagent/tweakClass/classpath/anti-attach);
   2) mod caricate secondo logs/latest.log vs jar su disco (JiJ annidati inclusi);
   3) artefatti noti di cheat client nella .minecraft (solo nomi, mai contenuto). */
(function () {
    'use strict';
    const J = window.J, $ = J.$, esc = J.esc, ic = J.ic;
    const out = $('rt-out'), ph = $('rt-ph'), btn = $('btn-rt'),
        gameEl = $('rt-game'), noteEl = $('rt-note');
    let busy = false;

    if (!btn) return;

    const SEV = { CRITICAL: 'bad', HIGH: 'bad', MEDIUM: 'unk', LOW: 'new', INFO: 'new' };
    function sb(s) { return SEV[String(s || '').toUpperCase()] || 'new'; }

    async function currentPath() {
        if (J.modsPath) {
            const p = J.modsPath();
            if (p) return p;
        }
        const r = await J.api('/api/mods/locate');
        return (r.best && r.best.exists !== false) ? r.best.path : null;
    }

    function cmdRow(f) {
        if (f.note) return '<div class="ph" style="margin:2px 0">' + esc(f.note) + '</div>';
        return '<div class="mrw"><div class="mr"><span class="pic">' + ic('shield', 20) + '</span>'
            + '<div><b>' + esc(f.title || f.flag) + '</b><small>' + esc(f.detail || '') + '</small></div>'
            + '<span class="sb ' + sb(f.severity) + '" title="flag ' + esc(f.flag || '') + '">' + esc(f.severity || '') + '</span></div></div>';
    }

    function ghostRow(g) {
        return '<div class="mrw"><div class="mr"><span class="pic">' + ic('jar', 20) + '</span>'
            + '<div><b>' + esc(g.id) + '</b><small>' + esc(g.detail || '') + '</small></div>'
            + '<span class="sb ' + sb(g.severity) + '">' + esc(g.severity || '') + '</span></div></div>';
    }

    function fileGhostRow(name, stale) {
        const sev = stale ? 'LOW' : 'MEDIUM';
        return '<div class="mrw"><div class="mr"><span class="pic">' + ic('jar', 20) + '</span>'
            + '<div><b>' + esc(name) + '</b><small>Il loader ha aperto questo file, ma nella cartella mods non c\'è.</small></div>'
            + '<span class="sb ' + sb(sev) + '">' + sev + '</span></div></div>';
    }

    function crashRow(t) {
        const flags = (t.flags || []).join(', ');
        return '<div class="mrw"><div class="mr"><span class="pic">' + ic('alert', 20) + '</span>'
            + '<div><b>' + esc(t.file || 'crash log') + '</b><small>' + esc(t.kind || 'crash')
            + ' · flag nella sessione: ' + esc(flags) + '</small></div>'
            + '<span class="sb unk">TRACCIA</span></div></div>';
    }

    function artifactRow(a) {
        return '<div class="mrw"><div class="mr"><span class="pic">' + ic('shield', 20) + '</span>'
            + '<div><b>' + esc(a.name || a.path) + '</b><small>' + esc(a.path || '') + ' · client: ' + esc(a.family || '?') + '</small></div>'
            + '<span class="sb ' + sb(a.severity) + '">' + esc(a.severity || '') + '</span></div></div>';
    }

    function logBox(l) {
        if (!l || l.error) return '<div class="ph" style="margin:4px 22px 12px">Log: ' + esc((l && l.error) || 'non leggibile') + '</div>';
        let h = '<div class="ph" style="margin:4px 22px 6px">Log ' + esc(l.logFile || 'latest.log')
            + ' (' + esc(l.format || '?') + '): ' + (l.loadedCount || 0) + ' id caricati · ' + (l.diskCount || 0) + ' id su disco'
            + (l.stale ? ' · <b>log della sessione precedente</b>' : '') + '</div>';
        if ((l.loadedNotOnDisk || []).length) {
            h += '<div style="padding:0 22px 6px"><b>Caricate senza jar su disco:</b></div>'
                + '<div style="padding:0 22px 10px">' + l.loadedNotOnDisk.map(ghostRow).join('') + '</div>';
        }
        if ((l.loadedFilesNotOnDisk || []).length) {
            h += '<div style="padding:0 22px 6px"><b>File aperti dal loader ma assenti dalla cartella mods:</b></div>'
                + '<div style="padding:0 22px 10px">'
                + l.loadedFilesNotOnDisk.map((f) => fileGhostRow(f, l.stale)).join('') + '</div>';
        }
        if ((l.onDiskNotLoaded || []).length) {
            const shown = l.onDiskNotLoaded.slice(0, 12).join(', ');
            h += '<div class="ph" style="margin:0 22px 6px">Su disco ma mai caricate (' + l.onDiskNotLoaded.length + '): ' + esc(shown)
                + (l.onDiskNotLoaded.length > 12 ? ' …' : '') + ' — disabilitate o mai avviate, solo nota.</div>';
        }
        (l.notes || []).forEach((n) => { h += '<div class="ph" style="margin:0 22px 4px"><small>' + esc(n) + '</small></div>'; });
        return h;
    }

    function render(d) {
        const g = d.game, c = d.counts || {};
        gameEl.textContent = g
            ? 'Minecraft ' + (g.exe || 'javaw') + ' · PID ' + g.pid
            : 'Nessun gioco attivo: controllo su cartella e log';
        noteEl.textContent = 'Cartella controllata: ' + (d.modsDir || '—');
        let h = '';
        const cmds = (d.cmdFindings || []).filter((f) => !f.note);
        const fileGhosts = ((d.logDiff || {}).loadedFilesNotOnDisk || []).length;
        const crashes = (d.crashLogs || []).filter((t) => t && (t.flags || []).length);
        h += '<div class="ph" style="margin:6px 22px 8px"><b>' + cmds.length + '</b> flag sospetti nella riga di comando · '
            + '<b>' + (c.loadedNotOnDisk || 0) + '</b> mod caricate senza jar su disco · '
            + '<b>' + (c.loadedFilesNotOnDisk || 0) + '</b> file aperti dal loader senza jar · '
            + '<b>' + (c.artifacts || 0) + '</b> artefatti cheat noti · '
            + '<b>' + (c.crashFlags || 0) + '</b> flag nei crash report.</div>';
        if (cmds.length) h += '<div style="padding:0 22px 10px">' + d.cmdFindings.map(cmdRow).join('') + '</div>';
        h += logBox(d.logDiff);
        if ((d.artifacts || []).length) {
            h += '<div style="padding:0 22px 6px"><b>Artefatti di cheat client trovati:</b></div>'
                + '<div style="padding:0 22px 10px">' + d.artifacts.map(artifactRow).join('') + '</div>';
        }
        if (crashes.length) {
            h += '<div style="padding:0 22px 6px"><b>Tracce JVM nei crash report e negli hs_err (solo nomi dei flag):</b></div>'
                + '<div style="padding:0 22px 10px">' + crashes.map(crashRow).join('') + '</div>';
        }
        if (!cmds.length && !(d.logDiff || {}).error && !((d.logDiff || {}).loadedNotOnDisk || []).length
            && !fileGhosts && !(d.artifacts || []).length && !crashes.length) {
            h += '<div class="mempty">Nulla di anomalo nel confronto runtime.</div>';
        }
        out.innerHTML = h;
    }

    async function run(quiet) {
        if (busy) return null;
        busy = true;
        btn.disabled = true;
        ph.textContent = 'Confronto riga di comando, log della partita e cartella del gioco…';
        try {
            const p = await currentPath();
            if (!p) {
                ph.textContent = quiet ? '' : 'Cartella mods non trovata: avvia Minecraft oppure scegli la cartella nella scheda qui sopra.';
                return null;
            }
            const d = await J.api('/api/mods/runtime?path=' + encodeURIComponent(p));
            ph.textContent = quiet ? 'Controllo automatico completato' : 'Controllo completato';
            render(d);
            const c = d.counts || {};
            if ((c.suspects || 0) > 0 && !quiet) J.error('Runtime: ' + c.suspects + ' segnali (flag, mod senza jar o artefatti)');
            return d;
        } catch (e) {
            ph.textContent = 'Controllo non riuscito';
            if (!quiet) {
                out.innerHTML = '<div class="mempty">' + esc(e.message || 'Errore') + '</div>';
                J.error(e.message || 'Controllo runtime non riuscito');
            }
            return null;
        } finally {
            busy = false;
            btn.disabled = false;
        }
    }

    /* Parte da solo dopo il journal (catena avviata dalla scansione della cartella). */
    async function auto() {
        if (busy) return;
        await run(true);
    }

    J.runtime = { auto: auto, run: () => run(false) };
    btn.addEventListener('click', () => run(false));
})();
