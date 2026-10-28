/* Confronto runtime (v1.3.0): cosa gira davvero rispetto a cosa c'è su disco.
   1) riga di comando del processo di gioco (javaagent/tweakClass/classpath/anti-attach);
   2) mod caricate secondo logs/latest.log vs jar su disco (JiJ annidati inclusi);
   3) artefatti noti di cheat client nella .minecraft (solo nomi, mai contenuto). */
(function () {
    'use strict';
    const J = window.J, esc = J.esc, ic = J.ic;
    /* Elementi che non esistono più (pulsanti, selettori) diventano segnaposto invisibili: il codice resta valido. */
    const ghost = {}, $ = (id) => J.$(id) || (ghost[id] = ghost[id] || document.createElement('div'));
    const out = $('rt-out'), ph = $('rt-ph'), btn = $('btn-rt'),
        gameEl = $('rt-game'), noteEl = $('rt-note');
    let busy = false;

    if (!btn) return;

    const SEV = { CRITICAL: 'bad', HIGH: 'bad', MEDIUM: 'unk', LOW: 'new', INFO: 'new' };
    const SEVN = { CRITICAL: 'Grave', HIGH: 'Serio', MEDIUM: 'Dubbio', LOW: 'Lieve', INFO: 'Nota' };
    function sb(s) { return SEV[String(s || '').toUpperCase()] || 'new'; }
    function sn(s) { return SEVN[String(s || '').toUpperCase()] || 'Nota'; }
    function cls(s) { const k = sb(s); return k === 'bad' ? ' fa' : k === 'unk' ? ' fm' : ''; }

    async function currentPath() {
        if (J.modsPath) {
            const p = J.modsPath();
            if (p) return p;
        }
        const r = await J.api('/api/mods/locate');
        return (r.best && r.best.exists !== false) ? r.best.path : null;
    }

    /* Ogni segnale diventa una riga dell'elenco mod, con una frase in parole semplici. */
    function item(icon, title, small, sev, why, pill) {
        return '<div class="mrw' + cls(sev) + '"><div class="mr"><span class="pic">' + ic(icon, 20) + '</span>'
            + '<div><b>' + esc(title) + '</b><small>' + esc(small || '') + '</small>'
            + '<div class="flag">' + ic('flag') + '<span><em>' + esc(why) + '</em></span></div></div>'
            + '<span class="sz">–</span><span class="sb ' + sb(sev) + '">' + esc(pill || sn(sev)) + '</span><span></span></div></div>';
    }
    function cmdItem(f) {
        return item('shield', f.title || f.flag, f.detail, f.severity,
            'Sono le opzioni con cui è stato avviato Minecraft: alcune servono a caricare codice extra nel gioco.');
    }
    function ghostItem(g) {
        return item('jar', g.id, g.detail, g.severity,
            'Il gioco ha caricato questa mod, ma il file non è nella cartella: potrebbe essere stato tolto dopo l\'avvio.');
    }
    function fileGhostItem(name, stale) {
        return item('jar', name, 'Il loader ha aperto questo file, ma nella cartella mods non c\'è.', stale ? 'LOW' : 'MEDIUM',
            stale ? 'Viene dal log della partita precedente: può essere una mod che hai già tolto.' : 'Era in uso durante la partita e ora non c\'è più.');
    }
    function crashItem(t) {
        return item('alert', t.file || 'crash log', (t.kind || 'crash') + ' · ' + (t.flags || []).join(', '), 'MEDIUM',
            'Nei file di errore di Java sono rimaste tracce di elementi sospetti. Sono solo i nomi, non il contenuto.', 'Traccia');
    }
    function artifactItem(a) {
        return item('shield', a.name || a.path, (a.path || '') + ' · client: ' + (a.family || '?'), a.severity,
            'File o cartelle di un client cheat noto trovati sul PC.');
    }
    function infoHtml(l, c, nCmd) {
        let h = '<div class="ph">Confronto con il gioco aperto: <b>' + nCmd + '</b> opzioni sospette all\'avvio · <b>' + (c.loadedNotOnDisk || 0)
            + '</b> mod caricate senza file · <b>' + (c.loadedFilesNotOnDisk || 0) + '</b> file spariti · <b>' + (c.artifacts || 0)
            + '</b> tracce di cheat client · <b>' + (c.crashFlags || 0) + '</b> segnali nei file di errore.</div>';
        if (l && !l.error) {
            h += '<div class="ph"><small>Log ' + esc(l.logFile || 'latest.log') + ': ' + (l.loadedCount || 0) + ' mod caricate · ' + (l.diskCount || 0) + ' nella cartella'
                + (l.stale ? ' · <b>log della partita precedente</b>' : '') + '.</small></div>';
            if ((l.onDiskNotLoaded || []).length) {
                h += '<div class="ph"><small>Nella cartella ma mai caricate (' + l.onDiskNotLoaded.length + '): ' + esc(l.onDiskNotLoaded.slice(0, 12).join(', '))
                    + (l.onDiskNotLoaded.length > 12 ? ' …' : '') + ' — disattivate o mai avviate, solo una nota.</small></div>';
            }
        } else if (l && l.error) {
            h += '<div class="ph"><small>Log non letto: ' + esc(l.error) + '</small></div>';
        }
        return h;
    }

    /* Pubblica le righe per l'elenco mod (gruppo «Dal gioco in esecuzione»). */
    function render(d) {
        const c = d.counts || {}, l = d.logDiff || {}, items = [];
        const cmds = (d.cmdFindings || []).filter((f) => !f.note);
        cmds.forEach((f) => items.push(cmdItem(f)));
        (l.loadedNotOnDisk || []).forEach((g) => items.push(ghostItem(g)));
        (l.loadedFilesNotOnDisk || []).forEach((n) => items.push(fileGhostItem(n, l.stale)));
        (d.artifacts || []).forEach((a) => items.push(artifactItem(a)));
        (d.crashLogs || []).filter((t) => t && (t.flags || []).length).forEach((t) => items.push(crashItem(t)));
        J.modsBadges.runtime = { items: items, info: infoHtml(l, c, cmds.length), game: d.game || null };
        if (J.modsRefresh) J.modsRefresh();
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
        if (busy) return null;
        return run(true);
    }

    J.runtime = { auto: auto, run: (q) => run(q === true) };
    btn.addEventListener('click', () => run(false));
})();
