/* Integrità mod: una mod è stata aggiunta o modificata dopo l'avvio di Minecraft (javaw)?
   Usa la cartella mods corrente (o la rileva dal processo) e, su richiesta, il journal USN di NTFS. */
(function () {
    'use strict';
    const J = window.J, $ = J.$, esc = J.esc, ic = J.ic;
    const out = $('jrnl-out'), ph = $('jrnl-ph'), btn = $('btn-jrnl'),
        gameEl = $('jrnl-game'), noteEl = $('jrnl-note'), usnBox = $('jrnl-usn');
    let busy = false;

    if (!btn) return;

    function fmt(ms) {
        if (!ms) return '–';
        const d = new Date(ms), p = (n) => String(n).padStart(2, '0');
        return p(d.getDate()) + '/' + p(d.getMonth() + 1) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    }

    async function currentPath() {
        if (J.modsPath) {
            const p = J.modsPath();
            if (p) return p;
        }
        const r = await J.api('/api/mods/locate');
        return (r.best && r.best.exists !== false) ? r.best.path : null;
    }

    function row(s) {
        const added = s.state === 'added';
        const label = added ? 'Aggiunta dopo l\'avvio' : 'Modificata dopo l\'avvio';
        return '<div class="mrw"><div class="mr"><span class="pic">' + ic('jar', 20) + '</span>'
            + '<div><b>' + esc(s.fileName) + '</b><small>creata ' + fmt(s.created) + ' · modificata ' + fmt(s.modified) + '</small></div>'
            + '<span class="sz">' + J.fmtBytes(s.size || 0) + '</span>'
            + '<span class="sb ' + (added ? 'bad' : 'unk') + '">' + esc(label) + '</span></div></div>';
    }

    function journalBox(j, since) {
        if (!j) return '';
        if (!j.available) {
            return '<div class="ph" style="margin:4px 22px 12px">Journal USN: ' + esc(j.note || 'non disponibile') + '</div>';
        }
        let h = '<div class="ph" style="margin:4px 22px 6px">Journal USN: ' + j.events.length + ' eventi nella cartella mods dalle ' + fmt(since || 0) + ' · eliminazioni/rinomine: ' + j.deleted + (j.truncated ? ' (elenco troncato)' : '') + '</div>';
        if (j.events.length) {
            h += '<div style="padding:0 22px 14px;max-height:220px;overflow:auto;font-size:12px;line-height:1.8">'
                + j.events.slice(0, 50).map((e) => '<div><small>' + fmt(e.time) + '</small> <span class="sb ' + (e.kind === 'deleted' ? 'bad' : e.kind === 'renamed' ? 'unk' : 'new') + '">' + esc(e.kind) + '</span> <code>' + esc(e.file) + '</code> <small>' + esc(e.reason) + '</small></div>').join('')
                + (j.events.length > 50 ? '<div><small>… altri ' + (j.events.length - 50) + ' eventi disponibili nel JSON</small></div>' : '')
                + '</div>';
        }
        return h;
    }

    function render(d) {
        const c = d.counts || {}, g = d.game;
        gameEl.textContent = g
            ? 'Minecraft ' + (g.exe || 'javaw') + ' · PID ' + g.pid + ' · avviato ' + fmt(g.start)
            : 'Avvio del gioco impostato a mano';
        noteEl.textContent = 'Cartella controllata: ' + (d.modsDir || '—');
        let h = '<div class="ph" style="margin:6px 22px 8px"><b>' + (c.checked || 0) + '</b> file controllati · '
            + '<b>' + (c.added || 0) + '</b> aggiunti e <b>' + (c.modified || 0) + '</b> modificati dopo l\'avvio del gioco.</div>';
        const rows = (d.suspects || []).map(row).join('');
        h += rows || '<div class="mempty">Nessuna mod aggiunta o modificata dopo l\'avvio: nulla da segnalare.</div>';
        h += journalBox(d.journal, d.since);
        out.innerHTML = h;
    }

    async function run() {
        if (busy) return;
        busy = true;
        btn.disabled = true;
        out.innerHTML = '';
        ph.textContent = 'Confronto degli orari dei file con l\'avvio del gioco…';
        try {
            const p = await currentPath();
            if (!p) {
                ph.textContent = 'Cartella mods non trovata: avvia Minecraft oppure scegli la cartella nella scheda qui sopra.';
                return;
            }
            const d = await J.api('/api/mods/journal?path=' + encodeURIComponent(p) + (usnBox && usnBox.checked ? '&usn=1' : ''));
            ph.textContent = 'Controllo completato';
            render(d);
            if (((d.counts || {}).added || 0) + ((d.counts || {}).modified || 0) > 0) {
                J.error('Attenzione: mod cambiate dopo l\'avvio del gioco');
            }
        } catch (e) {
            ph.textContent = 'Controllo non riuscito';
            out.innerHTML = '<div class="mempty">' + esc(e.message || 'Errore') + '</div>';
            J.error(e.message || 'Controllo non riuscito');
        } finally {
            busy = false;
            btn.disabled = false;
        }
    }

    btn.addEventListener('click', run);
})();
