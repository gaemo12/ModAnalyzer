/* Controllo delle mod rispetto all'avvio di Minecraft.
   Confronta gli orari dei file con l'avvio del gioco e, se possibile, legge il journal di Windows (USN):
   cosa è successo a ogni file (scritto, rinominato, attributi cambiati, eliminato) e quali file
   c'erano nella cartella mods e ora non ci sono più.
   v1.3: parte da solo dopo il controllo della cartella; gli esiti finiscono sulle righe dell'elenco mod. */
(function () {
    'use strict';
    const J = window.J, $ = J.$, esc = J.esc, ic = J.ic;
    const out = $('jrnl-out'), ph = $('jrnl-ph'), btn = $('btn-jrnl'),
        gameEl = $('jrnl-game'), noteEl = $('jrnl-note'), usnBox = $('jrnl-usn');
    let busy = false;

    if (!btn) return;

    const KIND = { written: 'scritto', closed: 'chiuso', deleted: 'eliminato', renamed_from: 'rinominato (vecchio nome)',
        renamed_to: 'rinominato (nuovo nome)', renamed: 'rinominato', attrs: 'date o permessi cambiati', other: 'altro' };

    function fmt(ms) {
        if (!ms) return '–';
        const d = new Date(ms), p = (n) => String(n).padStart(2, '0');
        return p(d.getDate()) + '/' + p(d.getMonth() + 1) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    }
    /* Ora breve: solo HH:MM se è lo stesso giorno dell'avvio del gioco. */
    function clock(ms, since) {
        if (!ms) return '–';
        const d = new Date(ms), p = (n) => String(n).padStart(2, '0'), s = since ? new Date(since) : null;
        const hm = p(d.getHours()) + ':' + p(d.getMinutes());
        return s && s.toDateString() === d.toDateString() ? hm : p(d.getDate()) + '/' + p(d.getMonth() + 1) + ' ' + hm;
    }

    async function currentPath() {
        if (J.modsPath) {
            const p = J.modsPath();
            if (p) return p;
        }
        const r = await J.api('/api/mods/locate');
        return (r.best && r.best.exists !== false) ? r.best.path : null;
    }

    /* ---------- cosa mostrare sulle righe dell'elenco mod ---------- */
    function meta() { return J.modsBadges.journalMeta || {}; }

    /** Frase che spiega cosa è successo al file, in parole semplici. */
    function why(info, official) {
        const g = meta(), t = clock(info.time, g.since), st = clock(g.since, g.since);
        const start = '(avvio alle ' + st + ')';
        if (info.state === 'added') {
            return '<b>Aggiunta alle ' + t + '</b>, dopo l\'avvio di Minecraft ' + start + '. <em>Non c\'era quando hai aperto il gioco. '
                + (official ? 'È una mod ufficiale: di solito significa che l\'hai installata tu.' : 'Se non l\'hai messa tu, toglila.') + '</em>';
        }
        if (info.state === 'renamed') {
            return '<b>Rinominata alle ' + t + '</b>' + (info.from ? ' (prima: <code>' + esc(info.from) + '</code>)' : '') + ' ' + start + '. <em>Il contenuto può essere lo stesso, ma il nome è cambiato mentre il gioco era aperto.</em>';
        }
        if (info.state === 'attrs') {
            return '<b>Date o permessi cambiati alle ' + t + '</b> ' + start + '. <em>Capita con i programmi di pulizia, ma può anche servire a far sembrare vecchio un file.</em>';
        }
        return '<b>Modificata alle ' + t + '</b>, dopo l\'avvio di Minecraft ' + start + '. <em>Il file è cambiato mentre il gioco era aperto.</em>';
    }

    /** Elenco di tutto ciò che il journal riporta per quel file. */
    function history(info) {
        const ev = (info.events || []).filter((e) => e.kind !== 'closed' || (info.events || []).length < 4);
        if (!ev.length) return '';
        const g = meta();
        return '<details class="jh"><summary>Cosa è successo a questo file <span class="chip">' + ev.length + (ev.length === 1 ? ' evento' : ' eventi') + '</span></summary><div class="jev">'
            + ev.map((e) => '<div><small>' + clock(e.time, g.since) + '</small><span class="sb ' + (e.kind === 'deleted' ? 'bad' : (e.kind === 'written' || e.kind === 'renamed_to' || e.kind === 'attrs') ? 'unk' : 'new') + '">' + esc(KIND[e.kind] || e.kind) + '</span>'
                + (e.from ? '<code>da ' + esc(e.from) + '</code>' : '') + '<small>' + esc(e.reason || '') + '</small></div>').join('') + '</div></details>';
    }

    function flag(info, official) {
        return '<div class="flag">' + ic('flag') + '<span>' + why(info, official) + '</span></div>' + history(info);
    }

    /** Riga "fantasma" per un file che c'era e ora non c'è più. */
    function ghostWhy(g) {
        const t = clock(g.time, meta().since);
        return g.kind === 'renamed'
            ? '<b>Rinominato' + (g.renamedTo ? ' in <code>' + esc(g.renamedTo) + '</code>' : '') + ' alle ' + t + '</b>. <em>Con il vecchio nome non c\'è più nella cartella.</em>'
            : '<b>Eliminato alle ' + t + '</b>. <em>C\'era nella cartella mods dopo l\'avvio e ora non c\'è più. Controlla se l\'hai tolto tu.</em>';
    }

    /* ---------- card del journal ---------- */
    function render(d) {
        const c = d.counts || {}, g = d.game, j = d.journal || {};
        gameEl.textContent = g
            ? 'Minecraft ' + (g.exe || 'javaw') + ' · PID ' + g.pid + ' · avviato ' + fmt(g.start)
            : 'Avvio del gioco impostato a mano';
        noteEl.textContent = 'Cartella controllata: ' + (d.modsDir || '—');
        const touched = Object.keys(J.modsBadges.journal).length, gone = (j.gone || []).length;
        const parts = [];
        if (c.added) parts.push(c.added + (c.added === 1 ? ' aggiunta' : ' aggiunte'));
        if (c.modified) parts.push(c.modified + (c.modified === 1 ? ' modificata' : ' modificate'));
        const ren = Object.values(J.modsBadges.journal).filter((x) => x.state === 'renamed').length;
        if (ren) parts.push(ren + (ren === 1 ? ' rinominata' : ' rinominate'));
        if (gone) parts.push(gone + (gone === 1 ? ' file sparito' : ' file spariti'));
        const total = touched + gone;
        let h = '<div class="jsum"><div class="big"><span class="pic ' + (total ? 'warn' : 'okc') + '">' + ic(total ? 'flag' : 'shield', 22) + '</span><div>'
            + '<b>' + (total ? total + (total === 1 ? ' elemento toccato' : ' elementi toccati') + ' dopo l\'avvio di Minecraft' : 'Nessuna mod toccata dopo l\'avvio di Minecraft') + '</b>'
            + '<small>' + esc(parts.length ? parts.join(' · ') + ' · ' : '') + (c.checked || 0) + ' file controllati</small></div></div>'
            + (total ? '<button class="btn" type="button" data-jr-show>' + ic('search') + 'Mostra nell\'elenco</button>' : '') + '</div>';
        if (j.available) {
            h += '<div class="ph" style="margin:0 22px 8px">Journal di Windows letto: <b>' + (j.events || []).length + '</b> eventi nella cartella mods dalle ' + fmt(d.since || 0)
                + ' · file eliminati o rinominati: <b>' + (j.deleted || 0) + '</b>' + (j.truncated ? ' (elenco troncato)' : '') + '</div>';
        } else {
            h += '<div class="jwarn">' + ic('alert') + '<span>' + esc(j.note || 'Journal di Windows non disponibile.') + '</span></div>';
        }
        if (gone) {
            h += '<div class="jgone"><h4>File che c\'erano nella cartella e ora non ci sono più <span class="chip">' + gone + '</span></h4>'
                + j.gone.map((x) => '<div class="grow"><span class="pic">' + ic('jar', 20) + '</span><div><b>' + esc(x.fileName) + '</b><small>' + ghostWhy(x) + '</small></div><span class="sb ' + (x.kind === 'deleted' ? 'bad' : 'unk') + '">' + (x.kind === 'deleted' ? 'Eliminato' : 'Rinominato') + '</span></div>').join('') + '</div>';
        }
        if (j.available && (j.events || []).length) {
            h += '<details class="jall"><summary>Tutti gli eventi del journal <span class="chip">' + j.events.length + '</span></summary><div class="jev" style="max-height:260px;overflow:auto">'
                + j.events.map((e) => '<div><small>' + fmt(e.time) + '</small><span class="sb ' + (e.kind === 'deleted' ? 'bad' : e.kind === 'renamed_from' || e.kind === 'renamed_to' || e.kind === 'written' || e.kind === 'attrs' ? 'unk' : 'new') + '">' + esc(KIND[e.kind] || e.kind) + '</span><code>' + esc(e.file) + '</code><small>' + esc(e.reason || '') + '</small></div>').join('') + '</div></details>';
        }
        out.innerHTML = h;
    }

    /* Esiti per la lista delle mod: chiave = nome file (minuscolo). */
    function publish(d) {
        const j = d.journal || {}, files = j.files || {}, map = {};
        (d.suspects || []).forEach((s) => {
            const key = String(s.fileName).toLowerCase();
            map[key] = { state: s.state === 'added' ? 'added' : 'modified', time: s.state === 'added' ? s.created : s.modified, events: files[key] || [] };
        });
        Object.keys(files).forEach((key) => {
            const ev = files[key] || [];
            const to = ev.filter((e) => e.kind === 'renamed_to').pop();
            const at = ev.filter((e) => e.kind === 'attrs').pop();
            const wr = ev.filter((e) => e.kind === 'written').pop();
            if (map[key]) { if (to) { map[key].from = to.from; } return; }
            if (to) map[key] = { state: 'renamed', from: to.from, time: to.time, events: ev };
            else if (wr) map[key] = { state: 'modified', time: wr.time, events: ev };
            else if (at) map[key] = { state: 'attrs', time: at.time, events: ev };
        });
        J.modsBadges.journal = map;
        J.modsBadges.gone = j.gone || [];
        J.modsBadges.journalMeta = { since: d.since, available: !!j.available, note: j.note || '' };
        if (J.modsRefresh) J.modsRefresh();
    }

    async function run(quiet) {
        if (busy) return null;
        busy = true;
        btn.disabled = true;
        if (!quiet) out.innerHTML = '';
        ph.textContent = 'Confronto degli orari dei file con l\'avvio del gioco…';
        try {
            const p = await currentPath();
            if (!p) {
                if (!quiet) ph.textContent = 'Cartella mods non trovata: avvia Minecraft oppure scegli la cartella nella scheda qui sopra.';
                return null;
            }
            const d = await J.api('/api/mods/journal?path=' + encodeURIComponent(p) + (usnBox && usnBox.checked ? '&usn=1' : ''));
            ph.textContent = quiet ? 'Controllo automatico completato' : 'Controllo completato';
            publish(d);
            render(d);
            const c = d.counts || {}, n = (c.added || 0) + (c.modified || 0) + (c.gone || 0);
            if (n > 0) {
                if (quiet) J.toast('Dopo l\'avvio del gioco: ' + n + (n === 1 ? ' file toccato' : ' file toccati') + ' nella cartella mods', 'error');
                else J.error('Attenzione: ci sono mod toccate dopo l\'avvio del gioco');
            }
            return d;
        } catch (e) {
            ph.textContent = 'Controllo non riuscito';
            if (!quiet) {
                out.innerHTML = '<div class="mempty">' + esc(e.message || 'Errore') + '</div>';
                J.error(e.message || 'Controllo non riuscito');
            }
            return null;
        } finally {
            busy = false;
            btn.disabled = false;
        }
    }

    /* Avvio automatico e silenzioso dopo il controllo della cartella;
       v1.3: in catena parte anche il confronto runtime (flag JVM, latest.log,
       artefatti cheat), poi il pid del gioco va all'auto-dump della memoria. */
    async function auto() {
        if (busy) return;
        const d = await run(true);
        if (J.runtime && J.runtime.auto) J.runtime.auto();
        if (d && d.game && d.game.pid && J.mem && J.mem.auto) J.mem.auto(String(d.game.pid));
    }

    J.journal = { auto: auto, run: () => run(false) };
    J.jr = { flag: flag, ghostWhy: ghostWhy };
    out.addEventListener('click', (e) => { if (e.target.closest('[data-jr-show]') && J.modsFilter) J.modsFilter('jr'); });
    btn.addEventListener('click', () => run(false));
})();
