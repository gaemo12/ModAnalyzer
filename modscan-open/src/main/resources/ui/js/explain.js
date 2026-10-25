/* ModScanOpen — traduce i rilevamenti tecnici in un linguaggio da giocatore di Minecraft.
   Nessuna modifica al motore: raggruppa i finding per "argomento", ne ricava un verdetto
   in parole semplici e dice cosa fare. I dettagli tecnici restano disponibili a parte. */
(function () {
    'use strict';
    const J = window.J;
    const E = J.Explain = {};

    const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    /* tier → [etichetta, classe colore già usata dalle gravità: c/h/m/i] */
    E.TIER = { grave: ['Grave', 'c'], serio: ['Serio', 'h'], dubbio: ['Da guardare', 'm'], nota: ['Nota', 'i'] };
    const TIER_RANK = { grave: 0, serio: 1, dubbio: 2, nota: 3 };

    E.CAVEAT = 'Il controllo cerca indizi nel codice e può sbagliare: un risultato verde non è una garanzia e uno rosso non è una condanna. Nel dubbio, scarica le mod solo da Modrinth o CurseForge.';

    /* L'ordine conta: il primo argomento che corrisponde vince (i più gravi e specifici stanno in alto).
       cat = categorie del motore; re = parole chiave cercate in famiglia, regola, titolo e categoria. */
    const TOPICS = [
        { k: 'ransom', tier: 'grave', icon: 'lock', label: 'Può bloccare i tuoi file',
          what: 'Cerca di cifrare o cancellare i file del PC e di chiedere un riscatto.',
          why: 'Potresti perdere mondi, screenshot e documenti.',
          head: 'Questa mod potrebbe bloccare o cifrare i tuoi file', soft: 'Alcuni indizi di cifratura dei file',
          re: /ransom|shadow ?copy|riscatto/ },
        { k: 'steal', tier: 'grave', icon: 'bug', label: 'Può rubare account e password',
          what: 'Cerca dati salvati (token di Discord, password del browser, sessione di Minecraft) e li manda fuori dal PC.',
          why: 'Chi li ottiene può entrare nel tuo account Microsoft/Minecraft, su Discord e nei server dove giochi.',
          head: 'Questa mod potrebbe rubare i tuoi account', soft: 'Alcuni indizi di furto di dati',
          re: /stealer|discord.*token|token.*discord|webhook|telegram|credential|cookie|wallet|clipper|keylog|exfil|session theft|minecraft-account|browser.*(password|login)/ },
        { k: 'remote', tier: 'grave', icon: 'cpu', label: 'Può dare il controllo del PC a qualcun altro',
          what: 'Apre un canale con un computer esterno: comandi a distanza, webcam, schermo o microfono.',
          why: 'Un “RAT” permette a un estraneo di usare il tuo PC mentre giochi, spesso senza che tu te ne accorga.',
          head: 'Questa mod potrebbe dare il controllo del tuo PC a qualcun altro', soft: 'Alcuni indizi di controllo remoto',
          re: /\brat\b|reverse shell|backdoor|websocket|\bc2\b|webcam|microfono|screen capture|remote access|accesso remoto/ },
        { k: 'miner', tier: 'grave', icon: 'cpu', label: 'Può usare il PC per minare criptovalute',
          what: 'Sfrutta processore e scheda video per guadagnare criptovalute per qualcun altro.',
          why: 'Minecraft va a scatti, il PC si scalda e la bolletta sale, senza alcun vantaggio per te.',
          head: 'Questa mod potrebbe usare il tuo PC per minare criptovalute', soft: 'Alcuni indizi di mining',
          re: /miner|stratum|mining|xmrig/ },
        { k: 'cheat', tier: 'serio', icon: 'alert', label: 'Contiene funzioni da cheat',
          what: 'Ha codice tipico dei client con vantaggi sleali: aimbot, kill aura, X-ray, modifica della rotazione.',
          why: 'Su molti server è vietato e porta al ban; i server con anti-cheat spesso lo individuano. In single player è una scelta tua.',
          head: 'Contiene funzioni da cheat', soft: 'Alcune funzioni sembrano da cheat',
          cat: ['CHEAT'], re: /cheat|aimbot|killaura|kill aura|triggerbot|autoclick|x-?ray|hitbox|scaffold|nofall|rotazione/ },
        { k: 'known', tier: 'grave', icon: 'shield', label: 'Riconosciuta come file pericoloso',
          what: 'Corrisponde a un file già segnalato come dannoso.',
          why: 'Meglio non usarla: file identici sono già stati usati per attaccare altri giocatori.',
          head: 'Questa mod è nota come pericolosa', soft: 'Somiglia a un file pericoloso noto',
          cat: ['MALWARE_SIGNATURE'], re: /known-malicious|firma nota/ },
        { k: 'download', tier: 'serio', icon: 'inject', label: 'Può scaricare o eseguire altro codice',
          what: 'Carica codice da fuori, lancia programmi o comandi sul PC, o si aggancia ad altri processi.',
          why: 'Una mod normale di solito non ne ha bisogno. È un modo per installare altro software di nascosto.',
          head: 'Può scaricare o eseguire altro codice', soft: 'Esegue comandi o carica codice dall’esterno',
          cat: ['EXECUTION', 'CODE_INJECTION'], re: /dropper|staged|payload|urlclassloader|classe remota|jni|attach\(|process ?injection|virtualprotect|\bjna\b|jndi|gadget|runtime\.exec|processbuilder|loadlibrary|shellcode/ },
        { k: 'deep', tier: 'nota', icon: 'code', label: 'Usa tecniche avanzate di Java',
          what: 'Modifica il gioco “dall’interno” (Mixin, reflection, accesso diretto alla memoria).',
          why: 'È il modo in cui lavorano moltissime mod, quindi di solito è normale. Conta di più se la mod non è ufficiale.',
          re: /mixin|reflection|unsafe|memoria jvm|premain|agent|retransform|redefine|instrument/ },
        { k: 'hide', tier: 'dubbio', icon: 'eye', label: 'Nasconde il proprio codice',
          what: 'Il codice è mescolato o cifrato, quindi è difficile capire cosa fa.',
          why: 'Alcune mod legittime lo fanno per proteggere il proprio lavoro, ma anche i malware lo usano per non farsi scoprire. Da solo non è una prova.',
          cat: ['OBFUSCATION', 'ENTROPY'], re: /offusc|obfusc|string ?encrypt|xor|opaque|nested try|proxy class|non-ascii|self-modifying|large-method|cyclomatic|lambda|decodific|base64|sourcefile|nomi classe/ },
        { k: 'network', tier: 'dubbio', icon: 'globe', label: 'Si collega a internet',
          what: 'Contiene indirizzi o connessioni verso server esterni.',
          why: 'È normale per le mod che controllano gli aggiornamenti o hanno funzioni online. È sospetto se la mod non dovrebbe averne bisogno o l’indirizzo è strano.',
          cat: ['NETWORK'], re: /url|porta|port|socket|http|ssl|tls/ },
        { k: 'files', tier: 'dubbio', icon: 'folder', label: 'Legge o scrive file sul PC',
          what: 'Accede a cartelle fuori da quella del gioco.',
          why: 'Alcune mod salvano configurazioni, ma se va a frugare nelle cartelle personali è un campanello d’allarme.',
          cat: ['FILE_ACCESS'], re: /traversal|zip-?slip/ },
        { k: 'struct', tier: 'nota', icon: 'file', label: 'File fatto in modo insolito',
          what: 'Struttura, manifest o firma del file hanno qualcosa di strano.',
          why: 'Spesso è solo un modo diverso di impacchettare la mod. Da solo non è un problema.',
          cat: ['STRUCTURE', 'MANIFEST', 'CERTIFICATE'], re: /archive-integrity|manifest|duplicat|oversize|traversal|unsigned|signed/ },
        { k: 'crypto', tier: 'nota', icon: 'lock', label: 'Usa la cifratura',
          what: 'Contiene codice per cifrare dati o chiavi.',
          why: 'Può servire per funzioni legittime (login, configurazioni). Va guardato solo insieme ad altri indizi.',
          cat: ['CRYPTO'] }
    ];
    const OTHER = { k: 'other', tier: 'nota', icon: 'file', label: 'Altre osservazioni',
        what: 'Note tecniche che non rientrano negli altri gruppi.', why: 'Di solito sono informazioni di contorno.' };

    function catKey(f) { return String(f.category || '').toUpperCase().replace(/[ -]+/g, '_'); }
    function blob(f) { return [f.family, f.ruleName, f.rule, f.title, f.category].filter(Boolean).join(' ').toLowerCase(); }
    function sevIdx(f) { const i = SEV_ORDER.indexOf(String(f.severity || 'INFO').toUpperCase()); return i < 0 ? 4 : i; }

    E.topicOf = function (f) {
        const c = catKey(f), b = blob(f);
        for (let i = 0; i < TOPICS.length; i++) {
            const t = TOPICS[i];
            if ((t.cat && t.cat.indexOf(c) >= 0) || (t.re && t.re.test(b))) return t;
        }
        return OTHER;
    };

    /** Raggruppa i finding per argomento: [{t, items:[{f,i,s}], worst}] dal più importante al meno. */
    E.group = function (findings) {
        const g = {};
        (findings || []).forEach((f, i) => {
            const t = E.topicOf(f), s = sevIdx(f);
            const o = g[t.k] || (g[t.k] = { t: t, items: [], worst: 9 });
            o.items.push({ f: f, i: i, s: s });
            o.worst = Math.min(o.worst, s);
        });
        return Object.keys(g).map((k) => g[k]).sort((a, b) =>
            TIER_RANK[a.t.tier] - TIER_RANK[b.t.tier] || a.worst - b.worst || b.items.length - a.items.length);
    };

    /** Verdetto in parole semplici.
        state: ok | note | warn | bad — flag: true se la mod merita attenzione anche in un elenco. */
    E.summarize = function (d) {
        const topics = E.group(d.findings);
        const mi = d.modInfo || {};
        const verified = mi.modrinthStatus === 'VERIFIED';
        const grave = topics.filter((g) => g.t.tier === 'grave');
        const serio = topics.filter((g) => g.t.tier === 'serio');
        const out = { topics: topics, verified: verified, state: 'ok', flag: false, headline: '', sub: '', also: '', advice: [] };
        const names = (list) => list.map((g) => g.t.label.charAt(0).toLowerCase() + g.t.label.slice(1));
        const strongGrave = grave.filter((g) => g.worst <= 1);
        const softGrave = grave.filter((g) => g.worst === 2);
        const strongSerio = serio.filter((g) => g.worst <= 1);
        const others = topics.filter((g) => g.t.tier !== 'nota' && g.t.tier !== 'grave' && g.t.tier !== 'serio' && g.worst <= 2);

        if (strongGrave.length) {
            const t = strongGrave[0].t;
            out.state = 'bad'; out.flag = true; out.headline = t.head; out.sub = t.what + ' ' + t.why;
            const rest = strongGrave.slice(1).concat(strongSerio);
            if (rest.length) out.also = 'Trovato anche: ' + names(rest).join('; ') + '.';
            out.advice = [
                'Non avviare Minecraft con questa mod: toglila dalla cartella mods.',
                'Se l’hai già usata, cambia le password di Microsoft/Minecraft e di Discord da un altro dispositivo.',
                'Fai una scansione del PC con il tuo antivirus.'
            ];
        } else if (strongSerio.length) {
            const t = strongSerio[0].t;
            out.state = 'warn'; out.flag = true;
            if (t.k === 'cheat' && verified) {
                out.headline = 'Mod ufficiale, ma con funzioni vietate su molti server';
                out.sub = 'È la versione pubblicata su Modrinth, però include funzioni tipiche dei cheat. ' + t.why;
            } else {
                out.headline = t.head; out.sub = t.what + ' ' + t.why;
            }
            const rest = strongSerio.slice(1).concat(softGrave);
            if (rest.length) out.also = 'Trovato anche: ' + names(rest).join('; ') + '.';
            out.advice = t.k === 'cheat'
                ? ['Se non l’hai scelta tu di proposito, toglila dalla cartella mods.',
                    'Prima di entrare in un server, leggi le sue regole sulle mod ammesse.',
                    'Se stai controllando il PC di un altro giocatore, è un indizio e non una prova: confrontalo con altri elementi.']
                : ['Usala solo se la conosci e l’hai scaricata da Modrinth o CurseForge.',
                    'Se non ti serve, toglila dalla cartella mods.'];
        } else if (softGrave.length) {
            const t = softGrave[0].t;
            out.state = 'warn'; out.flag = true; out.headline = t.soft; out.sub = 'Non è una prova, ma conviene guardare i dettagli qui sotto prima di usare la mod.';
            out.advice = ['Controlla i gruppi qui sotto.', 'Se la mod non è ufficiale, scaricala di nuovo da Modrinth o CurseForge e riscansionala.'];
        } else if (others.length && !verified) {
            out.state = 'warn'; out.headline = 'Niente di grave, ma ci sono punti da guardare';
            out.sub = 'Spesso sono comportamenti normali per una mod. Dai un’occhiata ai gruppi qui sotto.';
            out.advice = ['Se la mod non è ufficiale, scaricala di nuovo da Modrinth o CurseForge e riscansionala.', 'Se la conosci e ti fidi dell’autore, puoi ignorare le segnalazioni più lievi.'];
        } else if (verified) {
            out.state = 'ok'; out.headline = 'Mod ufficiale';
            out.sub = 'Il file coincide con la versione pubblicata su Modrinth' + (topics.length ? '. Le note qui sotto sono normali per una mod.' : ' e non contiene nulla di sospetto.');
            out.advice = ['Nessuna azione necessaria.'];
        } else if (topics.length) {
            out.state = 'note'; out.headline = 'Nessun problema evidente';
            out.sub = 'Ci sono solo note tecniche, normali in molte mod.';
            out.advice = ['Nessuna azione necessaria.', 'Scarica le mod solo da Modrinth o CurseForge.'];
        } else {
            out.state = 'ok'; out.headline = 'Nessun problema trovato';
            out.sub = 'Non abbiamo trovato niente di sospetto in questo file.';
            out.advice = ['Nessuna azione necessaria.', 'Scarica le mod solo da Modrinth o CurseForge.'];
        }
        return out;
    };
})();
