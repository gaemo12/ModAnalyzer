(function () {
    'use strict';

    // Utility condivisa per salvare file testuali (es. i report HTML esportati).
    //
    // La WebView JavaFX non supporta il download tramite Blob + <a download> (esattamente
    // come non supporta i dialoghi nativi di apertura file: per questo esiste già
    // window.javafxBridge.chooseFile()). Qui si usa lo stesso approccio per il salvataggio:
    // quando il bridge Java è presente, window.javafxBridge.saveFile(content, filename) apre
    // un FileChooser di salvataggio nativo e scrive il file su disco. Se invece l'app gira in
    // un browser normale (es. in sviluppo, fuori dalla WebView), si usa il classico fallback
    // Blob + <a download>.

    let pendingSaveResolve = null;

    // Richiamata da Java (WebUi.MsBridge.saveFile) al termine del salvataggio nativo.
    window.handleNativeSaveResult = function (success, path) {
        if (typeof pendingSaveResolve === 'function') {
            const resolve = pendingSaveResolve;
            pendingSaveResolve = null;
            resolve({ success: !!success, path: path || null });
        }
    };

    /**
     * Salva un contenuto testuale su disco, con un nome file suggerito.
     * Ritorna una Promise<{success:boolean, path:string|null}>.
     */
    function saveTextFile(content, filename, mimeType) {
        if (window.javafxBridge && typeof window.javafxBridge.saveFile === 'function') {
            return new Promise((resolve) => {
                pendingSaveResolve = resolve;
                try {
                    window.javafxBridge.saveFile(content, filename);
                } catch (err) {
                    pendingSaveResolve = null;
                    console.error('Errore nel richiamare javafxBridge.saveFile:', err);
                    resolve({ success: false, path: null });
                }
            });
        }

        // Fallback per browser reale (fuori dalla WebView JavaFX)
        return new Promise((resolve) => {
            try {
                const blob = new Blob([content], { type: mimeType || 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                resolve({ success: true, path: null });
            } catch (err) {
                console.error('Salvataggio file fallito:', err);
                resolve({ success: false, path: null });
            }
        });
    }

    window.ModScanOpenFileSaver = { saveTextFile: saveTextFile };
    window.JarAnalyzerFileSaver = window.ModScanOpenFileSaver;
})();
