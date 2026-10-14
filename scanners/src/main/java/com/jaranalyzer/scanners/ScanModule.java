package com.jaranalyzer.scanners;

import com.jaranalyzer.common.ModuleResult;

/**
 * Modulo di scansione eseguibile senza UI. L'identificatore è uno di
 * {@code common.ModuleId} (stessa allowlist del backend).
 */
public interface ScanModule {
    /** Identificatore del modulo, es. {@code "mods_folder"}. */
    String id();

    /**
     * Esegue la scansione indicata dal contesto. Non tocca la rete, non legge
     * configurazioni globali: tutto l'input arriva da {@code ctx}.
     *
     * @param ctx contesto tipizzato (il modulo rifiuta i tipi non supportati)
     * @param progress avanzamento + cancellazione (mai null; no-op ammesso)
     * @param signatures firme già validate dal chiamante (mai null; può essere vuoto)
     * @return esito serializzabile secondo il protocollo comune (mai null)
     * @throws ScanException FATAL o CANCELLED: il chiamante produce un ModuleResult fallito
     */
    ModuleResult run(ScanContext ctx, ProgressSink progress, SignatureSet signatures) throws ScanException;
}
