package com.jaranalyzer.common;

import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Client delle rotte Player (nessuna licenza: solo PIN monouso, poi token di sessione).
 * Flusso: {@link #verifyPin(String)} → consenso esplicito → {@link #getJob()} →
 * scansioni locali → {@link #getSignatures()} → {@link #submitResults(ScanReport)}.
 * Non richiede licenza, non legge risultati dettagliati, non esegue comandi remoti.
 */
public final class PlayerClient {
    private final ApiTransport transport;
    private PlayerSession session;

    public PlayerClient(ApiTransport transport) {
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    private Map<String, String> bearerHeaders() {
        PlayerSession s = requireAuth();
        Map<String, String> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        h.put("Authorization", "Bearer " + s.playerToken());
        h.put("Content-Type", "application/json");
        return h;
    }

    private PlayerSession requireAuth() {
        if (session == null) {
            throw new IllegalStateException("PIN non verificato: chiamare prima verifyPin");
        }
        return session;
    }

    /** Verifica il PIN e memorizza la sessione (token distinto dal PIN). */
    public PlayerSession verifyPin(String pin) {
        String body = new PinVerifyRequest(pin).toJson();
        Map<String, String> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        h.put("Content-Type", "application/json");
        ApiTransport.RawResponse r = transport.post(Protocol.PIN_VERIFY, h, body);
        if (r.status() == 200) {
            try {
                session = PlayerSession.fromJson(r.body());
                return session;
            } catch (JsonException | IllegalArgumentException e) {
                session = null;
                throw ApiException.protocol("risposta PIN illeggibile: " + e.getMessage());
            }
        }
        throw ApiException.http(r.status(), r.body());
    }

    /** Solo i moduli autorizzati dal job vengono eseguiti, dopo il consenso. */
    public JobInfo getJob() {
        ApiTransport.RawResponse r = transport.get(Protocol.JOB, bearerHeaders());
        if (r.status() == 200) {
            try {
                return JobInfo.fromJson(r.body());
            } catch (JsonException | IllegalArgumentException e) {
                throw ApiException.protocol("job illeggibile: " + e.getMessage());
            }
        }
        throw ApiException.http(r.status(), r.body());
    }

    /** Pacchetto firme: da verificare (firma + versione) e tenere in memoria. */
    public SignedBlob getSignatures() {
        ApiTransport.RawResponse r = transport.get(Protocol.SIGNATURES, bearerHeaders());
        if (r.status() == 200) {
            try {
                return SignedBlob.fromJson(r.body());
            } catch (JsonException | IllegalArgumentException e) {
                throw ApiException.protocol("firme illeggibili: " + e.getMessage());
            }
        }
        throw ApiException.http(r.status(), r.body());
    }

    /**
     * Invia i risultati (solo moduli della sessione; il server scarta il resto).
     * Il player non riceve mai i risultati indietro.
     */
    public void submitResults(ScanReport report) {
        Objects.requireNonNull(report, "report");
        PlayerSession s = requireAuth();
        for (String key : report.results().keySet()) {
            if (!s.modules().contains(key)) {
                throw ApiException.protocol("risultato per modulo non autorizzato: " + key);
            }
        }
        ApiTransport.RawResponse r = transport.post(Protocol.RESULTS, bearerHeaders(), report.toJson());
        if (r.status() != 200) {
            throw ApiException.http(r.status(), r.body());
        }
    }

    public boolean isAuthenticated() {
        return session != null;
    }

    public PlayerSession session() {
        return requireAuth();
    }

    @Override
    public String toString() {
        return "PlayerClient{authenticated=" + (session != null) + "}";
    }
}
