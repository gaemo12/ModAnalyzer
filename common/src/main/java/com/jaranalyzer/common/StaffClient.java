package com.jaranalyzer.common;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Client delle rotte Staff (autenticazione con token di licenza {@code JA1}).
 * Non condivide nulla con {@link PlayerClient}: credenziali e permessi restano separati.
 */
public final class StaffClient {
    private final ApiTransport transport;
    private final String licenseToken;
    private final String hwid;

    /**
     * @param licenseToken token {@code JA1...} completo (mai registrato in log)
     * @param hwid impronta {@code XXXX-...} se la licenza è legata al PC, altrimenti null
     */
    public StaffClient(ApiTransport transport, String licenseToken, String hwid) {
        this.transport = Objects.requireNonNull(transport, "transport");
        if (licenseToken == null || licenseToken.isBlank()) {
            throw new IllegalArgumentException("licenseToken assente");
        }
        this.licenseToken = licenseToken.strip();
        this.hwid = (hwid == null || hwid.isBlank()) ? null : hwid.strip();
    }

    private Map<String, String> authHeaders() {
        Map<String, String> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        h.put("Authorization", "Staff " + licenseToken);
        if (hwid != null) {
            h.put("X-HWID", hwid);
        }
        h.put("Content-Type", "application/json");
        return h;
    }

    /** Crea una sessione remota; il PIN va mostrato allo staff una sola volta. */
    public SessionCreated createSession(List<String> modules) {
        String body = new SessionRequest(modules).toJson();
        ApiTransport.RawResponse r = transport.post(Protocol.SESSIONS, authHeaders(), body);
        if (r.status() == 200) {
            try {
                return SessionCreated.fromJson(r.body());
            } catch (JsonException e) {
                throw ApiException.protocol("risposta sessione illeggibile: " + e.getMessage());
            }
        }
        throw ApiException.http(r.status(), r.body());
    }

    /** Legge stato ed eventuali risultati (poll con backoff a cura del chiamante). */
    public SessionView getSession(String sessionId) {
        if (sessionId == null || !sessionId.matches("[0-9a-fA-F-]{36}")) {
            throw ApiException.protocol("sessionId non valido");
        }
        ApiTransport.RawResponse r = transport.get(Protocol.SESSIONS + "/" + sessionId, authHeaders());
        if (r.status() == 200) {
            try {
                return SessionView.fromJson(r.body());
            } catch (JsonException e) {
                throw ApiException.protocol("stato sessione illeggibile: " + e.getMessage());
            }
        }
        throw ApiException.http(r.status(), r.body());
    }

    @Override
    public String toString() {
        return "StaffClient{licenseToken='******'" + (hwid != null ? ", hwid bound" : ", no hwid") + "}";
    }
}
