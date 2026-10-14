package com.jaranalyzer.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * Trasporto HTTP condiviso su {@code java.net.http.HttpClient} (solo JDK).
 * <ul>
 *   <li>Timeout di connessione e di richiesta configurabili.</li>
 *   <li>Niente redirect automatici: mai perdere credenziali verso altri host.</li>
 *   <li>Lettura con tetto in byte: risposte eccessive rifiutate senza OOM.</li>
 *   <li>Retry limitati e sicuri: solo GET idempotenti, solo su errori
 *       transitori (timeout, connessione, 429/502/503/504), backoff lineare.
 *       POST/PUT non ritentati mai (PIN monouso, semantica non ripetibile).</li>
 *   <li>Nessun log di token, PIN o corpi: gli errori espongono solo stato e messaggio.</li>
 * </ul>
 */
public final class ApiTransport {
    private final String baseUrl;
    private final ApiClientConfig config;
    private final HttpClient http;

    public ApiTransport(String baseUrl, ApiClientConfig config) {
        if (baseUrl == null || !(baseUrl.startsWith("http://") || baseUrl.startsWith("https://"))) {
            throw new IllegalArgumentException("baseUrl deve essere http(s): " + baseUrl);
        }
        this.config = Objects.requireNonNull(config, "config");
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(config.connectTimeoutMs()))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** Risposta grezza: stato + corpo (entro il tetto configurato). */
    public static final class RawResponse {
        private final int status;
        private final String body;

        RawResponse(int status, String body) {
            this.status = status;
            this.body = body;
        }

        public int status() {
            return status;
        }

        public String body() {
            return body;
        }
    }

    public RawResponse get(String path, Map<String, String> headers) {
        return execute("GET", path, headers, null, true);
    }

    public RawResponse post(String path, Map<String, String> headers, String body) {
        return execute("POST", path, headers, Objects.requireNonNull(body, "body"), false);
    }

    public RawResponse put(String path, Map<String, String> headers, String body) {
        return execute("PUT", path, headers, Objects.requireNonNull(body, "body"), false);
    }

    private RawResponse execute(String method, String path, Map<String, String> headers,
            String body, boolean idempotent) {
        int attempts = 1 + (idempotent ? config.maxRetries() : 0);
        ApiException last = null;
        for (int i = 1; i <= attempts; i++) {
            try {
                RawResponse r = sendOnce(method, path, headers, body);
                // Retry trasparente solo per letture GET su sovraccarico/non disponibile.
                // POST/PUT tornano subito: la risposta del server fa fede (operazione
                // non ripetibile: PIN monouso, invii singoli).
                if (idempotent && isBusy(r.status()) && i < attempts) {
                    sleepQuietly(500L * i);
                    continue;
                }
                return r;
            } catch (ApiException e) {
                last = e;
                if (!idempotent || !e.retryable() || i == attempts) {
                    throw e;
                }
                sleepQuietly(500L * i);
            }
        }
        throw last;
    }

    private static boolean isBusy(int status) {
        return status == 429 || status == 502 || status == 503 || status == 504;
    }

    private RawResponse sendOnce(String method, String path, Map<String, String> headers, String body) {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(Duration.ofMillis(config.requestTimeoutMs()))
                .header("User-Agent", config.userAgent())
                .header("Accept", "application/json");
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                b.header(e.getKey(), e.getValue());
            }
        }
        if ("GET".equals(method)) {
            b.GET();
        } else if (body != null) {
            b.method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<InputStream> res;
        try {
            res = http.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (HttpTimeoutException e) {
            throw ApiException.timeout("timeout di richiesta verso " + path, e);
        } catch (IOException e) {
            // Errori di connessione: transitori, il chiamante decide (retry solo se GET).
            throw new ApiException(-1, "errore di rete verso " + path + ": " + safe(e), true, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw ApiException.transport("richiesta interrotta verso " + path, e);
        }
        String payload;
        try (InputStream in = res.body()) {
            payload = readCapped(in, config.maxResponseBytes());
        } catch (ApiException e) {
            throw e;
        } catch (IOException e) {
            throw ApiException.transport("lettura risposta da " + path + " fallita: " + safe(e), e);
        }
        return new RawResponse(res.statusCode(), payload);
    }

    private static String readCapped(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(max, 65536));
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > max) {
                throw ApiException.protocol("risposta eccessiva (oltre " + max + " byte), scartata");
            }
            out.write(buf, 0, n);
        }
        return out.toString(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw ApiException.transport("attesa retry interrotta", e);
        }
    }

    private static String safe(Exception e) {
        String m = e.getMessage();
        return m == null ? e.getClass().getSimpleName() : m;
    }
}
