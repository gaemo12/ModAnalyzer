import com.jaranalyzer.common.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/**
 * Self-test del client HTTP condiviso contro un server locale reale
 * (com.sun.net.httpserver, solo JDK): auth, errori, JSON malformato,
 * timeout, risposte eccessive, retry solo-GET.
 */
public class ApiClientSelfTest {
  static int fails = 0;
  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }
  interface Part { void run() throws Exception; }
  static void throwsApi(String n, Part r, int status) {
    try { r.run(); check(n, false); }
    catch (ApiException e) { check(n + " [status=" + e.httpStatus() + "]", e.httpStatus() == status); }
    catch (Exception e) { System.out.println("  eccezione inattesa: " + e); check(n, false); }
  }

  // ---- server di prova
  static HttpServer server;
  static ExecutorService pool;
  static String base;
  static final Map<String, String> lastHeaders = new ConcurrentHashMap<>();
  static final Map<String, String> lastBodies = new ConcurrentHashMap<>();
  static final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
  static final Map<String, AtomicInteger> failLeft = new ConcurrentHashMap<>();
  static final Map<String, Integer> failStatus = new ConcurrentHashMap<>();
  static final Map<String, Integer> statusOf = new ConcurrentHashMap<>();
  static final Map<String, Long> delays = new ConcurrentHashMap<>();
  static final Map<String, String> canned = new ConcurrentHashMap<>();

  static void hit(String k) { hits.computeIfAbsent(k, x -> new AtomicInteger()).incrementAndGet(); }

  static void handle(HttpExchange ex, String key) throws IOException {
    hit(key);
    Headers req = ex.getRequestHeaders();
    for (String h : List.of("Authorization", "X-Hwid", "Content-Type", "User-Agent", "Accept"))
      if (req.containsKey(h)) lastHeaders.put(key + ":" + h, req.getFirst(h));
    lastBodies.put(key, new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
    Long d = delays.get(key);
    if (d != null) try { Thread.sleep(d); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    AtomicInteger fl = failLeft.get(key);
    if (fl != null && fl.getAndDecrement() > 0) {
      send(ex, failStatus.getOrDefault(key, 503), "{\"error\":\"transitorio\"}");
      return;
    }
    String body = canned.getOrDefault(key, "{\"ok\":true}");
    send(ex, statusOf.getOrDefault(key, 200), body);
  }

  static void send(HttpExchange ex, int status, String body) throws IOException {
    byte[] b = body.getBytes(StandardCharsets.UTF_8);
    ex.getResponseHeaders().set("Content-Type", "application/json");
    ex.sendResponseHeaders(status, b.length);
    try (OutputStream o = ex.getResponseBody()) { o.write(b); }
  }

  static ApiTransport transport() {
    return new ApiTransport(base, ApiClientConfig.defaults());
  }

  public static void main(String[] a) throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    pool = Executors.newCachedThreadPool();
    server.setExecutor(pool);
    try {
      runAll();
    } finally {
      server.stop(0);
      pool.shutdownNow();
    }
    System.out.println(fails == 0 ? "TUTTO OK" : "FALLITI: " + fails);
    System.exit(fails == 0 ? 0 : 1);
  }

  static void runAll() throws Exception {
    canned.put("sessions", "{\"sessionId\":\"123e4567-e89b-12d3-a456-426614174000\",\"pin\":\"482910\","
        + "\"modules\":[\"processes\"],\"expiresAt\":1790000000}");
    canned.put("session1", "{\"sessionId\":\"123e4567-e89b-12d3-a456-426614174000\",\"status\":\"done\","
        + "\"modules\":[\"processes\"],\"expiresAt\":1790000000,\"result\":{\"processes\":{\"success\":true}}}");
    canned.put("verify", "{\"playerToken\":\"tok-abc\",\"modules\":[\"processes\"],\"expiresAt\":1790000000}");
    canned.put("job", "{\"modules\":[\"processes\"],\"status\":\"claimed\",\"expiresAt\":1790000000}");
    server.createContext("/api/v2/sessions", ex -> handle(ex, "sessions"));
    server.createContext("/api/v2/sessions/123e4567-e89b-12d3-a456-426614174000", ex -> handle(ex, "session1"));
    server.createContext("/api/v2/pin/verify", ex -> handle(ex, "verify"));
    server.createContext("/api/v2/job", ex -> handle(ex, "job"));
    server.createContext("/api/v2/results", ex -> handle(ex, "results"));
    server.createContext("/slow", ex -> handle(ex, "slow"));
    server.createContext("/big", ex -> handle(ex, "big"));
    server.createContext("/empty500", ex -> handle(ex, "empty500"));
    server.start();
    base = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
    check("baseUrl con slash finale accettata", true);

    // ---- Staff
    StaffClient staff = new StaffClient(transport(), "JA1.payload.sig", "AAAA-BBBB-CCCC-DDDD-EEEE");
    SessionCreated sc = staff.createSession(List.of("processes"));
    check("staff create ok", sc.pin().equals("482910"));
    check("header Authorization Staff", "Staff JA1.payload.sig".equals(lastHeaders.get("sessions:Authorization")));
    check("header X-HWID", "AAAA-BBBB-CCCC-DDDD-EEEE".equals(lastHeaders.get("sessions:X-Hwid")));
    check("header Content-Type", "application/json".equals(lastHeaders.get("sessions:Content-Type")));
    check("body create esatto", "{\"modules\":[\"processes\"]}".equals(lastBodies.get("sessions")));
    StaffClient noHwid = new StaffClient(transport(), "JA1.payload.sig", null);
    lastHeaders.remove("sessions:X-Hwid");
    noHwid.createSession(List.of("processes"));
    check("senza HWID nessun header", !lastHeaders.containsKey("sessions:X-Hwid"));
    SessionView sv = staff.getSession("123e4567-e89b-12d3-a456-426614174000");
    check("staff get ok", sv.status() == SessionStatus.DONE && sv.resultJson() != null);
    int before = hits.getOrDefault("session1", new AtomicInteger()).get();
    throwsApi("uuid non valido senza richiesta", () -> staff.getSession("nope"), -1);
    check("nessuna chiamata per uuid invalido", hits.getOrDefault("session1", new AtomicInteger()).get() == before);
    canned.put("sessions", "{\"error\":\"Licenza revocata\"}");
    failLeft.put("sessions", new AtomicInteger(1)); failStatus.put("sessions", 403);
    throwsApi("staff 403 mappato", () -> staff.createSession(List.of("processes")), 403);
    failLeft.remove("sessions");

    // ---- Player
    PlayerClient player = new PlayerClient(transport());
    check("non autenticato all'avvio", !player.isAuthenticated());
    try { player.getJob(); check("job senza PIN rifiutato", false); }
    catch (IllegalStateException e) { check("job senza PIN rifiutato", true); }
    PlayerSession ps = player.verifyPin("482910");
    check("verify ok + autenticato", player.isAuthenticated() && ps.modules().equals(List.of("processes")));
    check("body verify esatto", "{\"pin\":\"482910\"}".equals(lastBodies.get("verify")));
    try { player.verifyPin("12ab"); check("PIN malformato rifiutato lato client", false); }
    catch (IllegalArgumentException e) { check("PIN malformato rifiutato lato client", true); }
    JobInfo job = player.getJob();
    check("job ok", job.status() == SessionStatus.CLAIMED);
    check("header Bearer", "Bearer tok-abc".equals(lastHeaders.get("job:Authorization")));
    ScanReport rep = new ScanReport(Map.of("processes", ModuleResult.ok("processes", 10)));
    player.submitResults(rep);
    Map<String, Object> sentBody = JsonCodec.parseObject(lastBodies.get("results"));
    check("results piatto (solo moduli)", sentBody.containsKey("processes") && sentBody.size() == 1);
    ScanReport bad = new ScanReport(Map.of("javaw", ModuleResult.ok("javaw", 1)));
    int rhits = hits.getOrDefault("results", new AtomicInteger()).get();
    throwsApi("modulo fuori sessione rifiutato", () -> player.submitResults(bad), -1);
    check("nessun invio per modulo non autorizzato",
        hits.getOrDefault("results", new AtomicInteger()).get() == rhits);
    check("User-Agent inviato", lastHeaders.get("job:User-Agent").startsWith("JarAnalyzer-Common/"));

    // ---- Errori, formato, limiti
    // 500 persistente con corpo vuoto: il client espone l'ultimo errore senza ritentare oltre
    statusOf.put("empty500", 500);
    canned.put("empty500", "");
    ApiTransport t = transport();
    // Il transport espone gli status HTTP grezzi; il mapping in ApiException sta nei client.
    ApiTransport.RawResponse r500 = t.get("/empty500", Map.of());
    check("500 vuoto esposto grezzo", r500.status() == 500);
    check("500 vuoto mappato", ApiError.fromJson(r500.status(), r500.body()).message().equals("HTTP 500"));
    statusOf.remove("empty500");
    String jobOk = canned.get("job");
    canned.put("job", "non-json{");
    throwsApi("JSON malformato = protocollo", () -> player.getJob(), -1);
    canned.put("job", jobOk);
    canned.put("big", "{\"d\":\"" + "x".repeat(5000) + "\"}");
    ApiTransport small = new ApiTransport(base,
        new ApiClientConfig(5000, 15000, 1024, 0, "t"));
    throwsApi("risposta eccessiva scartata", () -> small.get("/big", Map.of()), -1);
    delays.put("slow", 1500L);
    ApiTransport fast = new ApiTransport(base,
        new ApiClientConfig(5000, 400, 1024 * 1024, 0, "t"));
    throwsApi("timeout mappato", () -> fast.get("/slow", Map.of()), -1);
    delays.remove("slow");
    try { new ApiTransport("ftp://x", ApiClientConfig.defaults()); check("scheme non-http rifiutato", false); }
    catch (IllegalArgumentException e) { check("scheme non-http rifiutato", true); }
    try { new ApiClientConfig(0, 1, 1024, 0, "u"); check("timeout zero rifiutato", false); }
    catch (IllegalArgumentException e) { check("timeout zero rifiutato", true); }

    // ---- Retry: solo GET
    failLeft.put("job", new AtomicInteger(2)); failStatus.put("job", 503);
    int j0 = hits.getOrDefault("job", new AtomicInteger()).get();
    JobInfo jr = player.getJob();
    check("GET ritentato fino a 200", jr.status() == SessionStatus.CLAIMED
        && hits.get("job").get() - j0 == 3);
    failLeft.remove("job");
    failLeft.put("job", new AtomicInteger(1)); failStatus.put("job", 429);
    j0 = hits.get("job").get();
    player.getJob();
    check("GET 429 ritentato", hits.get("job").get() - j0 == 2);
    failLeft.remove("job");
    failLeft.put("results", new AtomicInteger(5)); failStatus.put("results", 500);
    int r0 = hits.getOrDefault("results", new AtomicInteger()).get();
    throwsApi("POST mai ritentato", () -> player.submitResults(rep), 500);
    check("POST una sola tentativa", hits.get("results").get() - r0 == 1);
    failLeft.remove("results");
    failLeft.put("results", new AtomicInteger(1)); failStatus.put("results", 429);
    r0 = hits.get("results").get();
    throwsApi("POST 429 mai ritentato", () -> player.submitResults(rep), 429);
    check("POST 429 una sola tentativa", hits.get("results").get() - r0 == 1);
    failLeft.remove("results");
    // connessione rifiutata (GET): transitorio, ritentato maxRetries volte
    ApiTransport dead = new ApiTransport("http://127.0.0.1:9/",
        new ApiClientConfig(1000, 1000, 1024 * 1024, 2, "t"));
    long start = System.currentTimeMillis();
    try { dead.get("/x", Map.of()); check("connessione rifiutata = errore", false); }
    catch (ApiException e) {
      check("connessione rifiutata = errore", e.httpStatus() == -1 && e.retryable());
    }
    check("refused veloce (niente attese infinite)", System.currentTimeMillis() - start < 15000);
  }
}
