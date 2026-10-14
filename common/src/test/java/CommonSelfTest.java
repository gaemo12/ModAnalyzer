import com.jaranalyzer.common.*;
import java.security.*;
import java.util.*;

/**
 * Self-test di common (stile CoreSelfTest, zero dipendenze):
 * DTO, allowlist, JSON, firme, fixture esatte del contratto /api/v2.
 * Esecuzione: javac + `java -cp ... CommonSelfTest` (vedere scripts/run-selftests).
 */
public class CommonSelfTest {
  static int fails = 0;
  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }
  static void throwsIt(String n, Runnable r) {
    try { r.run(); check(n, false); }
    catch (IllegalArgumentException | JsonException | SignedToken.TokenException e) { check(n, true); }
  }

  public static void main(String[] a) throws Exception {
    // ---- ModuleId: allowlist identica al backend (stesso ordine e contenuto)
    check("allowlist esatta", ModuleId.ALLOWED.equals(
        List.of("mods_folder", "processes", "javaw", "minecraft_accounts", "single_jar")));
    check("isAllowed", ModuleId.isAllowed("processes") && !ModuleId.isAllowed("evil") && !ModuleId.isAllowed(null));
    check("dedup preservando ordine", ModuleId.requireAllowedList(List.of("javaw", "processes", "javaw"))
        .equals(List.of("javaw", "processes")));
    throwsIt("sconosciuto rifiutato", () -> ModuleId.requireAllowedList(List.of("processes", "rm -rf")));
    throwsIt("vuota rifiutata", () -> ModuleId.requireAllowedList(List.of()));
    throwsIt("nulla rifiutata", () -> ModuleId.requireAllowedList(null));

    // ---- JsonCodec
    Map<String, Object> nested = new LinkedHashMap<>();
    nested.put("s", "a\"b\ncè");
    nested.put("i", 42L);
    nested.put("d", 1.5);
    nested.put("b", true);
    nested.put("n", null);
    nested.put("l", List.of(1L, "x", Map.of("k", 2L)));
    String w = JsonCodec.write(nested);
    Object back = JsonCodec.parse(w);
    check("round-trip JSON", back.equals(nested));
    check("double distinto da long", JsonCodec.parse("1.5") instanceof Double && JsonCodec.parse("42") instanceof Long);
    check("escape unicode", JsonCodec.parse("\"\\u00e8\"").equals("è"));
    throwsIt("NaN rifiutato in scrittura", () -> JsonCodec.write(Map.of("x", Double.NaN)));
    throwsIt("Infinity rifiutato in scrittura", () -> JsonCodec.write(Map.of("x", Double.POSITIVE_INFINITY)));
    throwsIt("spazzatura rifiutata", () -> JsonCodec.parse("{oops"));
    throwsIt("testo dopo valore rifiutato", () -> JsonCodec.parse("{} {}"));
    StringBuilder deep = new StringBuilder();
    for (int i = 0; i < 80; i++) deep.append('[');
    throwsIt("annidamento oltre limite rifiutato", () -> JsonCodec.parse(deep.toString()));
    check("surrogato isolato escaped", JsonCodec.write(Map.of("x", "a\ud800b")).contains("\\ud800"));

    // ---- Fixture ESATTE del backend (contratto /api/v2)
    SessionCreated sc = SessionCreated.fromJson(
        "{\"sessionId\":\"123e4567-e89b-12d3-a456-426614174000\",\"pin\":\"482910\","
        + "\"modules\":[\"processes\",\"javaw\"],\"expiresAt\":1790000000}");
    check("fixture SessionCreated", sc.pin().equals("482910") && sc.modules().size() == 2
        && sc.expiresAt() == 1790000000L);
    check("PIN oscurato in toString", !sc.toString().contains("482910"));
    throwsIt("PIN malformato rifiutato", () ->
        SessionCreated.fromJson("{\"sessionId\":\"x\",\"pin\":\"12ab\",\"modules\":[\"processes\"],\"expiresAt\":1}"));
    check("fixture SessionRequest esatta", new SessionRequest(List.of("processes")).toJson()
        .equals("{\"modules\":[\"processes\"]}"));
    check("fixture PinVerifyRequest esatta", new PinVerifyRequest("482910").toJson()
        .equals("{\"pin\":\"482910\"}"));
    throwsIt("PIN corto rifiutato", () -> new PinVerifyRequest("12345"));
    PlayerSession ps = PlayerSession.fromJson(
        "{\"playerToken\":\"tok123\",\"modules\":[\"mods_folder\"],\"expiresAt\":1790000000}");
    check("fixture PlayerSession", ps.modules().equals(List.of("mods_folder")));
    check("token oscurato in toString", !ps.toString().contains("tok123"));
    JobInfo job = JobInfo.fromJson("{\"modules\":[\"javaw\"],\"status\":\"claimed\",\"expiresAt\":1790000000}");
    check("fixture JobInfo", job.status() == SessionStatus.CLAIMED);
    check("stato ignoto tollerato", SessionStatus.fromString("futuro") == SessionStatus.UNKNOWN);
    SessionView sv = SessionView.fromJson(
        "{\"sessionId\":\"s1\",\"status\":\"done\",\"modules\":[\"processes\"],"
        + "\"expiresAt\":1790000000,\"result\":{\"processes\":{\"success\":true}}}");
    check("fixture SessionView con result", sv.resultJson() != null && sv.status() == SessionStatus.DONE);
    SessionView sv2 = SessionView.fromJson(
        "{\"sessionId\":\"s1\",\"status\":\"waiting\",\"modules\":[\"processes\"],"
        + "\"expiresAt\":1790000000,\"result\":null}");
    check("fixture SessionView senza result", sv2.resultJson() == null);
    ApiError err = ApiError.fromJson(404, "{\"error\":\"PIN non valido\"}");
    check("fixture ApiError", err.httpStatus() == 404 && err.message().equals("PIN non valido"));
    check("ApiError corpo non-JSON", ApiError.fromJson(500, "x").message().equals("HTTP 500"));
    check("serverBusy", new ApiException(503, "x", false).serverBusy()
        && !new ApiException(400, "x", false).serverBusy());
    SignedBlob blob = SignedBlob.fromJson("{\"token\":\"JS1.abc.def\",\"issuedAt\":1790000000}");
    check("fixture SignedBlob", blob.token().equals("JS1.abc.def"));

    // ---- ModuleResult / ScanReport: formato PIATTO come il server
    ModuleResult mr = new ModuleResult("processes", true, 120,
        List.of(new Finding("r1", "Titolo", "HIGH", "NETWORK", "loc", null)),
        Map.of("files", 3L), null);
    check("round-trip ModuleResult", ModuleResult.fromMap("processes", mr.toMap()).equals(mr));
    throwsIt("fallito senza error rifiutato", () -> new ModuleResult("processes", false, 1, List.of(), Map.of(), null));
    throwsIt("durata negativa rifiutata", () -> ModuleResult.ok("processes", -1));
    throwsIt("modulo ignoto rifiutato", () -> ModuleResult.ok("evil", 1));
    ScanReport rep = new ScanReport(Map.of("processes", mr));
    String repJson = rep.toJson();
    Map<String, Object> repMap = JsonCodec.parseObject(repJson);
    check("ScanReport piatto (niente wrapper)", repMap.containsKey("processes")
        && !repMap.containsKey("protocol") && !repMap.containsKey("results"));
    check("round-trip ScanReport", ScanReport.fromJson(repJson).equals(rep));
    throwsIt("ScanReport vuoto rifiutato", () -> new ScanReport(Map.of()));
    Progress pg = new Progress("javaw", "scan", 50, "metà");
    check("round-trip Progress", Progress.fromJson(pg.toJson()).equals(pg));
    throwsIt("percent oltre 100 rifiutata", () -> new Progress("javaw", "scan", 101, null));

    // ---- SignedToken (Ed25519 JDK, stesso formato license-core/backend)
    KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
    KeyPair kp = g.generateKeyPair(), other = g.generateKeyPair();
    String tok = signToken("JS1", Map.of("v", 1L, "issued", 1790000000L), kp.getPrivate());
    check("formato token", tok.startsWith("JS1.") && tok.split("\\.").length == 3);
    check("verifica ok", SignedToken.verify("JS1", tok, kp.getPublic()).get("v").equals(1L));
    String[] parts = tok.split("\\.");
    String forgedPayload = Base64.getUrlEncoder().withoutPadding()
        .encodeToString("{\"v\":1,\"issued\":1}".getBytes());
    String forged = parts[0] + "." + forgedPayload + "." + parts[2];
    throwsIt("payload manomesso rifiutato", () -> SignedToken.verify("JS1", forged, kp.getPublic()));
    throwsIt("altra chiave rifiutata", () -> SignedToken.verify("JS1", tok, other.getPublic()));
    throwsIt("prefisso errato rifiutato", () -> SignedToken.verify("JV1", tok, kp.getPublic()));
    throwsIt("spazzatura rifiutata", () -> SignedToken.verify("JS1", "ciao", kp.getPublic()));
    throwsIt("oltre il limite rifiutato", () -> SignedToken.verify("JS1", "x".repeat(2_000_001), kp.getPublic()));
    check("limite costante allineata al backend", SignedToken.MAX_TOKEN_CHARS == 2_000_000);

    System.out.println(fails == 0 ? "TUTTO OK" : "FALLITI: " + fails);
    System.exit(fails == 0 ? 0 : 1);
  }

  static String signToken(String prefix, Map<String, Object> payload, PrivateKey key) throws Exception {
    String p = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(JsonCodec.write(payload).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    Signature s = Signature.getInstance("Ed25519");
    s.initSign(key);
    s.update((prefix + "." + p).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    return prefix + "." + p + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign());
  }
}
