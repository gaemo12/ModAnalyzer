package modscan;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Locale;

/**
 * Validazione dei file trascinati nella WebView (drag &amp; drop nativo JavaFX).
 * Il file non passa mai dalla memoria del browser: si ricava il percorso reale con
 * {@code Dragboard.getFiles()} e la UI chiama la rotta esistente
 * {@code POST /api/analyze-local}, che riesegue gli stessi controlli lato Java
 * (estensione, file regolare, 512 MB). Qui si scartano subito, con messaggio
 * chiaro, gli input palesemente non validi.
 */
public final class DragValidator {
    private DragValidator() {
    }

    /** Esito: percorso canonico pronto da passare alla UI, oppure messaggio per l'utente. */
    public record Result(boolean ok, String path, String error) {
        static Result ok(String path) {
            return new Result(true, path, null);
        }

        static Result err(String error) {
            return new Result(false, null, error);
        }
    }

    public static Result check(List<File> files) {
        if (files == null || files.isEmpty()) {
            return Result.err("Nessun file ricevuto dal trascinamento.");
        }
        if (files.size() != 1) {
            return Result.err("Trascina un solo file .jar alla volta.");
        }
        File f = files.get(0);
        if (f == null || !f.exists() || !f.isFile()) {
            return Result.err("Il percorso trascinato non è un file valido.");
        }
        String canonical;
        try {
            canonical = f.getCanonicalPath().replace("\\", "/");
        } catch (IOException e) {
            return Result.err("Impossibile risolvere il percorso trascinato.");
        }
        String name = new File(canonical).getName();
        if (!name.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            return Result.err("Formato non valido: solo file .jar.");
        }
        long len = f.length();
        if (len <= 0) {
            return Result.err("Il file è vuoto.");
        }
        if (len > OpenApi.MAX_LOCAL_JAR_BYTES) {
            return Result.err("Il file è troppo grande (" + fmtBytes(len) + "). Massimo 512 MB.");
        }
        return Result.ok(canonical);
    }

    static String fmtBytes(long n) {
        if (n >= 1024L * 1024 * 1024) {
            return String.format(Locale.ROOT, "%.1f GB", n / 1073741824.0);
        }
        return String.format(Locale.ROOT, "%.1f MB", n / 1048576.0);
    }
}
