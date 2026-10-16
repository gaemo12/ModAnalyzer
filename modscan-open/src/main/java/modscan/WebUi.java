package modscan;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Worker;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.layout.BorderPane;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.Window;
import netscape.javascript.JSObject;

/**
 * Finestra di ModScanOpen. La UI è la stessa della vecchia JarAnalyzer (HTML/CSS/JS) mostrata
 * in una WebView incorporata e caricata da una cartella temporanea: NESSUN server, nessuna
 * porta, nessuna rete. Le chiamate della UI arrivano a Java attraverso {@link MsBridge#request}
 * e sono instradate su {@link OpenApi} verso il motore di scansione locale.
 */
public final class WebUi extends Application {

    /** Risorse della UI incluse nel jar (elenco fisso: sono tutte e sole quelle referenziate). */
    private static final String[] UI_RESOURCES = {
            "index.html",
            "css/style.css",
            "js/core.js",
            "js/report.js",
            "js/jar.js",
            "js/mods.js",
            "js/save-file.js"
    };

    private WebEngine webEngine;
    private Path uiDir;
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "modscan-api");
        t.setDaemon(true);
        return t;
    });

    @Override
    public void start(Stage stage) {
        try {
            stage.setTitle("ModScanOpen");
            uiDir = extractUi();
            WebView webView = new WebView();
            webView.setContextMenuEnabled(false);
            webEngine = webView.getEngine();
            webEngine.setJavaScriptEnabled(true);
            webEngine.setUserAgent(webEngine.getUserAgent() + " ModScanOpenDesktop");
            webEngine.setOnAlert(e -> System.out.println("[JS] " + e.getData()));
            webEngine.setOnError(e -> System.err.println("[WebView] " + e.getMessage()));
            OpenApi api = new OpenApi();
            MsBridge bridge = new MsBridge(stage, webEngine, api, pool);

            webEngine.getLoadWorker().stateProperty().addListener((obs, old, state) -> {
                if (state == Worker.State.SUCCEEDED) {
                    Platform.runLater(() -> {
                        try {
                            JSObject win = (JSObject) webEngine.executeScript("window");
                            win.setMember("javafxBridge", bridge);
                        } catch (Exception ex) {
                            System.err.println("Registrazione del bridge fallita: " + ex.getMessage());
                        }
                    });
                } else if (state == Worker.State.FAILED) {
                    System.err.println("Caricamento dell'interfaccia fallito: " + webEngine.getLoadWorker().getException());
                }
            });
            webEngine.load(uiDir.resolve("index.html").toUri().toString());

            webView.setOnDragOver(event -> {
                if (event.getDragboard().hasFiles()) {
                    event.acceptTransferModes(javafx.scene.input.TransferMode.COPY_OR_MOVE);
                }
                event.consume();
            });
            webView.setOnDragDropped(event -> {
                javafx.scene.input.Dragboard db = event.getDragboard();
                boolean ok = false;
                if (db.hasFiles()) {
                    DragValidator.Result r = DragValidator.check(db.getFiles());
                    if (r.ok()) {
                        String path = r.path();
                        Platform.runLater(() -> callJs("handleLocalFileSelection", path));
                        ok = true;
                    } else {
                        String msg = r.error();
                        Platform.runLater(() -> callJs("handleLocalFileError", msg));
                    }
                }
                event.setDropCompleted(ok);
                event.consume();
            });

            Scene scene = new Scene(new BorderPane(webView), 1280, 820);
            stage.setMinWidth(980);
            stage.setMinHeight(640);
            stage.setScene(scene);
            stage.show();
        } catch (Exception e) {
            System.err.println("Errore fatale nell'avvio dell'interfaccia: " + e);
            Alert a = new Alert(Alert.AlertType.ERROR, "Impossibile avviare ModScanOpen:\n" + (e.getMessage() == null ? e.toString() : e.getMessage()));
            a.showAndWait();
            Platform.exit();
        }
    }

    private void callJs(String function, String arg) {
        try {
            webEngine.executeScript("if(window." + function + "){window." + function + "(" + js(arg) + ");}");
        } catch (Exception ex) {
            System.err.println("Chiamata JS " + function + " fallita: " + ex.getMessage());
        }
    }

    @Override
    public void stop() {
        pool.shutdownNow();
        if (uiDir != null) {
            deleteQuietly(uiDir);
        }
        Platform.exit();
    }

    /* ---------- estrazione delle risorse UI ---------- */

    private static Path extractUi() throws IOException {
        Path dir = Files.createTempDirectory("modscan-open-ui-");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> deleteQuietly(dir), "modscan-ui-cleanup"));
        int copied = 0;
        for (String res : UI_RESOURCES) {
            try (InputStream in = WebUi.class.getResourceAsStream("/ui/" + res)) {
                if (in == null) {
                    throw new IOException("Risorsa UI mancante nel pacchetto: ui/" + res);
                }
                Path target = dir.resolve(res).normalize();
                if (!target.startsWith(dir)) {
                    continue;
                }
                Files.createDirectories(target.getParent());
                Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
                copied++;
            }
        }
        if (copied < UI_RESOURCES.length || !Files.isRegularFile(dir.resolve("index.html"))) {
            throw new IOException("Risorse dell'interfaccia incomplete in ui/.");
        }
        return dir;
    }

    private static void deleteQuietly(Path dir) {
        try (Stream<Path> s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException ignored) {
            // cartella temporanea: se resta qualcosa lo ripulisce il sistema
        }
    }

    /** Letterale stringa JavaScript sicuro (gestisce apici, backslash, a capo e U+2028/2029). */
    static String js(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < value.length(); ++i) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '<': sb.append("\\u003c"); break;
                default:
                    if (c == 0x2028 || c == 0x2029) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }

    /** Oggetto esposto alla pagina come window.javafxBridge. Deve restare pubblico per la reflection di JavaFX. */
    public static class MsBridge {
        private final Stage stage;
        private final WebEngine webEngine;
        private final OpenApi api;
        private final ExecutorService pool;

        MsBridge(Stage stage, WebEngine webEngine, OpenApi api, ExecutorService pool) {
            this.stage = stage;
            this.webEngine = webEngine;
            this.api = api;
            this.pool = pool;
        }

        /**
         * Chiamata API dalla UI (sostituisce fetch verso un server). La risposta torna in modo
         * asincrono con window.__javaResponse(id, status, bodyJson).
         */
        public void request(String id, String method, String url, String body, String pin) {
            pool.submit(() -> {
                OpenApi.Response r = api.handle(method, url, body);
                Platform.runLater(() -> {
                    try {
                        ((JSObject) webEngine.executeScript("window")).call("__javaResponse", id, r.status, r.body);
                    } catch (Exception ex) {
                        System.err.println("Consegna della risposta " + id + " fallita: " + ex.getMessage());
                    }
                });
            });
        }

        public void chooseFile() {
            Platform.runLater(() -> {
                FileChooser fc = new FileChooser();
                fc.setTitle("Seleziona il file JAR da analizzare");
                fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("File JAR (*.jar)", "*.jar"));
                File f = fc.showOpenDialog((Window) stage);
                if (f != null) {
                    notifyJs("handleLocalFileSelection", f.getAbsolutePath().replace("\\", "/"));
                }
            });
        }

        public void chooseFolder() {
            chooseFolderAt(null);
        }

        /** Selettore cartella che parte da una cartella indicata (es. quella trovata dal processo javaw). */
        public void chooseFolderAt(String initialPath) {
            Platform.runLater(() -> {
                DirectoryChooser dc = new DirectoryChooser();
                dc.setTitle("Seleziona la cartella mods da analizzare");
                File initial = null;
                if (initialPath != null && !initialPath.isBlank()) {
                    File f = new File(initialPath);
                    while (f != null && !f.isDirectory()) {
                        f = f.getParentFile();
                    }
                    initial = f;
                }
                if (initial == null) {
                    String appData = System.getenv("APPDATA");
                    File def = appData != null ? new File(appData, ".minecraft/mods") : new File(System.getProperty("user.home"), "AppData/Roaming/.minecraft/mods");
                    initial = def.isDirectory() ? def : new File(System.getProperty("user.home"));
                }
                if (initial.isDirectory()) {
                    dc.setInitialDirectory(initial);
                }
                File sel = dc.showDialog((Window) stage);
                if (sel != null) {
                    notifyJs("handleModsFolderSelection", sel.getAbsolutePath().replace("\\", "/"));
                }
            });
        }

        public void saveFile(String content, String suggestedName) {
            Platform.runLater(() -> {
                boolean ok = false;
                String saved = null;
                try {
                    FileChooser fc = new FileChooser();
                    fc.setTitle("Salva file");
                    if (suggestedName != null && !suggestedName.isBlank()) {
                        fc.setInitialFileName(suggestedName);
                    }
                    File target = fc.showSaveDialog((Window) stage);
                    if (target != null) {
                        Files.writeString(target.toPath(), content == null ? "" : content, StandardCharsets.UTF_8);
                        saved = target.getAbsolutePath().replace("\\", "/");
                        ok = true;
                    }
                } catch (Exception ex) {
                    System.err.println("Salvataggio fallito: " + ex.getMessage());
                }
                try {
                    webEngine.executeScript("if(window.handleNativeSaveResult){window.handleNativeSaveResult(" + ok + "," + js(saved) + ");}");
                } catch (Exception ex) {
                    System.err.println("Notifica del salvataggio fallita: " + ex.getMessage());
                }
            });
        }

        /** Apre la pagina delle issue GitHub nel browser di sistema (la WebView non naviga mai fuori). */
        public void openIssues() {
            String url = "https://github.com/gaemo12/ModAnalyzer/issues/new";
            try {
                java.awt.Desktop d = java.awt.Desktop.getDesktop();
                if (d.isSupported(java.awt.Desktop.Action.BROWSE)) {
                    d.browse(new java.net.URI(url));
                    return;
                }
            } catch (Exception ex) {
                System.err.println("Apertura issue fallita: " + ex.getMessage());
            }
            notifyJs("handleBugFallback", url);
        }

        private void notifyJs(String fn, String arg) {
            try {
                webEngine.executeScript("if(window." + fn + "){window." + fn + "(" + js(arg) + ");}");
            } catch (Exception ex) {
                System.err.println("Chiamata JS " + fn + " fallita: " + ex.getMessage());
            }
        }
    }
}
