package com.jaranalyzer.scanners;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Contesto di esecuzione tipizzato: l'unico input di un {@link ScanModule}.
 * Gli scanner non leggono variabili d'ambiente, configurazioni globali o
 * percorsi impliciti: l'host (Staff/Player) risolve tutto e lo passa qui.
 */
public interface ScanContext {

    /** Contesto per {@code single_jar}: percorso locale esplicito del file. */
    final class JarFileContext implements ScanContext {
        private final Path jar;

        public JarFileContext(Path jar) {
            this.jar = Objects.requireNonNull(jar, "jar");
        }

        public Path jar() {
            return jar;
        }
    }

    /** Contesto per {@code mods_folder}: cartella autorizzata da analizzare. */
    final class DirectoryContext implements ScanContext {
        private final Path directory;

        public DirectoryContext(Path directory) {
            this.directory = Objects.requireNonNull(directory, "directory");
        }

        public Path directory() {
            return directory;
        }
    }

    /**
     * Contesto per {@code processes}, {@code javaw}, {@code minecraft_accounts}:
     * scansioni della macchina locale. Le basi da cui partire sono esplicite
     * (l'host le ricava dall'ambiente); gli scanner non chiamano
     * {@code System.getenv} e non toccano il backend.
     */
    final class HostContext implements ScanContext {
        private final Path appData;
        private final Path userProfile;
        private final Path home;
        private final Path systemRoot;

        public HostContext(Path appData, Path userProfile, Path home) {
            this(appData, userProfile, home, null);
        }

        /** Variante completa: base di Windows (es. C:\Windows) per hosts e sistema. */
        public HostContext(Path appData, Path userProfile, Path home, Path systemRoot) {
            this.appData = appData;
            this.userProfile = userProfile;
            this.home = home;
            this.systemRoot = systemRoot;
        }

        public Path systemRoot() {
            return systemRoot;
        }

        /** Es. %APPDATA% su Windows; null se non disponibile. */
        public Path appData() {
            return appData;
        }

        /** Es. %USERPROFILE% su Windows; null se non disponibile. */
        public Path userProfile() {
            return userProfile;
        }

        /** Home utente; null se non disponibile. */
        public Path home() {
            return home;
        }
    }
}
