package com.jaranalyzer.scanners;

import com.jaranalyzer.common.Progress;
import java.util.List;

/**
 * Avanzamento e cancellazione. Lo scanner non conosce la UI: riporta fasi e
 * percentuali e controlla regolarmente {@link #isCancelled()}.
 * Il throttling visivo (~10/s) spetta al chiamante, non allo scanner.
 */
public interface ProgressSink {
    /** Fase in corso (percentuale 0..100). Non deve lanciare eccezioni. */
    void report(String module, String phase, int percent);

    /** Vero se l'operazione è stata annullata: lo scanner si ferma appena possibile. */
    boolean isCancelled();

    /** Sink che ignora tutto e non cancella mai (default per uso programmatico). */
    static ProgressSink noop() {
        return new ProgressSink() {
            @Override
            public void report(String module, String phase, int percent) {
            }

            @Override
            public boolean isCancelled() {
                return false;
            }
        };
    }

    /** Sink di test: registra gli eventi come {@code common.Progress}. */
    final class Recording implements ProgressSink {
        private final java.util.List<Progress> events = new java.util.ArrayList<>();
        private volatile boolean cancelled;

        @Override
        public synchronized void report(String module, String phase, int percent) {
            events.add(new Progress(module, phase, percent, null));
        }

        @Override
        public boolean isCancelled() {
            return cancelled;
        }

        public void cancel() {
            cancelled = true;
        }

        public synchronized List<Progress> events() {
            return List.copyOf(events);
        }
    }
}
