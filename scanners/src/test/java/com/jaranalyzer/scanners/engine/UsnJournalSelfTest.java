package com.jaranalyzer.scanners.engine;

import java.util.List;

/**
 * Self-test del parser USN (stile progetto, zero dipendenze). Riproduce
 * l'output reale di {@code fsutil usn readjournal}, dove "File name" è
 * seguito da "File name length": prima della v1.3.2 la lunghezza sovrascriveva
 * il nome e nessun evento veniva trattenuto.
 */
public class UsnJournalSelfTest {
  static int fails = 0;

  static void check(String n, boolean ok) {
    System.out.println((ok ? "OK   " : "FAIL ") + n);
    if (!ok) fails++;
  }

  static final List<String> SAMPLE = List.of(
      "Usn               : 0x0000000001234567",
      "File name         : ghost.jar",
      "File name length  : 9",
      "Reason            : 0x80000200 (FILE_CREATE)",
      "Time stamp        : 2026-10-16 22:46:03.1234567",
      "",
      "Usn               : 0x0000000001234568",
      "File name         : sodium.jar",
      "File name length  : 10",
      "Reason            : 0x80000100 (Rename: Old Name)",
      "Time stamp        : 2026-10-16 22:47:00.0000000",
      "");

  public static void main(String[] a) {
    UsnJournal.Read all = UsnJournal.parseEvents(SAMPLE, f -> f.endsWith(".jar"), 10);
    check("due record letti", all.events().size() == 2);
    check("File name length non sovrascrive il nome",
        all.events().get(0).file().equals("ghost.jar"));
    check("USN esadecimale interpretato",
        all.events().get(0).usn() == 0x0000000001234567L);
    check("motivo conservato",
        all.events().get(0).reason().contains("FILE_CREATE"));
    check("timestamp interpretato", all.events().get(0).timeMillis() > 0);
    check("secondo record con rename",
        all.events().get(1).reason().contains("Rename: Old Name"));
    check("nessun troncamento con tetto ampio", !all.truncated());

    UsnJournal.Read filtered = UsnJournal.parseEvents(SAMPLE, f -> f.equals("ghost.jar"), 10);
    check("filtro sul nome applicato", filtered.events().size() == 1
        && filtered.events().get(0).file().equals("ghost.jar"));

    UsnJournal.Read capped = UsnJournal.parseEvents(SAMPLE, f -> f.endsWith(".jar"), 1);
    check("tetto eventi rispettato", capped.events().size() == 1 && capped.truncated());

    UsnJournal.Read none = UsnJournal.parseEvents(SAMPLE, f -> f.endsWith(".txt"), 10);
    check("nessun falso positivo su estensione diversa", none.events().isEmpty());

    check("parseTime accetta il formato fsutil", UsnJournal.parseTime("2026-10-16 22:46:03.1234567") > 0);
    check("parseLong accetta 0x", UsnJournal.parseLong("0x10") == 16L);

    System.out.println(fails == 0 ? "USN-JOURNAL-SELFTEST PASS" : "USN-JOURNAL-SELFTEST FAIL(" + fails + ")");
    if (fails != 0) System.exit(1);
  }
}
