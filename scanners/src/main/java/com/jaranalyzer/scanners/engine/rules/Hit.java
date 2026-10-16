package com.jaranalyzer.scanners.engine.rules;

/**
 * Occorrenza di una regola: il campione è già redatto
 * ({@link RuleEngine#redact(String)}), mai il segreto in chiaro.
 */
public record Hit(Rule rule, String where, String sample) {
}
