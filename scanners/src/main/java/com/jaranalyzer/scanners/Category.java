/*
 * Decompiled with CFR 0.152.
 */
package com.jaranalyzer.scanners;

public enum Category {
    MALWARE_SIGNATURE("Malware Signature", "virus"),
    SUSPICIOUS_API("Suspicious API", "api"),
    NETWORK("Network", "network"),
    FILE_ACCESS("File Access", "folder"),
    OBFUSCATION("Obfuscation", "shuffle"),
    STRUCTURE("Structure", "sitemap"),
    MANIFEST("Manifest", "file-text"),
    ENTROPY("Entropy", "chart-bar"),
    MALWARE_BEHAVIOR("Malware Behavior", "alert-triangle"),
    CODE_INJECTION("Code Injection", "code"),
    CRYPTO("Crypto", "lock"),
    EXECUTION("Execution", "terminal"),
    CERTIFICATE("Certificate", "shield"),
    VIRUSTOTAL("VirusTotal", "scan"),
    CHEAT("Cheat", "gamepad"),
    PROCESS("Process", "cpu"),
    MEMORY("Memory", "database"),
    SYSTEM("System", "monitor");

    private final String displayName;
    private final String iconName;

    private Category(String displayName, String iconName) {
        this.displayName = displayName;
        this.iconName = iconName;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    public String getIconName() {
        return this.iconName;
    }
}
