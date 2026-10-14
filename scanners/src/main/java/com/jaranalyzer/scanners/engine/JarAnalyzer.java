/*
 * Decompiled with CFR 0.152.
 */
package com.jaranalyzer.scanners.engine;

import com.jaranalyzer.scanners.Finding;
import java.io.File;
import java.util.List;

public interface JarAnalyzer {
    public List<Finding> analyze(File var1) throws Exception;

    public String getName();
}
