package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.DetectionCheck;
import com.ace.envsimulator.model.DetectionResult;

abstract class BaseCheck implements DetectionCheck {
    private final String id;
    private final String title;
    final String category;

    BaseCheck(String id, String category, String title) {
        this.id = id; this.category = category; this.title = title;
    }

    @Override public String id() { return id; }
    @Override public String title() { return title; }

    final DetectionResult pass(long start, String summary, String evidence, String rule, int confidence) {
        return DetectionResult.pass(id, category, title, summary, evidence, rule, confidence, elapsed(start));
    }
    final DetectionResult suspicious(long start, String summary, String evidence, String rule, int confidence) {
        return DetectionResult.suspicious(id, category, title, summary, evidence, rule, confidence, elapsed(start));
    }
    final DetectionResult risk(long start, String summary, String evidence, String rule, int confidence) {
        return DetectionResult.risk(id, category, title, summary, evidence, rule, confidence, elapsed(start));
    }
    private long elapsed(long start) { return (System.nanoTime() - start) / 1_000_000L; }
}
