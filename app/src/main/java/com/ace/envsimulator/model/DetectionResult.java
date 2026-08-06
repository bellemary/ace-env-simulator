package com.ace.envsimulator.model;

public final class DetectionResult {
    public final String id;
    public final String category;
    public final String title;
    public final DetectionStatus status;
    public final String summary;
    public final String evidence;
    public final String rule;
    public final int confidence;
    public final long durationMs;
    public final boolean riskSignal;

    public DetectionResult(String id, String category, String title, DetectionStatus status,
                           String summary, String evidence, String rule, int confidence,
                           long durationMs, boolean riskSignal) {
        this.id = id;
        this.category = category;
        this.title = title;
        this.status = status;
        this.summary = nonBlank(summary, "该项没有返回摘要，按未决风险处理");
        this.evidence = nonBlank(evidence, "该项没有返回原始反馈，按未决风险处理");
        this.rule = nonBlank(rule, "该项判定标准尚未恢复，按未决风险处理");
        this.confidence = confidence;
        this.durationMs = durationMs;
        this.riskSignal = riskSignal;
    }

    public static DetectionResult pass(String id, String category, String title, String summary,
                                       String evidence, String rule, int confidence, long durationMs) {
        return new DetectionResult(id, category, title, DetectionStatus.PASS, summary, evidence,
                rule, confidence, durationMs, false);
    }

    public static DetectionResult suspicious(String id, String category, String title, String summary,
                                             String evidence, String rule, int confidence, long durationMs) {
        return new DetectionResult(id, category, title, DetectionStatus.SUSPICIOUS, summary, evidence,
                rule, confidence, durationMs, true);
    }

    public static DetectionResult risk(String id, String category, String title, String summary,
                                       String evidence, String rule, int confidence, long durationMs) {
        return new DetectionResult(id, category, title, DetectionStatus.RISK, summary, evidence,
                rule, confidence, durationMs, true);
    }

    public static DetectionResult ledger(String id, String category, String title, DetectionStatus status,
                                         String summary, String evidence, String rule, int confidence,
                                         long durationMs) {
        return new DetectionResult(id, category, title, status, summary, evidence, rule,
                confidence, durationMs, false);
    }

    private static String nonBlank(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value;
    }
}
