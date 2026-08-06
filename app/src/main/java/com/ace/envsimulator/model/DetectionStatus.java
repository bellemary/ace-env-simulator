package com.ace.envsimulator.model;

public enum DetectionStatus {
    PASS("通过"), SUSPICIOUS("可疑"), RISK("风险");

    public final String label;

    DetectionStatus(String label) {
        this.label = label;
    }
}
