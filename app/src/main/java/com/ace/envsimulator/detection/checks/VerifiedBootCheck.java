package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;

public final class VerifiedBootCheck extends BaseCheck {
    public VerifiedBootCheck() { super("verified.boot", "启动可信度", "Verified Boot 状态"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String state = CheckSupport.getProp("ro.boot.verifiedbootstate");
        String verity = CheckSupport.getProp("ro.boot.veritymode");
        String evidence = "ro.boot.verifiedbootstate=" + value(state) + "\nro.boot.veritymode=" + value(verity);
        if (!state.isEmpty() && !"green".equalsIgnoreCase(state)) return risk(start, "Verified Boot 不是 green", evidence,
                "已恢复的原生分支将非 green 作为异常信号", 96);
        if (state.isEmpty()) return suspicious(start, "Verified Boot 属性缺失", evidence,
                "设备画像的未知值处理尚未闭合", 82);
        return pass(start, "Verified Boot 为 green", evidence, "ro.boot.verifiedbootstate==green", 96);
    }
    private String value(String v) { return v.isEmpty() ? "<empty>" : v; }
}
