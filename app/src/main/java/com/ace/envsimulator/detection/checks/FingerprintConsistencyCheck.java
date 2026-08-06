package com.ace.envsimulator.detection.checks;

import android.content.Context;
import android.os.Build;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public final class FingerprintConsistencyCheck extends BaseCheck {
    public FingerprintConsistencyCheck() { super("fingerprint.consistency", "设备画像", "系统指纹输入观察"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        Map<String, String> values = new LinkedHashMap<>();
        values.put("ro.build.fingerprint", CheckSupport.getProp("ro.build.fingerprint"));
        values.put("ro.system.build.fingerprint", CheckSupport.getProp("ro.system.build.fingerprint"));
        values.put("ro.vendor.build.fingerprint", CheckSupport.getProp("ro.vendor.build.fingerprint"));
        values.put("ro.odm.build.fingerprint", CheckSupport.getProp("ro.odm.build.fingerprint"));
        values.put("ro.bootimage.build.fingerprint", CheckSupport.getProp("ro.bootimage.build.fingerprint"));
        int missing = 0;
        boolean generic = false;
        StringBuilder evidence = new StringBuilder();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            String value = entry.getValue();
            if (value.isEmpty()) missing++;
            String lower = value.toLowerCase(Locale.US);
            if (lower.contains("generic") || lower.contains("unknown") || lower.contains("test-keys")) generic = true;
            evidence.append(entry.getKey()).append('=').append(value.isEmpty() ? "<empty>" : value).append('\n');
        }
        evidence.append("Build.FINGERPRINT=").append(Build.FINGERPRINT);
        if (generic) return risk(start, "指纹包含通用、未知或测试构建特征", evidence.toString(),
                "多分区 fingerprint 输入已证实；精确交叉谓词尚未闭合", 88);
        if (missing >= 3) return suspicious(start, "多个分区指纹缺失", evidence.toString(),
                "缺省值与服务端阈值未知，按风险展示", 82);
        return suspicious(start, "未发现明显异常关键字，交叉一致性谓词仍未恢复", evidence.toString(),
                "仅给出已证实输入的可观察结论，不冒充未恢复的 VM 综合谓词", 80);
    }
}
