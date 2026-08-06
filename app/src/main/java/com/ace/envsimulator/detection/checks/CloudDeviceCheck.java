package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;
import java.util.Locale;

public final class CloudDeviceCheck extends BaseCheck {
    public CloudDeviceCheck() { super("cloud.device", "设备画像", "云机与云游戏平台"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String[] keys = {"ro.vendor.platform", "init.svc.cloudAppEngine", "ro.boottime.cloudAppEngine",
                "ro.com.cph.cloud_app_engine", "init.svc_debug_pid.cloudAppEngine", "ro.cloud.gaming",
                "storage.cloud.mode", "ro.hardware.fps.cph", "ro.build.characteristics"};
        StringBuilder evidence = new StringBuilder();
        boolean confirmed = false;
        boolean candidate = false;
        for (String key : keys) {
            String value = CheckSupport.getProp(key);
            evidence.append(key).append('=').append(value.isEmpty() ? "<empty>" : value).append('\n');
            String lower = value.toLowerCase(Locale.US);
            if (key.equals("ro.vendor.platform") &&
                    (lower.equals("cloudmatrix1") || lower.equals("cloudmatrix2") || lower.equals("cloudmatrix3"))) confirmed = true;
            if (lower.contains("cloudmatrix") || lower.contains("cloudappengine") || lower.contains("cloudphone") ||
                    (!value.isEmpty() && key.contains("cloudAppEngine")) || "1".equals(value) && key.contains("cloud")) candidate = true;
        }
        if (confirmed) return risk(start, "命中已闭合的 CloudMatrix 平台值", evidence.toString(),
                "ro.vendor.platform == cloudmatrix1/2/3", 99);
        if (candidate) return suspicious(start, "发现云机属性候选，值谓词与交叉条件尚未闭合", evidence.toString(),
                "cloudAppEngine/cloud gaming 属性族仅确认了输入，非空本身不作为风险结论", 99);
        return pass(start, "未命中已恢复的云机属性", evidence.toString(), "逐项读取已证实的云机属性输入", 90);
    }
}
