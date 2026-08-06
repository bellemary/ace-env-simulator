package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;

public final class AdbEnvironmentCheck extends BaseCheck {
    public AdbEnvironmentCheck() { super("adb.environment", "开发环境", "ADB 与 adbd 状态"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        int adb = CheckSupport.globalSetting(context, "adb_enabled");
        String service = CheckSupport.getProp("init.svc.adbd");
        String tcp = CheckSupport.getProp("service.adb.tcp.port");
        String evidence = "adb_enabled=" + adb + "\ninit.svc.adbd=" + value(service) + "\nservice.adb.tcp.port=" + value(tcp);
        boolean active = adb == 1 || "running".equals(service) || (!tcp.isEmpty() && !"-1".equals(tcp) && !"0".equals(tcp));
        if (active) return risk(start, "ADB 环境处于活动状态", evidence,
                "任一已恢复 ADB 输入活动即命中该独立环境信号；综合处罚权重另行汇总", 96);
        if (adb < 0 && service.isEmpty()) return suspicious(start, "ADB 状态输入不完整", evidence,
                "未知值按风险展示", 75);
        return pass(start, "未观察到活动的 ADB 环境", evidence, "ADB/adbd 输入均未命中", 90);
    }
    private String value(String v) { return v.isEmpty() ? "<empty>" : v; }
}
