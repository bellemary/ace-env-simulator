package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;

public final class VendorRootPropertiesCheck extends BaseCheck {
    public VendorRootPropertiesCheck() { super("persona.vendor.root", "设备画像", "厂商 Root 启动属性"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String boot = CheckSupport.getProp("ro.boot.bootisroot");
        String device = CheckSupport.getProp("ro.boot.deviceisroot");
        String evidence = "ro.boot.bootisroot=" + value(boot) + "\nro.boot.deviceisroot=" + value(device);
        if ("1".equals(boot) || "1".equals(device) || "true".equalsIgnoreCase(boot) || "true".equalsIgnoreCase(device))
            return risk(start, "厂商启动属性明确标记 Root", evidence,
                    "bootisroot/deviceisroot 任一为 1 或 true", 98);
        if (boot.isEmpty() && device.isEmpty()) return suspicious(start, "两个厂商 Root 属性均不可读", evidence,
                "缺少画像输入，按风险继续排查", 88);
        return pass(start, "厂商启动属性未标记 Root", evidence,
                "所有可读 bootisroot/deviceisroot 均不是 1/true", 94);
    }
    private String value(String value) { return value.isEmpty() ? "<empty>" : value; }
}
