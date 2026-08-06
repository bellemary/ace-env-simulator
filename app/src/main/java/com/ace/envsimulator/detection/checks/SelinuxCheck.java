package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;

public final class SelinuxCheck extends BaseCheck {
    public SelinuxCheck() { super("selinux", "系统策略", "SELinux 强制状态"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String enforce = CheckSupport.readText("/sys/fs/selinux/enforce", 32).trim();
        String command = CheckSupport.command(1200, "getenforce").stdout.trim();
        String evidence = "/sys/fs/selinux/enforce=" + value(enforce) + "\ngetenforce=" + value(command);
        if ("0".equals(enforce) || "Permissive".equalsIgnoreCase(command) || "Disabled".equalsIgnoreCase(command))
            return risk(start, "SELinux 未处于 Enforcing", evidence, "enforce==0、Permissive 或 Disabled", 98);
        if ("1".equals(enforce) || "Enforcing".equalsIgnoreCase(command))
            return pass(start, "SELinux 处于 Enforcing", evidence, "enforce==1 或 getenforce==Enforcing", 98);
        return suspicious(start, "SELinux 状态不可确定", evidence, "未知值单独展示", 75);
    }
    private String value(String v) { return v.isEmpty() ? "<empty>" : v; }
}
