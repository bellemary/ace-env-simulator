package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;

public final class BootloaderCheck extends BaseCheck {
    public BootloaderCheck() { super("bootloader.lock", "启动可信度", "Bootloader 锁状态"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String flash = CheckSupport.getProp("ro.boot.flash.locked");
        String vbmeta = CheckSupport.getProp("ro.boot.vbmeta.device_state");
        String evidence = "ro.boot.flash.locked=" + blank(flash) + "\nro.boot.vbmeta.device_state=" + blank(vbmeta);
        if ("0".equals(flash) || "unlocked".equalsIgnoreCase(vbmeta)) return risk(start, "设备启动锁已解锁", evidence,
                "flash.locked==0 或 vbmeta.device_state==unlocked", 98);
        if (flash.isEmpty() || vbmeta.isEmpty()) return suspicious(start, "启动锁输入不完整", evidence,
                "画像 VM 的缺省值和矛盾优先级尚未闭合，未决按风险展示", 85);
        return pass(start, "设备启动锁属性为锁定", evidence, "flash.locked!=0 且 vbmeta.device_state!=unlocked", 96);
    }
    private String blank(String value) { return value.isEmpty() ? "<empty>" : value; }
}
