package com.ace.envsimulator.detection.checks;

import android.content.Context;
import android.os.Build;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;

public final class BootHistoryCheck extends BaseCheck {
    public BootHistoryCheck() { super("persona.boot.history", "设备画像", "内核、构建时间与启动原因"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String evidence = "ro.build.type=" + CheckSupport.getProp("ro.build.type") +
                "\nro.build.date.utc=" + CheckSupport.getProp("ro.build.date.utc") +
                "\nro.bootimage.build.date.utc=" + CheckSupport.getProp("ro.bootimage.build.date.utc") +
                "\nro.boot.bootreason=" + CheckSupport.getProp("ro.boot.bootreason") +
                "\nro.boot.boot_devices=" + CheckSupport.getProp("ro.boot.boot_devices") +
                "\n/proc/version=" + CheckSupport.readText("/proc/version", 4096).trim() +
                "\nBuild.TIME=" + Build.TIME;
        return suspicious(start, "启动历史输入已采集，交叉谓词与事件码未闭合", evidence,
                "画像 VM 已确认采集这些输入；不以单个值伪造综合结论", 90);
    }
}
