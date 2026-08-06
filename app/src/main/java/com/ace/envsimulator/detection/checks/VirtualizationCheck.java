package com.ace.envsimulator.detection.checks;

import android.content.Context;
import android.os.Build;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class VirtualizationCheck extends BaseCheck {
    public VirtualizationCheck() { super("virtualization.dex", "虚拟化", "Java VM 位掩码与 Build 特征"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String[] paths = {"/sys/class/misc/vhost", "/sys/class/misc/qemu", "/system/lib/vbox",
                "/system/lib/ko", "/system/bin/qemud", "/system/bin/qemu-props", "/sys/bus/virtio",
                "/sys/class/misc/vbox"};
        List<String> confirmedHits = new ArrayList<>();
        List<String> candidates = new ArrayList<>();
        for (String path : paths) if (new File(path).exists()) confirmedHits.add(path);
        String[] procFiles = {"/proc/iomem", "/proc/ioports", "/proc/misc", "/proc/kallsyms"};
        String[] procMarkers = {"qemu-pipe", "goldfish", "vbox", "virtio", "qemu", "kvm"};
        for (String proc : procFiles) {
            String content = CheckSupport.readText(proc, 2_000_000).toLowerCase(Locale.US);
            for (String marker : procMarkers) if (content.contains(marker)) candidates.add(proc + ":" + marker);
        }
        String build = (Build.FINGERPRINT + " " + Build.MODEL + " " + Build.MANUFACTURER + " " +
                Build.BRAND + " " + Build.DEVICE + " " + Build.PRODUCT).toLowerCase(Locale.US);
        String[] markers = {"generic", "goldfish", "genymotion", "vbox", "nox", "android_x86", "emulator", "netease"};
        for (String marker : markers) if (build.contains(marker)) candidates.add("Build:" + marker);
        if (!confirmedHits.isEmpty()) return risk(start, "命中已恢复的虚拟化文件节点", String.join("\n", confirmedHits) +
                        (candidates.isEmpty() ? "" : "\n候选输入（不参与风险判定）：\n" + String.join("\n", candidates)),
                "DEX 虚拟化文件节点检查；proc 与 Build 组合谓词单独保持未决", 96);
        if (!candidates.isEmpty()) return suspicious(start, "发现虚拟化候选输入，精确组合谓词尚未闭合", String.join("\n", candidates),
                "GetVmInfo 只确认 11 个特定 file+marker 组合，禁止扩展为笛卡尔积", 99);
        return pass(start, "Java 虚拟化信号未命中", "Build=" + build + "\n已检查 8 个文件节点和 4 组 proc 输入",
                "DEX 侧独立虚拟化输入", 90);
    }
}
