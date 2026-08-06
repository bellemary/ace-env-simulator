package com.ace.envsimulator.detection.checks;

import android.content.Context;

import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.detection.DetectionCheck;
import com.ace.envsimulator.detection.NativeProbe;
import com.ace.envsimulator.model.DetectionResult;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public final class RootProbeChecks {
    private static final String CATEGORY = "ACE Root 客户端环境槽";

    private RootProbeChecks() {}

    public static List<DetectionCheck> create() {
        List<DetectionCheck> checks = new ArrayList<>();
        checks.add(simple(0, "PATH 中的 su", RootProbeChecks::pathSu));
        checks.add(simple(1, "固定目录中的 su", RootProbeChecks::fixedSu));
        checks.add(simple(2, "Root 管理器与制品", RootProbeChecks::rootArtifacts));
        checks.add(simple(3, "动态扩展 Root 路径", RootProbeChecks::dynamicRootPaths));
        checks.add(simple(5, "ro.debuggable 属性", RootProbeChecks::debuggable));
        checks.add(simple(10, "Zygisk 加载器制品", RootProbeChecks::zygiskFiles));
        checks.add(simple(12, "APatch 内核页驻留探针", c -> nativeResult(12, "ap_ker")));
        checks.add(simple(13, "KernelSU 魔数页驻留探针", c -> nativeResult(13, "ksu_mtp")));
        return checks;
    }

    private interface ProbeBody { ProbeValue run(Context context) throws Exception; }

    private static DetectionCheck simple(int slot, String title, ProbeBody body) {
        return new DetectionCheck() {
            @Override public String id() { return "root.slot." + slot; }
            @Override public String title() { return "槽 " + slot + " · " + title; }

            @Override public DetectionResult run(Context context) throws Exception {
                long start = System.nanoTime();
                ProbeValue value = body.run(context);
                boolean runtimeGateUnknown = slot == 10 || slot == 12 || slot == 13;
                if (runtimeGateUnknown && value.state == State.SAFE) {
                    value = unknown("本地探针未命中，但目标运行时配置门状态未知",
                            value.evidence + "\n对应配置门未从目标 comm.dat 的实际值中闭合，不能据此声明 ACE 已判定通过。", 99);
                }
                long elapsed = (System.nanoTime() - start) / 1_000_000L;
                String rule = "libtersafe SHA-256 dc924a69…c50d3a / ACE_RunRootDetectorChain 槽 " + slot;
                if (value.state == State.HIT) {
                    return DetectionResult.risk(id(), CATEGORY, title(), value.summary, value.evidence, rule, value.confidence, elapsed);
                }
                if (value.state == State.UNKNOWN) {
                    return DetectionResult.suspicious(id(), CATEGORY, title(), value.summary, value.evidence, rule, value.confidence, elapsed);
                }
                return DetectionResult.pass(id(), CATEGORY, title(), value.summary, value.evidence, rule, value.confidence, elapsed);
            }
        };
    }

    private static ProbeValue pathSu(Context context) {
        String path = System.getenv("PATH");
        if (path == null || path.isEmpty()) return unknown("PATH 不可读", "ACE 对 PATH 按冒号逐项扫描；本次没有取得值", 70);
        List<String> hits = new ArrayList<>();
        for (String dir : path.split(":")) {
            File target = new File(dir, "su");
            if (exists(target.getAbsolutePath())) hits.add(target.getAbsolutePath());
        }
        return hits.isEmpty() ? safe("PATH 中没有可见的 su", "PATH=" + path, 98)
                : hit("PATH 中发现 su", String.join("\n", hits), 99);
    }

    private static ProbeValue fixedSu(Context context) {
        String[] dirs = {"/data/local", "/data/local/bin", "/data/local/xbin", "/sbin", "/su/bin",
                "/system/bin", "/system/bin/.ext", "/system/bin/failsafe", "/system/sd/xbin",
                "/system/usr/we-need-root", "/system/xbin", "/cache", "/data", "/dev"};
        List<String> hits = new ArrayList<>();
        for (String dir : dirs) {
            File target = new File(dir, "su");
            if (exists(target.getAbsolutePath())) hits.add(target.getAbsolutePath());
        }
        return hits.isEmpty() ? safe("14 个固定目录均未发现可见 su", "已逐项检查：" + String.join(", ", dirs), 98)
                : hit("固定目录发现 su", String.join("\n", hits), 99);
    }

    private static ProbeValue rootArtifacts(Context context) {
        String[] paths = {"/data/data/com.topjohnwu.magisk", "/data/adb/magisk", "/data/adb/modules",
                "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ap", "/data/adb/apd",
                "/data/data/com.noshufou.android.su", "/data/data/com.noshufou.android.su.elite",
                "/data/data/eu.chainfire.supersu", "/data/data/com.koushikdutta.superuser",
                "/data/data/com.thirdparty.superuser", "/data/data/com.yellowes.su",
                "/data/data/com.kingroot.kinguser", "/data/data/com.kingo.root",
                "/data/data/com.smedialink.oneclickroot", "/data/data/com.zhiqupk.root.global",
                "/data/data/com.alephzain.framaroot", "/data/data/com.zachspong.temprootremovejb",
                "/data/data/com.ramdroid.appquarantine", "/system/app/Superuser.apk",
                "/system/etc/init.d/99SuperSUDaemon", "/dev/com.koushikdutta.superuser.daemon",
                "/system/xbin/daemonsu", "/data/data/me.weishu.kernelsu",
                "/data/data/com.rifsxd.ksunext", "/data/data/me.bmax.apatch"};
        List<String> hits = new ArrayList<>();
        for (String path : paths) if (exists(path)) hits.add(path);
        String[] packages = {"com.topjohnwu.magisk", "me.weishu.kernelsu", "com.rifsxd.ksunext", "me.bmax.apatch"};
        List<String> visible = com.ace.envsimulator.detection.CheckSupport.visiblePackages(context);
        for (String rule : packages) if (visible.contains(rule)) hits.add("package:" + rule);
        if (!hits.isEmpty()) return hit("发现 Root 管理器或系统制品", String.join("\n", hits), 99);
        return unknown("公开制品未命中，私有目录可见性不足", "已执行全部 " + paths.length +
                " 个路径和 " + packages.length + " 个包名；普通 UID 对 /data/adb 和其他包私有目录可能不可见", 96);
    }

    private static ProbeValue dynamicRootPaths(Context context) {
        return unknown("动态规则尚未取得", "探针要求运行时配置 root_ext_cnt/root_path_%d；静态样本不含下发值", 99);
    }

    private static ProbeValue debuggable(Context context) {
        String value = CheckSupport.getProp("ro.debuggable");
        if (value.isEmpty()) return unknown("ro.debuggable 读取为空", "getprop ro.debuggable 无输出", 85);
        return "1".equals(value) ? hit("系统为可调试构建", "ro.debuggable=1", 99)
                : safe("系统未标记为可调试构建", "ro.debuggable=" + value, 99);
    }

    private static ProbeValue zygiskFiles(Context context) {
        String[] paths = {"/system/zygisk_magic", "/system/lib/libzygisk_loader.so",
                "/system/lib64/libzygisk_loader.so", "/system/lib/libzygisk_injector.so",
                "/system/lib64/libzygisk_injector.so"};
        List<String> hits = new ArrayList<>();
        for (String path : paths) if (exists(path)) hits.add(path);
        return hits.isEmpty() ? safe("5 个加载器制品均未命中", String.join(", ", paths), 98)
                : hit("发现 Zygisk 加载器制品", String.join("\n", hits), 99);
    }

    private static ProbeValue nativeResult(int id, String label) {
        String raw = NativeProbe.run(id);
        String[] parts = raw.split("\\|", 2);
        String evidence = parts.length > 1 ? parts[1] : raw;
        if (raw.startsWith("HIT|")) return hit("命中 " + label, evidence, 98);
        if (raw.startsWith("SAFE|")) return safe("未命中 " + label, evidence, 98);
        return unknown("原生探针未得到确定结果", evidence, 75);
    }

    private static boolean exists(String path) {
        int nativeValue = NativeProbe.pathExists(path);
        return nativeValue >= 0 ? nativeValue == 1 : new File(path).exists();
    }

    private enum State { SAFE, UNKNOWN, HIT }
    private static final class ProbeValue {
        final State state; final String summary; final String evidence; final int confidence;
        ProbeValue(State state, String summary, String evidence, int confidence) {
            this.state = state; this.summary = summary; this.evidence = evidence; this.confidence = confidence;
        }
    }
    private static ProbeValue safe(String s, String e, int c) { return new ProbeValue(State.SAFE, s, e, c); }
    private static ProbeValue unknown(String s, String e, int c) { return new ProbeValue(State.UNKNOWN, s, e, c); }
    private static ProbeValue hit(String s, String e, int c) { return new ProbeValue(State.HIT, s, e, c); }
}
