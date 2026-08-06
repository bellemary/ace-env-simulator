package com.ace.envsimulator.detection.checks;

import android.content.Context;
import android.os.Build;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import com.ace.envsimulator.model.DetectionResult;

public final class JavaRootCheck extends BaseCheck {
    public JavaRootCheck() { super("java.root", "Java 设备画像", "Java Root 与 test-keys"); }

    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String[] paths = {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sd/xbin/su",
                "/system/bin/failsafe/su", "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
                "/su/bin/su", "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
                "/system/etc/init.d/99SuperSUDaemon", "/system/xbin/daemonsu",
                "/dev/com.koushikdutta.superuser.daemon", "/system/bin/conbb", "/system/xbin/cufsd",
                "/system/xbin/cufsm", "/system/xbin/cufae", "/system/xbin/cufa"};
        List<String> hits = new ArrayList<>();
        for (String path : paths) if (new File(path).exists()) hits.add(path);
        boolean testKeys = Build.TAGS != null && Build.TAGS.contains("test-keys");
        String evidence = "Build.TAGS=" + Build.TAGS + "\n命中路径=" + (hits.isEmpty() ? "无" : String.join(", ", hits)) +
                "\n逆向链=classes.dex 0x96D8BC -> DeviceInfoHelper.<init> 0x96C786 -> " +
                "GPMNativeHelper.initNativeDeviceInfo 0x96C812 -> libGPM 0x86710 [device+0x1624] -> 0x94BE4 序列化";
        if (!hits.isEmpty() || testKeys) return risk(start, "Java Root 证据码将大于 0", evidence,
                "19 个 SU_FILES 命中计数；无路径命中后 test-keys 返回 100", 97);
        return pass(start, "Java Root 证据码为 0", evidence,
                "19 个 SU_FILES 均未命中且 Build.TAGS 不含 test-keys", 97);
    }
}
