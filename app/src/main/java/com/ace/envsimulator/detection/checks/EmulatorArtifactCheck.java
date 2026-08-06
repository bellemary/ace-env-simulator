package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.model.DetectionResult;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public final class EmulatorArtifactCheck extends BaseCheck {
    public EmulatorArtifactCheck() { super("emulator.artifacts", "虚拟化", "Titan、VPhone、Nox 与 BlueStacks"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String[] paths = {"/init.titan.rc", "/ueventd.titan.rc", "/egl/libEGL_titan.so",
                "/hw/gralloc.titan.so", "/hw/audio.primary.titan.so", "/hw/audio.primary.titan_legacy.so",
                "/hw/camera.titan.so", "/hw/camera.titan.jpeg.so", "/hw/fingerprint.titan.so",
                "/hw/gatekeeper.titan.so", "/hw/sensors.titan.so", "/hw/vibrator.titan.so",
                "/hw/vulkan.titan.so", "/hw/gps.titan.so", "/dev/vphone_pipe", "/system/bin/qemud"};
        List<String> hits = new ArrayList<>();
        for (String path : paths) if (new File(path).exists()) hits.add(path);
        if (!hits.isEmpty()) return risk(start, "发现模拟器或虚拟手机制品", String.join("\n", hits),
                "Titan/VPhone/Nox/BlueStacks 原生短路探针", 96);
        return suspicious(start, "未命中静态制品；进程挂载与 QEMU 协议输入未在基础模式读取",
                "已检查路径：" + String.join(", ", paths) +
                        "\n基础模式不读取自身或目标进程 /proc/self/mounts、/proc/self/root。",
                "不添加原 SO 中不存在的通用 ro.kernel.qemu 规则；协议级输入保持未决", 99);
    }
}
