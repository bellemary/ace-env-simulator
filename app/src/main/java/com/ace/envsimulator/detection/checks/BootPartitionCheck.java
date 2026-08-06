package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.NativeProbe;
import com.ace.envsimulator.model.DetectionResult;

public final class BootPartitionCheck extends BaseCheck {
    public BootPartitionCheck() { super("persona.boot.partition", "启动可信度", "Boot 分区节点可见性"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String[] paths = {"/dev/block/by-name/boot", "/dev/block/by-name/boot_a", "/dev/block/by-name/boot_b"};
        StringBuilder evidence = new StringBuilder();
        int visible = 0, unavailable = 0;
        for (String path : paths) {
            int value = NativeProbe.pathExists(path);
            if (value == 1) visible++;
            if (value < 0) unavailable++;
            evidence.append(path).append('=').append(value).append('\n');
        }
        if (visible > 0) return pass(start, "Boot 分区节点可见", evidence.toString(),
                "至少一个 boot/boot_a/boot_b 节点存在；基础模式不读取分区内容", 95);
        if (unavailable > 0) return suspicious(start, "Boot 分区节点探针不可用", evidence.toString(),
                "存在性输入未完整读取", 82);
        return suspicious(start, "未观察到常用 Boot 分区节点", evidence.toString(),
                "设备可能使用不同 by-name 路径；路径缺失语义尚未闭合", 88);
    }
}
