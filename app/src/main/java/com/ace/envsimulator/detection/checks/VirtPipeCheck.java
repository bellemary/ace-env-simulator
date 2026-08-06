package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.NativeProbe;
import com.ace.envsimulator.model.DetectionResult;

public final class VirtPipeCheck extends BaseCheck {
    public VirtPipeCheck() { super("persona.virtpipe", "虚拟化", "安全虚拟管道节点"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        int exists = NativeProbe.pathExists("/dev/virtpipe-sec");
        if (exists == 1) return risk(start, "发现安全虚拟管道节点",
                "/dev/virtpipe-sec exists_result=1", "/dev/virtpipe-sec 存在", 98);
        if (exists == 0) return pass(start, "未发现安全虚拟管道节点",
                "/dev/virtpipe-sec exists_result=0", "/dev/virtpipe-sec 不存在", 98);
        return suspicious(start, "安全虚拟管道节点不可读",
                "/dev/virtpipe-sec exists_result=" + exists, "原生 faccessat 探针不可用", 80);
    }
}
