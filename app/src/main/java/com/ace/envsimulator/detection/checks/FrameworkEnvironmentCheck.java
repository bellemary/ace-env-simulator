package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.detection.NativeProbe;
import com.ace.envsimulator.model.DetectionResult;
import java.util.ArrayList;
import java.util.List;

public final class FrameworkEnvironmentCheck extends BaseCheck {
    private static final String[] PACKAGES = {"de.robv.android.xposed.installer"};
    private static final String[] FILES = {"/data/local/tmp/12re.34frida.56server78", "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-server", "/system/bin/frida-server", "/system/framework/XposedBridge.jar"};
    public FrameworkEnvironmentCheck() { super("framework.environment", "应用环境", "Hook 与动态分析工具制品"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        List<String> hits = new ArrayList<>();
        for (String pkg : CheckSupport.visiblePackages(context))
            for (String rule : PACKAGES) if (pkg.equals(rule)) hits.add("package:" + pkg);
        for (String path : FILES) if (NativeProbe.pathExists(path) == 1) hits.add("file:" + path);
        if (!hits.isEmpty()) return risk(start, "发现 Hook/Frida 环境制品", String.join("\n", hits),
                "仅实现环境文件/包输入；按范围不检查目标自身是否被注入或附加", 96);
        return pass(start, "未发现公开的 Hook/Frida 环境制品", "已检查 1 个包和 5 个公开路径",
                "目标进程 maps/栈/线程检测不纳入本应用的环境范围", 92);
    }
}
