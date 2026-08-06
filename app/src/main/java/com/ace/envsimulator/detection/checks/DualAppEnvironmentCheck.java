package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;
import java.util.ArrayList;
import java.util.List;

public final class DualAppEnvironmentCheck extends BaseCheck {
    private static final String[] HOSTS = {"com.bly.dkplat", "com.depu.wxfs", "com.excean.dualaid.b32",
            "com.excean.maid", "com.excean.masaid", "com.iplay.assistant", "info.red.virtual",
            "com.qihoo.magicmutiple", "com.qihoo.magic", "com.lbe.parallel.intl", "com.svm.proteinbox_multi",
            "com.sellapk.goapp", "com.app.hider.master.pro.cn", "com.xunrui.duokai_box",
            "com.chaozhuo.gameassistant", "com.kongge", "com.bfire.da.nui", "com.vmos.app", "com.vmos.pro",
            "com.joke.chongya", "com.weifx.wfx"};
    public DualAppEnvironmentCheck() { super("dual.app.environment", "应用环境", "双开与虚拟空间宿主"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        List<String> hits = new ArrayList<>();
        for (String installed : CheckSupport.visiblePackages(context))
            for (String host : HOSTS) if (installed.equals(host)) hits.add(host);
        if (!hits.isEmpty()) return suspicious(start, "发现双开/虚拟空间宿主包候选，组合谓词尚未闭合",
                String.join("\n", hits) + "\n仅宿主包存在不等于目标的‘宿主包 + Stub 类’组合命中。",
                "已恢复 21 组宿主包输入；Stub Activity/Manager、UID 与文件一致性必须共同核对", 99);
        return suspicious(start, "未发现可见宿主包，Stub 类与 UID 组合谓词仍依赖目标进程上下文",
                "已检查 21 个宿主包；Android 包可见性可能形成假阴性", "不扫描游戏自身完整性，仅观察客户端环境", 88);
    }
}
