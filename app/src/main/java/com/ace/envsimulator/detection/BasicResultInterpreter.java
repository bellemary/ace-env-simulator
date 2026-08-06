package com.ace.envsimulator.detection;

import com.ace.envsimulator.model.DetectionResult;
import com.ace.envsimulator.model.DetectionStatus;
import java.util.ArrayList;
import java.util.List;

public final class BasicResultInterpreter {
    private BasicResultInterpreter() {}

    public static List<DetectionResult> appendSummaries(List<DetectionResult> input) {
        List<DetectionResult> results = new ArrayList<>(input);
        DetectionResult firstRootRisk = null;
        boolean rootUnknown = false;
        int explicitRisk = 0;
        int unresolved = 0;
        for (DetectionResult result : input) {
            if (result.status == DetectionStatus.RISK) explicitRisk++;
            if (result.status == DetectionStatus.SUSPICIOUS) unresolved++;
            if (result.id.startsWith("root.slot.") || result.id.equals("root.aggregate.config")) {
                if (firstRootRisk == null && result.status == DetectionStatus.RISK) firstRootRisk = result;
                if (result.status == DetectionStatus.SUSPICIOUS) rootUnknown = true;
            }
        }
        if (firstRootRisk != null) {
            results.add(DetectionResult.risk("root.chain.summary", "ACE Root 聚合", "Root 环境槽 OR 解释",
                    "已发现无需未知门控即可成立的 Root 命中", "first_known_hit=" + firstRootRisk.title +
                            "\n所有基础环境项目仍会继续执行；目标进程专属槽不进入本模式。",
                    "目标 15 槽中可独立复现的环境子集 + manager_flag && unlock_root 附加 OR", 96, 0));
        } else if (rootUnknown) {
            results.add(DetectionResult.suspicious("root.chain.summary", "ACE Root 聚合", "Root 环境槽 OR 解释",
                    "未观察到确定命中，但动态门值或目标进程上下文未闭合", "不能把未决槽位当作未命中",
                    "目标 15 槽中可独立复现的环境子集 + manager_flag && unlock_root 附加 OR", 96, 0));
        } else {
            results.add(DetectionResult.pass("root.chain.summary", "ACE Root 聚合", "Root 环境槽 OR 解释",
                    "所有可执行环境槽均未命中", "未观察到动态未决项", "目标 Root 聚合器的可独立复现环境子集", 94, 0));
        }
        String evidence = "explicit_risk=" + explicitRisk + "\nunresolved=" + unresolved +
                "\n说明：本地信号不会直接推导服务端已标记或坐标已销毁。";
        if (explicitRisk > 0) results.add(DetectionResult.risk("basic.summary", "基础模式", "客户端环境综合观察",
                "存在明确客户端环境风险信号", evidence, "仅汇总已证实原子信号；不推导服务端坐标状态", 95, 0));
        else if (unresolved > 0) results.add(DetectionResult.suspicious("basic.summary", "基础模式", "客户端环境综合观察",
                "没有明确命中，但仍存在未决输入", evidence, "未决与命中分开计数", 95, 0));
        else results.add(DetectionResult.pass("basic.summary", "基础模式", "客户端环境综合观察",
                    "当前可观察输入未发现异常", evidence, "不等价于服务端最终设备分类", 92, 0));
        return results;
    }
}
