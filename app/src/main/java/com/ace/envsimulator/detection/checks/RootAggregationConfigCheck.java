package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.model.DetectionResult;

public final class RootAggregationConfigCheck extends BaseCheck {
    public RootAggregationConfigCheck() { super("root.aggregate.config", "ACE Root 聚合", "动态门控与 unlock_root 附加 OR"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        return suspicious(start, "目标版本的动态门值尚未从运行态配置闭合",
                "待确认：root_ext_cnt/root_path_%d、zygisk_module、zygisk_stack、sec_context、ksu_files、" +
                        "ksu_mounts_ext、ap_ker、ksu_mtp、manager_flag && unlock_root",
                "15 槽探针之外，目标汇总器还执行 manager_flag && unlock_root 附加 OR", 99);
    }
}
