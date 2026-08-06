package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;

public final class OemUnlockCheck extends BaseCheck {
    public OemUnlockCheck() { super("oem.unlock", "启动可信度", "OEM 解锁许可"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        String allowed = CheckSupport.getProp("sys.oem_unlock_allowed");
        String evidence = "sys.oem_unlock_allowed=" + (allowed.isEmpty() ? "<empty>" : allowed);
        if (allowed.isEmpty()) return suspicious(start, "OEM 解锁输入未知", evidence,
                "该输入已在设备画像出现，但精确风险谓词未闭合", 80);
        if ("1".equals(allowed)) return suspicious(start, "系统允许 OEM 解锁", evidence,
                "允许解锁不等于已经解锁；作为画像风险信号保守展示", 80);
        return pass(start, "系统未开放 OEM 解锁许可", evidence, "sys.oem_unlock_allowed==0", 85);
    }
}
