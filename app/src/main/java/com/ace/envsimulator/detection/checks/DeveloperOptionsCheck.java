package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;

public final class DeveloperOptionsCheck extends BaseCheck {
    public DeveloperOptionsCheck() { super("developer.options", "开发环境", "开发者选项"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        int value = CheckSupport.globalSetting(context, "development_settings_enabled");
        if (value < 0) return suspicious(start, "开发者选项状态不可读", "Settings.Global 读取失败",
                "DEVELOPMENT_SETTINGS_ENABLED 是已证实输入，单独权重未知", 75);
        if (value == 1) return risk(start, "开发者选项已开启", "development_settings_enabled=1",
                "development_settings_enabled==1 命中该独立开发环境信号", 96);
        return pass(start, "开发者选项未开启", "development_settings_enabled=" + value,
                "DEVELOPMENT_SETTINGS_ENABLED 输入", 90);
    }
}
