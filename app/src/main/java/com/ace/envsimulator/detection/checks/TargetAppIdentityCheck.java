package com.ace.envsimulator.detection.checks;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;

public final class TargetAppIdentityCheck extends BaseCheck {
    private static final String TARGET = "com.tencent.tmgp.dfm";
    public TargetAppIdentityCheck() { super("persona.app.identity", "应用身份输入", "目标包、安装来源与签名"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        try {
            PackageManager pm = context.getPackageManager();
            int flags = Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES;
            PackageInfo info = pm.getPackageInfo(TARGET, flags);
            Signature[] signatures = Build.VERSION.SDK_INT >= 28 && info.signingInfo != null ?
                    info.signingInfo.getApkContentsSigners() : info.signatures;
            StringBuilder evidence = new StringBuilder("package=").append(TARGET)
                    .append("\nversion=").append(info.versionName).append(" (").append(info.versionCode).append(')')
                    .append("\ninstaller=").append(pm.getInstallerPackageName(TARGET));
            if (signatures != null) for (int i = 0; i < signatures.length; i++)
                evidence.append("\nsignature[").append(i).append("].sha256=").append(CheckSupport.sha256(signatures[i].toByteArray()));
            return suspicious(start, "目标包身份输入已读取，ACE 风险谓词尚未闭合", evidence.toString(),
                    "PackageManager signatures/installer 是画像输入；不与 KeyStore attestation 混用", 92);
        } catch (Exception e) {
            return suspicious(start, "目标包不可见、未安装或身份读取失败", e.getClass().getSimpleName() + ": " + e.getMessage(),
                    "采集可用性不等于设备风险", 85);
        }
    }
}
