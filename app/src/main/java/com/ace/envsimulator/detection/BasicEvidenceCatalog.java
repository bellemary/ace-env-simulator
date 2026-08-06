package com.ace.envsimulator.detection;

import com.ace.envsimulator.model.DetectionResult;
import com.ace.envsimulator.model.DetectionStatus;

/** Adds the same auditable evidence contract to every independent basic check. */
public final class BasicEvidenceCatalog {
    private BasicEvidenceCatalog() {}

    public static DetectionResult enrich(DetectionResult result) {
        String evidence = "采集对象=" + source(result.id) +
                "\n采集方式=" + method(result.id) +
                "\n原始读取：\n" + result.evidence +
                "\n判定谓词=" + result.rule +
                "\n" + factLabel(result.status) + "=" + result.summary +
                "\n最终结论=" + conclusion(result.status) +
                "\n上报边界=基础模式只复现客户端环境输入，不读取目标进程或推测服务端上报值";
        return new DetectionResult(result.id, result.category, result.title, result.status,
                result.summary, evidence, result.rule, result.confidence, result.durationMs,
                result.riskSignal);
    }

    private static String factLabel(DetectionStatus status) {
        if (status == DetectionStatus.RISK) return "命中事实";
        if (status == DetectionStatus.PASS) return "未命中事实";
        return "未决原因";
    }

    private static String conclusion(DetectionStatus status) {
        if (status == DetectionStatus.RISK) return "该独立环境信号已命中";
        if (status == DetectionStatus.PASS) return "该独立环境信号已完成且未命中";
        return "缺少目标动态门值或读取输入，按风险项继续排查";
    }

    private static String source(String id) {
        switch (id) {
            case "root.slot.0": return "进程 PATH 的每个目录下 su 文件";
            case "root.slot.1": return "ACE 固定 su 目录表";
            case "root.slot.2": return "Root 管理器包名及 Magisk/KernelSU/APatch 文件制品";
            case "root.slot.3": return "comm.dat 下发的 root_ext_cnt/root_path_%d";
            case "root.slot.5": return "系统属性 ro.debuggable";
            case "root.slot.10": return "Zygisk loader 固定文件表";
            case "root.slot.12": return "AArch64 syscall 45 后匿名页驻留状态";
            case "root.slot.13": return "AArch64 syscall 167 + 0xDEADBEEF 后匿名页驻留状态";
            case "root.aggregate.config": return "ACE Root 15 槽动态门与 unlock_root 汇总门";
            case "java.root": return "classes.dex DeviceInfoHelper.isDeviceRooted 的 Build.TAGS 与 19 个 SU_FILES；结果进入 libGPM rootedIndex/DeviceISRooted";
            case "bootloader.lock": return "ro.boot.flash.locked、ro.boot.vbmeta.device_state";
            case "verified.boot": return "ro.boot.verifiedbootstate、ro.boot.veritymode";
            case "oem.unlock": return "sys.oem_unlock_allowed";
            case "developer.options": return "Settings.Global development_settings_enabled";
            case "adb.environment": return "adb_enabled、init.svc.adbd、service.adb.tcp.port";
            case "selinux": return "/sys/fs/selinux/enforce 与 getenforce";
            case "fingerprint.consistency": return "system/vendor/odm/bootimage 多分区 build fingerprint";
            case "persona.vendor.root": return "ro.boot.bootisroot、ro.boot.deviceisroot";
            case "persona.boot.history": return "构建时间、内核版本、启动原因与 boot_devices";
            case "persona.boot.partition": return "/dev/block/by-name/boot、boot_a、boot_b";
            case "persona.virtpipe": return "/dev/virtpipe-sec";
            case "persona.app.identity": return "目标包版本、安装来源和 APK 签名证书";
            case "cloud.device": return "CloudMatrix/cloudAppEngine/cloud gaming 属性族";
            case "emulator.artifacts": return "Titan/VPhone/Nox/BlueStacks 固定文件节点";
            case "virtualization.dex": return "DEX 虚拟化节点、proc 标记与 Build 输入";
            case "risk.packages.processes": return "已恢复风险包名表、可见包及 /proc/PID/cmdline";
            case "dual.app.environment": return "双开宿主包名表、包可见性与上下文限制";
            case "framework.environment": return "Xposed/Frida 包名与固定文件路径";
            case "keystore.attestation": return "本应用 UID 的 AndroidKeyStore 硬件证明链";
            case "mediadrm.identity": return "Widevine MediaDrm PROPERTY_DEVICE_UNIQUE_ID";
            default: return "该独立检查声明的客户端环境输入";
        }
    }

    private static String method(String id) {
        if (id.startsWith("root.slot.12") || id.startsWith("root.slot.13"))
            return "与目标 AArch64 探针同类的 syscall + mincore 观测";
        if (id.contains("package") || id.contains("app.identity") || id.contains("dual.app"))
            return "Android PackageManager 与受系统包可见性约束的枚举";
        if (id.contains("keystore")) return "AndroidKeyStore API，结果按调用 UID 隔离";
        if (id.contains("mediadrm")) return "Android MediaDrm API，原始标识仅输出摘要";
        return "无 Root Java/原生只读采集；失败不短路后续项目";
    }
}
