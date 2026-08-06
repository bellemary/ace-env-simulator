package com.ace.envsimulator.detection.checks;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;
import java.util.ArrayList;
import java.util.List;

public final class RiskPackageProcessCheck extends BaseCheck {
    private static final String[] RULES = {
            "cn.com.opda.gamemaster", "cn.mc1.sq", "com.muzhiwan.gamehelper", "pj.ishuaji.cheat",
            "com.www.gamespeeder", "armbin", "binarm", "com.cih.game_cih", "com.huang.hl",
            "com.paojiao.youxia", "com.saitesoft.gamecheater", "com.xiongmaoxia.gameassistant",
            "com.yx.youxia", "com.gmd.speedtime", "org.sbtools.gamespeed", "com.xiaojianjian.sw.app",
            "org.sbtools.master", "gamehacker", "com.cyjh.gundam", "com.cyjh.mobileanjian",
            "com.jbbl.handjingling", "com.scriptelf", "net.aisence.Touchelper",
            "com.cyjh.gundam.service.ScriptService.p", "com.scriptelf.oneclickplay", "com.steady.autosimulate",
            "com.bayviewtech.game.roach", "com.ifengwoo.zyjdkj", "com.dr.nr", "com.zdnewproject",
            "com.diaobaosq", "com.kascend.chushou.lu", "com.leifeng.gametools",
            "com.dimonvideo.luckypatcher", "InAppBillingService.LUCK", "com.keramidas.TitaniumBackup",
            "com.flamingo.xxrgplugin", "com.dragon.android.pandaspace", "com.mf.guagua.ttfwks",
            "com.huluxia.gametools", "xxAssistant", "ui.robot.rotatedonate", "com.tgp.autologin",
            "com.uhaozu.autoapp", "cc.rs.gc", "com.uhaozu.app", "com.jym.mall",
            "com.zhanghaodaren.m_wzz", "com.tsy.tsy", "com.wanhaoba520.app", "com.daofeng.zuhaowan",
            "com.wuba.zhuanzhuan", "com.bdkj.LightningGameRental", "com.jj.jiasu", "com.speed.chick",
            "com.xh.kancn", "com.zx.a2_quickfox", "com.github.shadowsocks", "com.bige0.shadowsocksr",
            "co.solovpn", "com.fobwifi.transocks", "com.sticktoit", "bin.mt.plus",
            "com.speedsoftware.rootexplorer"
    };
    public RiskPackageProcessCheck() { super("risk.packages.processes", "应用与进程", "风险包与可见进程"); }
    @Override public DetectionResult run(Context context) {
        long start = System.nanoTime();
        List<String> hits = new ArrayList<>();
        for (String pkg : CheckSupport.visiblePackages(context)) {
            for (String rule : RULES) if (pkg.equals(rule)) hits.add("package:" + pkg);
        }
        for (String process : CheckSupport.readableProcCmdlines()) {
            for (String rule : RULES) if (process.contains(rule)) hits.add("process:" + process);
        }
        if (!hits.isEmpty()) return risk(start, "可见包或进程命中风险规则", String.join("\n", hits),
                "PackageManager 按规则包名精确查询；/proc/PID/cmdline 按目标 strstr 语义做子串匹配", 88);
        return suspicious(start, "未命中静态子集，但可见性和动态规则不完整", "可见包数=" + CheckSupport.visiblePackages(context).size() +
                "；已执行 64 项 ELF 静态表，comm.dat 动态扩展规则未知", "目标同样受 Android 包/进程可见性约束；未决单独展示", 92);
    }
}
