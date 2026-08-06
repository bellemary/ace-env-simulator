package com.ace.envsimulator.report;

import android.content.Context;
import android.content.Intent;
import androidx.core.content.FileProvider;
import com.ace.envsimulator.BuildConfig;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class ReportRepository {
    public enum Mode { BASIC, ADVANCED }

    public File write(Context context, Mode mode, List<DetectionResult> results) throws Exception {
        File directory = new File(context.getFilesDir(), "reports");
        if (!directory.exists() && !directory.mkdirs()) throw new IllegalStateException("cannot create reports directory");
        String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
        String name = mode == Mode.BASIC ? "基础root检测报告_" + stamp + ".txt" : "高级Ace运行会话与上报分析报告_" + stamp + ".txt";
        File file = new File(directory, name);
        for (int copy = 2; file.exists(); copy++) {
            file = new File(directory, name.substring(0, name.length() - 4) + "_" + copy + ".txt");
        }
        StringBuilder text = new StringBuilder();
        text.append("ACE 环境检测模拟器\n")
                .append("报告类型：").append(mode == Mode.BASIC ? "基础 Root 与客户端环境检测" : "高级 ACE 会话采集与文件解密").append('\n')
                .append("应用版本：v").append(BuildConfig.VERSION_NAME).append('\n')
                .append("设备：").append(CheckSupport.deviceLine()).append('\n')
                .append("生成时间：").append(new Date()).append('\n')
                .append(mode == Mode.BASIC
                        ? "判定口径：明确命中为风险；未恢复的动态配置、字段语义或不可见输入按可疑风险展示。\n"
                        : "报告说明：这里直接列出读到的文件和发现内容；完整原始文件与解密文件在报告压缩包内。\n");
        if (mode == Mode.ADVANCED) text.append("高级模式不重复基础检测；规则覆盖范围、本机观察值和最终上报分开列出。\n");
        text.append("\n");
        List<DetectionResult> reportResults = mode == Mode.ADVANCED ? advancedReportResults(results) : results;
        int pass = 0, suspicious = 0, risk = 0;
        for (DetectionResult result : reportResults) {
            switch (result.status) { case PASS: pass++; break; case SUSPICIOUS: suspicious++; break; case RISK: risk++; break; }
        }
        text.append("汇总：总项=").append(reportResults.size());
        if (mode == Mode.ADVANCED) text.append(" 已读取=").append(pass).append(" 需要确认=").append(suspicious).append(" 已发现=").append(risk);
        else text.append(" 通过=").append(pass).append(" 可疑=").append(suspicious).append(" 风险=").append(risk);
        text.append("\n\n");
        for (int i = 0; i < reportResults.size(); i++) {
            DetectionResult result = reportResults.get(i);
            String statusLabel = mode == Mode.ADVANCED
                    ? result.status == com.ace.envsimulator.model.DetectionStatus.PASS ? "已读取"
                    : result.status == com.ace.envsimulator.model.DetectionStatus.RISK ? "已发现" : "需要确认"
                    : result.status.label;
            text.append("[").append(i + 1).append('/').append(reportResults.size()).append("] ")
                    .append(statusLabel).append(" | ").append(result.category).append(" | ").append(result.title).append('\n')
                    .append("结论：").append(result.summary).append('\n');
            if (mode == Mode.ADVANCED) text.append("扫描与判定：\n").append(result.evidence).append("\n\n");
            else text.append("证据：\n").append(result.evidence).append('\n')
                    .append("规则：").append(result.rule).append('\n')
                    .append("置信度：").append(result.confidence).append("%\n")
                    .append("耗时：").append(result.durationMs).append(" ms\n\n");
        }
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(text.toString().getBytes(StandardCharsets.UTF_8));
        }
        return file;
    }

    private static List<DetectionResult> advancedReportResults(List<DetectionResult> results) {
        List<DetectionResult> selected = new ArrayList<>();
        for (DetectionResult result : results) {
            if (result.id.equals("advanced.files.summary") || result.id.startsWith("advanced.file.") ||
                    result.id.startsWith("advanced.finding.") || result.id.equals("advanced.classification") ||
                    result.id.equals("advanced.apk.inventory") || result.id.startsWith("advanced.runtime.") ||
                    result.id.startsWith("advanced.observation.") && result.status == com.ace.envsimulator.model.DetectionStatus.RISK)
                selected.add(result);
        }
        return selected;
    }

    public void share(Context context, File file) {
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType(file.getName().endsWith(".zip") ? "application/zip" : "text/plain");
        intent.putExtra(Intent.EXTRA_STREAM, FileProvider.getUriForFile(context, context.getPackageName() + ".files", file));
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        context.startActivity(Intent.createChooser(intent, "导出检测报告"));
    }

    public File writeAdvancedBundle(Context context, File report, File decodedDirectory) throws Exception {
        if (report == null || decodedDirectory == null || !decodedDirectory.isDirectory()) return report;
        String base = report.getName().endsWith(".txt") ? report.getName().substring(0, report.getName().length() - 4) : report.getName();
        File bundle = new File(report.getParentFile(), base + "_解密源文件.zip");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(bundle))) {
            addToZip(zip, report, "report/" + report.getName());
            addDirectoryToZip(zip, decodedDirectory, "decoded/");
        }
        return bundle;
    }

    private static void addDirectoryToZip(ZipOutputStream zip, File directory, String prefix) throws Exception {
        File[] children = directory.listFiles();
        if (children == null) return;
        for (File child : children) {
            String name = prefix + child.getName();
            if (child.isDirectory()) addDirectoryToZip(zip, child, name + "/");
            else addToZip(zip, child, name);
        }
    }

    private static void addToZip(ZipOutputStream zip, File file, String name) throws Exception {
        String normalized = name.replace('\\', '/');
        if (normalized.contains("../") || normalized.startsWith("/")) throw new IllegalArgumentException("invalid zip entry");
        zip.putNextEntry(new ZipEntry(normalized));
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            for (int n; (n = in.read(buffer)) >= 0; ) zip.write(buffer, 0, n);
        }
        zip.closeEntry();
    }
}
