package com.ace.envsimulator.advanced;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 实时报告写入器：将扫描结果实时追加到内部存储 Ace扫描报告.txt。
 * 格式统一为：扫描了 / 发现了 / 设备判定 / 上报结论。
 */
public final class ReportWriter {
    public static final String REPORT_NAME = "Ace扫描报告.txt";
    private static final int MAX_EVIDENCE_CHARS = 3000;
    private final File reportFile;
    private final SimpleDateFormat fmt =
            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);
    private final Map<String, Integer> categoryCounts = new LinkedHashMap<>();
    private int fileDecodedCount;
    private int memoryHitCount;
    private int pollCount;

    public ReportWriter(File filesDir) {
        reportFile = new File(filesDir, REPORT_NAME);
        writeHeader();
    }

    private void writeHeader() {
        StringBuilder sb = new StringBuilder();
        sb.append("========================================================\n");
        sb.append("ACE 环境检测实时扫描报告\n");
        sb.append("启动时间: ").append(fmt.format(new Date())).append("\n");
        sb.append("目标进程: com.tencent.tmgp.dfm\n");
        sb.append("扫描方式: 内存扫描(process_vm_readv + /proc/pid/mem) + ");
        sb.append("文件实时监控解密\n");
        sb.append("说明: 本报告在扫描过程中实时生成，每一条记录均带时间戳\n");
        sb.append("--------------------------------------------------------\n\n");
        write(sb.toString());
    }

    /** 文件实时解密结果 */
    public synchronized void writeFileDecoded(String fileName, String summary, String evidence) {
        fileDecodedCount++;
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(fmt.format(new Date())).append("] [文件解密 #").append(fileDecodedCount).append("]\n");
        sb.append("扫描了: ").append(fileName).append("\n");
        sb.append("发现了: ").append(summary).append("\n");
        if (evidence != null && !evidence.isEmpty()) {
            sb.append("解密详情:\n").append(truncate(evidence, MAX_EVIDENCE_CHARS)).append("\n");
        }
        sb.append("--------------------------------------------------------\n");
        write(sb.toString());
    }

    /** 内存扫描单条命中 */
    public synchronized void writeMemoryHit(String category, String pattern,
                                            String address, String context) {
        memoryHitCount++;
        categoryCounts.merge(category, 1, Integer::sum);
        String label = MemoryScanner.categoryLabel(category);
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(fmt.format(new Date())).append("] [内存命中 #").append(memoryHitCount).append("]\n");
        sb.append("扫描了: 目标进程内存\n");
        sb.append("发现了: [").append(label).append("] ").append(pattern);
        sb.append(" @ ").append(address).append("\n");
        if (context != null && !context.isEmpty()) {
            sb.append("内存上下文: ").append(context).append("\n");
        }
        sb.append("设备判定: ").append(verdictForCategory(category)).append("\n");
        sb.append("上报结论: ").append(uploadVerdictForCategory(category)).append("\n");
        sb.append("--------------------------------------------------------\n");
        write(sb.toString());
    }

    /** 内存扫描轮次汇总 */
    public synchronized void writeMemoryRound(int round, int hits, String source) {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(fmt.format(new Date())).append("] [内存扫描轮次]\n");
        sb.append("扫描了: 目标进程全部可写内存区域 + libtersafe.so 段 (").append(source).append(")\n");
        sb.append("发现了: 本轮 ").append(hits).append(" 项命中 (累计第 ").append(round).append(" 轮)\n");
        sb.append("--------------------------------------------------------\n");
        write(sb.toString());
    }

    /** 进程状态变化 */
    public synchronized void writeProcessStatus(String pid, int poll) {
        pollCount = poll;
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(fmt.format(new Date())).append("] [进程状态 #").append(poll).append("]\n");
        sb.append("扫描了: 目标进程生命周期\n");
        sb.append("发现了: PID=").append(pid == null || pid.isEmpty() ? "未运行" : pid).append("\n");
        sb.append("--------------------------------------------------------\n");
        write(sb.toString());
    }

    /** 文件变化但解密失败 */
    public synchronized void writeFileError(String fileName, String error) {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(fmt.format(new Date())).append("] [文件解密失败]\n");
        sb.append("扫描了: ").append(fileName).append("\n");
        sb.append("发现了: 解密失败 - ").append(error).append("\n");
        sb.append("--------------------------------------------------------\n");
        write(sb.toString());
    }

    /** 写入报告尾部汇总 */
    public synchronized void writeFooter() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n========================================================\n");
        sb.append("扫描结束: ").append(fmt.format(new Date())).append("\n");
        sb.append("采集轮次: ").append(pollCount).append("\n");
        sb.append("文件解密: ").append(fileDecodedCount).append(" 次\n");
        sb.append("内存命中: ").append(memoryHitCount).append(" 项\n");
        if (!categoryCounts.isEmpty()) {
            sb.append("命中分类:\n");
            for (Map.Entry<String, Integer> e : categoryCounts.entrySet()) {
                sb.append("  ").append(MemoryScanner.categoryLabel(e.getKey()))
                        .append(": ").append(e.getValue()).append(" 项\n");
            }
        }
        sb.append("报告路径: ").append(reportFile.getAbsolutePath()).append("\n");
        sb.append("========================================================\n");
        write(sb.toString());
    }

    public File getReportFile() { return reportFile; }
    public int getMemoryHitCount() { return memoryHitCount; }
    public int getFileDecodedCount() { return fileDecodedCount; }
    public Map<String, Integer> getCategoryCounts() { return categoryCounts; }

    private static String verdictForCategory(String category) {
        switch (category) {
            case "root": return "目标进程内存中发现 Root/KernelSU 相关数据，ACE 可能已检测到 Root 环境";
            case "boot": return "目标进程内存中发现 BL/Verified Boot 相关数据，ACE 可能已检测到解锁状态";
            case "frida": return "目标进程内存中发现 Frida 相关数据，ACE 可能已检测到注入环境";
            case "xposed": return "目标进程内存中发现 Xposed 相关数据，ACE 可能已检测到框架 Hook";
            case "hook": return "目标进程内存中发现 Hook/Substrate 相关数据，ACE 可能已检测到代码注入";
            case "cert": return "目标进程内存中发现证书相关数据，ACE 可能已读取设备证书信息";
            case "fingerprint": return "目标进程内存中发现指纹相关数据，ACE 可能已采集设备指纹";
            case "emulator": return "目标进程内存中发现模拟器相关数据，ACE 可能已检测到模拟器环境";
            case "report": return "目标进程内存中发现 TSS 报告接口数据，ACE 报告生成代码正在运行";
            case "upload": return "目标进程内存中发现上报相关数据，ACE 可能正在上传检测结果";
            case "tool": return "目标进程内存中发现工具相关数据，ACE 可能已检测到破解工具";
            case "ace": return "目标进程内存中发现 ACE 组件数据，检测引擎正在运行";
            default: return "目标进程内存中发现相关数据";
        }
    }

    private static String uploadVerdictForCategory(String category) {
        switch (category) {
            case "root":
            case "boot":
            case "frida":
            case "xposed":
            case "hook":
            case "emulator":
            case "tool":
                return "此类命中通常会被纳入 TSS 报告并上报服务端";
            case "cert":
            case "fingerprint":
                return "此类数据通常作为设备画像上报";
            case "report":
                return "报告接口正在运行，检测结果将被编码为报告负载";
            case "upload":
                return "上报通道活跃，数据可能正在传输";
            default:
                return "需结合 TSS 报告接口数据确认是否已上报";
        }
    }

    private void write(String text) {
        try (FileOutputStream out = new FileOutputStream(reportFile, true)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) { }
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "\n... (已截断)";
    }
}
