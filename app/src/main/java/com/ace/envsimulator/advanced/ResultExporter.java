package com.ace.envsimulator.advanced;

import android.content.Context;
import android.os.Environment;
import com.ace.envsimulator.model.DetectionResult;
import com.ace.envsimulator.model.DetectionStatus;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * v2.6: 高级模式结果持久化保存
 * 将内存特征点 + 解密文件明文 + 智能解释 + 综合结论保存到
 * /storage/emulated/0/ACE解密结果/ACE_Result_YYYY-MM-DD_HH-mm-ss.txt
 */
public final class ResultExporter {
    private static final String SAVE_DIR = "ACE解密结果";

    private ResultExporter() {}

    public static final class SaveResult {
        public final boolean success;
        public final String filePath;
        public final String error;
        SaveResult(boolean success, String filePath, String error) {
            this.success = success; this.filePath = filePath; this.error = error;
        }
    }

    /** 检查是否有写入外部存储的权限 */
    public static boolean hasStoragePermission() {
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            return Environment.isExternalStorageManager();
        }
        return true; // API 29 及以下由 WRITE_EXTERNAL_STORAGE 运行时权限处理
    }

    /** 保存高级模式完整报告 */
    public static SaveResult saveAdvancedReport(Context context, List<DetectionResult> results,
                                                  File artifactDirectory) {
        if (!hasStoragePermission()) {
            return new SaveResult(false, null, "缺少「所有文件访问」权限，无法保存到本地存储");
        }
        File external = Environment.getExternalStorageDirectory();
        if (external == null || !external.canWrite()) {
            return new SaveResult(false, null, "外部存储不可写");
        }
        File saveDir = new File(external, SAVE_DIR);
        if (!saveDir.exists() && !saveDir.mkdirs()) {
            return new SaveResult(false, null, "无法创建目录: " + saveDir.getAbsolutePath());
        }
        String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(new Date());
        String fileName = "ACE_Result_" + timestamp + ".txt";
        File target = new File(saveDir, fileName);
        String content = buildReportText(results, artifactDirectory);
        try (FileOutputStream out = new FileOutputStream(target)) {
            out.write(content.getBytes(StandardCharsets.UTF_8));
            return new SaveResult(true, target.getAbsolutePath(), null);
        } catch (Exception e) {
            return new SaveResult(false, null, "写入失败: " + e.getMessage());
        }
    }

    private static String buildReportText(List<DetectionResult> results, File artifactDirectory) {
        StringBuilder sb = new StringBuilder();
        String now = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
        sb.append("ACE 环境检测模拟器 v2.6 - 高级模式扫描报告\n");
        sb.append("扫描时间: ").append(now).append("\n");
        sb.append("==================================================\n\n");

        // ===== 内存特征点扫描结果 =====
        List<DetectionResult> features = new ArrayList<>();
        List<DetectionResult> memPatterns = new ArrayList<>();
        List<DetectionResult> files = new ArrayList<>();
        List<DetectionResult> findings = new ArrayList<>();
        List<DetectionResult> others = new ArrayList<>();
        DetectionResult classification = null;
        for (DetectionResult r : results) {
            if (r.id.startsWith("advanced.memscan.feature.")) features.add(r);
            else if (r.id.startsWith("advanced.memscan")) memPatterns.add(r);
            else if (r.id.startsWith("advanced.file.")) files.add(r);
            else if (r.id.startsWith("advanced.finding.") || r.id.startsWith("advanced.observation.")) findings.add(r);
            else if (r.id.equals("advanced.classification")) classification = r;
            else if (!r.id.startsWith("advanced.root") && !r.id.startsWith("advanced.crypto")
                    && !r.id.startsWith("advanced.runtime") && !r.id.startsWith("advanced.apk")
                    && !r.id.startsWith("advanced.limit") && !r.id.equals("advanced.files.summary")
                    && !r.id.equals("advanced.runtime.session")) others.add(r);
        }

        // 内存特征点
        sb.append("===== 内存特征点扫描结果 =====\n");
        if (features.isEmpty()) {
            sb.append("本轮未采集到内存特征点数据。\n\n");
        } else {
            int idx = 1;
            for (DetectionResult f : features) {
                if (f.id.endsWith(".summary")) continue; // 跳过总览，单独输出
                sb.append("[").append(idx++).append("] ").append(f.title).append("\n");
                sb.append("  状态: ").append(statusLabel(f.status)).append("\n");
                String module = extractField(f.evidence, "扫描了=", "\n");
                String address = extractField(f.evidence, "虚拟地址=", "\n");
                String hex = extractBlock(f.evidence, "读取内容(64字节 HEX)=\n", "\n设备判定=");
                String reason = extractField(f.evidence, "设备判定=", "\n");
                sb.append("  模块+偏移: ").append(module).append("\n");
                sb.append("  虚拟地址: ").append(address).append("\n");
                sb.append("  安全判定: ").append(reason).append("\n");
                sb.append("  十六进制内容 (64字节):\n");
                sb.append(formatHexBlock(hex)).append("\n");
                sb.append("  智能解释:\n").append(featureExplanation(f.title, f.status, reason)).append("\n");
                sb.append("  ---\n\n");
            }
            // 特征点总览
            for (DetectionResult s : features) {
                if (s.id.endsWith(".summary")) {
                    sb.append("[总览] ").append(s.summary).append("\n\n");
                    break;
                }
            }
        }

        // 内存模式扫描结果
        if (!memPatterns.isEmpty()) {
            sb.append("===== 内存模式扫描结果 =====\n");
            for (DetectionResult m : memPatterns) {
                sb.append("[").append(m.title).append("]\n");
                sb.append("  状态: ").append(statusLabel(m.status)).append("\n");
                sb.append("  摘要: ").append(m.summary).append("\n\n");
            }
        }

        // 解密文件结果
        sb.append("===== 解密文件结果 =====\n");
        if (files.isEmpty()) {
            sb.append("本轮未读取到解密文件。\n\n");
        } else {
            int idx = 1;
            for (DetectionResult f : files) {
                sb.append("[").append(idx++).append("] 文件名: ").append(f.title).append("\n");
                sb.append("  状态: ").append(statusLabel(f.status)).append("\n");
                String discovery = extractField(f.evidence, "发现内容=", "\n");
                sb.append("  发现内容: ").append(discovery).append("\n");
                // 读取完整解密明文 — 从 evidence 提取 artifact 名精确匹配
                String plaintext = readDecodedPlaintext(artifactDirectory, f);
                sb.append("  --- 完整解密明文 ---\n");
                sb.append(plaintext.isEmpty() ? "（未找到解密明文文件）" : plaintext).append("\n");
                sb.append("  --- 明文结束 ---\n\n");
                // 智能解释
                sb.append("  --- 智能解释 ---\n");
                sb.append(fileExplanation(f.title.toLowerCase(Locale.ROOT), f)).append("\n");
                sb.append("  --- 解释结束 ---\n\n");
            }
        }

        // 高级逐项解读
        if (!findings.isEmpty()) {
            sb.append("===== 高级逐项解读 =====\n");
            for (DetectionResult f : findings) {
                sb.append("[").append(f.title).append("]\n");
                sb.append("  状态: ").append(statusLabel(f.status)).append("\n");
                sb.append("  摘要: ").append(f.summary).append("\n\n");
            }
        }

        // 其他结果
        if (!others.isEmpty()) {
            sb.append("===== 其他检测结果 =====\n");
            for (DetectionResult o : others) {
                sb.append("[").append(o.title).append("]\n");
                sb.append("  状态: ").append(statusLabel(o.status)).append("\n");
                sb.append("  摘要: ").append(o.summary).append("\n\n");
            }
        }

        // 综合结论
        sb.append("===== 环境综合结论 =====\n");
        if (classification != null) {
            sb.append(classification.summary).append("\n\n");
        } else {
            int riskCount = 0, suspiciousCount = 0;
            for (DetectionResult r : results) {
                if (r.status == DetectionStatus.RISK) riskCount++;
                else if (r.status == DetectionStatus.SUSPICIOUS) suspiciousCount++;
            }
            if (riskCount > 0) {
                sb.append("根据内存特征与解密文件分析，当前环境【异常】。\n");
                sb.append("异常原因: 发现 ").append(riskCount).append(" 项明确异常观察值。\n\n");
            } else if (suspiciousCount > 0) {
                sb.append("根据内存特征与解密文件分析，当前环境【待确认】。\n");
                sb.append("存在 ").append(suspiciousCount).append(" 项未决信号，需进一步确认。\n\n");
            } else {
                sb.append("根据内存特征与解密文件分析，当前环境【正常】。\n");
                sb.append("未发现明确异常观察值。\n\n");
            }
        }

        sb.append("==================================================\n");
        sb.append("报告结束\n");
        return sb.toString();
    }

    /** 读取解密后的完整明文 — 从 evidence 提取 artifact 名精确匹配 */
    private static String readDecodedPlaintext(File artifactDirectory, DetectionResult result) {
        if (artifactDirectory == null) return "";
        File decodedDir = new File(artifactDirectory, "decoded");
        if (!decodedDir.isDirectory()) return "";

        // 1. 从 evidence 的 "解密文件=" 字段提取所有 .txt artifact 名
        List<String> artifactNames = extractArtifactNames(result.evidence);
        // 如果没有 .txt artifact，尝试 .bin（但标记为二进制）
        if (artifactNames.isEmpty()) {
            artifactNames = extractAllArtifactNames(result.evidence);
        }
        if (artifactNames.isEmpty()) {
            // 零字节文件或无 artifact 的情况
            if (result.evidence != null && result.evidence.contains("size=0")) {
                return "file=" + result.title + "\nsize=0\n（零字节临时占位文件）";
            }
            return "（该文件未生成解码 artifact）";
        }

        // 2. 在 decoded 目录下查找匹配的文件
        StringBuilder combined = new StringBuilder();
        for (String artifactName : artifactNames) {
            File target = findDecodedFile(decodedDir, artifactName);
            if (target == null) {
                combined.append("[").append(artifactName).append("]\n（未找到对应解码文件）\n\n");
                continue;
            }
            String content = readFileAsText(target);
            combined.append("[").append(artifactName).append("]\n").append(content).append("\n\n");
        }
        return combined.toString().trim();
    }

    /** 从 evidence 中提取所有 "解密文件=" 字段的值（包括 .bin） */
    private static List<String> extractAllArtifactNames(String evidence) {
        List<String> names = new ArrayList<>();
        if (evidence == null) return names;
        String[] lines = evidence.split("\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("解密文件=")) {
                String name = trimmed.substring("解密文件=".length()).trim();
                int paren = name.indexOf('（');
                if (paren > 0) name = name.substring(0, paren).trim();
                if (name.isEmpty() || name.contains("当前只保留原始文件")) continue;
                if (name.contains(".")) names.add(name);
            }
        }
        return names;
    }

    /** 从 evidence 中提取所有 "解密文件=" 字段的值，只保留 .txt 文本 artifact */
    private static List<String> extractArtifactNames(String evidence) {
        List<String> names = new ArrayList<>();
        if (evidence == null) return names;
        String[] lines = evidence.split("\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("解密文件=")) {
                String name = trimmed.substring("解密文件=".length()).trim();
                // 去掉 "（已放入报告压缩包）" 后缀
                int paren = name.indexOf('（');
                if (paren > 0) name = name.substring(0, paren).trim();
                // 过滤非文件名的占位文本
                if (name.isEmpty() || name.contains("当前只保留原始文件")) continue;
                // 有效 artifact 名必须包含点号（如 xxx.txt / xxx.bin）
                if (!name.contains(".")) continue;
                // 只保留 .txt 文本 artifact，跳过 .bin/.raw 等二进制文件
                // 这样 mrpcs 的 .decoded.bin 会被跳过，只保留 .strings.txt
                if (name.toLowerCase(Locale.ROOT).endsWith(".txt")) {
                    names.add(name);
                }
            }
        }
        return names;
    }

    /** 在 decoded 目录下查找匹配 artifact 名的文件，优先 .txt 避免 .bin */
    private static File findDecodedFile(File decodedDir, String artifactName) {
        final String target = artifactName.toLowerCase(Locale.ROOT);
        // 精确匹配：文件名以 _<artifact.name> 结尾（前缀是 <数字>_）
        File[] candidates = decodedDir.listFiles((dir, name) -> {
            String lower = name.toLowerCase(Locale.ROOT);
            return lower.endsWith("_" + target) || lower.equals(target);
        });
        if (candidates == null || candidates.length == 0) {
            // 回退：包含 artifactName 且以 .txt 结尾
            candidates = decodedDir.listFiles((dir, name) ->
                    name.toLowerCase(Locale.ROOT).contains(target) &&
                    name.toLowerCase(Locale.ROOT).endsWith(".txt"));
        }
        if (candidates == null || candidates.length == 0) return null;
        // 优先 .txt，避免 .bin 二进制
        for (File f : candidates) {
            if (f.getName().toLowerCase(Locale.ROOT).endsWith(".txt")) return f;
        }
        // 回退到非 .bin 文件
        for (File f : candidates) {
            if (!f.getName().toLowerCase(Locale.ROOT).endsWith(".bin")) return f;
        }
        return candidates[0];
    }

    /** 读取文件为文本，过滤不可打印字符，大文件截断显示 */
    private static String readFileAsText(File file) {
        long fileLen = file.length();
        if (fileLen > 512 * 1024) return "（文件过大，" + (fileLen / 1024) + "KB，请在报告压缩包中查看）";
        try (java.io.FileInputStream in = new java.io.FileInputStream(file)) {
            byte[] data = new byte[(int) fileLen];
            int offset = 0;
            while (offset < data.length) {
                int read = in.read(data, offset, data.length - offset);
                if (read < 0) break;
                offset += read;
            }
            String text = new String(data, 0, offset, StandardCharsets.UTF_8);
            StringBuilder clean = new StringBuilder();
            for (char c : text.toCharArray()) {
                if (c >= 32 || c == '\n' || c == '\r' || c == '\t') clean.append(c);
                else clean.append('.');
            }
            String result = clean.toString();
            // 对超大文本截断显示（保留前 32KB + 末尾 8KB）
            if (result.length() > 40 * 1024) {
                String head = result.substring(0, 32 * 1024);
                String tail = result.substring(result.length() - 8 * 1024);
                return head + "\n\n...（已截断，总长度 " + (result.length() / 1024) + " KB，完整内容请在报告压缩包中查看）...\n\n" + tail;
            }
            return result;
        } catch (Exception e) {
            return "（读取失败: " + e.getMessage() + "）";
        }
    }

    private static String featureExplanation(String title, DetectionStatus status, String reason) {
        StringBuilder sb = new StringBuilder();
        String lower = title.toLowerCase(Locale.ROOT);
        sb.append("该特征点位于 ").append(title.contains(" · ") ? title.split(" · ")[0] : title).append("，是 ACE 环境检测链中的关键位置。\n");
        if (lower.contains("rel_hook")) sb.append("REL_HOOK 系列是 libtprt 的内联 Hook 函数，用于拦截系统调用和关键 API。\n");
        else if (lower.contains("pfn_array") || lower.contains("ori_array")) sb.append("函数指针表保存了 ACE 拦截的系统函数地址，第三方工具会篡改此表以注入自定义逻辑。\n");
        else if (lower.contains("tp_syscall_imp")) sb.append("直接 syscall 实现是 ACE 反 Hook 的关键点，绕过 PLT 表直接调用内核。\n");
        else if (lower.contains("ptrace") || lower.contains("unwind")) sb.append("反调试检测核心，ACE 用 ptrace 和 unwind 检查是否有调试器附加。\n");
        else if (lower.contains("report") || lower.contains("tss")) sb.append("TSS 报告接口负责生成和发送环境检测报告。\n");
        else if (lower.contains("xor") || lower.contains("decrypt") || lower.contains("key_provider")) sb.append("XOR 解密函数和密钥提供者是 ACE 文件加密体系的核心。\n");
        else sb.append("该特征点用于验证 ACE 代码完整性。\n");
        if (status == DetectionStatus.RISK) sb.append("判定: 检测到异常信号，第三方工具可能正在干扰 ACE 检测逻辑。\n");
        else if (status == DetectionStatus.SUSPICIOUS) sb.append("判定: 存在可疑信号，需要进一步确认。\n");
        else sb.append("判定: 内容正常，未检测到篡改。\n");
        return sb.toString();
    }

    private static String fileExplanation(String name, DetectionResult result) {
        StringBuilder sb = new StringBuilder();
        // 文件作用
        sb.append("文件作用: ");
        if (name.contains("mrpcs")) sb.append("保存 ACE 要执行的环境扫描规则。\n");
        else if (name.contains("kvcache")) sb.append("保存 ACE 已写下的阶段性设备画像。\n");
        else if (name.contains("ano_rdp")) sb.append("保存设备指纹的摘要值。\n");
        else if (name.contains("ano.i.m")) sb.append("保存设备标识值。\n");
        else if (name.contains("comm.dat")) sb.append("保存检测开关和能力名称。\n");
        else if (name.contains("mpmc")) sb.append("保存 ACE 处理过的记录及完整性校验。\n");
        else if (name.contains("crt.i2")) sb.append("保存设备或客户端证书记录。\n");
        else if (name.contains("ano_ksh")) sb.append("保存内核 shell 环境信息。\n");
        else if (name.contains("kmc.dat")) sb.append("保存 ACE 可检查的设备节点和内核能力名称。\n");
        else sb.append("ACE 运行时创建或读取的辅助文件。\n");
        // ACE 检测中的角色
        sb.append("ACE 检测中的角色: ");
        if (name.contains("mrpcs") || name.startsWith("config")) sb.append("决定 ACE 检查哪些环境项目，是规则镜像本体。\n");
        else if (name.contains("kvcache") || name.contains("ano_rdp") || name.contains("mpmc")) sb.append("记录 ACE 从设备上读到的内容，供后续上报或复查使用。\n");
        else if (name.contains("comm")) sb.append("决定哪些检查开关和能力被启用。\n");
        else sb.append("属于 ACE 环境检测的辅助记录。\n");
        // 为何被检测
        sb.append("为何被检测: ");
        if (result.status == DetectionStatus.RISK) sb.append("该项已确认为风险观察值，应作为环境异常信号计入综合判断。\n");
        else if (result.status == DetectionStatus.SUSPICIOUS) sb.append("该项为未决信号，文件已读取但缺少明确命中值。\n");
        else sb.append("该项当前未呈现明确异常观察值。\n");
        // 环境判断
        sb.append("环境判断: ");
        sb.append(result.summary);
        return sb.toString();
    }

    private static String statusLabel(DetectionStatus status) {
        switch (status) {
            case PASS: return "正常";
            case RISK: return "异常";
            case SUSPICIOUS: return "可疑";
            default: return "未知";
        }
    }

    private static String extractField(String text, String prefix, String suffix) {
        if (text == null) return "—";
        int start = text.indexOf(prefix);
        if (start < 0) return "—";
        start += prefix.length();
        int end = text.indexOf(suffix, start);
        if (end < 0) end = text.length();
        return text.substring(start, end).trim();
    }

    private static String extractBlock(String text, String startMarker, String endMarker) {
        if (text == null) return "—";
        int start = text.indexOf(startMarker);
        if (start < 0) return "—";
        start += startMarker.length();
        int end = text.indexOf(endMarker, start);
        if (end < 0) end = text.length();
        return text.substring(start, end).trim();
    }

    private static String formatHexBlock(String hex) {
        if (hex == null || hex.isEmpty() || hex.equals("—")) return "  —";
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (int i = 0; i < hex.length(); i += 2) {
            if (count > 0 && count % 16 == 0) sb.append("\n  ");
            else if (count > 0) sb.append(" ");
            sb.append(hex, i, Math.min(i + 2, hex.length()));
            count++;
        }
        return "  " + sb.toString();
    }
}
