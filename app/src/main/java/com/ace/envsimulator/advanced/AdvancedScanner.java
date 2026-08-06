package com.ace.envsimulator.advanced;

import android.content.Context;
import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionResult;
import com.ace.envsimulator.model.DetectionStatus;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class AdvancedScanner {
    private static final String[] ANO_ROOTS = {
            "/data/user/0/com.tencent.tmgp.dfm/files/ano_tmp",
            "/data/data/com.tencent.tmgp.dfm/files/ano_tmp",
            "/data/user_de/0/com.tencent.tmgp.dfm/files/ano_tmp"
    };
    private static final String[] ANCHORS = {"ano_rdp.dat", "ano_rdp_2.dat", "mrpcs_a_v.data",
            "mrpcs_a_v_f.data", "mrpcs_a.data", "mrpcs_a_c.data", "comm.dat", "tss_ano.dat", "mpmc.dat"};
    // 手动创建的压缩包（非游戏生成），扫描时跳过不解码
    private static final Set<String> MANUAL_ARCHIVES = new LinkedHashSet<>(Arrays.asList(
            "ano_tmp.zip", "ano_dfh.zip", "大厅.zip", "对局.zip", "大厅前.zip"
    ));

    private static boolean isManualArchive(String name) {
        return MANUAL_ARCHIVES.contains(name);
    }

    public interface Listener { void onProgress(String stage, int completed, int total, DetectionResult result); }

    public ScanOutput run(Context context, Listener listener) {
        long scanStart = System.nanoTime();
        List<DetectionResult> results = new ArrayList<>();
        RootShell shell = new RootShell();
        if (Thread.currentThread().isInterrupted()) return new ScanOutput(results, "cancelled", "none", null);
        notify(listener, "正在请求 Root", 0, 1, null);
        RootShell.Result root = shell.request();
        if (root.exitCode != 0) {
            DetectionResult denied = DetectionResult.suspicious("advanced.root", "采集可用性", "Root 权限",
                    "高级模式未获得 uid 0", root.stderrText(), "高级模式只读访问目标私有目录前必须验证 id -u==0", 99,
                    elapsed(scanStart));
            results.add(denied); notify(listener, "Root 未授权", 1, 1, denied);
            return new ScanOutput(results, root.stderrText(), shell.variantName(), null);
        }
        DetectionResult granted = DetectionResult.pass("advanced.root", "高级模式", "Root 权限",
                "已获得只读采集所需的 uid 0", root.stdoutText(), "id -u==0；不修改目标目录", 99, elapsed(scanStart));
        results.add(granted); notify(listener, "Root 已授权，直接读取文件", 1, 1, granted);
        DetectionResult cryptoProfile = cryptoProfile(scanStart);
        results.add(cryptoProfile); notify(listener, "已加载文件族解码规格", 1, 1, cryptoProfile);
        File artifactDirectory = createArtifactDirectory(context);
        boolean sessionCopied = AdvancedSessionService.copyLastSession(context, artifactDirectory);
        DetectionResult runtimeSession = DetectionResult.ledger("advanced.runtime.session", "高级会话", "目标应用运行会话",
                sessionCopied ? DetectionStatus.PASS : DetectionStatus.SUSPICIOUS,
                sessionCopied ? "已保存目标进程生命周期、文件变化时间线和变化快照"
                        : "本轮没有找到完整的目标应用会话采集目录",
                "文件=runtime_session\n发现内容=" + AdvancedSessionService.sessionSummary(context) +
                        "\n说明=采集内容只包含进程是否存活、目标私有文件哈希与变化文件副本",
                "会话采集不读取或修改目标进程内存；只保存可复核的文件变化证据", 99, elapsed(scanStart));
        results.add(runtimeSession);
        notify(listener, "已整理目标应用会话", 1, 1, runtimeSession);
        DetectionResult apkInventory = scanApkInventory(shell, artifactDirectory, scanStart);
        results.add(apkInventory);
        notify(listener, "已遍历目标安装包文件", 1, 1, apkInventory);
        List<DecodedSource> decodedSources = new ArrayList<>();

        Set<String> paths = new LinkedHashSet<>();
        for (String rootPath : ANO_ROOTS) {
            if (Thread.currentThread().isInterrupted()) return new ScanOutput(results, "cancelled", shell.variantName(), artifactDirectory);
            StringBuilder direct = new StringBuilder();
            for (String anchor : ANCHORS) {
                String path = rootPath + "/" + anchor;
                direct.append("if [ -f ").append(RootShell.quote(path)).append(" ]; then printf '%s\\0' ")
                        .append(RootShell.quote(path)).append("; fi; ");
            }
            RootShell.Result anchors = shell.execute(direct.toString(), 4_000);
            if (anchors.exitCode == 0) addNullSeparated(paths, anchors.stdout);
            String filesRoot = rootPath.substring(0, rootPath.length() - "/ano_tmp".length());
            RootShell.Result listing = shell.execute("find " + RootShell.quote(filesRoot) + " -maxdepth 4 -type f -print0 2>/dev/null", 6_000);
            if (listing.exitCode == 0) addRelevant(paths, listing.stdout);
        }

        if (paths.isEmpty()) {
            String diagnostics = shell.diagnostics();
            DetectionResult missing = DetectionResult.suspicious("advanced.files.none", "采集可用性", "目标文件定位",
                    "未读取到 ano_tmp 或相关画像文件", "已直接尝试全部锚点并遍历三个包目录视图\n" + diagnostics,
                    "不等待大厅；文件存在但不可读时保留 su/SELinux/mount namespace 诊断", 95, elapsed(scanStart));
            results.add(missing); notify(listener, "没有可读文件", 1, 1, missing);
            return new ScanOutput(results, diagnostics, shell.variantName(), artifactDirectory);
        }

        ProfileParser parser = new ProfileParser();
        Set<String> seenContent = new LinkedHashSet<>();
        List<String> handledNames = new ArrayList<>();
        int resolvedFiles = 0;
        int pendingFiles = 0;
        int completed = 0;
        int total = Math.min(paths.size(), 256);
        int totalBytes = 0;
        for (String path : paths) {
            if (Thread.currentThread().isInterrupted()) break;
            if (completed >= 256) break;
            // 跳过手动创建的压缩包（非游戏生成，无需解码）
            String fname = fileName(path);
            if (isManualArchive(fname)) {
                notify(listener, "已跳过手动归档 " + fname, ++completed, total, null);
                continue;
            }
            long start = System.nanoTime();
            if (totalBytes >= 64 * 1024 * 1024) {
                DetectionResult boundary = DetectionResult.suspicious("advanced.limit", "采集可用性", "总读取上限",
                        "已达到 64 MiB 总读取上限，后续文件未读取", "next_path=" + path,
                        "资源边界不属于设备风险", 99, elapsed(start));
                results.add(boundary); notify(listener, "达到读取上限", ++completed, total, boundary); break;
            }
            RootShell.Result read = shell.readFile(path, 8 * 1024 * 1024);
            DetectionResult result;
            if (read.exitCode != 0) {
                result = DetectionResult.suspicious("advanced.file." + completed, "设备画像文件", fileName(path),
                        "文件已定位但读取失败", "path=" + path + "\nexit=" + read.exitCode + "\n" + read.stderrText(),
                        "单文件失败不终止后续解析", 85, elapsed(start));
            } else if ((long) totalBytes + read.stdout.length > 64L * 1024 * 1024) {
                result = DetectionResult.suspicious("advanced.file." + completed, "设备画像文件", fileName(path),
                        "达到 64 MiB 总读取上限", "path=" + path + "\nsize=" + read.stdout.length,
                        "只读采集的资源边界", 99, elapsed(start));
            } else {
                String name = fileName(path);
                String contentIdentity = name.toLowerCase(Locale.ROOT) + "|" + CheckSupport.sha256(read.stdout);
                if (!seenContent.add(contentIdentity)) {
                    notify(listener, "已跳过重复目录中的 " + name, ++completed, total, null);
                    continue;
                }
                totalBytes += read.stdout.length;
                ProfileParser.Interpretation parsed = parser.parse(path, read.stdout);
                decodedSources.add(new DecodedSource(path, parsed));
                handledNames.add(name);
                if (parsed.status == DetectionStatus.PASS) resolvedFiles++; else pendingFiles++;
                String friendly = friendlyFileSummary(name, parsed);
                StringBuilder evidenceBuilder = new StringBuilder("文件=").append(name)
                        .append("\n发现内容=").append(friendly).append('\n');
                String rawArtifact = writeArtifact(artifactDirectory, "raw/" + completed + "_" + fileName(path) + ".raw", read.stdout);
                evidenceBuilder.append("原始文件=").append(rawArtifact == null ? "本轮未能导出" : "已放入报告压缩包").append('\n');
                int decodedCount = 0;
                for (ProfileParser.Artifact artifact : parsed.artifacts) {
                    String decodedArtifact = writeArtifact(artifactDirectory, "decoded/" + completed + "_" + artifact.name, artifact.data);
                    if (decodedArtifact != null) { evidenceBuilder.append("解密文件=").append(artifact.name)
                            .append("（已放入报告压缩包）\n");
                        decodedCount++;
                    }
                }
                if (decodedCount == 0) evidenceBuilder.append("解密文件=当前只保留原始文件\n");
                String evidence = evidenceBuilder.toString();
                result = DetectionResult.ledger("advanced.file." + completed,
                        "本轮文件", name, parsed.status, friendly, evidence,
                        "按该文件对应的已验证格式读取；详细技术数据仅写入导出包", parsed.confidence, elapsed(start));
            }
            results.add(result);
            notify(listener, "正在解读设备画像", ++completed, total, result);
        }

        SessionDecodeStats sessionStats = decodeSessionSnapshots(parser, artifactDirectory, decodedSources,
                seenContent, results, listener, scanStart);
        resolvedFiles += sessionStats.resolved;
        pendingFiles += sessionStats.pending;
        handledNames.addAll(sessionStats.names);

        DetectionStatus filesStatus = pendingFiles == 0 ? DetectionStatus.PASS : DetectionStatus.SUSPICIOUS;
        DetectionResult filesSummary = DetectionResult.ledger("advanced.files.summary", "本轮结果", "本轮读取文件",
                filesStatus,
                "本轮共处理 " + handledNames.size() + " 个不重复文件，其中 " + resolvedFiles + " 个已按已知格式读取",
                "文件=" + String.join("、", handledNames) +
                        "\n说明=同一文件经多个 Root 目录别名出现时只计算一次",
                "逐个读取全部相关文件，按文件名与内容摘要去重", 99, elapsed(scanStart));
        results.add(filesSummary);
        notify(listener, "全部文件读取完成", 1, 1, filesSummary);

        addAdvancedFindings(results, listener, decodedSources, artifactDirectory, scanStart);
        return new ScanOutput(results, "", shell.variantName(), artifactDirectory);
    }

    private static SessionDecodeStats decodeSessionSnapshots(ProfileParser parser, File artifactDirectory,
                                                              List<DecodedSource> sources, Set<String> seenContent,
                                                              List<DetectionResult> results, Listener listener,
                                                              long scanStart) {
        SessionDecodeStats stats = new SessionDecodeStats();
        if (artifactDirectory == null) return stats;
        File snapshots = new File(new File(artifactDirectory, "runtime_session"), "snapshots");
        File[] files = snapshots.listFiles(File::isFile);
        if (files == null) return stats;
        Arrays.sort(files, (left, right) -> left.getName().compareTo(right.getName()));
        int index = 0;
        for (File snapshot : files) {
            if (index >= 256 || snapshot.length() > 8L * 1024L * 1024L) break;
            byte[] data = readLocal(snapshot, 8 * 1024 * 1024);
            if (data == null) continue;
            String originalName = sessionOriginalName(snapshot.getName());
            String identity = originalName.toLowerCase(Locale.ROOT) + "|" + CheckSupport.sha256(data);
            if (!seenContent.add(identity)) continue;
            ProfileParser.Interpretation parsed = parser.parse("/runtime_session/" + originalName, data);
            sources.add(new DecodedSource("/runtime_session/" + originalName, parsed));
            stats.names.add("会话快照:" + originalName);
            if (parsed.status == DetectionStatus.PASS) stats.resolved++; else stats.pending++;
            StringBuilder evidence = new StringBuilder("文件=").append(originalName)
                    .append("\n发现内容=").append(friendlyFileSummary(originalName, parsed))
                    .append("\n会话快照=").append(snapshot.getName())
                    .append("\n说明=该文件内容在目标应用运行期间发生变化并被只读保存");
            int artifactIndex = 0;
            for (ProfileParser.Artifact artifact : parsed.artifacts) {
                String decoded = writeArtifact(artifactDirectory,
                        "decoded/session_" + index + "_" + artifactIndex + "_" + artifact.name, artifact.data);
                if (decoded != null) evidence.append("\n解密文件=").append(new File(decoded).getName());
                artifactIndex++;
            }
            DetectionResult result = DetectionResult.ledger("advanced.file.session." + index,
                    "会话变化文件", originalName, parsed.status,
                    friendlyFileSummary(originalName, parsed), evidence.toString(),
                    "仅解析运行期间哈希发生变化的文件快照；相同内容按文件名与 SHA-256 去重",
                    parsed.confidence, elapsed(scanStart));
            results.add(result);
            notify(listener, "正在解读会话变化 " + originalName, index + 1, files.length, result);
            index++;
        }
        return stats;
    }

    private static byte[] readLocal(File file, int limit) {
        if (file.length() < 0 || file.length() > limit) return null;
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            int offset = 0;
            while (offset < data.length) {
                int read = in.read(data, offset, data.length - offset);
                if (read < 0) break;
                offset += read;
            }
            return offset == data.length ? data : null;
        } catch (Exception ignored) { return null; }
    }

    private static String sessionOriginalName(String snapshotName) {
        int first = snapshotName.indexOf('_');
        int last = snapshotName.lastIndexOf('_');
        if (first < 0 || last <= first) return snapshotName;
        return snapshotName.substring(first + 1, last);
    }

    private static final class SessionDecodeStats {
        int resolved;
        int pending;
        final List<String> names = new ArrayList<>();
    }

    private static File createArtifactDirectory(Context context) {
        File reports = new File(context.getFilesDir(), "reports");
        File directory = new File(reports, "advanced_sources_" +
                new SimpleDateFormat("yyyyMMdd_HHmmss_SSS", Locale.US).format(new Date()));
        return directory.mkdirs() || directory.isDirectory() ? directory : null;
    }

    private static DetectionResult scanApkInventory(RootShell shell, File artifactDirectory, long scanStart) {
        List<String> apkPaths = shell.targetApkPaths();
        if (apkPaths.isEmpty()) {
            return DetectionResult.ledger("advanced.apk.inventory", "安装包检查", "目标安装包文件",
                    DetectionStatus.SUSPICIOUS,
                    "没有从系统包管理器取得目标 APK 路径",
                    "安装包=未定位\n说明=这不影响 ano_tmp 文件读取，但无法检查安装包内的静态规则",
                    "只读取 pm path 返回的目标包路径", 90, elapsed(scanStart));
        }
        StringBuilder allEntries = new StringBuilder();
        List<String> interesting = new ArrayList<>();
        int failed = 0;
        for (String apk : apkPaths) {
            RootShell.Result listing = shell.execute("unzip -l " + RootShell.quote(apk) + " 2>/dev/null", 12_000);
            String name = fileName(apk);
            allEntries.append("APK=").append(name).append('\n');
            if (listing.exitCode != 0) {
                failed++;
                allEntries.append("读取=失败\n");
                continue;
            }
            for (String row : listing.stdoutText().split("\\r?\\n")) {
                String trimmed = row.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("Archive:") || trimmed.startsWith("Length") ||
                        trimmed.startsWith("--------") || trimmed.matches("\\d+ files?")) continue;
                String[] columns = trimmed.split("\\s+", 4);
                if (columns.length < 4) continue;
                String entry = columns[3];
                allEntries.append(entry).append('\n');
                String lower = entry.toLowerCase(Locale.ROOT);
                if (containsAny(lower, "ano_tmp", "mrpcs", "config2", "config3", "kvcache", "report", "upload",
                        "coordinate", "root", "ksu", "cert", "fingerprint", "deviceuniqueid"))
                    interesting.add(name + " -> " + entry);
            }
        }
        String artifact = writeArtifact(artifactDirectory, "apk/apk_entries.txt",
                allEntries.toString().getBytes(StandardCharsets.UTF_8));
        String evidence = "安装包数量=" + apkPaths.size() + "\n" +
                "安装包文件=" + String.join("、", apkFileNames(apkPaths)) + "\n" +
                "可疑文件名=" + (interesting.isEmpty() ? "未发现" : String.join("；", interesting)) +
                "\n完整文件清单=" + (artifact == null ? "本轮未能导出" : "已放入报告压缩包");
        if (interesting.isEmpty() && failed == 0) {
            return DetectionResult.ledger("advanced.apk.inventory", "安装包检查", "目标安装包文件",
                    DetectionStatus.PASS,
                    "已遍历全部安装包，没有发现单独保存本机检测结果的文件名",
                    evidence + "\n说明=安装包主要提供代码和规则；本机结果通常写入私有目录文件",
                    "只把文件名作为线索，不把静态规则当成本机命中", 98, elapsed(scanStart));
        }
        return DetectionResult.ledger("advanced.apk.inventory", "安装包检查", "目标安装包文件",
                DetectionStatus.SUSPICIOUS,
                interesting.isEmpty() ? "安装包已遍历，但部分文件清单读取失败" : "安装包中发现可能与检测或上报有关的文件名",
                evidence + "\n说明=安装包线索只能说明代码或规则存在，不能替代本机画像文件中的实际观察值",
                "APK 级结果只作为静态线索，运行时结果仍以目标私有文件为准", 98, elapsed(scanStart));
    }

    private static List<String> apkFileNames(List<String> paths) {
        List<String> names = new ArrayList<>();
        for (String path : paths) names.add(fileName(path));
        return names;
    }

    private static DetectionResult cryptoProfile(long scanStart) {
        String evidence = "结论来源=libtersafe.so 静态逆向 + 独立设备文件 CRC/结构校验\n" +
                "固定循环 XOR=sub_237E08；密钥提供者=sub_4E9A50(30548)；周期=36 字节\n" +
                "ano_rdp.dat=固定 36 字节循环 XOR，魔数 0x20220920\n" +
                "crt.i2.dat/ano_ksh.dat=同一固定字符串变换；分别由 sub_4D949C 与 sub_4D1EE8 读取\n" +
                "mrpcs_a_v.data=ZIP 内层 [4,EOF) XOR 0x4F + CRC32\n" +
                "mrpcs_a_v_f.data=ZIP 内层 [4,EOF) XOR 0x84 + CRC32\n" +
                "a64.dat=库内固定 256 字节查表 + XOR 0x23\n" +
                "运行态要求=解码上述已验证文件不需要目标进程存活；目标进程只影响文件是否已生成或刷新\n" +
                "未注册格式=尚未恢复容器或字段规格，不解释为动态密钥失败";
        return DetectionResult.ledger("advanced.crypto.profile", "文件解码台账", "密钥与运行态依赖",
                DetectionStatus.PASS, "已验证文件族使用静态、按格式区分的变换",
                evidence, "只有结构边界和 CRC/摘要同时通过才标记为已解码；未知文件保持未决", 99,
                elapsed(scanStart));
    }

    private static String interpretationMeaning(ProfileParser.Interpretation parsed) {
        if (parsed.status == DetectionStatus.RISK)
            return "出现可验证的明确异常；详情中的字节、摘要或环境字段是判定依据";
        if (parsed.status == DetectionStatus.PASS)
            return "容器、解码或完整性校验成功；规则能力字符串不等于本机已被命中";
        return "文件已经读取，但字段语义、配置开关或设备命中事件尚未闭合，暂不伪造结论";
    }

    private static String friendlyFileSummary(String name, ProfileParser.Interpretation parsed) {
        if ("mrpcs_a_v.data".equals(name) || "mrpcs_a_v_f.data".equals(name))
            return "已打开扫描规则，里面包含 Root、设备标识、应用和进程检查项";
        if ("mrpcs_a.data".equals(name) || "mrpcs_a_c.data".equals(name))
            return "已提取文件内容和可读文字，内部字段名称仍需确认";
        if ("kvcache8.dat".equals(name)) return "已读取设备画像记录";
        if ("ano_rdp.dat".equals(name)) return "已读取设备指纹摘要";
        if ("ano.i.m.dat".equals(name)) return "已读取设备标识记录";
        if ("ano.ano3.dat".equals(name) || "rcu.o.dat".equals(name) ||
                name.startsWith("ano_app_") || "tersafe.update".equals(name)) return parsed.summary;
        if ("comm.dat".equals(name) || "comm.zip".equals(name)) return "已读取检测开关表";
        if (parsed.status == DetectionStatus.PASS) return "文件已读取，当前内容没有直接显示设备异常";
        return "文件已读取，暂未找到可以直接告诉用户的检测结果";
    }

    private static String writeArtifact(File root, String relativeName, byte[] data) {
        if (root == null || data == null) return null;
        try {
            String[] pieces = relativeName.replace('\\', '/').split("/");
            File current = root;
            for (int i = 0; i < pieces.length - 1; i++) {
                String piece = pieces[i].replace("..", "_").replaceAll("[^A-Za-z0-9._-]", "_");
                current = new File(current, piece);
            }
            if (!current.exists() && !current.mkdirs()) return null;
            String leaf = pieces[pieces.length - 1].replace("..", "_").replaceAll("[^A-Za-z0-9._-]", "_");
            File target = new File(current, leaf);
            String rootPath = root.getCanonicalPath() + File.separator;
            if (!target.getCanonicalPath().startsWith(rootPath)) return null;
            try (FileOutputStream out = new FileOutputStream(target)) { out.write(data); }
            return target.getAbsolutePath();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static void addAdvancedFindings(List<DetectionResult> results, Listener listener,
                                            List<DecodedSource> sources, File artifactDirectory,
                                            long scanStart) {
        addDecodedObservations(results, listener, sources, scanStart);
        addRuntimeReportInterfaces(results, listener, artifactDirectory, scanStart);
        DecodedSource mrpcs = sourceContaining(sources, "/data/adb/ksud");
        if (mrpcs == null) mrpcs = sourceContaining(sources, "rule_capabilities=");
        DecodedSource rdp = sourceByName(sources, "ano_rdp.dat");
        DecodedSource crt = sourceByName(sources, "crt.i2.dat");
        DecodedSource key = sourceByName(sources, "key");
        DecodedSource serial = sourceByName(sources, "serial");
        DecodedSource rootEvent = sourceWithSignal(sources, "root.detected");
        DecodedSource managerEvent = sourceWithSignal(sources, "root.manager.detected");
        DecodedSource bootEvent = sourceWithSignal(sources, "boot.unlocked.detected");
        boolean ksuRule = mrpcs != null && mrpcs.parsed.evidence.toLowerCase(Locale.US).contains("/data/adb/ksud");

        addFinding(results, listener, finding("advanced.finding.root", "Root / KernelSU",
                rootEvent != null ? DetectionStatus.RISK : DetectionStatus.SUSPICIOUS,
                rootEvent != null ? "目标文件包含明确 Root 画像事件"
                        : ksuRule ? "MRPCS 完整解码文件包含 KernelSU 守护进程扫描路径，确认该规则镜像覆盖 KernelSU"
                        : "解码文件中尚未定位 Root 画像值或 KernelSU 扫描规则",
                rootEvent != null ? rootEvent : mrpcs,
                rootEvent != null ? signalEvidence(rootEvent, "root.detected") : ksuRule ? "rule_capabilities: /data/adb/ksud, ksud" : "未定位",
                rootEvent == null ? (mrpcs == null ? "规则镜像未解码" : mrpcs.parsed.evidence) : signalEvidence(rootEvent, "root.detected"),
                rootEvent != null ? "画像事件字段明确出现" : ksuRule ? "解码后的静态规则文件出现 KernelSU 专用扫描路径" : "未定位",
                rootEvent != null ? "本机画像发现 Root 事件" : ksuRule ? "确认 ACE 规则会扫描 KernelSU；不等价于本机已安装" : "未发现", scanStart));

        addFinding(results, listener, finding("advanced.finding.root_manager", "Root 管理器与工具",
                managerEvent != null ? DetectionStatus.RISK : DetectionStatus.SUSPICIOUS,
                managerEvent != null ? "目标文件包含明确管理器画像记录"
                        : ksuRule ? "解码规则镜像发现 KernelSU 管理器/守护进程扫描能力" : "未定位管理器画像或规则",
                managerEvent != null ? managerEvent : mrpcs,
                managerEvent != null ? signalEvidence(managerEvent, "root.manager.detected") : ksuRule ? "/data/adb/ksud" : "未定位",
                managerEvent == null ? (mrpcs == null ? "规则镜像未解码" : mrpcs.parsed.evidence) : signalEvidence(managerEvent, "root.manager.detected"),
                managerEvent != null ? "画像字段直接包含管理器记录" : ksuRule ? "专用路径存在于完整解码规则镜像" : "未定位",
                managerEvent != null ? "本机画像发现管理器记录" : ksuRule ? "确认扫描范围包含 KernelSU 管理器" : "未发现", scanStart));

        addFinding(results, listener, finding("advanced.finding.boot", "BL / Verified Boot",
                bootEvent == null ? DetectionStatus.SUSPICIOUS : DetectionStatus.RISK,
                bootEvent == null ? "未从目标持久文件解出 BL/Verified Boot 命中事件" : "目标文件包含明确 BL 风险事件值",
                bootEvent, bootEvent == null ? "尚未恢复经过验证的 BL 事件字段名" : signalEvidence(bootEvent, "boot.unlocked.detected"),
                bootEvent == null ? "未恢复对应字段" : signalEvidence(bootEvent, "boot.unlocked.detected"),
                bootEvent == null ? "缺少目标文件事件值，按风险待闭合" : "明确事件字段等于 1",
                bootEvent == null ? "未找到 ACE 持久化 BL 上报事件字段" : "目标解码文件提供明确命中值", scanStart));

        String rdpFields = rdp == null ? "文件未读取或格式未恢复" : rdp.parsed.evidence;
        addFinding(results, listener, finding("advanced.finding.fingerprint", "设备指纹",
                DetectionStatus.SUSPICIOUS,
                rdp != null && rdpFields.contains("decoded_digest=")
                        ? "ano_rdp 已解出设备摘要，但没有原像、有效/失效或上报判定字段"
                        : "指纹摘要或有效性判定尚未闭合",
                rdp, "decoded_digest", rdpFields,
                "只证明目标文件保存了摘要，不证明白名单通过或失效",
                "未找到 fingerprint_valid 或对应上报事件值", scanStart));

        addFinding(results, listener, finding("advanced.finding.certificate", "设备与客户端证书",
                DetectionStatus.SUSPICIOUS,
                crt == null ? "crt.i2.dat 未取得" : "crt.i2.dat 已解出证书记录，尚无本机证书匹配结果字段",
                crt, "certificate_id / subject / type", crt == null ? "无" : crt.parsed.evidence,
                "记录容器已解析；记录存在不等于本机命中",
                "未找到 certificate_hit/valid 的持久化事件值", scanStart));

        String keyEvidence = "key=" + (key == null ? "未读取" : fileName(key.path)) +
                "\nserial=" + (serial == null ? "未读取" : fileName(serial.path)) +
                "\n规则能力=" + (mrpcs == null ? "未恢复" : "MRPCS 出现 files/key 与 files/serial 读取路径");
        addFinding(results, listener, finding("advanced.finding.device_key", "设备密钥与序列",
                DetectionStatus.SUSPICIOUS, "已确认读取能力，但本次没有密钥有效/失效或黑白名单命中字段",
                key != null ? key : serial, "files/key / files/serial", keyEvidence,
                "实体文件与名单比较结果缺失",
                "未找到 key_valid、serial_valid 或名单命中上报值", scanStart));

        addFinding(results, listener, finding("advanced.finding.packages", "应用、工具与客户端异常",
                DetectionStatus.SUSPICIOUS,
                mrpcs == null ? "尚未解码包、文件与进程扫描规则" : "MRPCS 解码结果确认包含包、文件、maps 与工具扫描规则",
                mrpcs, "package/path/process rule capability", mrpcs == null ? "MRPCS 未解码" : mrpcs.parsed.evidence,
                mrpcs == null ? "未定位" : "完整规则镜像中存在对应扫描端点",
                mrpcs == null ? "未发现" : "确认 ACE 的扫描范围；本机观察值另见设备画像条目", scanStart));

        addFinding(results, listener, finding("advanced.finding.upload", "ACE 最终上报数据",
                DetectionStatus.SUSPICIOUS, "已采集文件中没有完整明文上报包或事件码到含义映射",
                null, "report payload / event code", "已解码文件数=" + sources.size(),
                "解码台账不参与设备风险；只接受实际事件字段",
                "当前持久文件未提供可验证的最终上报值", scanStart));

        addFinding(results, listener, finding("advanced.finding.coordinate", "坐标销毁关联状态",
                DetectionStatus.SUSPICIOUS, "尚未在 ano_tmp 中恢复客户端环境判定到坐标销毁状态的持久化关联字段",
                null, "environment verdict -> coordinate state", "未找到可验证关联字段",
                "不得用规则文件、CRC 或本机 Root 权限推断坐标状态",
                "未找到 coordinate_destroy/encrypt_state 的上报或状态值", scanStart));

        addMemoryScanFindings(results, listener, artifactDirectory, scanStart);

        int definite = 0;
        for (DetectionResult item : results)
            if ((item.id.startsWith("advanced.finding.") || item.id.startsWith("advanced.observation."))
                    && item.status == DetectionStatus.RISK) definite++;
        DetectionResult classification = definite > 0
                ? DetectionResult.risk("advanced.classification", "高级结论", "ACE 画像证据综合结论",
                "完整解码中发现 " + definite + " 项本机明确观察值；逐项来源、字段和值均已公示",
                "本机明确观察项=" + definite + "\n解密文件=已随报告压缩包导出" +
                        "\n结论边界=规则能力与本机画像分开标记；不推测服务端是否接收",
                "只汇总明确的画像观察或事件值；静态扫描规则不计入本机命中", 99, elapsed(scanStart))
                : DetectionResult.suspicious("advanced.classification", "高级结论", "ACE 画像证据综合结论",
                "完整解码中尚未发现可确认的本机异常观察值；规则覆盖范围与未决项已逐项列出",
                "解密文件=已随报告压缩包导出\n解码文件数=" + sources.size(),
                "只按解码字段和值执行固定归类公式；规则字符串不计作本机命中", 99, elapsed(scanStart));
        results.add(classification);
        notify(listener, "高级文件解码与逐项解读完成", 1, 1, classification);
    }

    private static void addMemoryScanFindings(List<DetectionResult> results, Listener listener,
                                              File artifactDirectory, long scanStart) {
        File memscanDir = artifactDirectory == null ? null :
                new File(new File(artifactDirectory, "runtime_session"), "memscan");
        if (memscanDir == null || !memscanDir.isDirectory()) {
            DetectionResult none = DetectionResult.ledger("advanced.memscan.summary", "运行时内存扫描",
                    "目标进程内存扫描结果",
                    DetectionStatus.SUSPICIOUS,
                    "本轮会话未采集到内存扫描数据",
                    "扫描来源=ace_scanner 原生二进制 + root shell\n" +
                    "发现=未运行或会话目录未找到 memscan 子目录\n" +
                    "设备判定=需要用户在高级模式下进入目标应用并手动结束后才会生成内存扫描数据\n" +
                    "上报结论=内存扫描未执行，无法确认运行时检测内容",
                    "内存扫描是 v2.2 新增能力；确保高级会话期间目标进程在前台运行", 99, elapsed(scanStart));
            results.add(none);
            notify(listener, "内存扫描未执行", 1, 1, none);
            return;
        }

        // ===== v2.5: 优先输出特征点定位扫描结果 (FEATURE| 格式) =====
        List<MemoryScanner.MemFeature> features = MemoryScanner.parseFeatures(memscanDir);
        if (!features.isEmpty()) {
            addFeatureScanResults(results, listener, artifactDirectory, features, scanStart);
        }

        // ===== 保留原模式扫描结果 (HIT| 格式) =====
        List<MemoryScanner.MemHit> hits = MemoryScanner.parseResults(memscanDir);
        Map<String, List<MemoryScanner.MemHit>> categorized = MemoryScanner.categorize(hits);

        int totalHits = hits.size();
        int categories = categorized.size();

        // 保存原始内存扫描结果到 artifact
        if (artifactDirectory != null && !hits.isEmpty()) {
            StringBuilder dump = new StringBuilder();
            dump.append("内存扫描命中汇总\n");
            dump.append("总命中数=").append(totalHits).append("\n");
            dump.append("分类数=").append(categories).append("\n\n");
            for (Map.Entry<String, List<MemoryScanner.MemHit>> entry : categorized.entrySet()) {
                dump.append("=== ").append(MemoryScanner.categoryLabel(entry.getKey()))
                   .append(" (").append(entry.getValue().size()).append(" 命中) ===\n");
                for (MemoryScanner.MemHit h : entry.getValue()) {
                    dump.append("  ").append(h.pattern).append(" @ ").append(h.address);
                    if (!h.context.isEmpty()) dump.append(" ctx=").append(h.context);
                    dump.append("\n");
                }
                dump.append("\n");
            }
            writeArtifact(artifactDirectory, "memscan/memscan_results.txt",
                    dump.toString().getBytes(StandardCharsets.UTF_8));
        }

        // 内存扫描总览
        String summaryText = totalHits == 0
                ? "内存扫描已完成，本轮在目标进程内存中未命中任何检测模式"
                : "内存扫描已完成，在目标进程内存中命中 " + totalHits + " 项检测模式，覆盖 " + categories + " 个分类";
        StringBuilder evidenceBuilder = new StringBuilder();
        evidenceBuilder.append("扫描来源=ace_scanner 原生二进制(process_vm_readv root) + root shell(dd /proc/pid/mem)\n");
        evidenceBuilder.append("扫描了=目标进程 com.tencent.tmgp.dfm 的所有可写内存区域和 libtersafe.so 段\n");
        evidenceBuilder.append("发现了=").append(totalHits).append(" 项命中，覆盖 ").append(categories).append(" 个分类\n");
        if (categories > 0) {
            evidenceBuilder.append("命中分类=");
            for (String cat : categorized.keySet()) {
                evidenceBuilder.append(MemoryScanner.categoryLabel(cat))
                        .append("(").append(categorized.get(cat).size()).append(")、");
            }
            evidenceBuilder.append("\n");
        }
        evidenceBuilder.append("设备判定=");
        if (categorized.containsKey("root") || categorized.containsKey("frida") ||
            categorized.containsKey("xposed") || categorized.containsKey("hook"))
            evidenceBuilder.append("目标进程内存中发现 Root/Frida/Xposed/Hook 相关数据，ACE 可能已扫描到这些环境特征\n");
        else if (totalHits > 0)
            evidenceBuilder.append("目标进程内存中发现 ACE 检测相关数据，但未发现明确的 Root/注入/Hook 命中\n");
        else
            evidenceBuilder.append("目标进程内存中未发现 ACE 检测模式的运行时数据\n");
        evidenceBuilder.append("上报结论=内存中的模式命中表示 ACE 的扫描代码和规则在运行时存在；具体是否已上报需结合 TSS 报告接口数据\n");
        evidenceBuilder.append("原始数据=已随报告压缩包导出 memscan/memscan_results.txt\n");

        DetectionResult summary = DetectionResult.ledger("advanced.memscan.summary", "运行时内存扫描",
                "目标进程内存扫描结果",
                totalHits > 0 && (categorized.containsKey("root") || categorized.containsKey("frida") ||
                        categorized.containsKey("xposed") || categorized.containsKey("hook"))
                        ? DetectionStatus.RISK : totalHits > 0 ? DetectionStatus.SUSPICIOUS : DetectionStatus.PASS,
                summaryText, evidenceBuilder.toString(),
                "双路并行扫描：原生二进制 process_vm_readv + root shell dd /proc/pid/mem；结果去重后按分类汇总", 99,
                elapsed(scanStart));
        results.add(summary);
        notify(listener, "内存扫描结果汇总", 1, 1, summary);

        // 按分类输出详细结果
        int catIndex = 0;
        for (Map.Entry<String, List<MemoryScanner.MemHit>> entry : categorized.entrySet()) {
            String cat = entry.getKey();
            List<MemoryScanner.MemHit> catHits = entry.getValue();
            String label = MemoryScanner.categoryLabel(cat);

            StringBuilder catEvidence = new StringBuilder();
            catEvidence.append("扫描来源=目标进程内存 (").append(memscanDir.getName()).append(")\n");
            catEvidence.append("扫描了=").append(label).append(" 相关内存模式\n");
            catEvidence.append("发现了=").append(catHits.size()).append(" 项命中\n");
            int shown = 0;
            for (MemoryScanner.MemHit h : catHits) {
                if (shown >= 20) { catEvidence.append("...更多命中见导出文件\n"); break; }
                catEvidence.append("  [").append(h.pattern).append("] @ ").append(h.address);
                if (!h.context.isEmpty()) catEvidence.append("  ctx=").append(h.context);
                catEvidence.append("\n");
                shown++;
            }
            catEvidence.append("设备判定=");
            boolean isRisk = "root".equals(cat) || "frida".equals(cat) || "xposed".equals(cat) ||
                    "hook".equals(cat) || "boot".equals(cat);
            if (isRisk) catEvidence.append("在目标进程内存中发现 ").append(label).append(" 相关数据，ACE 可能已检测到此项\n");
            else catEvidence.append("在目标进程内存中发现 ").append(label).append(" 相关数据\n");
            catEvidence.append("上报结论=内存命中表示 ACE 的扫描代码在运行时处理了这些模式；是否已生成报告需结合 TSS 接口数据\n");

            DetectionResult catResult = DetectionResult.ledger(
                    "advanced.memscan." + cat, "内存扫描 · " + label,
                    label + " 内存命中",
                    isRisk ? DetectionStatus.RISK : DetectionStatus.SUSPICIOUS,
                    catHits.size() + " 项 " + label + " 相关内存命中",
                    catEvidence.toString(),
                    "内存扫描命中按分类汇总；同一模式和地址已去重", 95, elapsed(scanStart));
            results.add(catResult);
            notify(listener, "内存扫描 " + label, 1, 1, catResult);
            catIndex++;
        }
    }

    // v2.5: 特征点定位扫描结果 - 逐点输出，作为首屏结果
    private static void addFeatureScanResults(List<DetectionResult> results, Listener listener,
                                               File artifactDirectory,
                                               List<MemoryScanner.MemFeature> features, long scanStart) {
        int scanned = 0, passCount = 0, suspiciousCount = 0, riskCount = 0, unreadableCount = 0;

        // 保存特征点原始数据到 artifact
        if (artifactDirectory != null) {
            StringBuilder dump = new StringBuilder();
            dump.append("内存特征点定位扫描结果 (v2.5)\n");
            dump.append("总特征点数=").append(features.size()).append("\n\n");
            for (MemoryScanner.MemFeature f : features) {
                dump.append("[").append(f.status).append("] ").append(f.module).append("+").append(f.offset)
                   .append(" @ ").append(f.address).append("  ").append(f.name).append("\n");
                dump.append("  原因: ").append(f.reason).append("\n");
                dump.append("  内容: ").append(f.hex).append("\n\n");
            }
            writeArtifact(artifactDirectory, "memscan/feature_points.txt",
                    dump.toString().getBytes(StandardCharsets.UTF_8));
        }

        // 逐点输出
        for (int i = 0; i < features.size(); i++) {
            MemoryScanner.MemFeature f = features.get(i);
            DetectionStatus status;
            switch (f.status) {
                case "pass": status = DetectionStatus.PASS; passCount++; break;
                case "risk": status = DetectionStatus.RISK; riskCount++; break;
                case "suspicious": status = DetectionStatus.SUSPICIOUS; suspiciousCount++; break;
                case "unreadable":
                case "unavailable":
                default: status = DetectionStatus.SUSPICIOUS; unreadableCount++; break;
            }
            scanned++;

            String categoryLabel = featureCategoryLabel(f);
            StringBuilder evidence = new StringBuilder();
            evidence.append("扫描来源=ace_scanner v2.5 (process_vm_readv + /proc/pid/mem 回退)\n");
            evidence.append("扫描了=").append(f.module).append("+").append(f.offset).append("\n");
            evidence.append("虚拟地址=").append(f.address).append("\n");
            evidence.append("特征点=").append(f.name).append("\n");
            evidence.append("读取内容(64字节 HEX)=\n").append(formatHexDisplay(f.hex)).append("\n");
            evidence.append("设备判定=").append(f.reason).append("\n");
            evidence.append("上报结论=");
            if ("risk".equals(f.status)) {
                evidence.append("该特征点检测到异常，ACE 可能已记录此项\n");
            } else if ("pass".equals(f.status)) {
                evidence.append("该特征点内容正常，ACE 未在此处发现异常\n");
            } else if ("unreadable".equals(f.status) || "unavailable".equals(f.status)) {
                evidence.append("该特征点不可读取或模块未加载，需要确认目标进程是否在前台运行\n");
            } else {
                evidence.append("该特征点存在可疑信号，需要进一步分析\n");
            }

            DetectionResult result = DetectionResult.ledger(
                    "advanced.memscan.feature." + i, "内存特征点 · " + categoryLabel,
                    f.module + "+" + f.offset + " · " + f.name,
                    status,
                    f.reason,
                    evidence.toString(),
                    "特征点定位扫描：/proc/[pid]/maps 解析模块基址 (ASLR-aware) + process_vm_readv 读取 64 字节 + 基线对比判定",
                    99, elapsed(scanStart));
            results.add(result);
            notify(listener, "特征点 " + f.name, i + 1, features.size(), result);
        }

        // 特征点扫描总览
        DetectionStatus overviewStatus = riskCount > 0 ? DetectionStatus.RISK
                : suspiciousCount > 0 || unreadableCount > 0 ? DetectionStatus.SUSPICIOUS
                : DetectionStatus.PASS;
        String overviewText = String.format(Locale.ROOT,
                "特征点定位扫描完成 · 已扫描 %d · 正常 %d · 可疑 %d · 异常 %d · 不可读 %d",
                scanned, passCount, suspiciousCount, riskCount, unreadableCount);
        StringBuilder overviewEvidence = new StringBuilder();
        overviewEvidence.append("扫描来源=ace_scanner v2.5 (30+ 特征点数据库)\n");
        overviewEvidence.append("扫描了=libtersafe.so / libtprt.so / libUE4.so / libGPM.so 关键偏移\n");
        overviewEvidence.append("发现了=").append(riskCount).append(" 项异常，").append(suspiciousCount)
                       .append(" 项可疑，").append(passCount).append(" 项正常\n");
        overviewEvidence.append("设备判定=");
        if (riskCount > 0) overviewEvidence.append("检测到 Hook 篡改或反调试绕过，环境异常\n");
        else if (suspiciousCount > 0) overviewEvidence.append("部分特征点可疑，需进一步分析\n");
        else overviewEvidence.append("所有特征点代码完整，环境正常\n");
        overviewEvidence.append("上报结论=特征点扫描结果反映 ACE 自身代码完整性；Hook/反调试异常会直接影响环境判定\n");
        overviewEvidence.append("原始数据=已随报告压缩包导出 memscan/feature_points.txt\n");

        DetectionResult overview = DetectionResult.ledger(
                "advanced.memscan.feature.summary", "内存特征点扫描", "特征点定位扫描总览",
                overviewStatus, overviewText, overviewEvidence.toString(),
                "v2.5 特征点定位扫描：基于 IDA 逆向的 30+ 关键偏移，逐一读取并基线对比", 99, elapsed(scanStart));
        results.add(overview);
        notify(listener, "特征点扫描总览", 1, 1, overview);
    }

    private static String featureCategoryLabel(MemoryScanner.MemFeature f) {
        String cat = f.category();
        switch (cat) {
            case "hook": return "Hook 检测";
            case "antidebug": return "反调试";
            case "report": return "TSS 报告";
            case "crypto": return "加密/密钥";
            case "cert": return "证书";
            case "fingerprint": return "设备指纹";
            case "string": return "字符串常量";
            case "engine": return "引擎";
            case "gpm": return "GPM SDK";
            default: return "ACE 组件";
        }
    }

    private static String formatHexDisplay(String hex) {
        if (hex == null || hex.isEmpty() || hex.equals("READ_FAILED") || hex.equals("UNAVAILABLE")) {
            return hex == null ? "—" : hex;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            if (i > 0 && (i % 32) == 0) sb.append("\n");
            else if (i > 0 && (i % 2) == 0) sb.append(" ");
            sb.append(hex, i, Math.min(i + 2, hex.length()));
        }
        return sb.toString();
    }

    private static void addDecodedObservations(List<DetectionResult> results, Listener listener,
                                               List<DecodedSource> sources, long scanStart) {
        int index = 0;
        for (DecodedSource source : sources) {
            for (ProfileParser.Observation observation : source.parsed.observations) {
                ObservationDecision decision = classifyObservation(observation);
                String evidence = "文件=" + fileName(source.path) +
                        "\n解码字段=" + observation.field +
                        "\n解码值=" + empty(observation.value) +
                        "\n字段说明=" + observation.meaning +
                        "\n归类公式=" + decision.formula +
                        "\n归类结果=" + decision.summary +
                        "\n边界=该条目表示目标文件保存的观察值，不推测服务端接收状态";
                DetectionResult item = decision.discovery
                        ? DetectionResult.risk("advanced.observation." + index, "设备画像观察值", decision.title,
                        decision.summary, evidence, decision.formula, 99, elapsed(scanStart))
                        : DetectionResult.ledger("advanced.observation." + index, "设备画像观察值", decision.title,
                        DetectionStatus.PASS, decision.summary, evidence, decision.formula, 99, elapsed(scanStart));
                results.add(item);
                notify(listener, "归类画像字段 " + observation.field, 1, 1, item);
                index++;
            }
        }
    }

    private static ObservationDecision classifyObservation(ProfileParser.Observation observation) {
        String field = observation.field == null ? "" : observation.field;
        String value = observation.value == null ? "" : observation.value;
        String text = (field + " " + value).toLowerCase(Locale.ROOT);
        boolean positive = !(value.trim().isEmpty() || value.trim().matches("(?i)0|false|none|null|no|off|\\[\\]|\\{\\}"));
        if (containsAny(text, "kernelsu", "ksud", "magisk", "zygisk", "apatch", "supersu", "superuser") && positive)
            return new ObservationDecision(true, "Root 管理器画像", "画像字段中发现 Root 管理器或守护进程观察值",
                    "字段名或字段值包含 Root 管理器标识，且值不是 0/false/none");
        if (containsAny(text, "bootloader=unlocked", "device_state=unlocked", "verifiedbootstate=orange", "bl_unlock", "boot_unlocked") && positive)
            return new ObservationDecision(true, "BL / Verified Boot 画像", "画像字段中发现 BL 解锁或 Verified Boot 异常观察值",
                    "字段值包含已验证的解锁/橙色启动状态标识");
        if (containsAny(text, "frida", "xposed", "lsposed", "mt2.cn", "bin.mt.plus", "rootexplorer") && positive)
            return new ObservationDecision(true, "工具与框架画像", "画像字段中发现工具、注入框架或文件管理器标识",
                    "字段名或字段值包含工具/框架标识，且值不是否定值");
        if (containsAny(text, "emulator", "vphone", "bluestacks", "nox", "cloudphone") && positive)
            return new ObservationDecision(true, "虚拟化画像", "画像字段中发现模拟器、云机或虚拟化标识",
                    "字段名或字段值包含虚拟化标识，且值不是否定值");
        return new ObservationDecision(false, "画像字段 · " + field,
                "已从目标文件解出字段和值，当前公式未将其归类为异常扫描发现",
                "完整公开字段和值；仅对明确标识且为肯定值的 Root/BL/工具/虚拟化信息归类");
    }

    private static final class ObservationDecision {
        final boolean discovery; final String title; final String summary; final String formula;
        ObservationDecision(boolean discovery, String title, String summary, String formula) {
            this.discovery = discovery; this.title = title; this.summary = summary; this.formula = formula;
        }
    }

    private static DetectionResult finding(String id, String title, DetectionStatus status, String summary,
                                           DecodedSource source, String field, String value,
                                           String predicate, String upload, long start) {
        String evidence = "扫描来源=" + (source == null ? "本轮持久文件中未找到" : fileName(source.path)) +
                "\n扫描了=" + plainFindingContent(id) +
                "\n发现了=" + empty(value) +
                "\n设备判定=" + predicate +
                "\n上报结论=" + upload;
        if (status == DetectionStatus.RISK)
            return DetectionResult.risk(id, "高级逐项解读", title, summary, evidence,
                    "源文件 -> 解码字段/规则 -> 固定归类公式 -> 扫描或画像结论", 99, elapsed(start));
        if (status == DetectionStatus.PASS)
            return DetectionResult.pass(id, "高级逐项解读", title, summary, evidence,
                    "明确未命中值才判定通过", 98, elapsed(start));
        return DetectionResult.suspicious(id, "高级逐项解读", title, summary, evidence,
                "缺少任一证据链环节即按风险继续排查", 99, elapsed(start));
    }

    private static String plainFindingContent(String id) {
        if (id.endsWith(".root")) return "KernelSU 和 Root 路径检查";
        if (id.endsWith(".root_manager")) return "Root 管理器检查";
        if (id.endsWith(".boot")) return "BL 解锁和启动状态";
        if (id.endsWith(".fingerprint")) return "设备指纹摘要";
        if (id.endsWith(".certificate")) return "设备和客户端证书";
        if (id.endsWith(".device_key")) return "设备密钥和序列号";
        if (id.endsWith(".packages")) return "应用、文件和进程扫描";
        if (id.endsWith(".upload")) return "最终上报内容";
        if (id.endsWith(".coordinate")) return "坐标状态";
        return "本轮解密结果";
    }

    private static void addRuntimeReportInterfaces(List<DetectionResult> results, Listener listener,
                                                   File artifactDirectory, long scanStart) {
        addRuntimeInterface(results, listener, artifactDirectory, "advanced.runtime.report1",
                "TSS 主报告缓冲区",
                "TssSDKGetReportData / TssSDKDelReportData",
                "IDA sub_4C03D4 已确认取得长度与缓冲区后交给发送链，并在同一循环释放",
                "释放前原始报告字节");
        addRuntimeInterface(results, listener, artifactDirectory, "advanced.runtime.report2",
                "TSS report_data2",
                "tss_get_report_data2",
                "IDA sub_4C075C 已确认按固定十六进制字段格式解析",
                "report_data2 十六进制字段值");
        addRuntimeInterface(results, listener, artifactDirectory, "advanced.runtime.report3",
                "TSS report_data3",
                "tss_get_report_data3 / tss_del_report_data3",
                "IDA sub_4C0824/sub_4C0CDC 已确认按类型分流，并经 sub_488E34 解码到临时缓冲区",
                "report_data3 原始与二次解码字节");
    }

    private static void addRuntimeInterface(List<DetectionResult> results, Listener listener,
                                            File artifactDirectory, String id, String title,
                                            String api, String chain, String required) {
        String leaf = id.substring(id.lastIndexOf('.') + 1) + ".bin";
        File captured = artifactDirectory == null ? null : new File(new File(artifactDirectory, "runtime_session"), leaf);
        boolean present = captured != null && captured.isFile() && captured.length() > 0;
        String evidence = "扫描来源=libtersafe 运行时接口\n扫描了=" + api +
                "\n发现了=" + (present ? "已保存 " + captured.length() + " 字节缓冲区" : "接口存在，未发现释放前缓冲区文件") +
                "\n设备判定=" + (present ? "缓冲区已取得，仍需按事件码映射解读" : chain) +
                "\n上报结论=" + (present ? "等待缓冲区字段解码" : "缺少 " + required + "，本轮上报内容保持未决");
        DetectionResult result = DetectionResult.ledger(id, "运行时结果接口", title,
                present ? DetectionStatus.PASS : DetectionStatus.SUSPICIOUS,
                present ? "已取得运行时报告缓冲区" : "已确认接口调用链，本轮尚无可验证的报告负载",
                evidence, "接口存在与报告内容分开判定；只有保存的实际字节参与设备和上报结论", 99, 0L);
        results.add(result);
        notify(listener, "核对 " + title, 1, 1, result);
    }

    private static void addFinding(List<DetectionResult> results, Listener listener, DetectionResult result) {
        results.add(result);
        notify(listener, "解读 " + result.title, 1, 1, result);
    }

    private static DecodedSource sourceByName(List<DecodedSource> sources, String name) {
        for (DecodedSource source : sources)
            if (fileName(source.path).equalsIgnoreCase(name)) return source;
        return null;
    }

    private static DecodedSource sourceContaining(List<DecodedSource> sources, String marker) {
        for (DecodedSource source : sources)
            if (source.parsed.evidence.contains(marker)) return source;
        return null;
    }

    private static DecodedSource sourceWithSignal(List<DecodedSource> sources, String signalId) {
        for (DecodedSource source : sources)
            for (ProfileParser.Signal signal : source.parsed.signals)
                if (signal.id.equals(signalId)) return source;
        return null;
    }

    private static String signalEvidence(DecodedSource source, String signalId) {
        if (source == null) return "未恢复";
        for (ProfileParser.Signal signal : source.parsed.signals)
            if (signal.id.equals(signalId)) return "id=" + signal.id + ", value=" + signal.value +
                    ", meaning=" + signal.meaning + ", reported=" + signal.reported;
        return "未恢复";
    }

    private static boolean containsAny(String value, String... needles) {
        String lower = value.toLowerCase(Locale.ROOT);
        for (String needle : needles) if (lower.contains(needle.toLowerCase(Locale.ROOT))) return true;
        return false;
    }

    private static String empty(String value) { return value == null || value.trim().isEmpty() ? "<无可验证值>" : value.trim(); }

    private static final class DecodedSource {
        final String path; final ProfileParser.Interpretation parsed;
        DecodedSource(String path, ProfileParser.Interpretation parsed) { this.path = path; this.parsed = parsed; }
    }

    private static void addNullSeparated(Set<String> paths, byte[] bytes) {
        String raw = new String(bytes, StandardCharsets.UTF_8);
        for (String path : raw.split("\\u0000")) if (!path.isEmpty()) paths.add(path);
    }

    private static void addRelevant(Set<String> paths, byte[] bytes) {
        String raw = new String(bytes, StandardCharsets.UTF_8);
        for (String path : raw.split("\\u0000")) if (!path.isEmpty() && isRelevant(path)) paths.add(path);
    }

    private static boolean isRelevant(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        // v2.4: 用户手动压缩包不参与扫描与展示（大厅.zip / 对局.zip / 大厅前.zip）
        if (lower.endsWith("/files/大厅.zip") || lower.endsWith("/files/对局.zip") ||
                lower.endsWith("/files/大厅前.zip")) return false;
        if (lower.contains("/ano_tmp/") || lower.contains("/tss_tmp/")) return true;
        if (lower.endsWith("/files/key") || lower.endsWith("/files/serial") ||
                lower.endsWith("/files/.save") || lower.endsWith("/files/ano_tmp.zip")) return true;
        for (String name : Arrays.asList("ob_x.zip", "a64.dat", "comm.dat", "tss_ano.dat", "mpmc.dat",
                "ano_rdp.dat", "ano_rdp_2.dat", "crt.i2.dat", "ano_ksh.dat", "atti_obv.dat", "kmc.dat",
                "mn_cache.dat", "tdm_cache.dat", "ace_cache_db.dat", "ano_dfh.zip"))
            if (lower.endsWith("/" + name)) return true;
        return false;
    }
    private static String fileName(String path) { int i = path.lastIndexOf('/'); return i < 0 ? path : path.substring(i + 1); }
    private static long elapsed(long start) { return (System.nanoTime() - start) / 1_000_000L; }
    private static void notify(Listener listener, String stage, int completed, int total, DetectionResult result) {
        if (listener != null) listener.onProgress(stage, completed, total, result);
    }

    public static final class ScanOutput {
        public final List<DetectionResult> results; public final String diagnostics; public final String suVariant;
        public final File artifactDirectory;
        ScanOutput(List<DetectionResult> results, String diagnostics, String suVariant, File artifactDirectory) {
            this.results = results; this.diagnostics = diagnostics; this.suVariant = suVariant; this.artifactDirectory = artifactDirectory;
        }
    }
}
