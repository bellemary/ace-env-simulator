package com.ace.envsimulator.advanced;

import android.content.Context;
import android.os.Build;
import com.ace.envsimulator.detection.NativeProbe;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 双路持续内存扫描：
 * 1. 原生二进制 (ace_scanner) - process_vm_readv root 执行，速度快
 * 2. Root Shell - dd /proc/pid/mem + grep，备用路径
 */
public final class MemoryScanner {
    private static final String TARGET_PACKAGE = "com.tencent.tmgp.dfm";
    private static final long SCAN_INTERVAL_MS = 2_000L;
    private static final int MAX_ROUNDS = 500;
    private static final String BINARY_PATH = "/data/local/tmp/ace_scanner";

    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger roundCounter = new AtomicInteger(0);
    private final AtomicInteger totalHits = new AtomicInteger(0);
    private Future<?> nativeBinaryTask;
    private Future<?> shellTask;
    private File outputDirectory;
    private Context context;
    private boolean binaryDeployed;

    public interface Listener {
        void onRound(int round, int totalHits, String summary);
        void onHit(String category, String pattern, String address, String context);
        void onError(String source, String message);
    }

    public void start(Context ctx, File outputDir, Listener listener) {
        if (running.get()) return;
        context = ctx;
        outputDirectory = outputDir;
        running.set(true);
        roundCounter.set(0);
        totalHits.set(0);
        if (!outputDirectory.exists()) outputDirectory.mkdirs();
        appendLog("memscan_manifest.txt", "started_at=" + new Date() +
                "\ntarget=" + TARGET_PACKAGE +
                "\ninterval_ms=" + SCAN_INTERVAL_MS +
                "\nmode=dual(native_binary+shell)\n");

        binaryDeployed = deployNativeBinary();
        appendLog("memscan_manifest.txt", "binary_deployed=" + binaryDeployed +
                " abi=" + Build.SUPPORTED_ABIS[0] + "\n");

        nativeBinaryTask = executor.submit(() -> runNativeBinaryScan(listener));
        shellTask = executor.submit(() -> runShellScan(listener));
    }

    public void stop() {
        running.set(false);
        if (nativeBinaryTask != null) nativeBinaryTask.cancel(true);
        if (shellTask != null) shellTask.cancel(true);
        executor.shutdownNow();
        appendLog("memscan_manifest.txt", "stopped_at=" + new Date() +
                "\ntotal_rounds=" + roundCounter.get() +
                "\ntotal_hits=" + totalHits.get() + "\n");
    }

    // ==================== 原生二进制扫描 (process_vm_readv root) ====================

    private boolean deployNativeBinary() {
        try {
            String abi = Build.SUPPORTED_ABIS[0];
            String assetName;
            if (abi.contains("arm64")) assetName = "ace_scanner_arm64";
            else if (abi.contains("x86_64")) assetName = "ace_scanner_x86_64";
            else return false;

            File localFile = new File(context.getFilesDir(), "ace_scanner");
            try (InputStream is = context.getAssets().open(assetName);
                 FileOutputStream out = new FileOutputStream(localFile)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) >= 0) out.write(buf, 0, n);
            }

            RootShell shell = new RootShell();
            RootShell.Result root = shell.request();
            if (root.exitCode != 0) return false;

            RootShell.Result deploy = shell.execute(
                    "cp " + RootShell.quote(localFile.getAbsolutePath()) +
                    " " + BINARY_PATH + " && chmod 755 " + BINARY_PATH, 10_000L);
            return deploy.exitCode == 0;
        } catch (Exception e) {
            appendLog("memscan_errors.txt", "deploy_failed: " + e.getMessage() + "\n");
            return false;
        }
    }

    private void runNativeBinaryScan(Listener listener) {
        if (!binaryDeployed) {
            appendLog("memscan_errors.txt", "native_binary not deployed, skipping\n");
            if (listener != null) listener.onError("native_binary", "binary not deployed");
            return;
        }

        Process process = null;
        try {
            ProcessBuilder pb = new ProcessBuilder("su", "-c",
                    BINARY_PATH + " " + TARGET_PACKAGE + " " + SCAN_INTERVAL_MS + " " + MAX_ROUNDS);
            pb.redirectErrorStream(false);
            process = pb.start();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            BufferedReader errReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8));

            StringBuilder roundBuffer = new StringBuilder();
            int round = 0;
            String line;

            while (running.get() && !Thread.currentThread().isInterrupted()) {
                line = reader.readLine();
                if (line == null) break;

                if (line.startsWith("SCAN_RESULT|")) {
                    round = roundCounter.incrementAndGet();
                    roundBuffer.setLength(0);
                    roundBuffer.append("[").append(new Date()).append("]\n");
                }
                roundBuffer.append(line).append("\n");

                if (line.startsWith("HIT|") && listener != null) {
                    String[] hp = line.split("\\|", 5);
                    if (hp.length >= 5) listener.onHit(hp[1], hp[2], hp[3], hp[4]);
                    else if (hp.length >= 3) listener.onHit(categorizePattern(hp[2]), hp[2],
                            hp.length > 3 ? hp[3] : "", "");
                }

                if (line.startsWith("SCAN_DONE")) {
                    String fileName = "memscan_native_" + round + ".txt";
                    appendLog(fileName, roundBuffer.toString());
                    int hits = countHits(roundBuffer.toString());
                    totalHits.addAndGet(hits);
                    if (listener != null) {
                        listener.onRound(round, totalHits.get(),
                                "native_binary: " + hits + " hits (round " + round + ")");
                    }
                }

                if (line.startsWith("SCANNER_END") || line.startsWith("NO_PROCESS") ||
                    line.startsWith("PROCESS_EXIT")) {
                    appendLog("memscan_native_events.txt", "[" + new Date() + "] " + line + "\n");
                }
            }

            // 读取 stderr
            if (errReader.ready()) {
                StringBuilder err = new StringBuilder();
                while ((line = errReader.readLine()) != null) err.append(line).append("\n");
                if (err.length() > 0) appendLog("memscan_native_stderr.txt", err.toString());
            }
        } catch (Exception e) {
            if (Thread.currentThread().isInterrupted()) {
                appendLog("memscan_native_events.txt", "[" + new Date() + "] interrupted\n");
            } else {
                appendLog("memscan_errors.txt", "native_binary_error: " + e.getMessage() + "\n");
                if (listener != null) listener.onError("native_binary", e.getMessage());
            }
        } finally {
            if (process != null) {
                process.destroyForcibly();
            }
        }
    }

    // ==================== Root Shell 扫描 (dd /proc/pid/mem) ====================

    private void runShellScan(Listener listener) {
        RootShell shell = new RootShell();
        RootShell.Result root = shell.request();
        if (root.exitCode != 0) {
            appendLog("memscan_shell_error.txt", "root denied: " + root.stderrText());
            if (listener != null) listener.onError("shell", "root denied");
            return;
        }
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            int round = roundCounter.incrementAndGet();
            if (round > MAX_ROUNDS) break;
            try {
                String script = buildShellScript();
                RootShell.Result result = shell.execute(script, 30_000L);
                String output = result.stdoutText();
                String fileName = "memscan_shell_" + round + ".txt";
                appendLog(fileName, "[" + new Date() + "]\n" + output);
                int hits = countHits(output);
                totalHits.addAndGet(hits);
                for (String outLine : output.split("\\r?\\n")) {
                    if (outLine.startsWith("HIT|") && listener != null) {
                        String[] hp = outLine.split("\\|", 5);
                        if (hp.length >= 3) {
                            String addr = hp[1];
                            String pat = hp[2];
                            listener.onHit(categorizePattern(pat), pat, addr,
                                    hp.length >= 4 ? hp[3] : "");
                        }
                    }
                }
                if (listener != null) {
                    listener.onRound(round, totalHits.get(),
                            "shell: " + hits + " hits (round " + round + ")");
                }
            } catch (Throwable e) {
                if (listener != null) listener.onError("shell", e.getMessage());
            }
            try { Thread.sleep(SCAN_INTERVAL_MS + 1000L); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
    }

    private static String buildShellScript() {
        return "pid=$(pidof com.tencent.tmgp.dfm 2>/dev/null | awk '{print $1}'); " +
                "if [ -z \"$pid\" ]; then echo 'NO_PROCESS'; exit 0; fi; " +
                "echo \"PID=$pid\"; " +
                "libline=$(cat /proc/$pid/maps 2>/dev/null | grep 'libtersafe' | head -1); " +
                "if [ -n \"$libline\" ]; then " +
                "  librange=$(echo \"$libline\" | awk '{print $1}'); " +
                "  libstart=$(echo \"$librange\" | cut -d- -f1); " +
                "  libend=$(echo \"$librange\" | cut -d- -f2); " +
                "  echo \"LIBTERSAFE=0x$libstart-0x$libend\"; " +
                "fi; " +
                "cat /proc/$pid/maps 2>/dev/null | " +
                "grep -E 'rw' | " +
                "grep -vE '\\[stack|\\[vdso|\\[vectors' | " +
                "head -80 | " +
                "while IFS= read -r line; do " +
                "  range=$(echo \"$line\" | awk '{print $1}'); " +
                "  start_hex=$(echo \"$range\" | cut -d- -f1); " +
                "  end_hex=$(echo \"$range\" | cut -d- -f2); " +
                "  start=$((16#$start_hex)); " +
                "  end=$((16#$end_hex)); " +
                "  size=$((end - start)); " +
                "  if [ $size -gt 8388608 ]; then size=8388608; fi; " +
                "  if [ $size -lt 256 ]; then continue; fi; " +
                "  blocks=$((size / 4096)); " +
                "  if [ $blocks -lt 1 ]; then blocks=1; fi; " +
                "  dd if=/proc/$pid/mem bs=4096 iflag=skip_bytes skip=$start count=$blocks 2>/dev/null | " +
                "  grep -aoE 'kernelsu|KernelSU|ksud|/data/adb/ksu|magisk|Magisk|zygisk|apatch|" +
                "frida|Frida|gum-js-loop|linjector|" +
                "xposed|Xposed|lsposed|LSPosed|edxp|" +
                "bootloader|verified_boot|verifiedboot|vbmeta|boot_unlocked|device_state|is_unlocked|" +
                "certificate|cert_hit|cert_valid|crt\\.i2|" +
                "fingerprint|device_id|android_id|deviceuniqueid|" +
                "emulator|qemu|goldfish|" +
                "TssSDK|tss_get_report|TssSDKGetReportData|report_data|tersafe|ano_tmp|mrpcs|" +
                "substrate|inject|hook_detoured|" +
                "mt2\\.cn|bin\\.mt\\.plus|rootexplorer|" +
                "upload_data|report_upload|send_report|coordinate|coordinate_destroy|encrypt_state|" +
                "root_detect|root_manager|su_binary|" +
                "libtersafe|kvcache|ano_rdp|comm\\.dat|kmc\\.dat|mn_cache|tdm_cache|ace_cache' 2>/dev/null | " +
                "  while IFS= read -r match; do " +
                "    echo \"HIT|0x$start_hex|$match\"; " +
                "  done; " +
                "done; " +
                "echo 'SCAN_DONE'";
    }

    // ==================== 结果解析 ====================

    public static List<MemHit> parseResults(File scanDir) {
        List<MemHit> all = new ArrayList<>();
        if (scanDir == null || !scanDir.isDirectory()) return all;
        File[] files = scanDir.listFiles((d, name) ->
                name.startsWith("memscan_") && name.endsWith(".txt"));
        if (files == null) return all;
        for (File f : files) {
            try {
                byte[] data = readFile(f, 4 * 1024 * 1024);
                if (data == null) continue;
                String text = new String(data, StandardCharsets.UTF_8);
                for (String line : text.split("\\r?\\n")) {
                    MemHit hit = parseLine(line);
                    if (hit != null) all.add(hit);
                }
            } catch (Exception ignored) {}
        }
        return deduplicate(all);
    }

    // ==================== v2.5 特征点解析 ====================

    public static List<MemFeature> parseFeatures(File scanDir) {
        List<MemFeature> all = new ArrayList<>();
        if (scanDir == null || !scanDir.isDirectory()) return all;
        File[] files = scanDir.listFiles((d, name) ->
                name.startsWith("memscan_") && name.endsWith(".txt"));
        if (files == null) return all;
        for (File f : files) {
            try {
                byte[] data = readFile(f, 4 * 1024 * 1024);
                if (data == null) continue;
                String text = new String(data, StandardCharsets.UTF_8);
                for (String line : text.split("\\r?\\n")) {
                    MemFeature feat = parseFeatureLine(line);
                    if (feat != null) all.add(feat);
                }
            } catch (Exception ignored) {}
        }
        return deduplicateFeatures(all);
    }

    private static MemFeature parseFeatureLine(String line) {
        if (line == null || !line.startsWith("FEATURE|")) return null;
        // 格式: FEATURE|<module>|<offset>|<address>|<hex>|<status>|<reason>|<name>
        // 失败格式: FEATURE|<module>|<offset>|<address>|READ_FAILED|unreadable|<reason>
        // 模块未加载: FEATURE|<module>|<offset>|0x0|UNAVAILABLE|module_not_loaded|<name>
        String[] parts = line.split("\\|", 8);
        if (parts.length < 7) return null;
        String module = parts[1];
        String offset = parts[2];
        String address = parts[3];
        String hex = parts[4];
        String status = parts[5];
        String reason = parts[6];
        String name = parts.length >= 8 ? parts[7] : "";
        return new MemFeature(module, offset, address, hex, status, reason, name);
    }

    private static List<MemFeature> deduplicateFeatures(List<MemFeature> features) {
        Map<String, MemFeature> seen = new LinkedHashMap<>();
        for (MemFeature f : features) {
            String key = f.module + "|" + f.offset;
            seen.put(key, f);  // 后来的覆盖前面的 (取最新一轮)
        }
        return new ArrayList<>(seen.values());
    }

    public static Map<String, List<MemHit>> categorize(List<MemHit> hits) {
        Map<String, List<MemHit>> map = new LinkedHashMap<>();
        for (MemHit h : hits) {
            map.computeIfAbsent(h.category, k -> new ArrayList<>()).add(h);
        }
        return map;
    }

    private static MemHit parseLine(String line) {
        if (line == null || line.isEmpty()) return null;
        String[] parts = line.split("\\|", 5);
        if (line.startsWith("HIT|") && parts.length >= 3) {
            if (parts.length >= 5) {
                return new MemHit(parts[1], parts[2], parts[3], parts[4]);
            } else if (parts.length >= 3) {
                return new MemHit(categorizePattern(parts[2]), parts[2], parts[1], "");
            }
        }
        return null;
    }

    private static String categorizePattern(String pattern) {
        String lower = pattern.toLowerCase(Locale.ROOT);
        if (lower.contains("kernel") || lower.contains("ksu") || lower.contains("magisk") ||
                lower.contains("zygisk") || lower.contains("apatch") || lower.contains("su_binary") ||
                lower.contains("root_detect") || lower.contains("root_manager") || lower.contains("busybox") ||
                lower.contains("superuser") || lower.contains("/sbin/su") || lower.contains("/system/bin/su"))
            return "root";
        if (lower.contains("boot") || lower.contains("vbmeta") || lower.contains("verified") ||
                lower.contains("device_state") || lower.contains("unlocked") || lower.contains("orange"))
            return "boot";
        if (lower.contains("frida") || lower.contains("gum") || lower.contains("linjector"))
            return "frida";
        if (lower.contains("xposed") || lower.contains("lsposed") || lower.contains("edxp"))
            return "xposed";
        if (lower.contains("cert"))
            return "cert";
        if (lower.contains("fingerprint") || lower.contains("device_id") ||
                lower.contains("android_id") || lower.contains("deviceuniqueid") || lower.contains("imei"))
            return "fingerprint";
        if (lower.contains("emulator") || lower.contains("qemu") || lower.contains("goldfish"))
            return "emulator";
        if (lower.contains("tss") || lower.contains("report_data") || lower.contains("tersafe") ||
                lower.contains("mrpcs") || lower.contains("ano_tmp") || lower.contains("report_payload"))
            return "report";
        if (lower.contains("inject") || lower.contains("substrate") || lower.contains("hook"))
            return "hook";
        if (lower.contains("upload") || lower.contains("coordinate") || lower.contains("encrypt_state"))
            return "upload";
        if (lower.contains("mt2") || lower.contains("rootexplorer") || lower.contains("blackmart"))
            return "tool";
        if (lower.contains("libtersafe") || lower.contains("kvcache") || lower.contains("ano_rdp") ||
                lower.contains("comm.dat") || lower.contains("kmc") || lower.contains("mn_cache") ||
                lower.contains("tdm_cache") || lower.contains("ace_cache") || lower.contains("tss_ano"))
            return "ace";
        return "other";
    }

    public static String categoryLabel(String category) {
        switch (category) {
            case "root": return "Root / KernelSU";
            case "boot": return "BL / Verified Boot";
            case "frida": return "Frida 注入";
            case "xposed": return "Xposed 框架";
            case "cert": return "设备证书";
            case "fingerprint": return "设备指纹";
            case "emulator": return "模拟器检测";
            case "report": return "TSS 报告接口";
            case "hook": return "Hook 检测";
            case "tool": return "工具检测";
            case "upload": return "数据上报";
            case "ace": return "ACE 组件";
            default: return "其他";
        }
    }

    private static List<MemHit> deduplicate(List<MemHit> hits) {
        Map<String, MemHit> seen = new LinkedHashMap<>();
        for (MemHit h : hits) {
            String key = h.category + "|" + h.pattern + "|" + h.address;
            if (!seen.containsKey(key)) seen.put(key, h);
        }
        return new ArrayList<>(seen.values());
    }

    private static int countHits(String text) {
        int count = 0;
        for (String line : text.split("\\r?\\n")) {
            if (line.startsWith("HIT|")) count++;
        }
        return count;
    }

    private void appendLog(String name, String text) {
        if (outputDirectory == null) return;
        try (FileOutputStream out = new FileOutputStream(new File(outputDirectory, name), true)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {}
    }

    private static byte[] readFile(File file, int limit) {
        if (file.length() < 0 || file.length() > limit) return null;
        try (java.io.FileInputStream in = new java.io.FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            int offset = 0;
            while (offset < data.length) {
                int read = in.read(data, offset, data.length - offset);
                if (read < 0) break;
                offset += read;
            }
            return offset == data.length ? data : null;
        } catch (Exception e) { return null; }
    }

    public static final class MemHit {
        public final String category;
        public final String pattern;
        public final String address;
        public final String context;
        MemHit(String category, String pattern, String address, String context) {
            this.category = category;
            this.pattern = pattern;
            this.address = address;
            this.context = context;
        }
        @Override public String toString() {
            return category + "|" + pattern + "@" + address;
        }
    }

    // v2.5: 特征点模型 - 单个内存特征点的扫描结果
    public static final class MemFeature {
        public final String module;    // 模块名 (libtersafe.so / libtprt.so / libUE4.so)
        public final String offset;    // 偏移量 (0x521500)
        public final String address;   // 实际虚拟地址 (base + offset)
        public final String hex;       // 64 字节十六进制内容
        public final String status;    // pass / suspicious / risk / unreadable / unavailable
        public final String reason;    // 判定原因
        public final String name;      // 特征点名称
        MemFeature(String module, String offset, String address, String hex,
                   String status, String reason, String name) {
            this.module = module;
            this.offset = offset;
            this.address = address;
            this.hex = hex;
            this.status = status;
            this.reason = reason;
            this.name = name;
        }
        public String category() {
            if (name.contains("REL_HOOK") || name.contains("pfn_array") ||
                name.contains("ori_array") || name.contains("syscall")) return "hook";
            if (name.contains("ptrace") || name.contains("unwind") || name.contains("debug")) return "antidebug";
            if (name.contains("report") || name.contains("TssSDK") || name.contains("tss_")) return "report";
            if (name.contains("xor") || name.contains("key") || name.contains("decoder") || name.contains("crypto")) return "crypto";
            if (name.contains("cert") || name.contains("crt")) return "cert";
            if (name.contains("fingerprint") || name.contains("ksh")) return "fingerprint";
            if (name.contains("string") || name.contains("magic") || name.contains("version")) return "string";
            if (name.contains("ue4") || name.contains("engine")) return "engine";
            if (name.contains("gpm")) return "gpm";
            return "ace";
        }
        @Override public String toString() {
            return module + "+" + offset + " @ " + address + " [" + status + "] " + name;
        }
    }
}
