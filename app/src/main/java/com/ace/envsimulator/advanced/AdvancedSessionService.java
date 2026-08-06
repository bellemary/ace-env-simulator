package com.ace.envsimulator.advanced;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import com.ace.envsimulator.MainActivity;
import com.ace.envsimulator.R;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 高级采集服务 v2.3：
 * 1. 自动启动目标进程
 * 2. 持续扫描目标进程内存（双路：process_vm_readv + /proc/pid/mem）
 * 3. 持续监控 ano_tmp 文件变化并实时解密
 * 4. 实时写入内部存储 Ace扫描报告.txt
 * 5. 用户手动结束后生成汇总
 */
public final class AdvancedSessionService extends Service {
    public static final String ACTION_START = "com.ace.envsimulator.action.START_ADVANCED_SESSION";
    public static final String ACTION_STOP = "com.ace.envsimulator.action.STOP_ADVANCED_SESSION";
    private static final String TARGET_PACKAGE = "com.tencent.tmgp.dfm";
    private static final String CHANNEL_ID = "advanced_collection";
    private static final int NOTIFICATION_ID = 2000;
    private static final String PREFS = "advanced_session";
    private static final String KEY_ACTIVE = "active";
    private static final String KEY_PATH = "path";
    private static final String KEY_REPORT = "report_path";
    private static final long MAX_SNAPSHOT_BYTES = 64L * 1024L * 1024L;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Map<String, String> hashes = new LinkedHashMap<>();
    private volatile boolean running;
    private File sessionDirectory;
    private File memscanDirectory;
    private long savedBytes;
    private int pollIndex;
    private MemoryScanner memoryScanner;
    private ReportWriter reportWriter;
    private ProfileParser profileParser;

    @Override public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            requestStop();
            return START_NOT_STICKY;
        }
        if (!running) {
            startForeground(NOTIFICATION_ID, buildNotification("正在启动目标应用并开始扫描"));
            startCollection();
        }
        return START_NOT_STICKY;
    }

    private void startCollection() {
        running = true;
        sessionDirectory = new File(new File(getFilesDir(), "reports"), "runtime_session_" + stamp());
        if (!sessionDirectory.mkdirs() && !sessionDirectory.isDirectory()) {
            append("session_error.txt", "创建会话目录失败\n");
            finishCollection();
            return;
        }
        memscanDirectory = new File(sessionDirectory, "memscan");
        if (!memscanDirectory.exists()) memscanDirectory.mkdirs();

        // 初始化实时报告写入器（写入内部存储 Ace扫描报告.txt）
        reportWriter = new ReportWriter(getFilesDir());
        profileParser = new ProfileParser();

        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putBoolean(KEY_ACTIVE, true)
                .putString(KEY_PATH, sessionDirectory.getAbsolutePath())
                .putString(KEY_REPORT, reportWriter.getReportFile().getAbsolutePath())
                .apply();

        append("session_manifest.txt", "mode=realtime_scan+decrypt+report\nstarted_at=" + new Date() +
                "\ntarget_package=" + TARGET_PACKAGE + "\npoll_interval_ms=2000\nmemscan=dual(native_binary+shell)\n" +
                "report_file=" + reportWriter.getReportFile().getAbsolutePath() + "\n");

        // 自动启动目标应用
        launchTargetApp();

        worker.execute(this::collectionLoop);
    }

    private void launchTargetApp() {
        try {
            Intent intent = getPackageManager().getLaunchIntentForPackage(TARGET_PACKAGE);
            if (intent != null) {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intent);
                reportWriter.writeProcessStatus("正在启动目标应用...", 0);
            } else {
                reportWriter.writeFileError("目标应用启动",
                        "未找到 " + TARGET_PACKAGE + " 的启动 Intent，请手动打开游戏");
            }
        } catch (Exception e) {
            reportWriter.writeFileError("目标应用启动", e.getMessage());
        }
    }

    private void collectionLoop() {
        RootShell shell = new RootShell();
        RootShell.Result root = shell.request();
        append("session_manifest.txt", "root_exit=" + root.exitCode + "\nsu_variant=" + root.variant +
                "\nroot_stdout=" + oneLine(root.stdoutText()) + "\nroot_stderr=" + oneLine(root.stderrText()) + "\n");
        if (root.exitCode != 0) {
            updateNotification("Root 授权未完成");
            reportWriter.writeFileError("Root 授权", "高级模式未获得 uid 0");
            finishCollection();
            return;
        }
        startMemoryScanner();
        while (running && !Thread.currentThread().isInterrupted()) {
            poll(shell);
            try { Thread.sleep(2_000L); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); break; }
        }
        stopMemoryScanner();
        append("session_manifest.txt", "stopped_at=" + new Date() + "\npolls=" + pollIndex +
                "\nsnapshot_bytes=" + savedBytes + "\n");
        finishCollection();
    }

    private void startMemoryScanner() {
        if (memscanDirectory == null || memoryScanner != null) return;
        memoryScanner = new MemoryScanner();
        memoryScanner.start(this, memscanDirectory, new MemoryScanner.Listener() {
            @Override public void onRound(int round, int totalHits, String summary) {
                append("memscan_status.txt", "[" + new Date() + "] round=" + round +
                        " total_hits=" + totalHits + " " + summary + "\n");
                if (reportWriter != null) {
                    String source = summary.contains("native") ? "原生二进制 process_vm_readv" : "root shell dd /proc/pid/mem";
                    reportWriter.writeMemoryRound(round, totalHits, source);
                }
            }
            @Override public void onHit(String category, String pattern, String address, String context) {
                if (reportWriter != null) {
                    reportWriter.writeMemoryHit(category, pattern, address, context);
                }
            }
            @Override public void onError(String source, String message) {
                append("memscan_errors.txt", "[" + new Date() + "] " + source + ": " + message + "\n");
            }
        });
        append("session_manifest.txt", "memscan_started=" + new Date() + "\n");
    }

    private void stopMemoryScanner() {
        if (memoryScanner != null) {
            memoryScanner.stop();
            memoryScanner = null;
            append("session_manifest.txt", "memscan_stopped=" + new Date() + "\n");
        }
    }

    private void poll(RootShell shell) {
        int current = ++pollIndex;
        String script = "pid=$(pidof " + TARGET_PACKAGE + " 2>/dev/null | awk '{print $1}'); " +
                "printf 'PID|%s\\n' \"$pid\"; " +
                "for base in /data/user/0/" + TARGET_PACKAGE + "/files /data/user_de/0/" + TARGET_PACKAGE + "/files; do " +
                "[ -d \"$base\" ] || continue; " +
                "find \"$base\" -maxdepth 4 -type f 2>/dev/null | while IFS= read -r f; do " +
                "case \"$f\" in */ano_tmp/*|*/tss_tmp/*|*/files/ano_tmp.zip|*/files/key|*/files/serial|*/files/.Save) " +
                "size=$(stat -c %s \"$f\" 2>/dev/null); hash=$(sha256sum \"$f\" 2>/dev/null | awk '{print $1}'); " +
                "printf 'FILE|%s|%s|%s\\n' \"$f\" \"$size\" \"$hash\";; esac; done; done";
        RootShell.Result result = shell.execute(script, 12_000L);
        String text = result.stdoutText();
        append("session_timeline.txt", "\n[poll " + current + "] " + new Date() + "\n" + text +
                (result.stderrText().isEmpty() ? "" : "stderr=" + result.stderrText()) + "\n");
        String pid = "";
        for (String line : text.split("\\r?\\n")) {
            if (line.startsWith("PID|")) {
                pid = line.substring(4).trim();
                continue;
            }
            if (!line.startsWith("FILE|")) continue;
            String[] parts = line.split("\\|", 4);
            if (parts.length != 4 || parts[1].isEmpty() || parts[3].isEmpty()) continue;
            String previous = hashes.put(parts[1], parts[3]);
            if (!parts[3].equals(previous)) snapshot(shell, parts[1], parts[2], parts[3], current);
        }
        // 实时写入进程状态到报告
        if (reportWriter != null) {
            reportWriter.writeProcessStatus(pid, current);
        }
        updateNotification(pid.isEmpty() ? "等待目标应用启动 · 已采集 " + current + " 轮 · 内存命中 " +
                (reportWriter == null ? 0 : reportWriter.getMemoryHitCount()) + " 项"
                : "目标进程 " + pid + " · 已采集 " + current + " 轮 · 内存命中 " +
                (reportWriter == null ? 0 : reportWriter.getMemoryHitCount()) + " 项");
    }

    private void snapshot(RootShell shell, String path, String sizeText, String hash, int poll) {
        long size;
        try { size = Long.parseLong(sizeText); }
        catch (NumberFormatException ignored) { size = -1L; }
        if (size < 0 || size > 8L * 1024L * 1024L || savedBytes + size > MAX_SNAPSHOT_BYTES) {
            append("snapshot_index.txt", "poll=" + poll + " skipped=" + path + " size=" + sizeText +
                    " sha256=" + hash + " reason=resource_limit\n");
            return;
        }
        RootShell.Result read = shell.readFile(path, 8 * 1024 * 1024);
        if (read.exitCode != 0) {
            append("snapshot_index.txt", "poll=" + poll + " failed=" + path + " exit=" + read.exitCode + "\n");
            if (reportWriter != null) reportWriter.writeFileError(fileName(path), "读取失败 exit=" + read.exitCode);
            return;
        }
        // 保存快照
        File snapshots = new File(sessionDirectory, "snapshots");
        if (!snapshots.exists() && !snapshots.mkdirs()) return;
        String leaf = String.format(Locale.US, "%04d_%s_%s.raw", poll, safeName(path), hash.substring(0, Math.min(12, hash.length())));
        File target = new File(snapshots, leaf);
        try (FileOutputStream out = new FileOutputStream(target)) {
            out.write(read.stdout);
            savedBytes += read.stdout.length;
            append("snapshot_index.txt", "poll=" + poll + " file=" + path + " size=" + read.stdout.length +
                    " sha256=" + hash + " snapshot=" + leaf + "\n");
        } catch (Exception e) {
            append("snapshot_index.txt", "poll=" + poll + " failed=" + path + " error=" + e.getClass().getSimpleName() + "\n");
        }
        // 实时解密并写入报告
        if (reportWriter != null && profileParser != null) {
            try {
                ProfileParser.Interpretation interp = profileParser.parse(path, read.stdout);
                reportWriter.writeFileDecoded(fileName(path), interp.summary, interp.evidence);
            } catch (Exception e) {
                reportWriter.writeFileError(fileName(path),
                        e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    private void requestStop() {
        running = false;
        stopMemoryScanner();
        if (reportWriter != null) {
            reportWriter.writeFooter();
        }
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_ACTIVE, false).apply();
        append("session_manifest.txt", "stop_requested_at=" + new Date() + "\n");
        updateNotification("正在整理采集结果与内存扫描数据");
    }

    private void finishCollection() {
        running = false;
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_ACTIVE, false).apply();
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private Notification buildNotification(String detail) {
        Intent open = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pending = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_scan)
                .setContentTitle("ACE 实时扫描进行中")
                .setContentText(detail)
                .setContentIntent(pending)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();
    }

    private void updateNotification(String detail) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) manager.notify(NOTIFICATION_ID, buildNotification(detail));
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) manager.createNotificationChannel(new NotificationChannel(
                CHANNEL_ID, "高级实时扫描", NotificationManager.IMPORTANCE_LOW));
    }

    private void append(String name, String text) {
        if (sessionDirectory == null) return;
        try (FileOutputStream out = new FileOutputStream(new File(sessionDirectory, name), true)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) { }
    }

    @Override public void onDestroy() {
        running = false;
        stopMemoryScanner();
        if (reportWriter != null) reportWriter.writeFooter();
        worker.shutdownNow();
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_ACTIVE, false).apply();
        super.onDestroy();
    }

    @Nullable @Override public IBinder onBind(Intent intent) { return null; }

    public static boolean hasSession(Context context) {
        String path = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_PATH, "");
        return !path.isEmpty() && new File(path).isDirectory();
    }

    public static boolean isActive(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_ACTIVE, false);
    }

    public static String getReportPath(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_REPORT, "");
    }

    public static String sessionSummary(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String path = prefs.getString(KEY_PATH, "");
        String reportPath = prefs.getString(KEY_REPORT, "");
        File directory = path.isEmpty() ? null : new File(path);
        if (directory == null || !directory.isDirectory()) return "会话文件=未生成";
        File timeline = new File(directory, "session_timeline.txt");
        File index = new File(directory, "snapshot_index.txt");
        File memscanDir = new File(directory, "memscan");
        File memscanManifest = new File(memscanDir, "memscan_manifest.txt");
        int memscanFiles = 0;
        if (memscanDir.isDirectory()) {
            File[] msFiles = memscanDir.listFiles((d, name) -> name.startsWith("memscan_") && name.endsWith(".txt"));
            memscanFiles = msFiles == null ? 0 : msFiles.length;
        }
        File reportFile = reportPath.isEmpty() ? null : new File(reportPath);
        return "会话目录=" + directory.getName() +
                "\n时间线字节=" + timeline.length() +
                "\n快照索引字节=" + index.length() +
                "\n内存扫描文件=" + memscanFiles +
                "\n内存扫描清单=" + (memscanManifest.exists() ? "已生成" : "未生成") +
                "\n实时报告=" + (reportFile != null && reportFile.exists() ? reportFile.getAbsolutePath() : "未生成") +
                "\n采集模式=实时扫描+实时解密+实时写入报告";
    }

    public static boolean copyLastSession(Context context, File destination) {
        if (destination == null) return false;
        String path = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_PATH, "");
        File source = path.isEmpty() ? null : new File(path);
        File target = new File(destination, "runtime_session");
        return source != null && source.isDirectory() && copyTree(source, target);
    }

    private static boolean copyTree(File source, File target) {
        if (source.isDirectory()) {
            if (!target.exists() && !target.mkdirs()) return false;
            File[] children = source.listFiles();
            if (children == null) return true;
            boolean ok = true;
            for (File child : children) ok &= copyTree(child, new File(target, child.getName()));
            return ok;
        }
        try (FileInputStream in = new FileInputStream(source); FileOutputStream out = new FileOutputStream(target)) {
            byte[] buffer = new byte[8192];
            for (int read; (read = in.read(buffer)) >= 0; ) out.write(buffer, 0, read);
            return true;
        } catch (Exception ignored) { return false; }
    }

    private static String stamp() {
        return new SimpleDateFormat("yyyyMMdd_HHmmss_SSS", Locale.US).format(new Date());
    }

    private static String fileName(String path) {
        int slash = path.lastIndexOf('/');
        return slash < 0 ? path : path.substring(slash + 1);
    }

    private static String safeName(String path) {
        return fileName(path).replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private static String oneLine(String value) {
        return value == null ? "" : value.replace('\r', ' ').replace('\n', ' ').trim();
    }
}
