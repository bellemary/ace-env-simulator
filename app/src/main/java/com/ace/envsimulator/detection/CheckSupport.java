package com.ace.envsimulator.detection;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public final class CheckSupport {
    private CheckSupport() {}

    public static String getProp(String key) {
        CommandResult result = command(1500, "getprop", key);
        return result.exitCode == 0 ? result.stdout.trim() : "";
    }

    public static CommandResult command(long timeoutMs, String... args) {
        Process process = null;
        try {
            process = new ProcessBuilder(args).redirectErrorStream(true).start();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Process finalProcess = process;
            Thread drain = new Thread(() -> drain(finalProcess.getInputStream(), out, 1_048_576), "ace-shell-drain");
            drain.start();
            boolean done = waitFor(process, timeoutMs);
            if (!done) {
                process.destroy();
                drain.join(300);
                return new CommandResult(-1, out.toString(StandardCharsets.UTF_8.name()), "timeout");
            }
            drain.join(300);
            return new CommandResult(process.exitValue(), out.toString(StandardCharsets.UTF_8.name()), "");
        } catch (Exception e) {
            return new CommandResult(-1, "", e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (process != null) process.destroy();
        }
    }

    private static void drain(InputStream in, ByteArrayOutputStream out, int limit) {
        byte[] buffer = new byte[8192];
        int total = 0;
        try {
            for (int n; (n = in.read(buffer)) >= 0 && total < limit; ) {
                int take = Math.min(n, limit - total);
                out.write(buffer, 0, take);
                total += take;
            }
        } catch (Exception ignored) { }
    }

    public static boolean waitFor(Process process, long timeoutMs) throws InterruptedException {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        while (System.nanoTime() < deadline) {
            try {
                process.exitValue();
                return true;
            } catch (IllegalThreadStateException running) {
                Thread.sleep(20L);
            }
        }
        try {
            process.exitValue();
            return true;
        } catch (IllegalThreadStateException running) {
            return false;
        }
    }

    public static String readText(String path, int limit) {
        File file = new File(path);
        if (!file.isFile()) return "";
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] bytes = readBytes(in, limit);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    public static byte[] readBytes(InputStream in, int limit) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        for (int n; (n = in.read(buffer)) >= 0; ) {
            if (total + n > limit) throw new IllegalStateException("data exceeds limit " + limit);
            out.write(buffer, 0, n);
            total += n;
        }
        return out.toByteArray();
    }

    public static List<String> readableProcCmdlines() {
        File[] entries = new File("/proc").listFiles();
        if (entries == null) return Collections.emptyList();
        List<String> values = new ArrayList<>();
        int seen = 0;
        for (File entry : entries) {
            if (seen++ >= 10_000 || !entry.getName().matches("[0-9]+")) continue;
            String text = readText(entry.getAbsolutePath() + "/cmdline", 4096);
            if (!text.isEmpty()) values.add(text.split("\\u0000", 2)[0]);
        }
        return values;
    }

    public static List<String> visiblePackages(Context context) {
        List<String> result = new ArrayList<>();
        try {
            for (PackageInfo info : context.getPackageManager().getInstalledPackages(0)) {
                result.add(info.packageName);
            }
        } catch (Exception ignored) { }
        return result;
    }

    public static int globalSetting(Context context, String key) {
        try {
            return Settings.Global.getInt(context.getContentResolver(), key);
        } catch (Settings.SettingNotFoundException | SecurityException e) {
            return -1;
        }
    }

    public static String sha256(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder out = new StringBuilder();
            for (byte b : digest) out.append(String.format(Locale.US, "%02x", b));
            return out.toString();
        } catch (Exception e) {
            return "unavailable";
        }
    }

    public static String deviceLine() {
        return Build.MANUFACTURER + " " + Build.MODEL + " / Android " + Build.VERSION.RELEASE +
                " (API " + Build.VERSION.SDK_INT + ")";
    }

    public static final class CommandResult {
        public final int exitCode;
        public final String stdout;
        public final String error;

        public CommandResult(int exitCode, String stdout, String error) {
            this.exitCode = exitCode;
            this.stdout = stdout;
            this.error = error;
        }
    }
}
