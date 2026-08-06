package com.ace.envsimulator.advanced;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import com.ace.envsimulator.detection.CheckSupport;

public final class RootShell {
    private static final int DEFAULT_LIMIT = 16 * 1024 * 1024;
    private static final String PID_PREFIX = "__ACE_PID=";
    private final List<Variant> variants = Arrays.asList(
            new Variant("su -c", new String[]{"su", "-c"}),
            new Variant("su 0 -c", new String[]{"su", "0", "-c"}),
            new Variant("su -M -c", new String[]{"su", "-M", "-c"}),
            new Variant("su -mm -c", new String[]{"su", "-mm", "-c"}),
            new Variant("su --mount-master -c", new String[]{"su", "--mount-master", "-c"})
    );
    private Variant preferred;

    public Result request() {
        Variant variant = variants.get(0);
        Result result = executeWith(variant, "id -u; id -Z 2>/dev/null || true", 6_000, 256 * 1024);
        if (result.exitCode == 0 && firstLine(result.stdoutText()).trim().equals("0")) {
            preferred = variant;
            return new Result(0, result.stdout, result.stderr, variant.name);
        }
        String error = variant.name + ": exit=" + result.exitCode + " stderr=" + result.stderrText();
        return new Result(-1, result.stdout, error.getBytes(StandardCharsets.UTF_8), variant.name);
    }

    public Result execute(String script, long timeoutMs) {
        List<Variant> order = new ArrayList<>();
        if (preferred != null) order.add(preferred);
        for (Variant variant : variants) if (variant != preferred) order.add(variant);
        Result last = null;
        for (Variant variant : order) {
            last = executeWith(variant, script, timeoutMs, DEFAULT_LIMIT);
            if (last.exitCode == 0) {
                preferred = variant;
                return new Result(0, last.stdout, last.stderr, variant.name);
            }
            if (last.exitCode == 68 || last.exitCode == 124) return last;
        }
        return last == null ? new Result(-1, new byte[0], "no su variants".getBytes(StandardCharsets.UTF_8), "none") : last;
    }

    public Result readFile(String path, int limit) {
        if (!isAllowed(path)) return new Result(65, new byte[0], "path outside target package".getBytes(StandardCharsets.UTF_8), "rejected");
        return readAllowedPath(path, limit);
    }

    public List<String> targetApkPaths() {
        Result result = execute("pm path com.tencent.tmgp.dfm 2>/dev/null", 6_000);
        List<String> paths = new ArrayList<>();
        if (result.exitCode != 0) return paths;
        for (String line : result.stdoutText().split("\\r?\\n")) {
            if (!line.startsWith("package:")) continue;
            String path = line.substring("package:".length()).trim();
            if (isAllowedApk(path)) paths.add(path);
        }
        return paths;
    }

    public Result readApk(String path, int limit) {
        if (!isAllowedApk(path)) return new Result(65, new byte[0], "path outside APK locations".getBytes(StandardCharsets.UTF_8), "rejected");
        return readAllowedPath(path, limit);
    }

    private Result readAllowedPath(String path, int limit) {
        String quoted = quote(path);
        String script = "if [ -L " + quoted + " ]; then echo symbolic-link >&2; exit 66; fi; " +
                "if [ ! -f " + quoted + " ]; then exit 67; fi; cat " + quoted;
        List<Variant> order = new ArrayList<>();
        if (preferred != null) order.add(preferred);
        for (Variant variant : variants) if (variant != preferred) order.add(variant);
        Result last = null;
        for (Variant variant : order) {
            last = executeWith(variant, script, 6_000, limit);
            if (last.exitCode == 0) {
                preferred = variant;
                return new Result(0, last.stdout, last.stderr, variant.name);
            }
            if (last.exitCode == 68 || last.exitCode == 124) return last;
        }
        return last == null ? new Result(-1, new byte[0], new byte[0], "none") : last;
    }

    public String diagnostics() {
        Result result = execute("id; id -Z 2>/dev/null || true; readlink /proc/self/ns/mnt; readlink /proc/1/ns/mnt; " +
                "ls -ldZ /data /data/user /data/user/0 /data/user/0/com.tencent.tmgp.dfm " +
                "/data/user/0/com.tencent.tmgp.dfm/files /data/user/0/com.tencent.tmgp.dfm/files/ano_tmp 2>&1", 8_000);
        return result.stdoutText() + "\n" + result.stderrText();
    }

    public String variantName() { return preferred == null ? "none" : preferred.name; }

    private Result executeWith(Variant variant, String script, long timeoutMs, int limit) {
        Process process = null;
        StreamCollector stderr = null;
        try {
            List<String> command = new ArrayList<>(Arrays.asList(variant.argv));
            command.add("echo " + PID_PREFIX + "$$ >&2; " + script);
            process = new ProcessBuilder(command).start();
            StreamCollector stdout = new StreamCollector(process.getInputStream(), limit);
            stderr = new StreamCollector(process.getErrorStream(), 2 * 1024 * 1024);
            Thread outThread = new Thread(stdout, "ace-root-out");
            Thread errThread = new Thread(stderr, "ace-root-err");
            outThread.start(); errThread.start();
            boolean done = CheckSupport.waitFor(process, timeoutMs);
            if (!done) {
                errThread.join(150);
                terminateDescendants(variant, parseShellPid(stderr.bytes()));
                process.destroy();
                closeProcessStreams(process);
            }
            outThread.join(500); errThread.join(500);
            if (stdout.overflow) return new Result(68, stdout.bytes(), "stdout limit exceeded".getBytes(StandardCharsets.UTF_8), variant.name);
            return new Result(done ? process.exitValue() : 124, stdout.bytes(), sanitizeStderr(stderr.bytes()), variant.name);
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            if (process != null) {
                terminateDescendants(variant, stderr == null ? -1 : parseShellPid(stderr.bytes()));
                process.destroy();
            }
            return new Result(-1, new byte[0], (e.getClass().getSimpleName() + ": " + e.getMessage()).getBytes(StandardCharsets.UTF_8), variant.name);
        } finally {
            if (process != null) {
                process.destroy();
                closeProcessStreams(process);
            }
        }
    }

    private static int parseShellPid(byte[] raw) {
        String value = new String(raw, StandardCharsets.UTF_8);
        int start = value.indexOf(PID_PREFIX);
        if (start < 0) return -1;
        start += PID_PREFIX.length();
        int end = start;
        while (end < value.length() && Character.isDigit(value.charAt(end))) end++;
        if (end == start) return -1;
        try { return Integer.parseInt(value.substring(start, end)); }
        catch (NumberFormatException ignored) { return -1; }
    }

    private static byte[] sanitizeStderr(byte[] raw) {
        StringBuilder clean = new StringBuilder();
        for (String line : new String(raw, StandardCharsets.UTF_8).split("\\r?\\n")) {
            if (!line.startsWith(PID_PREFIX) && !line.isEmpty()) clean.append(line).append('\n');
        }
        return clean.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void terminateDescendants(Variant variant, int shellPid) {
        if (shellPid <= 1) return;
        Process killer = null;
        boolean interrupted = Thread.interrupted();
        try {
            List<String> command = new ArrayList<>(Arrays.asList(variant.argv));
            command.add("for c in $(cat /proc/" + shellPid + "/task/" + shellPid +
                    "/children 2>/dev/null); do kill -9 \"$c\" 2>/dev/null; done; kill -9 " +
                    shellPid + " 2>/dev/null; true");
            killer = new ProcessBuilder(command).redirectErrorStream(true).start();
            long deadline = System.currentTimeMillis() + 800;
            while (System.currentTimeMillis() < deadline) {
                try { killer.exitValue(); break; }
                catch (IllegalThreadStateException running) {
                    try { Thread.sleep(10); }
                    catch (InterruptedException e) { interrupted = true; break; }
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (killer != null) {
                killer.destroy();
                closeProcessStreams(killer);
            }
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private static void closeProcessStreams(Process process) {
        closeQuietly(process.getOutputStream());
        closeQuietly(process.getInputStream());
        closeQuietly(process.getErrorStream());
    }

    private static void closeQuietly(Closeable stream) {
        try { stream.close(); } catch (Exception ignored) { }
    }

    private static boolean isAllowed(String path) {
        return path.startsWith("/data/user/0/com.tencent.tmgp.dfm/") ||
                path.startsWith("/data/data/com.tencent.tmgp.dfm/") ||
                path.startsWith("/data/user_de/0/com.tencent.tmgp.dfm/");
    }

    private static boolean isAllowedApk(String path) {
        return path.startsWith("/data/app/") || path.startsWith("/data/app-private/") ||
                path.startsWith("/mnt/expand/") && path.contains("/app/");
    }

    public static String quote(String value) { return "'" + value.replace("'", "'\\''") + "'"; }
    private static String firstLine(String value) { int i = value.indexOf('\n'); return i < 0 ? value : value.substring(0, i); }

    private static final class Variant {
        final String name; final String[] argv;
        Variant(String name, String[] argv) { this.name = name; this.argv = argv; }
    }

    private static final class StreamCollector implements Runnable {
        private final InputStream input; private final int limit;
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        volatile boolean overflow;
        StreamCollector(InputStream input, int limit) { this.input = input; this.limit = limit; }
        @Override public void run() {
            byte[] buffer = new byte[8192];
            try {
                for (int n; (n = input.read(buffer)) >= 0; ) {
                    int remaining = limit - output.size();
                    if (remaining > 0) output.write(buffer, 0, Math.min(n, remaining));
                    if (n > remaining) overflow = true;
                }
            } catch (Exception ignored) { }
        }
        byte[] bytes() { return output.toByteArray(); }
    }

    public static final class Result {
        public final int exitCode; public final byte[] stdout; public final byte[] stderr; public final String variant;
        Result(int exitCode, byte[] stdout, byte[] stderr, String variant) {
            this.exitCode = exitCode; this.stdout = stdout; this.stderr = stderr; this.variant = variant;
        }
        public String stdoutText() { return new String(stdout, StandardCharsets.UTF_8); }
        public String stderrText() { return new String(stderr, StandardCharsets.UTF_8); }
    }
}
