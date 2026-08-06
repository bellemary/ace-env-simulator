package com.ace.envsimulator.detection;

public final class NativeProbe {
    private static final boolean LOADED;

    static {
        boolean loaded;
        try {
            System.loadLibrary("aceprobe");
            loaded = true;
        } catch (Throwable ignored) {
            loaded = false;
        }
        LOADED = loaded;
    }

    private NativeProbe() {}

    private static native String runProbeNative(int probeId);
    private static native int pathExistsNative(String path);
    private static native String scanTargetMemoryNative(String packageName);
    private static native String readTargetMapsNative(String packageName);

    public static String run(int probeId) {
        if (!LOADED) return "UNAVAILABLE|native probe library not loaded";
        try {
            return runProbeNative(probeId);
        } catch (Throwable error) {
            return "UNAVAILABLE|" + error.getClass().getSimpleName() + ": " + error.getMessage();
        }
    }

    public static int pathExists(String path) {
        if (!LOADED) return -1;
        try {
            return pathExistsNative(path);
        } catch (Throwable ignored) {
            return -1;
        }
    }

    public static String scanTargetMemory(String packageName) {
        if (!LOADED) return "ERROR|native probe library not loaded";
        try {
            return scanTargetMemoryNative(packageName);
        } catch (Throwable error) {
            return "ERROR|" + error.getClass().getSimpleName() + ": " + error.getMessage();
        }
    }

    public static String readTargetMaps(String packageName) {
        if (!LOADED) return "ERROR|native probe library not loaded";
        try {
            return readTargetMapsNative(packageName);
        } catch (Throwable error) {
            return "ERROR|" + error.getClass().getSimpleName() + ": " + error.getMessage();
        }
    }
}
