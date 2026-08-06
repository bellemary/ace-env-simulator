#include <jni.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <pthread.h>

namespace {

// ==================== page-residency probe (existing) ====================

std::string page_probe(long syscall_number, bool kernel_su) {
#if !defined(__aarch64__)
    return "UNAVAILABLE|page-residency syscall probe is AArch64-specific";
#else
    const long page_size = sysconf(_SC_PAGESIZE);
    void *page = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return "UNAVAILABLE|mmap failed";
    madvise(page, static_cast<size_t>(page_size), MADV_DONTNEED);
    unsigned char before = 0;
    if (mincore(page, static_cast<size_t>(page_size), &before) != 0) {
        munmap(page, static_cast<size_t>(page_size));
        return "UNAVAILABLE|mincore before failed";
    }
    if (before & 1) {
        munmap(page, static_cast<size_t>(page_size));
        return "UNAVAILABLE|probe page could not be evicted";
    }
    if (kernel_su) {
        int out = 0;
        syscall(syscall_number, 0xDEADBEEFUL, 1UL, page, 0UL, &out);
    } else {
        syscall(syscall_number, page, static_cast<off_t>(-1));
    }
    unsigned char after = 0;
    bool ok = mincore(page, static_cast<size_t>(page_size), &after) == 0;
    munmap(page, static_cast<size_t>(page_size));
    if (!ok) return "UNAVAILABLE|mincore after failed";
    return (after & 1) ? "HIT|probe page became resident" : "SAFE|probe page remained non-resident";
#endif
}

// ==================== process_vm_readv memory scanner ====================

struct MemRegion {
    unsigned long start;
    unsigned long end;
    bool writable;
    char name[256];
};

struct ScanHit {
    std::string category;
    std::string pattern;
    unsigned long address;
    std::string context;
};

static int g_scan_pid = -1;

static int get_syscall_readv() {
#if defined(__aarch64__)
    return 270;
#elif defined(__arm__)
    return 376;
#elif defined(__i386__)
    return 347;
#else
    return 310;
#endif
}

static bool vm_read(unsigned long addr, void *buf, size_t size) {
    if (g_scan_pid <= 0) return false;
    struct iovec local_iov = { buf, size };
    struct iovec remote_iov = { (void *)addr, size };
    ssize_t n = syscall(get_syscall_readv(), g_scan_pid, &local_iov, 1, &remote_iov, 1, 0);
    return n == (ssize_t)size;
}

static int find_pid(const char *pkg) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *e;
    int found = -1;
    while ((e = readdir(d)) != nullptr) {
        int id = atoi(e->d_name);
        if (id <= 0) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", id);
        FILE *fp = fopen(path, "r");
        if (!fp) continue;
        char cmdline[256] = {0};
        if (fgets(cmdline, sizeof(cmdline), fp) != nullptr) {
            if (strncmp(pkg, cmdline, strlen(pkg)) == 0) {
                found = id;
                fclose(fp);
                break;
            }
        }
        fclose(fp);
    }
    closedir(d);
    return found;
}

static std::vector<MemRegion> parse_maps(int pid) {
    std::vector<MemRegion> regions;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return regions;
    char line[512];
    while (fgets(line, sizeof(line), fp) != nullptr) {
        MemRegion r = {};
        r.name[0] = '\0';
        char perms[8] = {0};
        unsigned long off;
        unsigned int dev_maj, dev_min;
        long inode;
        char name[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %x:%x %ld %255[^\n]",
                       &r.start, &r.end, perms, &off, &dev_maj, &dev_min, &inode, name);
        if (n < 3) continue;
        r.writable = perms[1] == 'w';
        strncpy(r.name, name, sizeof(r.name) - 1);
        regions.push_back(r);
    }
    fclose(fp);
    return regions;
}

struct PatternDef {
    const char *category;
    const char *pattern;
};

static const PatternDef PATTERNS[] = {
    {"root", "kernelsu"},
    {"root", "KernelSU"},
    {"root", "ksud"},
    {"root", "/data/adb/ksud"},
    {"root", "/data/adb/ksu"},
    {"root", "magisk"},
    {"root", "Magisk"},
    {"root", "zygisk"},
    {"root", "Zygisk"},
    {"root", "apatch"},
    {"root", "APatch"},
    {"root", "/sbin/su"},
    {"root", "/system/bin/su"},
    {"root", "/system/xbin/su"},
    {"root", "superuser"},
    {"root", "SuperSU"},
    {"root", "busybox"},
    {"root", "/data/adb/magisk"},
    {"root", "root_detected"},
    {"root", "root_manager"},
    {"boot", "bootloader"},
    {"boot", "verified_boot"},
    {"boot", "verifiedboot"},
    {"boot", "vbmeta"},
    {"boot", "boot_unlocked"},
    {"boot", "device_state"},
    {"boot", "is_unlocked"},
    {"boot", "orange"},
    {"boot", "unlocked"},
    {"frida", "frida"},
    {"frida", "Frida"},
    {"frida", "gum-js-loop"},
    {"frida", "linjector"},
    {"frida", "gadget"},
    {"frida", "/data/local/tmp/re."},
    {"xposed", "xposed"},
    {"xposed", "Xposed"},
    {"xposed", "lsposed"},
    {"xposed", "LSPosed"},
    {"xposed", "edxp"},
    {"xposed", "EdXposed"},
    {"cert", "certificate"},
    {"cert", "cert_hit"},
    {"cert", "cert_valid"},
    {"cert", "crt.i2"},
    {"cert", "certificate_id"},
    {"fingerprint", "fingerprint"},
    {"fingerprint", "device_id"},
    {"fingerprint", "android_id"},
    {"fingerprint", "deviceuniqueid"},
    {"fingerprint", "imei"},
    {"fingerprint", "serial"},
    {"emulator", "emulator"},
    {"emulator", "qemu"},
    {"emulator", "goldfish"},
    {"emulator", "vphone"},
    {"emulator", "nox"},
    {"emulator", "bluestacks"},
    {"report", "TssSDK"},
    {"report", "tss_get_report"},
    {"report", "TssSDKGetReportData"},
    {"report", "tss_get_report_data2"},
    {"report", "tss_get_report_data3"},
    {"report", "report_data"},
    {"report", "tersafe"},
    {"report", "ano_tmp"},
    {"report", "mrpcs"},
    {"report", "report_payload"},
    {"hook", "substrate"},
    {"hook", "Substrate"},
    {"hook", "inject"},
    {"hook", "hook_detoured"},
    {"tool", "mt2.cn"},
    {"tool", "bin.mt.plus"},
    {"tool", "rootexplorer"},
    {"tool", "RootExplorer"},
    {"tool", "blackmart"},
    {"upload", "upload_data"},
    {"upload", "report_upload"},
    {"upload", "send_report"},
    {"upload", "coordinate"},
    {"upload", "coordinate_destroy"},
    {"upload", "encrypt_state"},
    {nullptr, nullptr}
};

static void scan_buffer(const unsigned char *buf, size_t len, unsigned long base,
                        std::vector<ScanHit> &hits) {
    for (const PatternDef *p = PATTERNS; p->pattern != nullptr; p++) {
        size_t plen = strlen(p->pattern);
        if (plen == 0 || plen > len) continue;
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(buf + i, p->pattern, plen) != 0) continue;
            // 提取上下文 (前后各32字节可打印部分)
            char ctx[80] = {0};
            size_t ctx_start = i >= 32 ? i - 32 : 0;
            size_t ctx_end = i + plen + 32;
            if (ctx_end > len) ctx_end = len;
            size_t ci = 0;
            for (size_t j = ctx_start; j < ctx_end && ci < sizeof(ctx) - 1; j++) {
                ctx[ci++] = (buf[j] >= 0x20 && buf[j] < 0x7f) ? buf[j] : '.';
            }
            ctx[ci] = '\0';
            hits.push_back({p->category, p->pattern, base + i, ctx});
            i += plen - 1;
        }
    }
}

static std::string format_hits(const std::vector<ScanHit> &hits,
                               unsigned long libtersafe_base,
                               int regions_scanned,
                               unsigned long bytes_scanned) {
    std::string out;
    char header[256];
    snprintf(header, sizeof(header),
             "SCAN_RESULT|pid=%d|libtersafe_base=0x%lx|regions=%d|bytes=%lu|hits=%zu\n",
             g_scan_pid, libtersafe_base, regions_scanned, bytes_scanned, hits.size());
    out += header;
    for (size_t i = 0; i < hits.size() && i < 500; i++) {
        const ScanHit &h = hits[i];
        char line[512];
        snprintf(line, sizeof(line), "HIT|%s|%s|0x%lx|%s\n",
                 h.category.c_str(), h.pattern.c_str(), h.address, h.context.c_str());
        out += line;
    }
    if (hits.size() > 500) {
        char tail[64];
        snprintf(tail, sizeof(tail), "TRUNCATED|%zu more hits omitted\n", hits.size() - 500);
        out += tail;
    }
    return out;
}

} // namespace

// ==================== JNI entry points ====================

extern "C" JNIEXPORT jstring JNICALL
Java_com_ace_envsimulator_detection_NativeProbe_runProbeNative(JNIEnv *env, jclass, jint probe_id) {
    std::string result;
    switch (probe_id) {
        case 12: result = page_probe(45, false); break;
        case 13: result = page_probe(167, true); break;
        default: result = "UNAVAILABLE|unknown native probe"; break;
    }
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_ace_envsimulator_detection_NativeProbe_pathExistsNative(JNIEnv *env, jclass, jstring input) {
    const char *path = env->GetStringUTFChars(input, nullptr);
    if (path == nullptr) return -1;
#if defined(__aarch64__)
    long result = syscall(48, AT_FDCWD, path, F_OK, 0);
#else
    long result = faccessat(AT_FDCWD, path, F_OK, 0);
#endif
    env->ReleaseStringUTFChars(input, path);
    return result == 0 ? 1 : 0;
}

// 内存扫描：查找目标进程并扫描其可写内存区域
extern "C" JNIEXPORT jstring JNICALL
Java_com_ace_envsimulator_detection_NativeProbe_scanTargetMemoryNative(JNIEnv *env, jclass, jstring pkg) {
    const char *package = env->GetStringUTFChars(pkg, nullptr);
    if (package == nullptr) return env->NewStringUTF("ERROR|null package");

    g_scan_pid = find_pid(package);
    env->ReleaseStringUTFChars(pkg, package);

    if (g_scan_pid <= 0) {
        return env->NewStringUTF("NO_PROCESS|target process not found");
    }

    std::vector<MemRegion> regions = parse_maps(g_scan_pid);
    if (regions.empty()) {
        return env->NewStringUTF("ERROR|cannot read maps");
    }

    unsigned long libtersafe_base = 0;
    int regions_scanned = 0;
    unsigned long bytes_scanned = 0;
    std::vector<ScanHit> all_hits;

    // 扫描缓冲区：64KB chunks
    const size_t CHUNK = 65536;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);
    if (!buf) return env->NewStringUTF("ERROR|alloc failed");

    for (const MemRegion &r : regions) {
        // 只扫描可写区域（检测结果和报告在可写内存中生成）
        if (!r.writable) continue;

        // 记录 libtersafe.so 基址
        if (libtersafe_base == 0 && strstr(r.name, "libtersafe") != nullptr) {
            libtersafe_base = r.start;
        }

        // 限制单区域扫描大小（最大 16MB）
        unsigned long region_size = r.end - r.start;
        if (region_size > 16UL * 1024 * 1024) region_size = 16UL * 1024 * 1024;

        // 限制总扫描大小（最大 128MB）
        if (bytes_scanned + region_size > 128UL * 1024 * 1024) {
            region_size = 128UL * 1024 * 1024 - bytes_scanned;
            if (region_size == 0) break;
        }

        regions_scanned++;
        for (unsigned long off = 0; off < region_size; off += CHUNK) {
            size_t to_read = CHUNK;
            if (off + to_read > region_size) to_read = region_size - off;
            if (vm_read(r.start + off, buf, to_read)) {
                scan_buffer(buf, to_read, r.start + off, all_hits);
                bytes_scanned += to_read;
            }
        }
    }

    // 也扫描 libtersafe.so 的只读段（规则和字符串常量）
    if (libtersafe_base != 0) {
        for (const MemRegion &r : regions) {
            if (strstr(r.name, "libtersafe") == nullptr) continue;
            unsigned long region_size = r.end - r.start;
            if (region_size > 8UL * 1024 * 1024) region_size = 8UL * 1024 * 1024;
            regions_scanned++;
            for (unsigned long off = 0; off < region_size; off += CHUNK) {
                size_t to_read = CHUNK;
                if (off + to_read > region_size) to_read = region_size - off;
                if (vm_read(r.start + off, buf, to_read)) {
                    scan_buffer(buf, to_read, r.start + off, all_hits);
                    bytes_scanned += to_read;
                }
            }
        }
    }

    free(buf);
    std::string result = format_hits(all_hits, libtersafe_base, regions_scanned, bytes_scanned);
    return env->NewStringUTF(result.c_str());
}

// 读取 /proc/pid/maps 获取目标进程内存映射
extern "C" JNIEXPORT jstring JNICALL
Java_com_ace_envsimulator_detection_NativeProbe_readTargetMapsNative(JNIEnv *env, jclass, jstring pkg) {
    const char *package = env->GetStringUTFChars(pkg, nullptr);
    if (package == nullptr) return env->NewStringUTF("ERROR|null package");

    int pid = find_pid(package);
    env->ReleaseStringUTFChars(pkg, package);

    if (pid <= 0) return env->NewStringUTF("NO_PROCESS|target not found");

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return env->NewStringUTF("ERROR|cannot open maps");

    std::string out;
    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), fp) != nullptr && count < 2000) {
        if (strstr(line, "libtersafe") || strstr(line, "libtp") || strstr(line, "libtprt")) {
            out += line;
            count++;
        }
    }
    fclose(fp);

    if (out.empty()) out = "NO_LIBTERSAFE|libtersafe.so not found in maps";
    return env->NewStringUTF(out.c_str());
}
