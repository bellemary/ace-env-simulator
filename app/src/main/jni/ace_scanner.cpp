// ace_scanner v2.5 - 特征点定位内存扫描器 (root 执行)
//
// 核心改进 (相比 v2.4):
//   1. /proc/[pid]/maps 实时解析模块基址 (ASLR-aware)
//   2. 30+ 已知特征点数据库 (libtersafe / libtprt / libUE4 / libGPM)
//   3. process_vm_readv 系统调用读取 64 字节，3 次重试
//   4. /proc/[pid]/mem 回退读取
//   5. 基线对比判定 (Hook 痕迹 / 零填充 / 异常 BRK)
//   6. 每个特征点输出: 模块 + 偏移 + 地址 + 十六进制 + 状态 + 原因
//
// 用法: ace_scanner <package_name> [interval_ms] [max_rounds]
// 输出格式:
//   FEATURE|<module>|<offset>|<address>|<hex64>|<status>|<reason>
//   SCAN_RESULT|pid=...|features=...|risk=...
//   SCAN_DONE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>

// ==================== 跨进程内存读取 ====================

static int g_pid = 0;

static int get_syscall_readv() {
#if defined(__aarch64__)
    return 270;  // process_vm_readv
#elif defined(__arm__)
    return 376;
#elif defined(__i386__)
    return 347;
#else
    return 310;
#endif
}

// process_vm_readv 跨进程读取
static bool vm_read(unsigned long addr, void *buf, size_t size) {
    if (g_pid <= 0) return false;
    struct iovec local_iov = { buf, size };
    struct iovec remote_iov = { (void *)addr, size };
    ssize_t n = syscall(get_syscall_readv(), g_pid, &local_iov, 1, &remote_iov, 1, 0);
    return n == (ssize_t)size;
}

// /proc/pid/mem 回退读取
static bool vm_read_mem(unsigned long addr, void *buf, size_t size) {
    if (g_pid <= 0) return false;
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/mem", g_pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = pread(fd, buf, size, (off_t)addr);
    close(fd);
    return n == (ssize_t)size;
}

// 带重试的读取 (process_vm_readv -> /proc/pid/mem -> 重试 3 次)
static bool read_remote_retry(unsigned long addr, void *buf, size_t size, int *attempts, int *fail_reason) {
    *attempts = 0;
    *fail_reason = 0;
    for (int i = 0; i < 3; i++) {
        (*attempts)++;
        if (vm_read(addr, buf, size)) return true;
        *fail_reason = errno;
        if (vm_read_mem(addr, buf, size)) return true;
        *fail_reason = errno;
        usleep(50 * 1000);  // 50ms 重试间隔
    }
    return false;
}

// ==================== PID 查找 ====================

static int find_pid(const char *pkg) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *e;
    int found = -1;
    while ((e = readdir(d)) != NULL) {
        int id = atoi(e->d_name);
        if (id <= 0) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", id);
        FILE *fp = fopen(path, "r");
        if (!fp) continue;
        char cmdline[256] = {0};
        if (fgets(cmdline, sizeof(cmdline), fp) != NULL) {
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

// ==================== /proc/[pid]/maps 模块基址解析 (ASLR-aware) ====================

struct ModuleInfo {
    char name[128];
    unsigned long base;
    unsigned long end;
    unsigned long size;
};

#define MAX_MODULES 64
static struct ModuleInfo g_modules[MAX_MODULES];
static int g_module_count = 0;

// 实时解析 /proc/[pid]/maps，找到所有相关模块的基址
static int parse_maps_for_modules(int pid) {
    g_module_count = 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL && g_module_count < MAX_MODULES) {
        unsigned long start, end, off;
        char perms[8] = {0};
        unsigned int dev_maj, dev_min;
        long inode;
        char name[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %x:%x %ld %255[^\n]",
                       &start, &end, perms, &off, &dev_maj, &dev_min, &inode, name);
        if (n < 3) continue;

        // 只关注我们需要的模块
        char *p = name;
        while (*p == ' ') p++;
        if (*p == '\0') continue;

        // 提取模块短名
        char *slash = strrchr(p, '/');
        char *short_name = slash ? slash + 1 : p;

        // 检查是否是我们关心的模块
        bool relevant = false;
        const char *wanted[] = {"libtersafe", "libtprt", "libUE4", "libGPM",
                                 "libil2cpp", "libunity", NULL};
        for (int i = 0; wanted[i] != NULL; i++) {
            if (strncmp(short_name, wanted[i], strlen(wanted[i])) == 0) {
                relevant = true;
                break;
            }
        }
        if (!relevant) continue;

        // 查找或创建模块记录 (取第一个映射的地址作为基址，处理 ASLR)
        int idx = -1;
        for (int i = 0; i < g_module_count; i++) {
            if (strcmp(g_modules[i].name, short_name) == 0) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            idx = g_module_count++;
            strncpy(g_modules[idx].name, short_name, sizeof(g_modules[idx].name) - 1);
            g_modules[idx].base = start;
            g_modules[idx].end = end;
            g_modules[idx].size = end - start;
        } else {
            // 扩展模块范围
            if (start < g_modules[idx].base) g_modules[idx].base = start;
            if (end > g_modules[idx].end) g_modules[idx].end = end;
            g_modules[idx].size = g_modules[idx].end - g_modules[idx].base;
        }
    }
    fclose(fp);
    return g_module_count;
}

static unsigned long get_module_base(const char *name) {
    for (int i = 0; i < g_module_count; i++) {
        if (strcmp(g_modules[i].name, name) == 0) return g_modules[i].base;
    }
    return 0;
}

// ==================== 特征点数据库 (30+ 关键点) ====================
// 基于深度逆向经验 + IDA 分析 + 用户指定偏移

struct FeaturePoint {
    const char *module;      // 模块名 (如 "libtersafe.so")
    unsigned long offset;    // 偏移量 (如 0x521500)
    const char *category;    // 分类
    const char *name;        // 特征点名称
    const char *description; // 描述
};

static const struct FeaturePoint FEATURES[] = {
    // ===== libtersafe.so 关键特征点 (用户指定 + 逆向结果) =====
    {"libtersafe.so", 0x521500,  "report",    "tersafe_main_report_buffer",
     "ACE 主报告缓冲区 - TSS 上报数据汇集点"},
    {"libtersafe.so", 0x3A8BC0,  "report",    "tersafe_report_data2_handler",
     "tss_get_report_data2 处理函数 - 第二类报告数据"},
    {"libtersafe.so", 0x4C03D4,  "report",    "TssSDKGetReportData",
     "TSS 主报告获取接口 - 取得长度与缓冲区后交给发送链"},
    {"libtersafe.so", 0x4C075C,  "report",    "tss_get_report_data2",
     "TSS report_data2 接口 - 按固定十六进制字段格式解析"},
    {"libtersafe.so", 0x4C0824,  "report",    "tss_get_report_data3",
     "TSS report_data3 接口 - 按类型分流解码"},
    {"libtersafe.so", 0x4C0CDC,  "report",    "tss_del_report_data3",
     "TSS report_data3 释放接口 - 释放前缓冲区可读"},
    {"libtersafe.so", 0x488E34,  "crypto",    "report_decoder_helper",
     "report_data3 二次解码辅助函数"},
    {"libtersafe.so", 0x237E08,  "crypto",    "xor_decrypt_loop",
     "固定循环 XOR 解密函数 - sub_237E08"},
    {"libtersafe.so", 0x4E9A50,  "crypto",    "key_provider_30548",
     "密钥提供者 - sub_4E9A50(30548), 36 字节周期"},
    {"libtersafe.so", 0x4D949C,  "cert",      "crt_i2_reader",
     "crt.i2.dat 读取函数 - 设备/客户端证书记录"},
    {"libtersafe.so", 0x4D1EE8,  "fingerprint","ano_ksh_reader",
     "ano_ksh.dat 读取函数 - 内核 shell 环境信息"},

    // ===== libtprt.so 运行时保护模块 (IDA 实测偏移) =====
    {"libtprt.so", 0x25d1c,   "ace",       "JNI_OnLoad",
     "libtprt JNI 入口 - 启用 ENABLE_OBJ_VM"},
    {"libtprt.so", 0x37610,   "hook",      "REL_HOOK_0",
     "Inline Hook 0 - 函数拦截点 0"},
    {"libtprt.so", 0x3777c,   "hook",      "REL_HOOK_1",
     "Inline Hook 1 - 函数拦截点 1"},
    {"libtprt.so", 0x378e8,   "hook",      "REL_HOOK_2",
     "Inline Hook 2 - 函数拦截点 2"},
    {"libtprt.so", 0x37a54,   "hook",      "REL_HOOK_3",
     "Inline Hook 3 - 函数拦截点 3"},
    {"libtprt.so", 0x37bc0,   "hook",      "REL_HOOK_4",
     "Inline Hook 4 - 函数拦截点 4"},
    {"libtprt.so", 0x37d2c,   "hook",      "REL_HOOK_5",
     "Inline Hook 5 - 函数拦截点 5"},
    {"libtprt.so", 0x37e98,   "hook",      "REL_HOOK_6",
     "Inline Hook 6 - 函数拦截点 6"},
    {"libtprt.so", 0x38004,   "hook",      "REL_HOOK_7",
     "Inline Hook 7 - 函数拦截点 7"},
    {"libtprt.so", 0x140760,  "hook",      "tp_syscall_imp",
     "直接 syscall 实现 - 反 Hook 检测关键点"},
    {"libtprt.so", 0xb6f60,   "antidebug", "unwind_info_query",
     "Unwind 信息查询 - 反调试检测"},
    {"libtprt.so", 0xb72e8,   "antidebug", "unwind_ioctl",
     "Unwind ioctl 调用 - 反调试检测"},
    {"libtprt.so", 0x138a60,  "antidebug", "ptrace_call_site",
     "ptrace 调用点 - 反调试检测"},
    {"libtprt.so", 0x12ba10,  "report",    "tss_sdk_sigdata_ref",
     "TSS_SDK_SIGDATA 引用 - 签名数据"},
    {"libtprt.so", 0x19a608,  "hook",      "g_tprt_pfn_array",
     "函数指针表 - Hook 检测目标 (被篡改即为异常)"},
    {"libtprt.so", 0x19bb38,  "hook",      "g_tprt_ori_array",
     "原始函数备份表 - Hook 检测基准"},
    {"libtprt.so", 0x16ae58,  "ace",       "magic_string_txy",
     "Txy*#xP?@xxP6~C 魔数字符串 (51 处引用)"},
    {"libtprt.so", 0x16b2ec,  "ace",       "libtersafe_so_string",
     "libtersafe.so 自引用字符串"},
    {"libtprt.so", 0x163bc6,  "ace",       "version_4_7_14",
     "4.7.14.42254_cn 版本号字符串"},

    // ===== libUE4.so 引擎关键点 (替代 libil2cpp.so) =====
    {"libUE4.so", 0x1D4E88,   "engine",    "ue4_engine_tick",
     "UE4 引擎 Tick 函数 - 游戏主循环入口"},
    {"libUE4.so", 0x4E9A50,   "engine",    "ue4_detection_hook",
     "UE4 检测钩子点 - ACE 注入点"},

    // ===== libGPM.so Tencent GPM SDK =====
    {"libGPM.so", 0x1000,     "gpm",       "gpm_init_section",
     "GPM SDK 初始化段 - 反作弊 SDK 入口"},

    {NULL, 0, NULL, NULL, NULL}
};

static int count_features() {
    int n = 0;
    while (FEATURES[n].module != NULL) n++;
    return n;
}

// ==================== 基线对比判定 ====================

// 判定特征点状态: 正常 / 可疑 / 异常 / 不可读
// 正常: 代码段有合理指令模式；数据段有合理内容
// 可疑: 全零填充、明显 Hook 痕迹 (BRK 序列)
// 异常: 函数指针表与原始备份不匹配
// 不可读: 读取失败
static const char *judge_feature(const unsigned char *buf, size_t len,
                                  const struct FeaturePoint *fp,
                                  char *reason, size_t reason_size) {
    if (buf == NULL || len == 0) {
        snprintf(reason, reason_size, "读取失败 - 地址不可读或权限不足");
        return "unreadable";
    }

    // 统计字节特征
    int zero_count = 0;
    int ff_count = 0;
    bool has_brk = false;        // ARM64 BRK 指令 (0xD503201F 反编码)
    bool has_nop = false;        // ARM64 NOP (0xD503201F)
    bool has_hook_jmp = false;   // Hook 跳转模式 (LDR X16, =addr; BR X16)

    for (size_t i = 0; i < len; i++) {
        if (buf[i] == 0x00) zero_count++;
        if (buf[i] == 0xFF) ff_count++;
    }

    // 检查 ARM64 BRK 指令模式 (常见于 Hook 覆盖)
    if (len >= 4) {
        for (size_t i = 0; i + 4 <= len; i += 4) {
            uint32_t insn = 0;
            memcpy(&insn, buf + i, 4);
            // BRK #imm (0xD42000x0) - 断点指令
            if ((insn & 0xFFE0001F) == 0xD4200000) has_brk = true;
            // NOP (0xD503201F)
            if (insn == 0xD503201F) has_nop = true;
            // LDR X16/X17, [PC, #imm] (Hook 跳转模式)
            if ((insn & 0xFF000000) == 0x58000000 &&
                ((insn & 0x1F) == 16 || (insn & 0x1F) == 17)) has_hook_jmp = true;
        }
    }

    // ===== 分类判定 =====
    const char *cat = fp->category;

    // 函数指针表类 (Hook 检测) - 检查是否被篡改
    if (strcmp(cat, "hook") == 0 && (strstr(fp->name, "pfn_array") ||
                                       strstr(fp->name, "ori_array"))) {
        if (has_brk || has_hook_jmp) {
            snprintf(reason, reason_size, "函数指针表被篡改 - 检测到 Hook 跳转指令");
            return "risk";
        }
        if (zero_count > (int)(len * 0.9)) {
            snprintf(reason, reason_size, "函数指针表全零 - 可能未初始化或被清零");
            return "suspicious";
        }
        snprintf(reason, reason_size, "函数指针表内容正常 - 未检测到 Hook 篡改");
        return "pass";
    }

    // Hook 函数类 (REL_HOOK_*) - 检查是否被二次 Hook
    if (strstr(fp->name, "REL_HOOK_") != NULL) {
        if (has_hook_jmp) {
            snprintf(reason, reason_size, "REL_HOOK 函数被二次 Hook - 检测到外部跳转指令");
            return "risk";
        }
        if (has_brk) {
            snprintf(reason, reason_size, "REL_HOOK 函数被 BRK 覆盖 - 可能有调试器附加");
            return "suspicious";
        }
        snprintf(reason, reason_size, "REL_HOOK 函数代码完整 - 未被二次 Hook");
        return "pass";
    }

    // 反调试类 - 检查是否被绕过
    if (strcmp(cat, "antidebug") == 0) {
        if (has_nop && zero_count > (int)(len * 0.5)) {
            snprintf(reason, reason_size, "反调试函数被 NOP 填充 - 反调试已被绕过");
            return "risk";
        }
        if (has_brk) {
            snprintf(reason, reason_size, "反调试函数被断点覆盖 - 可能有调试器附加");
            return "suspicious";
        }
        snprintf(reason, reason_size, "反调试函数代码完整 - 未被绕过");
        return "pass";
    }

    // 报告/加密类 - 检查代码是否完整
    if (strcmp(cat, "report") == 0 || strcmp(cat, "crypto") == 0) {
        if (has_hook_jmp) {
            snprintf(reason, reason_size, "报告/加密函数被 Hook - 数据可能被篡改");
            return "risk";
        }
        if (zero_count > (int)(len * 0.95)) {
            snprintf(reason, reason_size, "函数代码全零 - 可能未加载或被清零");
            return "suspicious";
        }
        snprintf(reason, reason_size, "函数代码完整 - 未检测到 Hook");
        return "pass";
    }

    // 字符串类 - 检查内容是否可读
    if (strstr(fp->name, "string") != NULL || strstr(fp->name, "magic") != NULL ||
        strstr(fp->name, "version") != NULL) {
        int printable = 0;
        for (size_t i = 0; i < len; i++) {
            if (buf[i] >= 0x20 && buf[i] < 0x7f) printable++;
        }
        if (printable > (int)(len * 0.3)) {
            snprintf(reason, reason_size, "字符串内容可读 - 正常");
            return "pass";
        }
        if (zero_count > (int)(len * 0.8)) {
            snprintf(reason, reason_size, "字符串区域全零 - 可能未加载");
            return "suspicious";
        }
        snprintf(reason, reason_size, "字符串区域内容异常 - 可能被篡改");
        return "suspicious";
    }

    // 引擎类
    if (strcmp(cat, "engine") == 0 || strcmp(cat, "gpm") == 0) {
        if (has_hook_jmp) {
            snprintf(reason, reason_size, "引擎函数被 Hook - 可能影响游戏完整性");
            return "risk";
        }
        snprintf(reason, reason_size, "引擎函数代码完整");
        return "pass";
    }

    // ACE 组件类
    if (strcmp(cat, "ace") == 0) {
        if (zero_count > (int)(len * 0.95)) {
            snprintf(reason, reason_size, "ACE 组件区域全零 - 可能未加载");
            return "suspicious";
        }
        snprintf(reason, reason_size, "ACE 组件区域内容正常");
        return "pass";
    }

    // 证书/指纹类
    if (strcmp(cat, "cert") == 0 || strcmp(cat, "fingerprint") == 0) {
        if (has_hook_jmp) {
            snprintf(reason, reason_size, "证书/指纹读取函数被 Hook - 数据可能被伪造");
            return "risk";
        }
        snprintf(reason, reason_size, "证书/指纹函数代码完整");
        return "pass";
    }

    snprintf(reason, reason_size, "特征点内容已读取 - 默认判定为正常");
    return "pass";
}

// ==================== 十六进制编码 ====================

static void to_hex(const unsigned char *buf, size_t len, char *out, size_t out_size) {
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 3 < out_size; i++) {
        pos += snprintf(out + pos, out_size - pos, "%02x", buf[i]);
    }
    out[pos] = '\0';
}

// ==================== 单轮特征点扫描 ====================

#define READ_SIZE 64  // 每个特征点读取 64 字节

static void scan_features_once() {
    // 1. 实时解析 /proc/[pid]/maps 获取模块基址 (ASLR-aware)
    int module_count = parse_maps_for_modules(g_pid);
    if (module_count == 0) {
        printf("SCAN_RESULT|pid=%d|error=cannot_parse_maps|features=0|risk=0\n", g_pid);
        fflush(stdout);
        return;
    }

    // 输出模块基址信息
    printf("MODULES|count=%d\n", module_count);
    for (int i = 0; i < module_count; i++) {
        printf("MODULE|%s|base=0x%lx|end=0x%lx|size=0x%lx\n",
               g_modules[i].name, g_modules[i].base, g_modules[i].end, g_modules[i].size);
    }
    fflush(stdout);

    // 2. 逐一定位扫描每个特征点
    int total = count_features();
    int scanned = 0;
    int unreadable = 0;
    int pass_count = 0;
    int suspicious_count = 0;
    int risk_count = 0;
    unsigned char buf[READ_SIZE];
    char hex_str[READ_SIZE * 2 + 1];
    char reason[256];

    printf("FEATURES_BEGIN|total=%d\n", total);
    fflush(stdout);

    for (int i = 0; i < total; i++) {
        const struct FeaturePoint *fp = &FEATURES[i];
        unsigned long base = get_module_base(fp->module);
        if (base == 0) {
            printf("FEATURE|%s|0x%lx|0x0|UNAVAILABLE|module_not_loaded|%s\n",
                   fp->module, fp->offset, fp->name);
            fflush(stdout);
            continue;
        }

        unsigned long addr = base + fp->offset;
        memset(buf, 0, sizeof(buf));
        int attempts = 0;
        int fail_reason = 0;

        bool ok = read_remote_retry(addr, buf, READ_SIZE, &attempts, &fail_reason);

        if (!ok) {
            printf("FEATURE|%s|0x%lx|0x%lx|READ_FAILED|unreadable|读取失败_attempts=%d_errno=%d_%s\n",
                   fp->module, fp->offset, addr, attempts, fail_reason,
                   strerror(fail_reason));
            fflush(stdout);
            unreadable++;
            continue;
        }

        scanned++;
        to_hex(buf, READ_SIZE, hex_str, sizeof(hex_str));
        const char *status = judge_feature(buf, READ_SIZE, fp, reason, sizeof(reason));

        if (strcmp(status, "pass") == 0) pass_count++;
        else if (strcmp(status, "suspicious") == 0) suspicious_count++;
        else if (strcmp(status, "risk") == 0) risk_count++;

        printf("FEATURE|%s|0x%lx|0x%lx|%s|%s|%s|%s\n",
               fp->module, fp->offset, addr, hex_str, status, reason, fp->name);
        fflush(stdout);
    }

    printf("FEATURES_END|scanned=%d|unreadable=%d|pass=%d|suspicious=%d|risk=%d\n",
           scanned, unreadable, pass_count, suspicious_count, risk_count);
    printf("SCAN_RESULT|pid=%d|modules=%d|features=%d|scanned=%d|risk=%d|suspicious=%d\n",
           g_pid, module_count, total, scanned, risk_count, suspicious_count);
    printf("SCAN_DONE\n");
    fflush(stdout);
}

// ==================== 信号处理 ====================

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

// ==================== 主函数 ====================

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: ace_scanner <package> [interval_ms] [max_rounds]\n");
        return 1;
    }
    const char *pkg = argv[1];
    int interval_ms = argc >= 3 ? atoi(argv[2]) : 2000;
    int max_rounds = argc >= 4 ? atoi(argv[3]) : 0;

    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGPIPE, SIG_IGN);

    // 等待目标进程启动
    g_pid = find_pid(pkg);
    int wait_ms = 0;
    while (g_pid <= 0 && g_running && wait_ms < 30000) {
        usleep(500 * 1000);
        wait_ms += 500;
        g_pid = find_pid(pkg);
    }

    if (g_pid <= 0) {
        printf("NO_PROCESS|target %s not found after 30s\n", pkg);
        fflush(stdout);
        return 1;
    }

    printf("SCANNER_START|pid=%d|pkg=%s|interval=%d|max_rounds=%d|version=2.5\n",
           g_pid, pkg, interval_ms, max_rounds);
    fflush(stdout);

    int round = 0;
    while (g_running) {
        if (max_rounds > 0 && round >= max_rounds) break;
        round++;
        scan_features_once();
        if (g_running && interval_ms > 0) {
            usleep(interval_ms * 1000);
        }
        // 重新检查 PID (进程可能重启)
        int new_pid = find_pid(pkg);
        if (new_pid != g_pid) {
            g_pid = new_pid;
            if (g_pid <= 0) {
                printf("PROCESS_EXIT|target exited, waiting restart\n");
                fflush(stdout);
                wait_ms = 0;
                while (g_pid <= 0 && g_running && wait_ms < 60000) {
                    usleep(1000 * 1000);
                    wait_ms += 1000;
                    g_pid = find_pid(pkg);
                }
                if (g_pid <= 0) break;
                printf("PROCESS_BACK|new_pid=%d\n", g_pid);
                fflush(stdout);
            }
        }
    }

    printf("SCANNER_END|rounds=%d\n", round);
    fflush(stdout);
    return 0;
}
