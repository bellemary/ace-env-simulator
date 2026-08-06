package com.ace.envsimulator.advanced;

import com.ace.envsimulator.detection.CheckSupport;
import com.ace.envsimulator.model.DetectionStatus;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class ProfileParser {
    private static final byte[] ANO_KEY = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] A64_TABLE = hexToBytes(
            "abe47fa84624589d7db8f09108138060d697ff1569f8c2d9302916ee3ebb83f9" +
            "47cd621d4ef47823648fa7747096a575d3393436177392073bc10efa320f03da" +
            "be31672aafef8488e5e7d179e9760cccc425a2017bbf6af12e6dc9277a483a9a" +
            "555bfe3c0bae896c547c2c42909b1a8dca5f334c6135aa2ba4bc26df85b54fde" +
            "0ae80640509f19edb0f2ec6551bac857044dd7a08a56eaf55c71444577ac9312" +
            "00e0c3c5bdad6ffc18b10d1b2895f3c772378b871f6eb9b766d0d2d4c6213f2d" +
            "1efdf6dc9e8ce25d86101ca1c0097e4a9405d8b49952a649119843a981ce6322" +
            "9cb3f714dde18e6859e6db38b2535eebd5cb4b02825aa32041b62ffb3dcfe36b");
    private static final String[] COMM_KEYS = {"FakeToken", "report_bk", "allow_acu", "tcj_small_map", "frida_scan",
            "ss_c_a_e", "anti_profiler", "builtin_init_sdk", "v.bss", "vm_so_scan", "foo_9001",
            "enable_mrpcs_lib_parse", "simulate", "slice", "touch", "popup", "scripts", "slot", "dlcrc",
            "getlinker_openinfo", "rootkit_ver", "dlopen", "down_mrpcs", "up_wifi", "mslice", "soscan2", "soscan",
            "sync_state", "cert", "hi_gp4", "cert_content_chk", "cert2", "TssOpenIDRetriever", "tcj_wifi_limit",
            "tcj_today_wifi_limit", "elf_timehook", "chk_elf_header", "appdata", "tcj_app", "gp4_pagemap", "strip",
            "jni_apk", "report_apk", "hi_apk", "vm_vap", "blur_sensor", "emu_tp", "am_cnt", "rcv_by_thread",
            "allow_append_path", "ksu_mounts", "ve_rsa", "l_p_v_r", "x86_mem_failed", "mem_trap3"};

    public Interpretation parse(String path, byte[] blob) {
        String name = path.substring(path.lastIndexOf('/') + 1);
        try {
            if (blob.length == 0) return new Interpretation(DetectionStatus.PASS,
                    "零字节临时占位文件，已登记但没有可解码负载",
                    "size=0\nsha256=" + CheckSupport.sha256(blob),
                    "空文件只表示该路径已创建；不映射为设备异常或扫描命中", 99,
                    Collections.singletonList(new Artifact(name + ".empty.txt",
                            ("file=" + name + "\nsize=0\n").getBytes(StandardCharsets.UTF_8),
                            "零字节文件台账")));
            if ("ano_rdp.dat".equals(name)) return parseAnoRdp(blob);
            if ("ano_rdp_2.dat".equals(name)) return opaque(name, blob, "ano_rdp_2.dat 尚无经过原始校验的格式规格");
            if (name.startsWith("mrpcs_a_v_f")) return parseMrpcs(blob, 0x84, "mrpcs_a_v_f");
            if (name.startsWith("mrpcs_a_v")) return parseMrpcs(blob, 0x4f, "mrpcs_a_v");
            if (name.equals("mrpcs_a.data")) return parseMrpcsBody(blob, 0x08, "mrpcs_a");
            if (name.equals("mrpcs_a_c.data")) return parseMrpcsBody(blob, 0xd7, "mrpcs_a_c");
            if ("mpmc.dat".equals(name)) return parseMpmc(blob);
            if ("comm.dat".equals(name)) return parseComm(blob);
            if ("comm.zip".equals(name)) return parseCommZip(blob);
            if ("crt.i2.dat".equals(name)) return parseCrtI2(blob);
            if ("ano_ksh.dat".equals(name)) return parseAnoKsh(blob);
            if ("kmc.dat".equals(name)) return parseKmc(blob);
            if ("mn_cache.dat".equals(name)) return parseMnCache(blob);
            if ("kvcache8.dat".equals(name)) return parseKvCache8(blob);
            if (name.startsWith("config2.dat")) return parseConfig2(blob);
            if (name.startsWith("config3.dat")) return parseConfig3(blob);
            if ("h_rcd.dat".equals(name)) return parseFixedWords(name, blob, 0x20221118L);
            if ("rcu.o.dat".equals(name)) return parseRcu(blob);
            if ("ano.i.m.dat".equals(name)) return parseAnoIm(blob);
            if ("ano.ano3.dat".equals(name)) return parseAno3(blob);
            if (name.startsWith("ano_app_") && name.endsWith(".dat"))
                return parseAnoApp(name, blob);
            if ("SpeedUpCCH.dat".equals(name)) return parseBigEndianWords(name, blob, 0x20200715L, true);
            if ("up_cache.dat".equals(name)) return parseBigEndianWords(name, blob, 0x20240403L, true);
            if ("ace_shell_db.dat".equals(name)) return parseBigEndianWords(name, blob, 0x20210526L, false);
            if ("tersafe.update".equals(name)) return parseTersafeUpdate(blob);
            if ("a64.dat".equals(name)) return parseA64(blob);
            if ("ob_x.zip".equals(name)) return parseObX(blob);
            return opaque(name, blob, "未注册格式");
        } catch (Exception e) {
            return new Interpretation(DetectionStatus.SUSPICIOUS, "文件版本不兼容、读取竞争或完整性校验失败",
                    "size=" + blob.length + "\nsha256=" + CheckSupport.sha256(blob) + "\n" + e.getClass().getSimpleName() + ": " + e.getMessage(),
                    "解析失败不会阻止后续文件", 88);
        }
    }

    private Interpretation parseAnoRdp(byte[] blob) throws Exception {
        if (blob.length < 8) throw new IllegalArgumentException("shorter than 8-byte header");
        ByteBuffer buffer = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN);
        long magic = Integer.toUnsignedLong(buffer.getInt());
        int length = buffer.getInt();
        if (magic != 0x20220920L) throw new IllegalArgumentException(String.format(Locale.US, "bad magic 0x%08x", magic));
        if (length != blob.length - 8) throw new IllegalArgumentException("payload size mismatch");
        byte[] plain = new byte[length];
        for (int i = 0; i < length; i++) plain[i] = (byte) (blob[8 + i] ^ ANO_KEY[i % ANO_KEY.length]);
        String digest = new String(plain, StandardCharsets.US_ASCII);
        if (!digest.matches("[0-9a-fA-F]{32}")) throw new IllegalArgumentException("payload is not 32 hex chars");
        String evidence = "magic=0x20220920\npayload_length=" + length + "\ndecoded_digest=" + digest +
                "\nsource_scope=仅来自目标 ano_rdp.dat；高级模式不混入本应用重新采集的系统属性";
        return new Interpretation(DetectionStatus.PASS,
                "已读取 32 字节十六进制设备指纹摘要",
                evidence + "\n说明：摘要本身不是通过、失效或上报命中字段。",
                "容器/XOR/MD5 已验证；该文件不是完整画像或风险判定字段", 96,
                Collections.singletonList(new Artifact("ano_rdp.decoded.txt", (digest + "\n").getBytes(StandardCharsets.US_ASCII), "XOR 解码后的摘要")));
    }

    private Interpretation parseMrpcs(byte[] outer, int key, String family) throws Exception {
        byte[] encoded = unzipPayload(outer);
        if (encoded.length < 4) throw new IllegalArgumentException("inner payload shorter than 4 bytes");
        byte[] decoded = encoded.clone();
        for (int i = 4; i < decoded.length; i++) decoded[i] = (byte) (decoded[i] ^ key);
        long stored = Integer.toUnsignedLong(ByteBuffer.wrap(decoded, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
        CRC32 crc = new CRC32(); crc.update(decoded, 4, decoded.length - 4);
        long calculated = crc.getValue();
        List<String> capabilities = capabilityStrings(decoded);
        String evidence = "family=" + family + "\nouter_sha256=" + CheckSupport.sha256(outer) +
                "\ninner_size=" + encoded.length + "\ntransform=[4,EOF) XOR 0x" + String.format(Locale.US, "%02X", key) +
                "\nstored_crc32=" + hex32(stored) + "\ncalculated_crc32=" + hex32(calculated) +
                "\ncrc_matches=" + (stored == calculated) + "\ndecoded_sha256=" + CheckSupport.sha256(decoded) +
                "\nrule_capabilities=" + (capabilities.isEmpty() ? "未提取" : String.join(", ", capabilities)) +
                "\n说明：这些字符串描述规则能力，不代表本机已经命中。";
        List<Artifact> artifacts = new ArrayList<>();
        artifacts.add(new Artifact(family + ".decoded.bin", decoded, "已应用该文件族 XOR 的完整二进制"));
        artifacts.add(new Artifact(family + ".strings.txt", printableStrings(decoded).getBytes(StandardCharsets.UTF_8),
                "完整解码二进制中的可打印字符串及文件偏移"));
        if (stored != calculated) return new Interpretation(DetectionStatus.SUSPICIOUS, "MRPCS 版本不匹配、读取竞争或 CRC 异常", evidence,
                "首 4 字节 LE32 CRC32(decoded[4..EOF])", 99,
                artifacts);
        return new Interpretation(DetectionStatus.PASS, "MRPCS 规则镜像解码与 CRC 校验通过", evidence,
                "已验证密钥仅适用于该文件族；完整解码文件与字符串清单均导出", 99, artifacts);
    }

    private Interpretation parseMrpcsBody(byte[] outer, int key, String family) throws Exception {
        byte[] inner = unzipPayload(outer);
        if (inner.length < 4) throw new IllegalArgumentException("inner payload shorter than 4 bytes");
        byte[] decoded = inner.clone();
        for (int i = 4; i < decoded.length; i++) decoded[i] = (byte) (decoded[i] ^ key);
        String strings = printableStrings(decoded);
        List<String> capabilities = capabilityStrings(decoded);
        List<Artifact> artifacts = new ArrayList<>();
        artifacts.add(new Artifact(family + ".decoded.bin", decoded, "完整内层主体变换结果"));
        artifacts.add(new Artifact(family + ".strings.txt", strings.getBytes(StandardCharsets.UTF_8),
                "主体变换后的全部可打印字符串与偏移"));
        return new Interpretation(DetectionStatus.SUSPICIOUS, "MRPCS 内层主体已完整变换，首字段完整性语义待闭合",
                "family=" + family + "\nouter_sha256=" + CheckSupport.sha256(outer) + "\ninner_size=" + inner.length +
                        "\ntransform=[4,EOF) XOR 0x" + String.format(Locale.US, "%02X", key) +
                        "\nleading_word=" + hex32(Integer.toUnsignedLong(ByteBuffer.wrap(decoded).order(ByteOrder.LITTLE_ENDIAN).getInt())) +
                        "\ndecoded_sha256=" + CheckSupport.sha256(decoded) +
                        "\nrule_capabilities=" + (capabilities.isEmpty() ? "未提取" : String.join(", ", capabilities)),
                "三阶段密文完全一致；固定字节变换后零填充和结构字段恢复。首四字节尚未验证为 CRC，因此保持待解析",
                97, artifacts);
    }

    private Interpretation parseMpmc(byte[] blob) {
        if (blob.length < 12) throw new IllegalArgumentException("shorter than 12-byte header");
        ByteBuffer buffer = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        long magic = Integer.toUnsignedLong(buffer.getInt());
        long stored = Integer.toUnsignedLong(buffer.getInt());
        long count = Integer.toUnsignedLong(buffer.getInt());
        if (magic != 0x20250812L) throw new IllegalArgumentException("unexpected magic/version " + hex32(magic));
        if (count > 100 || 12L + count * 24L != blob.length) throw new IllegalArgumentException("record count/size mismatch");
        byte[] crcBytes = blob.clone();
        for (int i = 4; i < 8; i++) crcBytes[i] = 0;
        CRC32 crc = new CRC32(); crc.update(crcBytes);
        StringBuilder evidence = new StringBuilder("magic_or_version=").append(hex32(magic))
                .append("\ncount=").append(count).append("\nstored_crc32=").append(hex32(stored))
                .append("\ncalculated_crc32=").append(hex32(crc.getValue())).append("\ncrc_matches=").append(stored == crc.getValue());
        for (int i = 0; i < count; i++) {
            long f0 = buffer.getLong(), f1 = buffer.getLong();
            long f2 = Integer.toUnsignedLong(buffer.getInt()), f3 = Integer.toUnsignedLong(buffer.getInt());
            evidence.append("\nrecord[").append(i).append("]=")
                    .append(String.format(Locale.US, "%016x,%016x,%08x,%08x", f0, f1, f2, f3));
        }
        DetectionStatus status = stored == crc.getValue() ? DetectionStatus.PASS : DetectionStatus.SUSPICIOUS;
        return new Interpretation(status, stored == crc.getValue() ? "MPMC 结构和 CRC 有效，字段语义待定" : "MPMC CRC 不匹配",
                evidence.toString(), "LE32 header + count*24；四字段语义尚未闭合", 98,
                Collections.singletonList(new Artifact("mpmc.fields.txt", evidence.toString().getBytes(StandardCharsets.UTF_8), "MPMC 结构化字段导出")));
    }

    private Interpretation parseComm(byte[] blob) {
        String text = new String(blob, StandardCharsets.ISO_8859_1);
        List<String> keys = new ArrayList<>();
        for (String key : COMM_KEYS) if (text.contains(key)) keys.add(key);
        String extracted = keys.isEmpty() ? "verified_keys=无\n" : "verified_keys=" + String.join(", ", keys) + "\n";
        return new Interpretation(DetectionStatus.SUSPICIOUS, "发现运行时配置容器，键值语义尚未闭合",
                "size=" + blob.length + "\nsha256=" + CheckSupport.sha256(blob) + "\nverified_keys=" +
                        (keys.isEmpty() ? "无" : String.join(", ", keys)),
                "仅报告实际出现的已验证键；不把字符串存在解释为配置已启用", 92,
                Collections.singletonList(new Artifact("comm.verified-keys.txt", extracted.getBytes(StandardCharsets.UTF_8), "从配置容器提取的已验证键名")));
    }

    private Interpretation parseCommZip(byte[] blob) throws Exception {
        byte[] inner = unzipPayload(blob);
        Interpretation parsed = parseComm(inner);
        List<Artifact> artifacts = new ArrayList<>(parsed.artifacts);
        artifacts.add(new Artifact("comm.zip/comm.dat", inner, "ZIP 内完整 comm.dat"));
        return new Interpretation(parsed.status, "comm.zip 已展开；" + parsed.summary,
                "outer_sha256=" + CheckSupport.sha256(blob) + "\ninner_size=" + inner.length + "\n" + parsed.evidence,
                parsed.rule, parsed.confidence, artifacts);
    }

    private Interpretation parseKvCache8(byte[] blob) {
        if (blob.length < 20) throw new IllegalArgumentException("shorter than kvcache8 envelope");
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        long magic = Integer.toUnsignedLong(b.getInt());
        if (magic != 0x20250125L) throw new IllegalArgumentException("unexpected kvcache8 magic " + hex32(magic));
        long count = Integer.toUnsignedLong(b.getInt());
        if (count > 4096) throw new IllegalArgumentException("kvcache8 item count too large");
        StringBuilder decoded = new StringBuilder("magic=").append(hex32(magic)).append("\nitem_count=").append(count);
        List<Observation> observations = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String key = readXorString(b, 4096);
            String value = readXorString(b, 1024 * 1024);
            decoded.append("\nitem[").append(i).append("].key=").append(key)
                    .append("\nitem[").append(i).append("].value=").append(value);
            observations.add(new Observation("kvcache8." + i, key, value,
                    "阶段性设备画像键值；字段业务缩写保持原样公示"));
        }
        ensureRemaining(b, 12);
        long firstTail = Integer.toUnsignedLong(b.getInt());
        int crcBoundary = b.position();
        long storedCrc = Integer.toUnsignedLong(b.getInt());
        long finalTail = Integer.toUnsignedLong(b.getInt());
        if (firstTail != magic || finalTail != magic || b.hasRemaining())
            throw new IllegalArgumentException("kvcache8 trailing boundary mismatch");
        CRC32 crc = new CRC32(); crc.update(blob, 0, crcBoundary);
        decoded.append("\nfirst_tail_magic=").append(hex32(firstTail))
                .append("\nstored_crc32=").append(hex32(storedCrc))
                .append("\ncalculated_crc32=").append(hex32(crc.getValue()))
                .append("\ncrc_matches=").append(storedCrc == crc.getValue())
                .append("\nfinal_tail_magic=").append(hex32(finalTail));
        String text = decoded.toString();
        DetectionStatus status = storedCrc == crc.getValue() ? DetectionStatus.PASS : DetectionStatus.SUSPICIOUS;
        return new Interpretation(status,
                storedCrc == crc.getValue() ? "阶段性设备画像键值与 CRC 已完整解码" : "设备画像键值已解码但 CRC 不匹配",
                text, "LE32 0x20250125 + count*(XOR key, XOR value) + magic + CRC32(prefix) + magic",
                99, Collections.singletonList(new Artifact("kvcache8.decoded.txt",
                (text + "\n").getBytes(StandardCharsets.UTF_8), "完整键值画像")), Collections.emptyList(), observations);
    }

    private Interpretation parseAnoIm(byte[] blob) {
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        ensureRemaining(b, 16);
        long magic = Integer.toUnsignedLong(b.getInt());
        long marker = Integer.toUnsignedLong(b.getInt());
        if (magic != 0x20170116L || marker != 5715L)
            throw new IllegalArgumentException("ano.i.m header mismatch");
        String deviceId = readXorString(b, 256);
        ensureRemaining(b, 4);
        long tail = Integer.toUnsignedLong(b.getInt());
        if (tail != 5715L || b.hasRemaining())
            throw new IllegalArgumentException("ano.i.m tail mismatch");
        String text = "magic=" + hex32(magic) + "\nmarker=" + marker +
                "\ndevice_identifier=" + deviceId + "\ntrailing_marker=" + tail;
        return new Interpretation(DetectionStatus.PASS,
                "已读取设备标识记录",
                text,
                "IDA libtersafe sub_4CF128：LE32 头、5715 标记、循环 XOR 字符串、5715 尾标记",
                99,
                Collections.singletonList(new Artifact("ano.i.m.decoded.txt",
                        (text + "\n").getBytes(StandardCharsets.UTF_8), "设备标识记录")),
                Collections.emptyList(),
                Collections.singletonList(new Observation("ano.i.m.device_identifier",
                        "device_identifier", deviceId, "ACE 本地保存的设备标识")));
    }

    private Interpretation parseAno3(byte[] blob) {
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        ensureRemaining(b, 20);
        long magic = Integer.toUnsignedLong(b.getInt());
        if (magic != 0x20220909L) throw new IllegalArgumentException("ano.ano3 header mismatch");
        long value = Integer.toUnsignedLong(b.getInt());
        long firstCount = Integer.toUnsignedLong(b.getInt());
        if (firstCount > 4096 || firstCount * 4L > b.remaining())
            throw new IllegalArgumentException("ano.ano3 first count invalid");
        StringBuilder text = new StringBuilder("magic=").append(hex32(magic))
                .append("\nvalue=").append(hex32(value)).append("\nfirst_count=").append(firstCount);
        for (int i = 0; i < firstCount; i++)
            text.append("\nfirst[").append(i).append("]=")
                    .append(hex32(Integer.toUnsignedLong(b.getInt())));
        ensureRemaining(b, 8);
        long secondCount = Integer.toUnsignedLong(b.getInt());
        if (secondCount > 4096) throw new IllegalArgumentException("ano.ano3 second count invalid");
        text.append("\nsecond_count=").append(secondCount);
        for (int i = 0; i < secondCount; i++) {
            String first = readXorString(b, 1024 * 1024);
            String second = readXorString(b, 1024 * 1024);
            ensureRemaining(b, 4);
            long recordValue = Integer.toUnsignedLong(b.getInt());
            text.append("\nrecord[").append(i).append("].first=").append(first)
                    .append("\nrecord[").append(i).append("].second=").append(second)
                    .append("\nrecord[").append(i).append("].value=").append(hex32(recordValue));
        }
        ensureRemaining(b, 4);
        long tail = Integer.toUnsignedLong(b.getInt());
        if (tail != magic || b.hasRemaining())
            throw new IllegalArgumentException("ano.ano3 tail mismatch");
        text.append("\ntrailing_magic=").append(hex32(tail));
        String summary = firstCount == 0 && secondCount == 0
                ? "文件里没有记录到项目"
                : "已读取 " + firstCount + " 条编号记录和 " + secondCount + " 条详细记录";
        return new Interpretation(DetectionStatus.PASS, summary, text.toString(),
                "IDA libtersafe sub_2A2E8C：LE32 头、两组计数记录、循环 XOR 字符串、尾魔数",
                99, Collections.singletonList(new Artifact("ano.ano3.decoded.txt",
                (text + "\n").getBytes(StandardCharsets.UTF_8), "ano.ano3 完整记录")));
    }

    private Interpretation parseAnoApp(String name, byte[] blob) {
        if (blob.length != 24) throw new IllegalArgumentException("ano_app record must be 24 bytes");
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN);
        long magic = Integer.toUnsignedLong(b.getInt());
        if (magic != 0x20240812L) throw new IllegalArgumentException("ano_app header mismatch");
        StringBuilder text = new StringBuilder("magic=").append(hex32(magic));
        for (int i = 0; i < 4; i++) {
            long stored = Integer.toUnsignedLong(b.getInt());
            long decoded = stored ^ 0x34761120L;
            text.append("\nfield[").append(i).append("].stored=").append(hex32(stored))
                    .append("\nfield[").append(i).append("].decoded=").append(hex32(decoded));
        }
        long tail = Integer.toUnsignedLong(b.getInt());
        if (tail != magic) throw new IllegalArgumentException("ano_app tail mismatch");
        text.append("\ntrailing_magic=").append(hex32(tail));
        return new Interpretation(DetectionStatus.PASS,
                "已读取应用环境校验记录",
                text.toString(),
                "IDA libtersafe sub_2DD8F0/sub_2DDDE4：BE32 头尾与四个字段 XOR 0x34761120",
                99, Collections.singletonList(new Artifact(name + ".decoded.txt",
                (text + "\n").getBytes(StandardCharsets.UTF_8), "应用环境校验记录")));
    }

    private Interpretation parseRcu(byte[] blob) {
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        ensureRemaining(b, 16);
        long update = Integer.toUnsignedLong(b.getInt());
        long build = Integer.toUnsignedLong(b.getInt());
        long status = Integer.toUnsignedLong(b.getInt());
        String detail = readXorString(b, 1024 * 1024);
        if (b.hasRemaining()) throw new IllegalArgumentException("rcu.o trailing bytes");
        String text = "update=" + hex32(update) + "\nbuild=" + build +
                "\nstatus=" + status + "\ndetail=" + detail;
        return new Interpretation(DetectionStatus.PASS,
                status == 0 && detail.isEmpty() ? "当前状态为 0，没有附加内容" : "已读取状态和附加内容",
                text,
                "IDA libtersafe sub_295780：三个 LE32 字段和一个循环 XOR 字符串",
                99, Collections.singletonList(new Artifact("rcu.o.decoded.txt",
                (text + "\n").getBytes(StandardCharsets.UTF_8), "RCU 状态记录")));
    }

    private Interpretation parseTersafeUpdate(byte[] blob) {
        if (blob.length != 4) throw new IllegalArgumentException("tersafe.update must be one LE32 value");
        long value = Integer.toUnsignedLong(ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN).getInt());
        String text = "update_token=" + hex32(value);
        return new Interpretation(DetectionStatus.PASS, "已读取组件更新标记", text,
                "IDA libtersafe sub_237E80：单个 LE32 更新标记", 99,
                Collections.singletonList(new Artifact("tersafe.update.decoded.txt",
                        (text + "\n").getBytes(StandardCharsets.UTF_8), "组件更新标记")));
    }

    private Interpretation parseConfig2(byte[] blob) {
        ByteBuffer b = signedConfigPayload(blob);
        StringBuilder text = new StringBuilder("config2\n");
        long firstMagic = readExpected(b, 0x20250308L, "config2 first section");
        int commonCount = checkedCount(b, 256, "config2 common file count");
        text.append("first_magic=").append(hex32(firstMagic)).append("\ncommon_file_count=").append(commonCount);
        for (int i = 0; i < commonCount; i++) appendConfigFile(text, b, "common[" + i + "]");
        readExpected(b, firstMagic, "config2 first tail");

        long secondMagic = readExpected(b, 0x20250309L, "config2 version section");
        int versionCount = checkedCount(b, 256, "config2 version count");
        text.append("\nsecond_magic=").append(hex32(secondMagic)).append("\nversion_count=").append(versionCount);
        for (int i = 0; i < versionCount; i++) {
            ensureRemaining(b, 8);
            long versionCode = Integer.toUnsignedLong(b.getInt());
            int fileCount = checkedCount(b, 32, "config2 version file count");
            text.append("\nversion[").append(i).append("].code=").append(hex32(versionCode))
                    .append("\nversion[").append(i).append("].file_count=").append(fileCount);
            for (int j = 0; j < fileCount; j++) appendConfigFile(text, b, "version[" + i + "].file[" + j + "]");
        }
        readExpected(b, secondMagic, "config2 second tail");
        if (b.hasRemaining()) throw new IllegalArgumentException("config2 trailing bytes");
        String decoded = text.toString();
        return new Interpretation(DetectionStatus.PASS,
                "已读取 " + commonCount + " 个公共文件记录和 " + versionCount + " 组版本规则",
                decoded,
                "IDA libtersafe sub_21924C/sub_218054：签名封套 + 0x20250308/0x20250309 记录表",
                99, Collections.singletonList(new Artifact("config2.decoded.txt",
                (decoded + "\n").getBytes(StandardCharsets.UTF_8), "config2 完整规则表")));
    }

    private Interpretation parseConfig3(byte[] blob) {
        ByteBuffer b = signedConfigPayload(blob);
        long magic = readExpected(b, 0x20250308L, "config3 section");
        int versionCount = checkedCount(b, 256, "config3 version count");
        StringBuilder text = new StringBuilder("config3\nmagic=").append(hex32(magic))
                .append("\nversion_count=").append(versionCount);
        for (int i = 0; i < versionCount; i++) {
            String version = readXorString(b, 256);
            ensureRemaining(b, 4);
            long versionCode = Integer.toUnsignedLong(b.getInt());
            String module = readXorString(b, 1024);
            String offset = readXorString(b, 1024);
            int fileCount = checkedCount(b, 32, "config3 file count");
            text.append("\nversion[").append(i).append("].name=").append(version)
                    .append("\nversion[").append(i).append("].code=").append(hex32(versionCode))
                    .append("\nversion[").append(i).append("].module=").append(module)
                    .append("\nversion[").append(i).append("].offset=").append(offset)
                    .append("\nversion[").append(i).append("].file_count=").append(fileCount);
            for (int j = 0; j < fileCount; j++) appendConfigFile(text, b, "version[" + i + "].file[" + j + "]");
        }
        readExpected(b, magic, "config3 tail");
        if (b.hasRemaining()) throw new IllegalArgumentException("config3 trailing bytes");
        String decoded = text.toString();
        return new Interpretation(DetectionStatus.PASS,
                "已读取 " + versionCount + " 组游戏版本、模块和规则文件记录",
                decoded,
                "IDA libtersafe sub_21924C/sub_218054：签名封套 + 0x20250308 版本记录表",
                99, Collections.singletonList(new Artifact("config3.decoded.txt",
                (decoded + "\n").getBytes(StandardCharsets.UTF_8), "config3 完整版本规则表")));
    }

    private ByteBuffer signedConfigPayload(byte[] blob) {
        if (blob.length < 276) throw new IllegalArgumentException("signed config too short");
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN);
        readExpected(b, 0x20250307L, "signed config header");
        ensureRemaining(b, 4 + 256 + 4);
        b.getInt();
        b.position(b.position() + 256);
        readExpected(b, 0x20250307L, "signed config envelope tail");
        return b;
    }

    private void appendConfigFile(StringBuilder text, ByteBuffer b, String prefix) {
        String name = readXorString(b, 4096);
        ensureRemaining(b, 12);
        long weight = Integer.toUnsignedLong(b.getInt());
        long checksum = b.getLong();
        text.append('\n').append(prefix).append(".name=").append(name)
                .append('\n').append(prefix).append(".weight=").append(weight)
                .append('\n').append(prefix).append(".checksum=")
                .append(String.format(Locale.US, "0x%016x", checksum));
    }

    private long readExpected(ByteBuffer b, long expected, String label) {
        ensureRemaining(b, 4);
        long value = Integer.toUnsignedLong(b.getInt());
        if (value != expected) throw new IllegalArgumentException(label + " mismatch: " + hex32(value));
        return value;
    }

    private int checkedCount(ByteBuffer b, int max, String label) {
        ensureRemaining(b, 4);
        long value = Integer.toUnsignedLong(b.getInt());
        if (value > max) throw new IllegalArgumentException(label + " too large: " + value);
        return (int) value;
    }

    private Interpretation parseFixedWords(String name, byte[] blob, long expectedMagic) {
        if ((blob.length & 3) != 0 || blob.length == 0) throw new IllegalArgumentException("not a non-empty LE32 word container");
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        StringBuilder decoded = new StringBuilder("file=").append(name).append("\nword_count=").append(blob.length / 4);
        int index = 0;
        while (b.hasRemaining()) decoded.append("\nword[").append(index++).append("]=")
                .append(hex32(Integer.toUnsignedLong(b.getInt())));
        if (expectedMagic >= 0 && Integer.toUnsignedLong(ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN).getInt()) != expectedMagic)
            throw new IllegalArgumentException("unexpected leading word");
        String text = decoded.append("\nsha256=").append(CheckSupport.sha256(blob)).toString();
        return new Interpretation(DetectionStatus.SUSPICIOUS, "全部 LE32 字段已公开，业务语义待差分命名", text,
                "结构边界已验证；未知字段不映射为设备命中", 96,
                Collections.singletonList(new Artifact(name + ".words.txt", (text + "\n").getBytes(StandardCharsets.UTF_8), "完整 LE32 字段导出")));
    }

    private Interpretation parseBigEndianWords(String name, byte[] blob, long expectedMagic, boolean repeatedTail) {
        if ((blob.length & 3) != 0 || blob.length < 4) throw new IllegalArgumentException("not a BE32 word container");
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN);
        long first = Integer.toUnsignedLong(b.getInt());
        if (first != expectedMagic) throw new IllegalArgumentException("unexpected leading word " + hex32(first));
        long tail = Integer.toUnsignedLong(ByteBuffer.wrap(blob, blob.length - 4, 4).order(ByteOrder.BIG_ENDIAN).getInt());
        if (repeatedTail && tail != first) throw new IllegalArgumentException("leading/trailing version mismatch");
        b.position(0);
        StringBuilder decoded = new StringBuilder("file=").append(name)
                .append("\nbyte_order=BE\nword_count=").append(blob.length / 4);
        int index = 0;
        while (b.hasRemaining()) decoded.append("\nword[").append(index++).append("]=")
                .append(hex32(Integer.toUnsignedLong(b.getInt())));
        decoded.append("\nleading_version=").append(hex32(first))
                .append("\ntrailing_version=").append(hex32(tail))
                .append("\nframing_matches=").append(!repeatedTail || tail == first)
                .append("\nsha256=").append(CheckSupport.sha256(blob));
        String text = decoded.toString();
        return new Interpretation(DetectionStatus.SUSPICIOUS,
                "版本边界与全部 BE32 字段已公开，中间负载变换及业务字段待闭合",
                text, "只确认版本头/尾和字段边界；未知负载不映射为设备扫描命中", 97,
                Collections.singletonList(new Artifact(name + ".be32.txt",
                        (text + "\n").getBytes(StandardCharsets.UTF_8), "完整 BE32 字段导出")));
    }

    private Interpretation parseCrtI2(byte[] blob) throws Exception {
        if (blob.length < 28) throw new IllegalArgumentException("shorter than crt.i2 header");
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        long magic = Integer.toUnsignedLong(b.getInt());
        long storedCrc = Integer.toUnsignedLong(b.getInt());
        if (magic != 0x20220606L) throw new IllegalArgumentException("unexpected crt.i2 magic " + hex32(magic));
        byte[] crcInput = blob.clone();
        for (int i = 4; i < 8; i++) crcInput[i] = 0;
        CRC32 crc = new CRC32(); crc.update(crcInput);
        long seedA = Integer.toUnsignedLong(b.getInt());
        long seedB = Integer.toUnsignedLong(b.getInt());
        long groupCount = seedA ^ seedB;
        if (groupCount > 128) throw new IllegalArgumentException("crt.i2 group count too large");
        StringBuilder decoded = new StringBuilder();
        decoded.append("magic=").append(hex32(magic))
                .append("\nstored_crc32=").append(hex32(storedCrc))
                .append("\ncalculated_crc32=").append(hex32(crc.getValue()))
                .append("\ncrc_matches=").append(storedCrc == crc.getValue())
                .append("\ngroup_count=").append(groupCount);
        int records = 0;
        for (int group = 0; group < groupCount; group++) {
            ensureRemaining(b, 16);
            long groupId = Integer.toUnsignedLong(b.getInt());
            long stamp = b.getLong();
            long count = Integer.toUnsignedLong(b.getInt());
            if (count > 4096) throw new IllegalArgumentException("crt.i2 record count too large");
            decoded.append("\ngroup[").append(group).append("].id=").append(hex32(groupId))
                    .append("\ngroup[").append(group).append("].stamp=").append(Long.toUnsignedString(stamp))
                    .append("\ngroup[").append(group).append("].record_count=").append(count);
            for (int index = 0; index < count; index++) {
                ensureRemaining(b, 4);
                long type = Integer.toUnsignedLong(b.getInt());
                String id = readXorString(b, 32);
                String value = readXorString(b, 127);
                decoded.append("\nrecord[").append(records).append("].type=").append(type)
                        .append("\nrecord[").append(records).append("].certificate_id=").append(id)
                        .append("\nrecord[").append(records).append("].subject=").append(value);
                records++;
            }
        }
        ensureRemaining(b, 4);
        long tail = Integer.toUnsignedLong(b.getInt());
        if (tail != magic || b.hasRemaining()) throw new IllegalArgumentException("crt.i2 trailing boundary mismatch");
        decoded.append("\ntrailing_magic=").append(hex32(tail));
        String text = decoded.toString();
        DetectionStatus status = storedCrc == crc.getValue() ? DetectionStatus.PASS : DetectionStatus.SUSPICIOUS;
        return new Interpretation(status,
                storedCrc == crc.getValue() ? "证书记录容器已完整解码" : "证书记录已解码但 CRC 不匹配",
                text + "\n说明：记录表示 ACE 证书数据，不自动等价于本机证书命中。",
                "IDA sub_4D9214/sub_4D949C：LE32 0x20220606、CRC32、分组记录、36 字节循环 XOR",
                99, Collections.singletonList(new Artifact("crt.i2.decoded.txt",
                (text + "\n").getBytes(StandardCharsets.UTF_8), "证书记录容器结构化解码")));
    }

    private Interpretation parseAnoKsh(byte[] blob) {
        if (blob.length < 25) throw new IllegalArgumentException("shorter than ano_ksh envelope");
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        long magic = Integer.toUnsignedLong(b.getInt());
        if (magic != 0x20230407L) throw new IllegalArgumentException("unexpected ano_ksh magic " + hex32(magic));
        int count = Byte.toUnsignedInt(b.get());
        if (count > 64) throw new IllegalArgumentException("ano_ksh item count too large");
        StringBuilder decoded = new StringBuilder("magic=").append(hex32(magic)).append("\nitem_count=").append(count);
        for (int i = 0; i < count; i++)
            decoded.append("\nitem[").append(i).append("]=").append(readXorString(b, 511));
        String payload = readXorString(b, 511);
        decoded.append("\npayload=").append(payload);
        ensureRemaining(b, 20);
        for (int i = 0; i < 3; i++)
            decoded.append("\nfield[").append(i).append("]=").append(Integer.toUnsignedLong(b.getInt()));
        int crcBoundary = b.position();
        long storedCrc = Integer.toUnsignedLong(b.getInt());
        long tail = Integer.toUnsignedLong(b.getInt());
        if (tail != magic || b.hasRemaining()) throw new IllegalArgumentException("ano_ksh trailing boundary mismatch");
        CRC32 crc = new CRC32(); crc.update(blob, 0, crcBoundary);
        decoded.append("\nstored_crc32=").append(hex32(storedCrc))
                .append("\ncalculated_crc32=").append(hex32(crc.getValue()))
                .append("\ncrc_matches=").append(storedCrc == crc.getValue())
                .append("\ntrailing_magic=").append(hex32(tail));
        String text = decoded.toString();
        DetectionStatus status = storedCrc == crc.getValue() ? DetectionStatus.PASS : DetectionStatus.SUSPICIOUS;
        return new Interpretation(status,
                storedCrc == crc.getValue() ? "ano_ksh 容器、字符串与 CRC 已完整解码" : "ano_ksh 已解码但 CRC 不匹配",
                text + "\n说明：field[0..2] 的业务名称尚未闭合，不解释为检测命中。",
                "IDA libtersafe sub_4D1EE8：LE32 0x20230407、U8 count、XOR string、3*LE32、CRC32、尾魔数",
                99, Collections.singletonList(new Artifact("ano_ksh.decoded.txt",
                (text + "\n").getBytes(StandardCharsets.UTF_8), "ano_ksh 结构化解码")));
    }

    private Interpretation parseKmc(byte[] blob) {
        if (blob.length < 12) throw new IllegalArgumentException("shorter than kmc envelope");
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        long magic = Integer.toUnsignedLong(b.getInt());
        if (magic != 0x20240116L) throw new IllegalArgumentException("unexpected kmc magic " + hex32(magic));
        long count = Integer.toUnsignedLong(b.getInt());
        if (count > 256) throw new IllegalArgumentException("kmc item count too large");
        StringBuilder decoded = new StringBuilder("magic=").append(hex32(magic)).append("\nitem_count=").append(count);
        for (int i = 0; i < count; i++) decoded.append("\nnode[").append(i).append("]=").append(readXorString(b, 1024));
        ensureRemaining(b, 4);
        long tail = Integer.toUnsignedLong(b.getInt());
        if (tail != magic || b.hasRemaining()) throw new IllegalArgumentException("kmc trailing boundary mismatch");
        decoded.append("\ntrailing_magic=").append(hex32(tail));
        String text = decoded.toString();
        return new Interpretation(DetectionStatus.PASS,
                "设备节点与内核能力清单已完整解码",
                text + "\n说明：清单描述可检查的设备节点，不代表本机命中。",
                "LE32 0x20240116 + count*(LE32 length + 36 字节循环 XOR string) + 尾魔数",
                99, Collections.singletonList(new Artifact("kmc.decoded.txt",
                (text + "\n").getBytes(StandardCharsets.UTF_8), "kmc 设备节点清单")));
    }

    private Interpretation parseMnCache(byte[] blob) {
        if (blob.length < 16) throw new IllegalArgumentException("shorter than mn_cache envelope");
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        long magic = Integer.toUnsignedLong(b.getInt());
        if (magic != 0x20160816L) throw new IllegalArgumentException("unexpected mn_cache magic " + hex32(magic));
        long count = Integer.toUnsignedLong(b.getInt());
        if (count > 512) throw new IllegalArgumentException("mn_cache item count too large");
        long metadata0 = Integer.toUnsignedLong(b.getInt());
        long metadata1 = Integer.toUnsignedLong(b.getInt());
        StringBuilder decoded = new StringBuilder("magic=").append(hex32(magic))
                .append("\nitem_count=").append(count)
                .append("\nmetadata[0]=").append(hex32(metadata0))
                .append("\nmetadata[1]=").append(hex32(metadata1));
        for (int i = 0; i < count; i++) decoded.append("\nlibrary[").append(i).append("]=").append(readXorString(b, 1024));
        if (b.hasRemaining()) throw new IllegalArgumentException("mn_cache trailing bytes=" + b.remaining());
        String text = decoded.toString();
        return new Interpretation(DetectionStatus.PASS,
                "已加载组件库清单完整解码",
                text + "\n说明：库名表示已登记组件，不代表环境异常。",
                "LE32 0x20160816 + count + 8 字节元数据 + count*(LE32 length + 36 字节循环 XOR string)",
                99, Collections.singletonList(new Artifact("mn_cache.decoded.txt",
                (text + "\n").getBytes(StandardCharsets.UTF_8), "mn_cache 组件库清单")));
    }

    private String readXorString(ByteBuffer b, int maxLength) {
        int length = checkedLength(b, maxLength);
        byte[] value = new byte[length];
        b.get(value);
        for (int i = 0; i < value.length; i++) value[i] ^= ANO_KEY[i % ANO_KEY.length];
        return new String(value, StandardCharsets.UTF_8);
    }

    private void ensureRemaining(ByteBuffer b, int count) {
        if (b.remaining() < count) throw new IllegalArgumentException("truncated structure");
    }

    private Interpretation parseA64(byte[] blob) {
        ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN);
        if (b.remaining() < 12 || Integer.toUnsignedLong(b.getInt()) != 0x20220118L) throw new IllegalArgumentException("bad leading magic");
        long count = Integer.toUnsignedLong(b.getInt());
        if (count > 100) throw new IllegalArgumentException("record count too large");
        List<String> names = new ArrayList<>();
        List<Artifact> artifacts = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            int nameLength = checkedLength(b, 4096);
            byte[] name = new byte[nameLength]; b.get(name);
            for (int i = 0; i < name.length; i++) name[i] ^= ANO_KEY[i % ANO_KEY.length];
            String decodedName = new String(name, StandardCharsets.US_ASCII);
            int bodyLength = checkedLength(b, 32 * 1024 * 1024);
            byte[] encodedBody = new byte[bodyLength]; b.get(encodedBody);
            byte[] decodedBody = new byte[bodyLength];
            for (int i = 0; i < encodedBody.length; i++) decodedBody[i] = A64_TABLE[(encodedBody[i] ^ 0x23) & 0xff];
            names.add(decodedName + "(" + bodyLength + " bytes, decoded_sha256=" + CheckSupport.sha256(decodedBody) + ")");
            artifacts.add(new Artifact("a64/" + decodedName + ".decoded.bin", decodedBody, "a64 body 解码结果"));
        }
        if (b.remaining() != 4 || Integer.toUnsignedLong(b.getInt()) != 0x20220118L) throw new IllegalArgumentException("bad trailing magic/data");
        return new Interpretation(DetectionStatus.PASS, "a64 规则容器边界与模块表有效",
                "record_count=" + count + "\nmodules=" + String.join(", ", names) + "\nsha256=" + CheckSupport.sha256(blob),
                "名称循环 XOR；body[i]=table[cipher[i] XOR 0x23]；设备画像 VM 字段谓词仍保持未决", 98, artifacts);
    }

    private Interpretation parseObX(byte[] blob) throws Exception {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(blob))) {
            for (ZipEntry entry; (entry = zip.getNextEntry()) != null; ) {
                if (entry.isDirectory() || !entry.getName().endsWith("a64.dat")) continue;
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                for (int n, total = 0; (n = zip.read(buffer)) >= 0; ) {
                    total += n;
                    if (total > 32 * 1024 * 1024) throw new IllegalArgumentException("a64.dat exceeds 32 MiB");
                    out.write(buffer, 0, n);
                }
                Interpretation inner = parseA64(out.toByteArray());
                List<Artifact> artifacts = new ArrayList<>(inner.artifacts);
                artifacts.add(new Artifact("ob_x/a64.dat", out.toByteArray(), "ZIP 内层 a64.dat 原始文件"));
                return new Interpretation(inner.status, "ob_x.zip 中的 " + inner.summary,
                        "outer_sha256=" + CheckSupport.sha256(blob) + "\nentry=" + entry.getName() + "\n" + inner.evidence,
                        inner.rule, inner.confidence, artifacts);
            }
        }
        throw new IllegalArgumentException("ob_x.zip does not contain a64.dat");
    }

    private Interpretation opaque(String name, byte[] blob, String reason) {
        String strings = printableStrings(blob);
        String baseName = name.contains(".") ? name.substring(0, name.indexOf('.')) : name;
        return new Interpretation(DetectionStatus.SUSPICIOUS, "文件已读取，格式保持 opaque",
                "reason=" + reason + "\nsize=" + blob.length + "\nsha256=" + CheckSupport.sha256(blob),
                "未知格式不尝试猜测密钥或伪造字段；原始完整副本与可打印字符串清单均导出", 99,
                Collections.singletonList(new Artifact(baseName + ".opaque.strings.txt",
                        strings.getBytes(StandardCharsets.UTF_8),
                        "未注册格式中的全部可打印字符串及文件偏移")));
    }

    private byte[] unzipPayload(byte[] outer) throws Exception {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(outer))) {
            for (ZipEntry entry; (entry = zip.getNextEntry()) != null; ) {
                if (entry.isDirectory()) continue;
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int total = 0;
                for (int n; (n = zip.read(buffer)) >= 0; ) {
                    total += n;
                    if (total > 8 * 1024 * 1024) throw new IllegalArgumentException("ZIP entry exceeds 8 MiB");
                    out.write(buffer, 0, n);
                }
                return out.toByteArray();
            }
        }
        throw new IllegalArgumentException("ZIP contains no file entry");
    }

    private List<String> capabilityStrings(byte[] data) {
        String text = new String(data, StandardCharsets.ISO_8859_1);
        String[] markers = {"/data/adb", "/data/adb/ksud", "ksud", "magisk", "zygisk", "frida", "deviceUniqueId",
                "/data/data/com.tencent.tmgp.dfm/files/.Save", "/data/data/com.tencent.tmgp.dfm/files/key",
                "/data/data/com.tencent.tmgp.dfm/files/serial", "/proc/self/maps", "/proc/self/smaps", "hook", "libtersafe.so"};
        List<String> found = new ArrayList<>();
        for (String marker : markers) if (text.toLowerCase(Locale.US).contains(marker.toLowerCase(Locale.US))) found.add(marker);
        return found;
    }

    private String printableStrings(byte[] data) {
        StringBuilder out = new StringBuilder();
        int start = -1;
        for (int i = 0; i <= data.length; i++) {
            boolean printable = i < data.length && (data[i] == 9 || data[i] >= 0x20 && data[i] <= 0x7e);
            if (printable && start < 0) start = i;
            if (!printable && start >= 0) {
                if (i - start >= 4) {
                    out.append(String.format(Locale.US, "0x%08x", start)).append("  ")
                            .append(new String(data, start, i - start, StandardCharsets.US_ASCII).replace('\t', ' ')).append('\n');
                }
                start = -1;
            }
        }
        return out.length() == 0 ? "未发现长度不少于 4 的 ASCII 可打印字符串\n" : out.toString();
    }

    private int checkedLength(ByteBuffer b, int max) {
        if (b.remaining() < 4) throw new IllegalArgumentException("truncated length");
        long value = Integer.toUnsignedLong(b.getInt());
        if (value > max || value > b.remaining()) throw new IllegalArgumentException("invalid record length " + value);
        return (int) value;
    }
    private static byte[] hexToBytes(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
    private static String hex32(long value) { return String.format(Locale.US, "0x%08x", value); }

    public static final class Interpretation {
        public final DetectionStatus status; public final String summary; public final String evidence; public final String rule; public final int confidence; public final List<Artifact> artifacts; public final List<Signal> signals; public final List<Observation> observations;
        Interpretation(DetectionStatus status, String summary, String evidence, String rule, int confidence) {
            this(status, summary, evidence, rule, confidence, Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
        }
        Interpretation(DetectionStatus status, String summary, String evidence, String rule, int confidence, List<Artifact> artifacts) {
            this(status, summary, evidence, rule, confidence, artifacts, Collections.emptyList(), Collections.emptyList());
        }
        Interpretation(DetectionStatus status, String summary, String evidence, String rule, int confidence,
                       List<Artifact> artifacts, List<Signal> signals) {
            this(status, summary, evidence, rule, confidence, artifacts, signals, Collections.emptyList());
        }
        Interpretation(DetectionStatus status, String summary, String evidence, String rule, int confidence,
                       List<Artifact> artifacts, List<Signal> signals, List<Observation> observations) {
            this.status = status; this.summary = summary; this.evidence = evidence; this.rule = rule; this.confidence = confidence;
            this.artifacts = artifacts == null ? Collections.emptyList() : artifacts;
            this.signals = signals == null ? Collections.emptyList() : signals;
            this.observations = observations == null ? Collections.emptyList() : observations;
        }
    }

    public static final class Artifact {
        public final String name; public final byte[] data; public final String description;
        Artifact(String name, byte[] data, String description) {
            this.name = name; this.data = data; this.description = description;
        }
    }

    /** Only verified event fields may populate this list; rule/capability strings never do. */
    public static final class Signal {
        public final String id; public final String value; public final String meaning; public final boolean reported;
        Signal(String id, String value, String meaning, boolean reported) {
            this.id = id; this.value = value; this.meaning = meaning; this.reported = reported;
        }
    }

    public static final class Observation {
        public final String id; public final String field; public final String value; public final String meaning;
        Observation(String id, String field, String value, String meaning) {
            this.id = id; this.field = field; this.value = value; this.meaning = meaning;
        }
    }
}
