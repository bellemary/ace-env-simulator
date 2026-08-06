# ACE 客户端环境检测模拟器

本地化 ACE 反作弊 SDK 环境检测模拟工具，不对接任何外部服务器。

## 功能概览

### 基础模式

不读取目标进程，逐项模拟 ACE SDK 对客户端环境的探测步骤，输出与游戏内判断一致的结果（通过 / 可疑 / 高风险）。覆盖 Root 探测链、Bootloader / Verified Boot、SELinux、开发者选项、系统属性指纹、云手机 / 模拟器制品、风险包名 / 多开框架、Keystore / MediaDrm 等 24 项检测。

### 高级模式

需要 Root 权限。流程：自动启动游戏 → 持续扫描内存特征点（`/proc/[pid]/maps` + `process_vm_readv`）→ 用户手动结束 → 扫描 `ano_tmp` 目录并逐一解密。

支持的解密文件族：

| 文件族 | 容器 | 解码方式 | 完整性校验 |
|--------|------|----------|------------|
| ano_rdp.dat | BE32 头 + XOR | ANO_KEY XOR | 32 位十六进制摘要 |
| kvcache8.dat | LE32 头 | ANO_KEY XOR | CRC32 尾部校验 |
| mrpcs_a_v.data | ZIP + XOR | [4,EOF) XOR 0x4F | LE32 CRC32 |
| mrpcs_a_v_f.data | ZIP + XOR | [4,EOF) XOR 0x84 | LE32 CRC32 |
| mpmc.dat | LE32 头 | 结构化字段 | CRC32 校验 |
| comm.dat / comm.zip | XOR + ZIP | ANO_KEY XOR | 字段名校验 |
| config2/3.dat.* | BE32 头 + XOR | ANO_KEY XOR | magic 校验 |
| ano.ano3.dat | LE32 头 | 结构化字段 | 尾部 magic 校验 |
| h_rcd.dat | LE32 头 | 固定字读取 | magic 校验 |
| tersafe.update | 无容器 | 结构化字段 | magic 校验 |
| ace_shell_db.dat | BE32 头 | 大端字读取 | magic 校验 |

高级模式结果自动保存至 `/storage/emulated/0/ACE解密结果/ACE_Result_YYYY-MM-DD_HH-mm-ss.txt`。

## 已知限制

- 解密结果因设备而异，软件提供解码能力而非对明文内容的统一判定
- 明文解读需人工或 AI 介入
- 手动压缩包（ano_tmp.zip、ano_dfh.zip、大厅.zip、对局.zip、大厅前.zip）已自动跳过
- 高级模式需 Root 权限，单轮总读取上限 64 MiB

详见 [检测原理与限制说明](docs/检测原理与限制说明.md)。

## 技术栈

- Android (minSdk 21, targetSdk 28, compileSdk 35)
- Java + AndroidX
- Gradle 构建系统

## 构建

```bash
./gradlew assembleDebug
```

输出 APK 位于 `app/build/outputs/apk/debug/`。

## 声明

本工具仅用于环境检测模拟与安全研究，不修改目标进程内存，不对接外部服务器。
