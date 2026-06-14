# MalGuard 自动化恶意软件分析系统

MalGuard 是一个面向防御与应急响应场景的 Python 工具，融合静态特征提取、动态沙箱日志归一化、静动态关联分析、HTML/JSON/STIX 报告导出能力，用于辅助识别木马样本中的网络反连地址、持久化驻留机制、本机文件与注册表修改、账号后门痕迹和可疑注入行为。

> 安全边界：本项目不鼓励在宿主机直接运行未知样本。`sandbox-run` 命令默认拒绝执行，只有在隔离虚拟机、快照可恢复、网络隔离或重定向到模拟 C2 的环境中，显式传入 `--i-understand-risk` 才会启动样本。

## 功能概览

- 预处理与格式识别：识别 PE、ELF、Mach-O、ZIP 等常见文件格式，并可选调用外部解包器。
- 静态分析：提取 ASCII/Unicode 字符串、文件哈希、PE 导入导出表、节区熵、ELF 基础头信息。
- IOC 提取：通过正则识别 IPv4、域名、URL、邮箱，并对域名进行轻量 DGA 可疑度评分。
- 行为线索识别：检测敏感 API 调用序列、进程注入模式、持久化位置、账号后门相关命令和字符串。
- YARA 集成：支持加载自定义 YARA 规则匹配已知木马家族或组织内规则。
- 动态分析接入：归一化 ProcMon CSV、strace 文本、MalGuard JSONL 等事件源。
- 关联分析：比对静态 C2 IOC 与动态网络连接，合并持久化机制，生成行为时间线并标注恶意置信度。
- 报告输出：生成统一 JSON 报告、HTML 可视化报告和 STIX 2.1 IOC Bundle。

## 项目结构

```text
malware-analysis-system/
  malguard/
    cli.py              # 命令行入口
    static_analysis.py  # 静态分析引擎
    dynamic.py          # 动态日志归一化与安全沙箱 runner
    correlate.py        # 静动态关联分析
    report.py           # JSON/HTML/STIX 报告生成
    ioc.py              # IOC 与 DGA 评分
  rules/
    suspicious_trojan.yar
  samples/
    dynamic_events.jsonl
  tests/
```

## 安装

建议使用 Python 3.10 或更高版本：

```powershell
cd C:\Users\user\Desktop\1\malware-analysis-system
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev,pe,yara]
```

如果暂时不需要 PE 深度解析或 YARA，可只安装核心包：

```powershell
python -m pip install -e .
```

## 快速使用

### 1. 静态分析

```powershell
malguard static .\path\to\sample.exe -o .\out\static.json --yara .\rules\suspicious_trojan.yar
```

输出 JSON 会包含：

- 样本基础信息与哈希
- 文件格式与结构信息
- 字符串与 IOC
- 敏感 API 序列
- 持久化与账号后门线索
- YARA 命中结果

### 2. 归一化动态日志

支持三类输入：

- ProcMon 导出的 CSV
- Linux `strace` 文本日志
- 已经是 MalGuard 事件结构的 JSON Lines

```powershell
malguard dynamic-normalize .\samples\dynamic_events.jsonl -o .\out\dynamic.jsonl
```

标准动态事件格式：

```json
{"ts_ms": 1532, "category": "network", "action": "connect", "data": {"dst_ip": "203.0.113.10", "dst_port": 443, "protocol": "tcp"}, "source": "sandbox"}
```

### 3. 静动态关联

```powershell
malguard correlate --static .\out\static.json --dynamic .\out\dynamic.jsonl -o .\out\correlation.json
```

关联分析会：

- 将静态 IOC 与动态网络连接进行命中比对
- 合并并去重持久化行为
- 生成毫秒级行为时间线
- 为动态事件计算恶意置信度

### 4. 生成报告

```powershell
malguard report `
  --static .\out\static.json `
  --dynamic .\out\dynamic.jsonl `
  --correlation .\out\correlation.json `
  --json .\out\report.json `
  --html .\out\report.html `
  --stix .\out\ioc-stix.json
```

HTML 报告会高亮 IOC，并以表格展示行为时间线；STIX 2.1 文件可导入威胁情报平台。

## 沙箱接入建议

推荐在隔离虚拟机中运行动态分析：

- Windows 10/11：ProcMon、Wireshark、API Monitor、Sysmon。
- Ubuntu 22.04：strace、tcpdump、auditd、eBPF/bpftrace。
- 网络：断开公网，或重定向到 INetSim、FakeNet-NG、内网模拟 C2。
- 快照：每次运行样本前恢复干净快照。
- 超时：默认建议 120 秒，可按样本类型调整。

如确需使用内置 runner：

```powershell
malguard sandbox-run .\sample.exe -o .\out\sandbox.jsonl --timeout 120 --i-understand-risk
```

该 runner 只记录基础进程启动和退出信息。完整文件、注册表、网络、账号、注入行为应由 ProcMon、strace、Sysmon、tcpdump 等外部监控工具采集后再导入 MalGuard。

## 事件类别

| 类别 | 示例行为 |
| --- | --- |
| `network` | TCP/UDP/HTTP/HTTPS 连接、五元组、前 256 字节载荷 |
| `file` | 创建、修改、删除、复制、隐藏，记录路径与前后哈希 |
| `registry` | Windows 注册表键值创建、修改、删除 |
| `account` | 创建/删除用户、改密、加入管理员组 |
| `persistence` | 服务、计划任务、Run 键、启动目录、crontab、systemd、`.bashrc` |
| `process` | 进程树、退出码、远程线程、内存修改、Hook |
| `anti_analysis` | 反调试、反沙箱、延迟执行、检测特定进程或注册表 |

## 持续维护计划

- 增加更多日志后端解析器：Sysmon EVTX、tcpdump/pcap、Wireshark JSON、auditd。
- 扩展 PE/ELF/Mach-O 深度结构解析。
- 增加更细粒度的 DGA 模型与家族聚类规则。
- 增加可配置评分策略和 MITRE ATT&CK 技术映射。
- 增加 Docker/VM 沙箱编排脚本，但默认保持安全拒绝执行策略。

## 合规用途

本工具仅用于授权环境下的恶意软件检测、应急响应、威胁情报提取、实验室分析和安全研究。请勿将其用于未授权的样本投递、攻击验证或规避检测。
