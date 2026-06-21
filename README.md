# MalGuard 自动化恶意软件分析系统

MalGuard 是一个面向防御、应急响应和样本初筛的 Python 工具。它整合静态字符串与 IOC 提取、基础文件结构解析、YARA 命中、沙箱事件归一化、静动态关联分析、HTML/JSON/STIX 报告导出能力，用于帮助分析可疑样本中的网络回连、持久化、注入、账号后门和家族化特征。

> 安全边界：本项目只用于授权环境下的恶意软件检测、应急响应、威胁情报提取和安全研究。不要在生产主机直接运行未知样本。`sandbox-run` 默认拒绝执行，只有在隔离虚拟机、快照可恢复、网络隔离或重定向到模拟 C2 的环境中，显式传入 `--i-understand-risk` 才会启动样本。

## 功能概览

- 文件格式识别：PE、ELF、Mach-O、ZIP 等常见格式。
- 静态分析：提取 ASCII/Unicode 字符串、文件哈希、PE 导入导出表、节区熵、ELF 头信息。
- IOC 提取：识别 IPv4、域名、URL、邮箱，并给域名生成轻量 DGA 可疑度。
- 行为线索识别：检测敏感 API、进程注入、注册表/计划任务/服务持久化、账号后门和防御规避命令。
- 家族特征识别：内置 SilverFox/银狐相关规则，输出 `family_matches`，便于后续扩展更多家族规则。
- YARA 集成：可加载 `rules/suspicious_trojan.yar` 或自定义规则。
- 动态日志归一化：支持 ProcMon CSV、strace 文本和 MalGuard JSONL。
- 静动态关联：匹配静态 IOC 与动态网络连接，合并持久化证据，生成带置信度的时间线。
- 报告输出：统一 JSON、HTML 可视化报告和 STIX 2.1 IOC Bundle。

## 项目结构

```text
malguard/
  cli.py              # 命令行入口
  static_analysis.py  # 静态分析引擎
  family_detection.py # 家族特征规则
  dynamic.py          # 动态日志归一化与安全沙箱 runner
  correlate.py        # 静动态关联分析
  report.py           # JSON/HTML/STIX 报告生成
  ioc.py              # IOC 与 DGA 评分
rules/
  suspicious_trojan.yar
samples/
tests/
```

## 安装

建议使用 Python 3.10 或更高版本：

```powershell
cd C:\Users\user\Desktop\MalGuard-main
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev,pe,yara]
```

如果暂时不需要 PE 深度解析或 YARA，可只安装核心包：

```powershell
python -m pip install -e .
```

## 快速使用

### 静态分析

```powershell
malguard static .\path\to\sample.exe -o .\out\static.json --yara .\rules\suspicious_trojan.yar
```

关键输出字段：

- `sample`：文件名、大小、格式、MD5/SHA1/SHA256。
- `strings`：提取到的字符串。
- `iocs`：IPv4、域名、URL、邮箱。
- `sensitive_api_sequences`：注入、网络、持久化、防御规避等 API/命令线索。
- `persistence`：Run/RunOnce、服务、计划任务、登录脚本、AppDomainManager 等持久化线索。
- `family_matches`：家族化命中，目前内置 SilverFox/银狐规则。
- `yara`：YARA 规则命中结果。

### 银狐特征识别

MalGuard 增加了 SilverFox/银狐防御侧特征，覆盖公开报告中常见的以下线索：

- 伪装安装器和释放物：`insttect.exe`、`Microsoft.dll`、`monitor.bat`、`PolicyManagement.xml`、`target.pid`。
- `.NET` 和 GAC/AppDomainManager 相关持久化：`.NET Framework NGEN vTie`、`AppDomainManagerAssembly`、`AppDomainManagerType`、`COR_ENABLE_PROFILING`。
- 防御规避和持久化命令：`Add-MpPreference`、`ExclusionPath`、`regsvr32`、`schtasks /create`、`UserInitMprLogonScript`。
- ActiveX/Internet Zone 安全配置弱化：`Internet Settings\Zones`、`1201`、`1001`、`1004`。
- 远控载荷和家族字符串：`Winos`、`ValleyRAT`、`HackBrian`、`VFPower` 以及常见 C2 端口线索。

这些规则用于样本初筛和证据聚合，不应作为单一判定依据。建议结合哈希、网络 IOC、落地文件、进程树、注册表和沙箱行为综合确认。

### 动态日志归一化

```powershell
malguard dynamic-normalize .\samples\dynamic_events.jsonl -o .\out\dynamic.jsonl
```

标准事件示例：

```json
{"ts_ms": 1532, "category": "network", "action": "connect", "data": {"dst_ip": "203.0.113.10", "dst_port": 443, "protocol": "tcp"}, "source": "sandbox"}
```

### 静动态关联

```powershell
malguard correlate --static .\out\static.json --dynamic .\out\dynamic.jsonl -o .\out\correlation.json
```

关联分析会输出：

- 静态 IOC 与动态网络连接命中。
- 静态和动态持久化证据去重合并。
- 按时间排序的行为时间线。
- `family_match_count`、`c2_match_count`、高置信行为数量等摘要。

### 报告生成

```powershell
malguard report `
  --static .\out\static.json `
  --dynamic .\out\dynamic.jsonl `
  --correlation .\out\correlation.json `
  --json .\out\report.json `
  --html .\out\report.html `
  --stix .\out\ioc-stix.json
```

## 沙箱接入建议

推荐在隔离虚拟机中运行动态分析：

- Windows 10/11：ProcMon、Wireshark、API Monitor、Sysmon。
- Linux：strace、tcpdump、auditd、eBPF/bpftrace。
- 网络：断开公网，或重定向到 INetSim、FakeNet-NG、内置模拟 C2。
- 快照：每次运行样本前恢复干净快照。
- 超时：默认建议 120 秒，可按样本类型调整。

如确需使用内置 runner：

```powershell
malguard sandbox-run .\sample.exe -o .\out\sandbox.jsonl --timeout 120 --i-understand-risk
```

内置 runner 只记录基础进程启动和退出信息。完整的文件、注册表、网络、账号、注入行为应由 ProcMon、Sysmon、tcpdump 等外部监控工具采集后再导入 MalGuard。

## 维护计划

- 增加 Sysmon EVTX、pcap、Wireshark JSON、auditd 等日志解析器。
- 扩展 PE/ELF/Mach-O 深度结构分析。
- 增加可配置评分策略和 MITRE ATT&CK 技术映射。
- 将家族特征规则拆分为可外置配置，便于团队维护内部情报。

