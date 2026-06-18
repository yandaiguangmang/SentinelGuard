# SentinelGuard 哨塔

> 面向 URL 与 APK 的多角色协同恶意检测平台，支持静态分析、动态沙箱线索采集与结构化安全报告导出。

SentinelGuard 是一个面向安全研判、样本初筛和演示展示的轻量级检测平台。项目围绕常见风险入口 **URL** 与 **Android APK** 构建统一检测链路：输入解析、静态特征提取、动态沙箱线索采集、多角色 API 协同研判、HTML / Markdown 报告导出。

项目的核心目标不是替代专业杀毒引擎，而是把“证据采集 → 多角色分析 → 可读报告”串成一条清晰、可扩展的安全分析流程。

## 功能特性

### URL 恶意检测

- 自动识别并规范化 URL
- 分析协议、主机、路径、参数、跳转参数等结构风险
- 可选抓取页面内容，提取 HTML / DOM / 表单 / 下载链接 / 外链脚本等页面线索
- 分析跳转链、跨域跳转、HTTP 降级等行为
- 支持多角色 API 深度研判

### APK 静态分析

- 使用 `androguard` 解析 APK 元数据
- 提取包名、版本号、权限、Activity / Service / Receiver / Provider 等组件信息
- 计算文件大小、SHA256、签名证书线索
- 扫描关键文件、DEX、资源配置与可疑字符串
- 基于静态证据生成初步风险线索

### APK 动态沙箱分析

基于 Android Studio 模拟器与 `adb`，对上传的 APK 进行最小可行动态分析：

- 安装 APK 到模拟器
- 启动应用并采集 `logcat`
- 收集运行时崩溃、ANR、网络线索
- 采集运行时权限、`appops`、包状态信息
- 检测可疑文件落地：`.dex` / `.jar` / `.apk` / `.so` / `.zip`
- 检测无障碍、设备管理器、通知监听等持久化服务线索
- 将动态线索整理为 JSON 证据包
- 将动态证据包输入五角色 API 协同研判，使用 API 返回结果作为动态研判结论

### 多角色协同研判

项目内置五类分析角色，适合模拟安全会诊式研判流程：

- 主持人
- 静态分析员
- 行为分析员
- 情报分析员
- 处置建议员

每个角色可以配置不同的 API Key、Base URL 和模型名称。最终由主持人汇总输出风险等级、风险分数、证据说明和处置建议。

### 报告导出

检测完成后自动生成：

- HTML 报告
- Markdown 报告
- APK 动态分析 JSON 证据包

报告内容包括：

- 检测对象摘要
- 风险等级与风险分数
- URL / APK 静态证据
- APK 动态沙箱线索
- 多角色协同研判结论
- 模型映射信息
- 处置建议

## 项目架构

```text
SentinelGuard/
├── parsers/
│   └── input_parser.py          # URL / APK 输入解析与统一 IR 构建
├── analyzers/
│   ├── url_analyzer.py          # URL 静态与页面线索分析
│   ├── url_deep_analyzer.py     # URL 多角色 API 深度研判
│   ├── apk_analyzer.py          # APK 静态分析，androguard 元数据提取
│   ├── apk_deep_analyzer.py     # APK 静态证据多角色 API 研判
│   └── apk_dynamic_analyzer.py  # APK 动态沙箱线索采集与动态协同研判
├── judgement.py                 # 检测流程编排与报告对象构建
├── report.py                    # HTML / Markdown 报告渲染与保存
├── state.py                     # IR、Finding、Report 数据结构
└── task_manager.py              # Web 异步任务状态管理

app.py                           # Flask Web 入口
templates/index.html             # Web 前端页面
config.py                        # 配置项
requirements.txt                 # Python 依赖
```

整体流程：

```text
输入 URL / APK
      ↓
统一解析为 TargetIR
      ↓
静态分析与证据提取
      ↓
可选：URL 深度研判 / APK 动态沙箱
      ↓
五角色 API 协同研判
      ↓
生成 HTML / Markdown / JSON 报告
```

## 快速开始

### 1. 克隆项目

```bash
git clone <your-repo-url>
cd code
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 启动服务

```bash
python app.py
```

默认访问：

```text
http://127.0.0.1:5000
```

## 使用方式

### URL 检测

1. 打开 Web 首页
2. 选择 URL 检测
3. 输入待检测 URL
4. 可选勾选页面抓取与深度研判
5. 查看检测结果与导出报告

### APK 静态检测

1. 切换到 APK 检测
2. 上传 `.apk` 文件
3. 选择静态分析
4. 查看包名、权限、组件、签名、字符串等静态证据

### APK 动态沙箱检测

动态分析依赖本机 Android Studio 模拟器与 `adb`。

1. 启动 Android Studio 模拟器
2. 确认 `adb devices` 能看到设备
3. 在 Web 页面上传 APK
4. 选择动态沙箱模式
5. 等待安装、启动、日志采集与 API 协同研判完成
6. 查看动态摘要、风险证据与 JSON 证据包

## 配置说明

项目支持通过 `.env` 或环境变量配置。

常用配置：

| 配置项 | 说明 |
| --- | --- |
| `HOST` | Flask 服务监听地址 |
| `PORT` | Flask 服务端口 |
| `DETECTION_REPORT_DIR` | 报告输出目录 |
| `DETECTION_TIMEOUT_SECONDS` | URL 页面抓取超时时间 |
| `DETECTION_USER_AGENT` | 页面抓取 User-Agent |
| `ADB_PATH` | adb 可执行文件路径，或 adb 所在目录 |
| `APK_DYNAMIC_RUNTIME_WINDOW_SECONDS` | APK 动态采集窗口时长 |

多角色 API 配置：

| 角色 | API Key | Base URL | Model |
| --- | --- | --- | --- |
| 主持人 | `DETECTION_HOST_API_KEY` | `DETECTION_HOST_BASE_URL` | `DETECTION_HOST_MODEL_NAME` |
| 静态分析员 | `DETECTION_STATIC_API_KEY` | `DETECTION_STATIC_BASE_URL` | `DETECTION_STATIC_MODEL_NAME` |
| 行为分析员 | `DETECTION_BEHAVIOR_API_KEY` | `DETECTION_BEHAVIOR_BASE_URL` | `DETECTION_BEHAVIOR_MODEL_NAME` |
| 情报分析员 | `DETECTION_INTEL_API_KEY` | `DETECTION_INTEL_BASE_URL` | `DETECTION_INTEL_MODEL_NAME` |
| 处置建议员 | `DETECTION_ADVICE_API_KEY` | `DETECTION_ADVICE_BASE_URL` | `DETECTION_ADVICE_MODEL_NAME` |

也可以在 Web 页面中临时填写 API Key 与 Base URL，仅用于本次检测任务。

## APK 动态沙箱采集内容

当前动态分析为最小可行沙箱能力，重点采集高价值行为线索：

| 线索类型 | 采集方式 | 用途 |
| --- | --- | --- |
| 安装结果 | `adb install` | 判断样本是否可安装 |
| 启动结果 | `monkey` | 判断样本是否可运行 |
| 崩溃 / ANR | `logcat` | 发现异常行为或环境对抗迹象 |
| 网络线索 | `logcat` URL / 域名 / IP 提取 | 判断是否存在外联行为 |
| 权限状态 | `dumpsys package` / `appops get` | 识别运行时高危权限线索 |
| 文件落地 | `ls -laR` 关键目录 | 发现 dex / jar / apk / so / zip 等动态载荷 |
| 持久化服务 | `dumpsys accessibility/device_policy/notification` | 识别无障碍、设备管理、通知监听等高危注册 |

动态阶段不会只依赖本地规则下结论，而是把整理后的沙盒线索作为 `dynamic_sandbox` 输入给五角色 API 协同分析，最终采用 API 返回结果作为动态研判结论。

## 测试

运行现有测试：

```bash
python -m pytest
```

或运行核心回归测试：

```bash
python -m pytest tests/test_sentinel_input_parser.py tests/test_sentinel_report.py tests/test_sentinel_deep_analyzer.py -q
```

## 适用场景

- 可疑链接初筛
- APK 样本初步研判
- 安全课程或竞赛展示
- 企业 / 校园安全演示系统
- 多角色协同分析流程验证
- 动态沙箱能力原型验证

## 安全说明

- 请仅分析你有权检测的 URL 或 APK 样本。
- APK 动态分析会在本机 Android 模拟器中安装和运行样本，建议使用专用隔离模拟器环境。
- 不建议在个人主力设备或真实账号环境中运行未知样本。
- 报告结论用于辅助研判，不应作为唯一处置依据。

## 后续规划

- 更完整的流量代理与 DNS / HTTP 证据采集
- 截图与界面行为证据
- 更细粒度的 Activity / Service 生命周期记录
- 威胁情报联动
- 样本家族聚类与相似度分析
- 小程序检测能力扩展
- 可视化证据链图谱

## License

本项目用于安全研究、教学演示与防御性检测场景。请在合法授权范围内使用。
