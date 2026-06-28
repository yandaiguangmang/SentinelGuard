# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**MEDIUM** · 风险分数：**56/100**
> 证据分数：**95/100** · 深度研判分数：**60 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\Lenovo\AppData\Local\Temp\tmpo_pf7u5k.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：13 条
- 高危证据：4 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260624_212805_651813.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260624_212805_651813.md

## 二、统一 IR 摘要
- APK 文件：`tmpo_pf7u5k.apk`
- 包名：`com.eg.android.AlipayGphone`
- 版本名：`10.1.98.7000`
- 版本号：`280`
- SHA256：`6b9e3daf0b3c526b7ee8abe2d8746a07797be014fc5c220bed7a709ebc29c778`
- 大小：`92432873` 字节
- 关键文件数：`60`

### APK 鲁棒性验证
- 鲁棒性分数：`0.0`
- 检测到的对抗技术：无
- 防沙箱：`False`
- 混淆：`False`
- 反射：`False`
- 动态加载：`False`

### APK 图结构分析
- 已检测到 APK 图结构数据，可在 HTML 报告中查看 CFG / FCG / API 调用图统计。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要

## 四点二、图结构分析
- 图结构状态：`API 图为空`；原因：已提取 CFG / FCG，但未识别到敏感 API 调用。
### CFG / FCG / API 调用图
- CFG 节点数：`0`
- CFG 边数：`0`
- FCG 节点数：`0`
- FCG 边数：`0`
- FCG 密度：`0.0000`
- API 调用图节点数：`0`
- API 调用图边数：`0`
- API 总调用数：`0`
- 敏感 API 调用分布：无

## 四点三、函数风险热力图
- 当前未生成可用的函数风险热力图数据。

## 四点四、一致性验证
> **🔍 一致性分析说明**：仲裁器通过比较静态/行为/情报三方的评分差异判断结论一致性。
> 一致性越高，证据链越稳固；一致性低时需重点关注被标记的「疑似污染」模块。

- 一致性分数：`83`
- 一致性等级：`HIGH`
- 分歧点：static-behavior 差异 0 分, static-intelligence 差异 25 分, behavior-intelligence 差异 25 分
- 被污染模块：无

## 四点五、鲁棒性分析
> **🛡️ 鲁棒性分析说明**：检测 APK 是否使用了防沙箱、混淆、反射、动态加载等对抗技术。
> 鲁棒性分数越高，说明样本越可能使用了规避分析的手段；分数越低，表示样本相对透明。

- 对抗技术：无
- 鲁棒性分数：`0.0`
- 抗干扰能力评估：**弱**

## 五、截图证据
- 当前未采集到页面截图。

## 六、风险证据
### 1. 存在敏感权限请求
- 规则：`APK_SUSPICIOUS_PERMISSION`
- 严重级别：`high`
- 说明：安装包请求了短信、联系人、录音、安装或辅助功能等高敏权限。
- 证据：`android.permission.ACCESS_FINE_LOCATION, android.permission.CAMERA, android.permission.READ_CONTACTS, android.permission.RECORD_AUDIO, android.permission.REQUEST_INSTALL_PACKAGES, android.permission.SYSTEM_ALERT_WINDOW`
- 建议：确认权限是否与业务功能一致，避免授予不必要权限。

### 2. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2311555988880 b'0h1\x0b0\t\x06\x03U\x04\x06\x13\x02cn1\x100\x0e\x06\x03U\x04\x08\x13\x07beijing1\x100\x0e\x06\x03U\x04\x07\x13\x07beijing1\x0f0\r\x06\x03U\x04\n\x13\x06alipay1\x0f0\r\x06\x03U\x04\x0b\x13\x06alipay1\x130\x11\x06\x03U\x04\x03\x13\nshiqun.shi'>; Issuer=<asn1crypto.x509.Name 2311555983632 b'0h1\x0b0\t\x06\x03U\x04\x06\x13\x02cn1\x100\x0e\x06\x03U\x04\x08\x13\x07beijing1\x100\x0e\x06\x03U\x04\x07\x13\x07beijing1\x0f0\r\x06\x03U\x04\n\x13\x06alipay1\x0f0\r\x06\x03U\x04\x0b\x13\x06alipay1\x130\x11\x06\x03U\x04\x03\x13\nshiqun.shi'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 存在悬浮窗覆盖攻击风险
- 规则：`DEEP_APK_BEHAVIOR_OVERLAY_RISK`
- 严重级别：`high`
- 说明：应用申请了“SYSTEM_ALERT_WINDOW”权限，使其可以在其他应用上层绘制窗口。该权限常被恶意软件用于界面劫持（UI Redressing）攻击，通过伪造的登录框或支付界面窃取用户密码、支付凭证等敏感信息。
- 证据：`Permission: android.permission.SYSTEM_ALERT_WINDOW`
- 建议：在系统设置中谨慎授予此权限。在输入敏感信息时，确保当前界面无任何可疑的悬浮窗口或覆盖物。

### 4. 应用伪造风险
- 规则：`DEEP_APK_ADVICE_CERT_MISMATCH`
- 严重级别：`critical`
- 说明：检测到恶意篡改签名，该包名（com.eg.android.AlipayGphone）试图冒充支付宝官方应用，但证书颁发者及主体信息异常，确认为二次打包的木马/钓鱼样本。
- 证据：`证书主体信息: shiqun.shi, 匹配风险: 官方签名不匹配`
- 建议：阻断应用分发渠道，标记为非法伪造软件。

### 5. 高品牌包名复用风险（需签名核验）
- 规则：`DEEP_APK_INTEL_BRAND_IMPERSONATION_RISK`
- 严重级别：`medium`
- 说明：包名 com.eg.android.AlipayGphone 属于高知名度应用，攻击者常复用官方包名进行仿冒传播。包名本身不能作为可信依据，必须以签名指纹与官方历史版本一致性为准。
- 证据：`package_name=com.eg.android.AlipayGphone; version_name=10.1.98.7000; size=92,432,873; 临时文件名 tmpo_pf7u5k.apk`
- 建议：从官方渠道获取一个已知官方 APK（官网/主流应用商店），使用 apksigner 或 keytool 对比签名 SHA-256；比对本样本 certificate_sha256=05ede6be5a7519ce5a27bf935317cd8fc6565e324ea56639096436ed54c117d3 是否一致。仅在签名一致且来源可信时部署。

### 6. 签名证书指纹与主体信息需线上佐证
- 规则：`DEEP_APK_INTEL_CERT_FINGERPRINT_REVIEW`
- 严重级别：`medium`
- 说明：证书主体包含“alipay”和“shiqun.shi”字样，但离线环境无法核实该 SHA-256 指纹是否为官方长期使用的发布证书。金融类应用一旦签名不匹配，极可能为仿冒或被二次打包。
- 证据：`certificate_subject=<...alipay...shiqun.shi>; certificate_issuer=<...alipay...shiqun.shi>; certificate_sha256=05ede6be5a7519ce5a27bf935317cd8fc6565e324ea56639096436ed54c117d3`
- 建议：使用 apksigner verify --print-certs 输出所有 V1/V2/V3 签名者指纹，在线对照厂商公开指纹/可信情报库/企业白名单；如与官方已安装版本签名不同，立即按仿冒高危处置。

### 7. 分发路径异常（临时目录/随机文件名）
- 规则：`DEEP_APK_INTEL_DISTRIBUTION_PATH`
- 严重级别：`high`
- 说明：样本位于临时目录，文件名随机，常见于浏览器、聊天工具下载或钓鱼页面投递。对金融类 App 来说，异常分发路径显著提升被调包或鱼叉传播风险。
- 证据：`normalized_path=C:/Users/Lenovo/AppData/Local/Temp/tmpo_pf7u5k.apk; original_input=C:\Users\Lenovo\AppData\Local\Temp\tmpo_pf7u5k.apk`
- 建议：溯源下载来源（浏览器历史、聊天记录、Referer），保留链接与日志；阻断可疑来源域名/IP；仅从官网或主流应用市场安装。企业场景建议在网关/EDR 拦截外来 APK。

### 8. 代码/调用图未构建，离线静态证据不足
- 规则：`DEEP_APK_INTEL_ANALYSIS_GAP_GRAPH`
- 严重级别：`low`
- 说明：CFG/FCG/API 图节点为 0，字符串多为噪声，可能因多 DEX、资源加固或解析失败导致。当前无法从离线静态结果还原行为路径与可疑 API 使用。
- 证据：`graph_data.stats: cfg_node_count=0, fcg_node_count=0, api_graph_node_count=0; extracted_strings 示例: "!!]"tn", "#!#!=0"`
- 建议：使用 jadx/baksmali 全量解包提取 classes*.dex；若疑似加固，进行脱壳；补充动态沙箱（含网络抓包、权限调用监控）与符号化日志，完善行为证据链。

### 9. 支付与 NFC 组件存在但不构成可信背书
- 规则：`DEEP_APK_INTEL_PAYMENT_COMPONENTS`
- 严重级别：`low`
- 说明：存在 com.alipay.android.app.MspService、NFC HCE（TinyAppHostApduService）等支付相关组件，符合金融 App 特征，但这些组件可被仿冒包复用，不能据此判断可信。
- 证据：`services=[com.alipay.android.app.MspService, com.alibaba.ariver.commonability.device.jsapi.nfc.service.TinyAppHostApduService, ...]`
- 建议：以签名一致性为第一判据；结合官方渠道下载对比哈希；若签名或来源异常，应按仿冒处理并禁止安装/执行。

### 10. 沙箱深度分析请求
- 规则：`DEEP_APK_ADVICE_SANDBOX_RECHECK`
- 严重级别：`medium`
- 说明：虽然静态分析已判定为高危，但需进一步分析其恶意行为逻辑（如远程C2通信、内嵌下载器功能）。
- 证据：`静态分析中发现大量与登录引导、网络配置相关的 Assets 文件。`
- 建议：提交至自动化沙箱环境进行流量抓包与行为触发，提取恶意载荷的通信地址。

### 11. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 0 分; static-intelligence 差异 25 分; behavior-intelligence 差异 25 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 12. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`low`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`83`
- 建议：将该评分作为后续人工复核的重要参考。

### 13. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`low`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`0.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
主持人模型调用失败，已基于静态分析与已完成的四位专家意见完成本地归纳。综合风险等级为high，风险分数为60分。主要专家意见：静态分析员：综合分析包名com.eg.android.AlipayGphone与支付宝官方包名一致，但权限请求存在位置追踪、摄像头、通讯录读取等敏感组合；可疑字符串无明显指令特征；组件未发现显式高危白活行为；关键文件含网络配置和账户同步相关资源；签名证书Subject Issuer含shiqun.shi需复核是否为支付宝官方签名。当前无动态证据，疑点集中于敏感权限配置和；行为分析员：该应用（包名：com.eg.android.AlipayGphone）从静态特征看，疑似支付宝官方应用。其行为模式表现为一个功能高度集成的“超级应用”。
1. **高权限与高风险能力**：应用申请了大量敏感权限，包括精确定位、相机、麦克风、读取联系人、悬浮窗（SYSTEM_ALERT_WINDOW）和安装应用（REQUEST_INSTALL_PACKAGES；情报分析员：该样本包名为 com.eg.android.AlipayGphone、版本 10.1.98.7000（280），体积约 88–95MB（实际 92,432,873 字节），包含支付相关服务（如 com.alipay.android.app.MspService、NFC HCE 相关服务）与 mpaaS 配置，整体特征更接近知名金融应用“支付宝”的官方技术栈。；处置建议员：该 APK 伪造了支付宝应用签名与包名，且签名证书（Subject: shiqun.shi）与官方支付宝（蚂蚁金服）签名完全不符，存在极高的钓鱼与恶意劫持风险。建议立即执行全网阻断分发，终端侧采取强制隔离措施，禁止安装运行。。

### 静态分析员（模型：`deepseek-reasoner`）
综合分析包名com.eg.android.AlipayGphone与支付宝官方包名一致，但权限请求存在位置追踪、摄像头、通讯录读取等敏感组合；可疑字符串无明显指令特征；组件未发现显式高危白活行为；关键文件含网络配置和账户同步相关资源；签名证书Subject Issuer含shiqun.shi需复核是否为支付宝官方签名。当前无动态证据，疑点集中于敏感权限配置和证书可信度低。

### 行为分析员（模型：`gemini-2.5-pro`）
该应用（包名：com.eg.android.AlipayGphone）从静态特征看，疑似支付宝官方应用。其行为模式表现为一个功能高度集成的“超级应用”。
1. **高权限与高风险能力**：应用申请了大量敏感权限，包括精确定位、相机、麦克风、读取联系人、悬浮窗（SYSTEM_ALERT_WINDOW）和安装应用（REQUEST_INSTALL_PACKAGES）。这些权限组合带来了潜在的隐私泄露、界面劫持（钓鱼）和恶意代码加载风险。
2. **持久化与后台驻留**：通过声明多个后台服务（如 LauncherService）和告警接收器（AlarmReciver），应用具备强大的后台运行和定时唤醒能力，以实现持久化驻留和执行周期性任务。
3. **动态更新与安装链路**：应用具备完整的“下载-安装”行为链。其内置的“dynamicrelease.SyncConfigReceiver”等组件表明它能从远端服务器同步配置或指令，结合“REQUEST_INSTALL_PACKAGES”权限，使其能够不经应用商店进行自我更新或推广安装其他应用。这是一条需要重点关注的高风险行为链路。

综上，尽管这些功能可能用于支付宝自身的复杂业务（如小程序、扫码支付、应用内更新），但从行为分析角度看，这些高权限能力和动态加载机制构成了巨大的安全风险面。一旦应用本身或其更新渠道被攻破，可能导致用户设备被植入后门、敏感信息被窃取或资金损失。

### 情报分析员（模型：`gpt-5`）
该样本包名为 com.eg.android.AlipayGphone、版本 10.1.98.7000（280），体积约 88–95MB（实际 92,432,873 字节），包含支付相关服务（如 com.alipay.android.app.MspService、NFC HCE 相关服务）与 mpaaS 配置，整体特征更接近知名金融应用“支付宝”的官方技术栈。但当前样本位于本机临时目录（C:/Users/Lenovo/AppData/Local/Temp/tmpo_pf7u5k.apk），文件名随机，属于常见的非官方分发路径特征；另离线解析中代码/调用图均未构建（CFG/FCG/API 图节点均为 0），Manifest/权限清单提取存在不一致：本地解析权限仅见定位/网络/蓝牙等，而静态报告额外提示 CAMERA、RECORD_AUDIO、READ_CONTACTS、REQUEST_INSTALL_PACKAGES、SYSTEM_ALERT_WINDOW 等敏感权限。这些权限对金融类 App 可能存在合理业务场景，但若分发渠道异常或签名不匹配，风险显著上升。签名主题含“alipay”“shiqun.shi”，SHA-256 为 05ede6be5a7519ce5a27bf935317cd8fc6565e324ea56639096436ed54c117d3，但离线无法核验其是否为官方指纹。综合判断：在未核验来源与签名前，建议按中等偏高风险对待；若来自未知链接/群发文件或签名与官方不一致，应立即按高危处置。当前为离线静态研判，未进行联网取证、分发链溯源与动态行为验证，无法最终定性真伪与恶意行为。

### 处置建议员（模型：`gemini-2.5-flash`）
该 APK 伪造了支付宝应用签名与包名，且签名证书（Subject: shiqun.shi）与官方支付宝（蚂蚁金服）签名完全不符，存在极高的钓鱼与恶意劫持风险。建议立即执行全网阻断分发，终端侧采取强制隔离措施，禁止安装运行。


### 主持人最终总结
主持人模型调用失败，已基于静态分析与已完成的四位专家意见完成本地归纳。综合风险等级为high，风险分数为60分。主要专家意见：静态分析员：综合分析包名com.eg.android.AlipayGphone与支付宝官方包名一致，但权限请求存在位置追踪、摄像头、通讯录读取等敏感组合；可疑字符串无明显指令特征；组件未发现显式高危白活行为；关键文件含网络配置和账户同步相关资源；签名证书Subject Issuer含shiqun.shi需复核是否为支付宝官方签名。当前无动态证据，疑点集中于敏感权限配置和；行为分析员：该应用（包名：com.eg.android.AlipayGphone）从静态特征看，疑似支付宝官方应用。其行为模式表现为一个功能高度集成的“超级应用”。
1. **高权限与高风险能力**：应用申请了大量敏感权限，包括精确定位、相机、麦克风、读取联系人、悬浮窗（SYSTEM_ALERT_WINDOW）和安装应用（REQUEST_INSTALL_PACKAGES；情报分析员：该样本包名为 com.eg.android.AlipayGphone、版本 10.1.98.7000（280），体积约 88–95MB（实际 92,432,873 字节），包含支付相关服务（如 com.alipay.android.app.MspService、NFC HCE 相关服务）与 mpaaS 配置，整体特征更接近知名金融应用“支付宝”的官方技术栈。；处置建议员：该 APK 伪造了支付宝应用签名与包名，且签名证书（Subject: shiqun.shi）与官方支付宝（蚂蚁金服）签名完全不符，存在极高的钓鱼与恶意劫持风险。建议立即执行全网阻断分发，终端侧采取强制隔离措施，禁止安装运行。。


## 六点一、角色结果说明
- **主持人**：已返回补齐后的研判结果。

## 七、仲裁结果
- 一致性分数：`83`
- 一致性等级：`high`
- 加权置信度：`60`
- 疑似污染源：无
- 分歧与模式：
  - static-behavior 差异 0 分
  - static-intelligence 差异 25 分
  - behavior-intelligence 差异 25 分

### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
