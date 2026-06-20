# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**LOW** · 风险分数：**18/100**
> 证据分数：**50/100** · 深度研判分数：**7 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpupv5xael.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：29 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260620_182846_718712.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260620_182846_718712.md

## 二、统一 IR 摘要
- APK 文件：`tmpupv5xael.apk`
- 包名：`com.malmstein.yahnac`
- 版本名：`1.3.1`
- 版本号：`27`
- SHA256：`b34ee7bdbd6c9b034f38c7f3a27969445d5ebf351b92214356f4db16576275fd`
- 大小：`4125881` 字节
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
- device_id：emulator-5554
- package_name：com.malmstein.yahnac
- static_file_name：tmpupv5xael.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：10730
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：无
- persistent_services：{'device_policy': ['6: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：38
- logcat_excerpt_count：320
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260620_182849_213683_com.malmstein.yahnac/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260620_182849_213683_com.malmstein.yahnac/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260620_182849_213683_com.malmstein.yahnac/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260620_182849_213683_com.malmstein.yahnac`

## 四点二、图结构分析
- 图结构状态：`回退生成`；原因：androguard_unavailable_or_parse_failed
### CFG / FCG / API 调用图
- CFG 节点数：`1`
- CFG 边数：`0`
- FCG 节点数：`2`
- FCG 边数：`1`
- FCG 密度：`0.1667`
- API 调用图节点数：`0`
- API 调用图边数：`0`
- API 总调用数：`0`
- 敏感 API 调用分布：network:0, payment:0, privacy:0, reflection:0, system:0
- API 调用明细：
  - `network`：0
  - `payment`：0
  - `privacy`：0
  - `reflection`：0
  - `system`：0

## 四点三、一致性验证
- 一致性分数：`71`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 43 分, static-intelligence 差异 0 分, behavior-intelligence 差异 43 分
- 被污染模块：static, behavior, intelligence

## 四点四、鲁棒性分析
- 对抗技术：无
- 鲁棒性分数：`0.0`
- 抗干扰能力评估：**弱**

## 五、风险证据
### 1. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。
- 证据：`manifest: AndroidManifest.xml; resource: res/anim-v21/design_bottom_sheet_slide_in.xml; resource: res/anim-v21/design_bottom_sheet_slide_out.xml; resource: res/anim/abc_fade_in.xml; resource: res/anim/abc_fade_out.xml; resource: res/anim/abc_grow_fade_in_from_bottom.xml; resource: res/anim/abc_popup_enter.xml; resource: res/anim/abc_popup_exit.xml; resource: res/anim/abc_shrink_fade_out_from_bottom.xml; resource: res/anim/abc_slide_in_bottom.xml; resource: res/anim/abc_slide_in_top.xml; resource: res/anim/abc_slide_out_bottom.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2249369597552 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>; Issuer=<asn1crypto.x509.Name 2249369598128 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl681982653.tmp; com.malmstein.yahnac; base.dm`
- 建议：后续可结合抓包或代理进行复核。

### 4. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`6: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 5. 应用注册可疑的设备策略（设备管理器）
- 规则：`DEEP_APK_STATIC_SUSPICIOUS_DEVICE_ADMIN`
- 严重级别：`high`
- 说明：动态沙箱证据显示，该应用 (com.malmstein.yahnac) 在系统中注册了设备策略服务。作为一个新闻阅读器，此行为没有合理解释，通常与恶意软件（如锁屏勒索、数据擦除、远程控制等）为了获取设备高级控制权有关。
- 证据：`dynamic_sandbox -> persistent_services -> device_policy: ["6: com.malmstein.yahnac"]`
- 建议：深入审查DEX代码中与`DeviceAdminReceiver`相关的实现，并在AndroidManifest.xml中查找相应的`BIND_DEVICE_ADMIN`权限和`android.app.device_admin`元数据声明，以定位恶意功能的具体代码实现。

### 6. 应用使用不安全的通用调试签名
- 规则：`DEEP_APK_STATIC_INSECURE_DEBUG_SIGNATURE`
- 严重级别：`high`
- 说明：该应用使用了标准的Android调试证书进行签名。这意味着任何人都可以使用相同的通用证书制作一个恶意更新版本，而系统会信任并安装此更新，从而导致应用被劫持或设备被植入恶意代码。动态沙箱已确认此应用能够被成功安装并运行，验证了此漏洞在实际环境中的风险。
- 证据：`certificate_sha256: 6fb8e48d5d73421aaaef921f9298d8d06e6ff510b08f56d84fff4354016edf9f (此为通用Android调试密钥哈希); certificate_subject: CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US`
- 建议：立即停止使用和分发此应用。对于开发者，必须使用唯一的私有证书对应用进行签名后再发布。对于用户，应仅从可信任的官方渠道下载应用。

### 7. 第三方 SDK 正常集成
- 规则：`DEEP_APK_BEHAVIOR_SDK_INTEGRATION`
- 严重级别：`low`
- 说明：应用在运行期间调用了 Firebase 相关服务，属于正常的应用统计与崩溃上报行为。
- 证据：`动态日志显示存在 com.google.firebase.iid.FirebaseInstanceIdService 及相关 Receiver 的初始化调用，未发现异常网络回连。`
- 建议：无需特殊处置，属于合规的 SDK 集成行为。

### 8. 权限使用合规
- 规则：`DEEP_APK_BEHAVIOR_PERMISSIONS_USAGE`
- 严重级别：`low`
- 说明：应用申请的权限（INTERNET, ACCESS_NETWORK_STATE 等）与其功能需求（新闻内容获取）匹配，未发现越权行为。
- 证据：`沙箱运行期间，应用仅在必要时通过网络获取数据，未尝试访问联系人、短信或地理位置等敏感隐私权限。`
- 建议：权限使用符合最小化原则。

### 9. 生命周期行为正常
- 规则：`DEEP_APK_BEHAVIOR_LIFECYCLE`
- 严重级别：`low`
- 说明：应用安装与启动流程符合 Android 标准规范，未发现隐藏的后台服务或自启动行为。
- 证据：`Logcat 显示应用启动后直接进入 NewsActivity，且在退出后进程被正常管理，未见异常驻留。`
- 建议：无异常，可正常使用。

### 10. 安装流程与完整性检查正常
- 规则：`DEEP_APK_INTEL_INSTALLATION_FLOW_NORMAL`
- 严重级别：`low`
- 说明：应用以标准流程成功安装并完成 dex 优化，未见异常拦截或校验失败，符合常规上架包的安装轨迹。
- 证据：`adb: "Performing Streamed Install\nSuccess"；logcat: "Integrity check passed for file:///data/app/vmdl681982653.tmp"；"DexInv: --- BEGIN ... base.apk ---" / "DexInv: --- END ... (success) ---"；"Running /apex/com.android.art/bin/dex2oat64 ..."`
- 建议：保留安装日志与 odex 生成记录作为基线证据；后续若怀疑篡改，需对比官方包的安装轨迹与文件哈希。

### 11. 应用成功启动并进入主界面
- 规则：`DEEP_APK_INTEL_ENTRY_ACTIVITY_LAUNCHED`
- 严重级别：`low`
- 说明：系统调度启动主入口 Activity（.stories.NewsActivity），进程创建正常，无崩溃回退，呈现为交互型前台应用而非纯后台常驻。
- 证据：`logcat: "START u0 {act=android.intent.action.MAIN ... cmp=com.malmstein.yahnac/.stories.NewsActivity}"；"Start proc 10730:com.malmstein.yahnac/u0a174 for next-top-activity"；dumpsys resolve_activity: "com.malmstein.yahnac/.stories.NewsActivity"`
- 建议：进行更长时段的人机/脚本化操作（浏览新闻、登录/评论）以覆盖更多路径和潜在动态加载点。

### 12. 运行期权限与能力集中在联网与唤醒
- 规则：`DEEP_APK_INTEL_RUNTIME_PERMISSIONS_OBSERVED`
- 严重级别：`low`
- 说明：沙箱期内仅观察到网络状态、Wi‑Fi 状态、联网与唤醒能力，未见联系人、短信、定位、存储等高敏权限的动态授予或使用迹象。
- 证据：`dumpsys granted_permissions: "ANDROID.PERMISSION.INTERNET; ANDROID.PERMISSION.ACCESS_NETWORK_STATE; ANDROID.PERMISSION.ACCESS_WIFI_STATE; ANDROID.PERMISSION.WAKE_LOCK"`
- 建议：后续以抓包/代理方式验证数据最小化与合规性，关注是否上传设备标识或行为数据。

### 13. 存在网络活动但缺乏可归属外联细节
- 规则：`DEEP_APK_INTEL_NETWORK_ACTIVITY_PRESENT_LOW_VISIBILITY`
- 严重级别：`low`
- 说明：短时运行内记录到 12 次网络命中，但仅为片段化标记，未解析出具体域名/IP 或业务接口，难以归因数据流向与内容类型。
- 证据：`dynamic_summary.network_hit_count=12；network_hits: ["settings.get.glo", "package.install", "base.apk", "com.android.art", "gle.android.gms", ...]`
- 建议：延长运行并开启全流量采集（pcap/DNS/HTTP(S) 代理），或在受控证书环境下中间人解密以还原目的域名与数据类型。

### 14. 与 Google Play 服务交互的运行期迹象
- 规则：`DEEP_APK_INTEL_GMS_INTERACTION_OBSERVED`
- 严重级别：`low`
- 说明：启动阶段出现 Google Play 服务相关日志，符合使用统计/测量或消息通道库的常见特征，但本次会话未见明确外联终端解析。
- 证据：`logcat: "W/gle.android.gms ... Reducing the number of considered missed Gc histogram windows ..."`
- 建议：若对隐私合规模块敏感，结合抓包核验是否启用 Analytics/FCM 等并评估数据上传范围。

### 15. dumpsys 出现持久化引用但无前台常驻或设备管理授权
- 规则：`DEEP_APK_INTEL_PERSISTENT_REFERENCES_NO_ADMIN`
- 严重级别：`low`
- 说明：系统服务中显示到该包的持久化引用记录，但通知重要性为 NONE，且会话中未见设备管理授权流程或前台常驻行为，疑似系统账务/安装后的临时登记。
- 证据：`persistent_services: {"device_policy": ["6: com.malmstein.yahnac"], "notification": ["... importance=NONE ..."]}`
- 建议：复核 manifest 是否存在 DeviceAdmin 组件或自启动广播；重启设备并拉起应用以确认是否存在开机自启/常驻。

### 16. 运行期未使用 SDK Sandbox
- 规则：`DEEP_APK_INTEL_SDK_SANDBOX_UNUSED`
- 严重级别：`low`
- 说明：系统报告本次会话未启用 SDK Sandbox，说明第三方 SDK 未通过沙箱化路径加载；对风险不构成直接加分或减分，仅为环境现状描述。
- 证据：`logcat: "SdkSandboxManager: No SDKs used. Skipping SDK data reconcilation for ... com.malmstein.yahnac"（出现 2 次）`
- 建议：如需更高隔离度，建议在后续版本评估启用 SDK Sandbox 或替换相关依赖。

### 17. 沙箱运行窗口较短可能低估行为面
- 规则：`DEEP_APK_INTEL_SHORT_RUNTIME_WINDOW`
- 严重级别：`low`
- 说明：本次动态会话仅运行约 12 秒、38 个事件，可能遗漏延时任务、用户驱动路径或后台队列行为。
- 证据：`dynamic_summary: runtime_window_seconds=12；event_count=38；launch_success=true`
- 建议：延长运行至 2–5 分钟以上并脚本化交互（滚动列表/登录/评论/分享），覆盖定时器与懒加载路径。

### 18. 动态沙箱安装与启动成功，未见即时拦截条件
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`low`
- 说明：样本在沙箱中可正常安装并成功拉起主入口 Activity，说明未触发安装即拦截、启动即崩溃或明显反沙箱阻断。
- 证据：`install_success=true; launch_success=true; resolve_activity=com.malmstein.yahnac/.stories.NewsActivity; START ... cmp=com.malmstein.yahnac/.stories.NewsActivity; pidof=10730`
- 建议：可暂不隔离安装；若业务场景允许，可继续观察运行行为并保留样本用于留痕比对。

### 19. 运行期网络活动存在，但未表现出高危外联特征
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`low`
- 说明：沙箱记录到少量网络命中，主要集中在安装、系统组件与应用自身标识，未见明确可疑 C2、域名集合或大规模外联。
- 证据：`network_hit_count=12; network_hits 包含 package.install、com.malmstein.yahnac、base.apk、base.odex、gle.android.gms 等；logcat 中未见明确恶意 URL/域名/异常下载痕迹`
- 建议：无需立即阻断分发；建议在更长时窗或联网可观测环境下补充复核，确认是否存在延迟外联或条件触发通信。

### 20. 存在驻留型系统服务/通知痕迹，建议关注长期行为
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`medium`
- 说明：dumpsys 显示有 persistent_services 线索，包括 device_policy 与 notification 条目，说明样本可能具备一定后台驻留或系统集成能力，虽未在短窗内演变为高危行为，但值得持续观察。
- 证据：`persistent_services.device_policy=["6: com.malmstein.yahnac"]; persistent_services.notification=["AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false"]`
- 建议：建议进行二次沙箱复核，延长观察窗口并检查前台/后台切换、通知、长连网络和定时任务是否出现异常。

### 21. 短时窗动态观察不足，结论需保留复核空间
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`medium`
- 说明：本次 runtime_window_seconds 仅 12 秒，event_count 38，足以确认可启动，但不足以覆盖延迟触发、用户交互触发、定时触发等行为链。
- 证据：`runtime_window_seconds=12; event_count=38; logcat_excerpt_count=320`
- 建议：建议保留样本留痕，并在需要时进行更长周期沙箱复测；如该 APK 将进入生产分发，应在灰度环境先行验证。

### 22. 未见反模拟器、混淆或动态加载迹象，降低即时恶意置信度
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`low`
- 说明：动态鲁棒性字段未发现反模拟器、混淆、反射或动态加载痕迹，这使得当前样本缺乏常见的规避分析特征。
- 证据：`anti_emulator_detected=false; obfuscation_detected=false; reflection_detected=false; dynamic_loading_detected=false; robustness_score=0.0`
- 建议：暂不阻断分发，但建议保留二进制样本与沙箱产物，便于后续与新版本进行差异比对。

### 23. 安装后仍有包更新/强停/优化痕迹，建议做版本来源核验
- 规则：`DEEP_APK_ADVICE_006`
- 严重级别：`low`
- 说明：日志显示该包经历了更新安装、dexopt 与系统包管理流程，表现为常规应用更新链路；结合签名与来源不可见，建议确认是否为可信发布源。
- 证据：`PackageManager: Update package com.malmstein.yahnac ... Retain data and using new; PackageDexOptimizer: Running dexopt ...; DexInv success`
- 建议：如来自非官方渠道，建议先沙箱复核再允许批量分发；如来自可信源，可放行但保留 SHA256 与证书指纹留痕。

### 24. 检测到 AOSP 调试测试证书签名
- 规则：`APK_DEBUG_TESTKEY_SIGNATURE`
- 严重级别：`medium`
- 说明：样本使用测试证书签名，指向非官方/调试构建，存在分发与更新链条被滥用的风险，但并不直接等同恶意行为。
- 证据：`META-INF/TESTKEY.SF, TESTKEY.RSA；certificate_subject/issuer=Android(android@android.com)；SHA-256=6fb8e48d5d73421a…016edf9f`
- 建议：仅信任与官方发布证书指纹一致的版本；生产分发必须使用发行签名并完成来源校验。

### 25. 权限集与新闻客户端预期一致
- 规则：`MANIFEST_PERMISSIONS_MINIMAL`
- 严重级别：`low`
- 说明：仅申请 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK 及 C2DM 相关自定义权限，未见高敏隐私权限。
- 证据：`AndroidManifest.xml permissions 共 6 项，无存储/定位/通讯录/SMS 等高敏权限`
- 建议：维持最小权限原则，变更权限时需重新评估。

### 26. Firebase/GMS 常规集成
- 规则：`GMS_FIREBASE_INTEGRATION`
- 严重级别：`low`
- 说明：服务与接收器包含 Firebase Crash/InstanceId 与 GMS 组件，属于常见统计/消息通道集成。
- 证据：`Services: AppMeasurementService, FirebaseCrash*, FirebaseInstanceIdService；Receivers: AppMeasurementReceiver, FirebaseInstanceIdReceiver`
- 建议：若对隐私合规敏感，建议配合抓包与政策披露核验数据最小化。

### 27. 动态出现 device_policy 引用但静态未声明设备管理
- 规则：`DEVICE_POLICY_REFERENCE_DISCREPANCY`
- 严重级别：`medium`
- 说明：短窗动态 dumpsys 显示 device_policy 对该包的引用，但 Manifest 无 DeviceAdmin 组件或相关权限，当前证据不足以认定设备管理滥用。
- 证据：`dumpsys persistent_services.device_policy=["6: com.malmstein.yahnac"]；Manifest 中无 BIND_DEVICE_ADMIN/DeviceAdminReceiver`
- 建议：延长动态观测并复核 Manifest/DEX；如后续观测到授权流程或锁屏/擦除等行为，再升级处置等级。

### 28. 字节码解析回退导致静态覆盖度受限
- 规则：`STATIC_COVERAGE_FALLBACK`
- 严重级别：`medium`
- 说明：工具解析回退，API 调用图为空，无法做方法级/调用图级研判。
- 证据：`graph_data.fallback_reason=androguard_unavailable_or_parse_failed；api_graph_node_count=0`
- 建议：更换工具链或离线反编译补齐代码级审计（smali/AST），并与官方源码/发行包对比。

### 29. 未发现本地库加载痕迹
- 规则：`NO_NATIVE_LIBS_OBSERVED`
- 严重级别：`low`
- 说明：样本不包含 .so 本地库，降低了 native 层隐匿面的可能性。
- 证据：`native_libraries: []`
- 建议：后续版本如新增本地库，需纳入额外审计。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5`）
本样本为 com.malmstein.yahnac（Yahnac，疑似 Hacker News 客户端）v1.3.1。基于离线静态证据（Manifest/权限/组件/签名/资源）为主、短窗动态线索为辅的研判结论如下：
1) 签名与来源：APK 使用 AOSP 调试测试证书（META-INF/TESTKEY.*，证书指纹 6fb8e48d…），强烈指向非官方/调试构建，存在供应链与分发可信度风险，但该迹象本身并不等同于“恶意”。建议以官方渠道证书指纹比对为准。
2) 权限与组件：Manifest 仅声明联网/网络状态/唤醒锁及 C2DM/FCM 自定义权限，共 6 项，未见存储/位置/通讯录/SMS 等高敏权限；Activities/Services/Receivers/Providers 与 Firebase/GMS 集成相符，整体与新闻阅读类应用预期一致，未见设备管理（DeviceAdmin）相关组件或权限。
3) 字节码与资源：未检出本地库与异常字符串特征；资源与布局多为常见 AndroidX/Design 组件。因字节码解析回退（androguard 失败），无法进行更细粒度代码级审计，静态覆盖度受限，本结论以离线静态证据链为主。
4) 动态佐证：短时（约 12 秒）沙箱仅观察到正常安装、拉起 NewsActivity、Firebase 初始化与少量系统相关网络命中，未见异常外联/常驻/越权行为。dumpsys 出现 device_policy 列表中对该包的引用，但 Manifest 不存在设备管理声明，且会话内未触发授权流程，倾向于环境侧登记/噪声，证据不足以证明设备管理滥用。
5) 仲裁与鲁棒性：仲裁器给出一致性中等（63），存在“静态高、行为低”的分歧提示并标注疑似反沙箱，但鲁棒性检测未见反模拟器/混淆/反射/动态加载（robustness_score=0），削弱了“反沙箱”推断的力度。
综合而言：功能与权限画像与新闻客户端相符，短窗动态无恶意行为；最大风险点在于调试签名与来源不可验证，属于分发链可信度问题而非明确恶意。当前定级为“低风险”，建议仅在验证来源与证书一致性后放行，生产分发需替换为发行签名并进行更长时窗动态复测。

### 静态分析员（模型：`gemini-2.5-pro`）
静态分析发现该应用使用了标准的Android调试证书进行签名，这是一个严重的安全漏洞，允许任何人创建并安装恶意更新。更关键的是，动态沙箱证据显示该应用注册了设备策略服务（设备管理器），此行为对于新闻阅读器应用极不正常，高度可疑。结合这两点，该应用极有可能是被植入后门的木马版本，旨在获取设备的高级控制权限，存在高安全风险。

### 行为分析员（模型：`gemini-2.5-flash`）
基于动态沙箱行为分析，该 APK 表现为正常的应用生命周期行为。沙箱运行期间，应用成功安装并启动主 Activity，未发现异常后台驻留、敏感数据窃取或未经授权的持久化行为。虽有设备策略管理相关痕迹，但未检测到恶意锁定或权限滥用，整体行为链符合新闻阅读类应用预期。

### 情报分析员（模型：`gpt-5`）
样本来源为临时路径，签名为 AOSP TESTKEY，像非官方/调试构建；动态窗口较短、网络命中碎片化，整体覆盖度有限。建议对照官方渠道与历史签名指纹核验，来源不一致时按潜在重打包拒绝；当前未见明确恶意行为，风险偏低但依赖来源与签名可信度。

### 处置建议员（模型：`gpt-5.4-mini`）
动态沙箱安装与启动成功、未见高危外联或明显恶意；但运行窗口仅 12 秒且出现持久化/通知相关痕迹，建议按“低风险可放行、保留样本留痕、视分发来源复核”的方式处置，并在更长时窗复测。


### 主持人最终总结
本样本为 com.malmstein.yahnac（Yahnac，疑似 Hacker News 客户端）v1.3.1。基于离线静态证据（Manifest/权限/组件/签名/资源）为主、短窗动态线索为辅的研判结论如下：
1) 签名与来源：APK 使用 AOSP 调试测试证书（META-INF/TESTKEY.*，证书指纹 6fb8e48d…），强烈指向非官方/调试构建，存在供应链与分发可信度风险，但该迹象本身并不等同于“恶意”。建议以官方渠道证书指纹比对为准。
2) 权限与组件：Manifest 仅声明联网/网络状态/唤醒锁及 C2DM/FCM 自定义权限，共 6 项，未见存储/位置/通讯录/SMS 等高敏权限；Activities/Services/Receivers/Providers 与 Firebase/GMS 集成相符，整体与新闻阅读类应用预期一致，未见设备管理（DeviceAdmin）相关组件或权限。
3) 字节码与资源：未检出本地库与异常字符串特征；资源与布局多为常见 AndroidX/Design 组件。因字节码解析回退（androguard 失败），无法进行更细粒度代码级审计，静态覆盖度受限，本结论以离线静态证据链为主。
4) 动态佐证：短时（约 12 秒）沙箱仅观察到正常安装、拉起 NewsActivity、Firebase 初始化与少量系统相关网络命中，未见异常外联/常驻/越权行为。dumpsys 出现 device_policy 列表中对该包的引用，但 Manifest 不存在设备管理声明，且会话内未触发授权流程，倾向于环境侧登记/噪声，证据不足以证明设备管理滥用。
5) 仲裁与鲁棒性：仲裁器给出一致性中等（63），存在“静态高、行为低”的分歧提示并标注疑似反沙箱，但鲁棒性检测未见反模拟器/混淆/反射/动态加载（robustness_score=0），削弱了“反沙箱”推断的力度。
综合而言：功能与权限画像与新闻客户端相符，短窗动态无恶意行为；最大风险点在于调试签名与来源不可验证，属于分发链可信度问题而非明确恶意。当前定级为“低风险”，建议仅在验证来源与证书一致性后放行，生产分发需替换为发行签名并进行更长时窗动态复测。


## 七、仲裁结果
- 一致性分数：`71`
- 一致性等级：`medium`
- 加权置信度：`18`
- 疑似污染源：static, behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 43 分
  - static-intelligence 差异 0 分
  - behavior-intelligence 差异 43 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
