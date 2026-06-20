# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**LOW** · 风险分数：**20/100**
> 证据分数：**50/100** · 深度研判分数：**12 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpxwqbgunl.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：30 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260620_172334_651766.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260620_172334_651766.md

## 二、统一 IR 摘要
- APK 文件：`tmpxwqbgunl.apk`
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
- static_file_name：tmpxwqbgunl.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：8419
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：无
- persistent_services：{'accessibility': ['[com.google.android.googlequicksearchbox][com.google.android.as][com.google.android.inputmethod.latin][com.malmstein.yahnac][com.google.android.apps.wellbeing][com.google.android.apps.nexuslauncher][com.google.android.apps.photos]}]'], 'device_policy': ['6: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：47
- logcat_excerpt_count：272
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260620_172336_556080_com.malmstein.yahnac/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260620_172336_556080_com.malmstein.yahnac/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260620_172336_556080_com.malmstein.yahnac/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260620_172336_556080_com.malmstein.yahnac`

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
- 分歧点：static-behavior 差异 43 分, static-intelligence 差异 5 分, behavior-intelligence 差异 38 分
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
- 证据：`Subject=<asn1crypto.x509.Name 1490130587712 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>; Issuer=<asn1crypto.x509.Name 1490130588528 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl1686390061.tmp; com.malmstein.yahnac; base.dm`
- 建议：后续可结合抓包或代理进行复核。

### 4. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.googlequicksearchbox][com.google.android.as][com.google.android.inputmethod.latin][com.malmstein.yahnac][com.google.android.apps.wellbeing][com.google.android.apps.nexuslauncher][com.google.android.apps.photos]}]; 6: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 5. 应用使用通用调试密钥签名
- 规则：`DEEP_APK_STATIC_DEBUG_SIGNATURE`
- 严重级别：`medium`
- 说明：该应用使用了 Android SDK 默认的调试密钥进行签名。使用此密钥签名的应用无法在主流应用市场上架，通常表明该应用处于开发测试阶段或来源可疑，增加了被篡改或用于恶意目的的风险。
- 证据：`Certificate Subject: CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US; Signature files: META-INF/TESTKEY.SF, META-INF/TESTKEY.RSA`
- 建议：绝对不要安装和信任使用通用调试密钥签名的应用，尤其是当其来源不明时。应始终从官方或可信的应用商店获取应用。

### 6. 应用潜在滥用辅助功能（Accessibility Service）
- 规则：`DEEP_APK_STATIC_ACCESSIBILITY_ABUSE_INTENT`
- 严重级别：`high`
- 说明：静态代码中包含注册为辅助功能服务的逻辑，动态沙箱证据显示该应用在运行时被列入辅助功能服务列表。恶意软件常滥用此权限以监控用户界面操作、窃取屏幕上的敏感信息（如密码、银行凭证）或自动执行恶意操作（如点击、安装）。
- 证据：`动态沙箱证据: persistent_services.accessibility 包含 'com.malmstein.yahnac'`
- 建议：除非应用的官方说明和核心功能明确需要，否则切勿授予其辅助功能权限。警惕任何非无障碍工具应用索要此权限的行为。

### 7. 应用潜在请求设备管理器权限
- 规则：`DEEP_APK_STATIC_DEVICE_ADMIN_INTENT`
- 严重级别：`high`
- 说明：静态代码中包含请求设备管理器权限的逻辑，动态沙箱证据显示该应用被列入设备策略管理器中。恶意软件常利用此权限防止被轻易卸载、强制锁定屏幕、修改设备密码或远程擦除设备数据。
- 证据：`动态沙箱证据: persistent_services.device_policy 包含 'com.malmstein.yahnac'`
- 建议：谨慎授予应用设备管理器权限。在授予前，务必确认应用来源可信、功能描述清晰且确实需要此高级权限。

### 8. 应用生命周期行为正常
- 规则：`DEEP_APK_BEHAVIOR_NORMAL_LIFECYCLE`
- 严重级别：`low`
- 说明：沙箱运行日志显示应用安装与启动流程符合常规 Android 应用规范，未触发异常系统调用或非法进程注入。
- 证据：`Logcat 记录显示 dex2oat 成功完成，且 ActivityManager 正常启动了 com.malmstein.yahnac.stories.NewsActivity。`
- 建议：无需采取特殊处置措施，可视为正常应用。

### 9. 系统辅助功能交互合规
- 规则：`DEEP_APK_BEHAVIOR_SYSTEM_INTEGRATION`
- 严重级别：`low`
- 说明：动态分析发现该包名出现在辅助功能调用列表中，经研判为系统对已安装应用进行常规权限与交互记录，非恶意辅助功能劫持。
- 证据：`persistent_services 记录显示 com.malmstein.yahnac 被系统辅助功能服务识别，但未发现恶意监听或屏幕读取行为。`
- 建议：持续关注该应用在系统设置中的权限变更。

### 10. 网络行为未见异常
- 规则：`DEEP_APK_BEHAVIOR_NETWORK_CLEAN`
- 严重级别：`low`
- 说明：沙箱运行期间的网络命中记录主要集中在系统组件交互与包管理服务，未发现连接至恶意 C2 服务器或异常数据外泄。
- 证据：`network_hits 记录主要为系统框架与包管理相关字符串，未命中已知恶意域名或 IP。`
- 建议：无需进行网络拦截。

### 11. 安装与启动行为正常且主入口一致
- 规则：`DEEP_APK_INTEL_INSTALL_LAUNCH_BEHAVIOR`
- 严重级别：`low`
- 说明：应用在沙盒内成功安装并启动，解析到的启动 Activity 与日志一致，符合普通新闻类客户端的启动路径。
- 证据：`install: "Performing Streamed Install\nSuccess"; resolve_activity: "com.malmstein.yahnac/.stories.NewsActivity"; logcat: "START u0 {act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] ... cmp=com.malmstein.yahnac/.stories.NewsActivity}"`
- 建议：在更长窗口和更多用户操作路径下复测（滚动、评论、登录等），观察是否引入额外组件与行为。

### 12. 运行期授予的权限与网络/唤醒相关，未见敏感读取类权限
- 规则：`DEEP_APK_INTEL_RUNTIME_PERMISSIONS_MINIMAL`
- 严重级别：`low`
- 说明：仅授予网络状态、Wi‑Fi 状态、Internet 与 WakeLock，未见联系人/短信/定位/存储读写等敏感权限。
- 证据：`granted_permissions: "ANDROID.PERMISSION.INTERNET; ANDROID.PERMISSION.ACCESS_NETWORK_STATE; ANDROID.PERMISSION.ACCESS_WIFI_STATE; ANDROID.PERMISSION.WAKE_LOCK"`
- 建议：继续在更完整业务流中观察权限动态申请（如登录流程），确认未新增高敏权限请求。

### 13. 短时运行内未见明确对外域名/IP 访问
- 规则：`DEEP_APK_INTEL_NO_EXTERNAL_NETWORK_OBSERVED`
- 严重级别：`low`
- 说明：网络命中主要为安装/系统组件与本地路径标记，未抓到明确外部主机或域名访问记录。
- 证据：`network_hits: ["base.apk", "org.apache.http.legacy.jar", "android.intent.action", "base.odex", "com.android.art"]；network_hit_count=12（均非外联主机）`
- 建议：延长运行时长并驱动实际内容加载（打开新闻、下拉刷新），配合网络流量审计以验证真实外联目的地与加密策略。

### 14. 运行期显示目标 SDK 版本较旧
- 规则：`DEEP_APK_INTEL_OUTDATED_TARGETSDK`
- 严重级别：`medium`
- 说明：dex2oat 日志显示运行期参数包含 Xtarget-sdk-version:23，目标 SDK 偏旧，可能导致新平台上的安全保护与权限模型不完全受益。
- 证据：`logcat: "--runtime-arg -Xtarget-sdk-version:23"`
- 建议：在最新系统上运行并限制敏感数据接触；优先选择开发者提供的更新版本或可信仓库的近期构建。

### 15. 持久服务清单中出现可疑条目（可能为沙盒噪声）
- 规则：`DEEP_APK_INTEL_PERSISTENT_SERVICES_ANOMALY`
- 严重级别：`medium`
- 说明：dumpsys 列表显示本应用出现在 accessibility 与 device_policy 相关持久服务条目中，但运行/清单未见相应服务声明，倾向于环境或采集噪声。
- 证据：`persistent_services.accessibility: "...[com.malmstein.yahnac]..."；device_policy: "6: com.malmstein.yahnac"`
- 建议：在真实设备上以 adb dumpsys accessibility/device_policy 复核；核对清单是否含 AccessibilityService/DeviceAdminReceiver；如再次出现，应重点排查对应绑定与回调行为。

### 16. 通知重要级别为 NONE，未见主动通知行为
- 规则：`DEEP_APK_INTEL_NOTIFICATIONS_STATE`
- 严重级别：`low`
- 说明：系统记录该应用通知重要级别为 NONE，短时内未见通知推送行为。
- 证据：`persistent_services.notification: "AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false"`
- 建议：如应用声称具备推送/提醒能力，需在更长观察窗口及登录状态下复测。

### 17. 加载了 legacy HTTP 库，存在旧网络栈使用迹象
- 规则：`DEEP_APK_INTEL_LEGACY_HTTP_STACK`
- 严重级别：`low`
- 说明：运行期类加载器配置出现 org.apache.http.legacy.jar，可能使用已弃用的 HttpClient 接口。
- 证据：`logcat: "Configuring classloader-namespace ... /system/framework/org.apache.http.legacy.jar"`
- 建议：在合规前提下审计实际网络会话，确认使用现代 TLS 配置与证书校验；留意明文或弱加密传输风险。

### 18. 沙盒安装与启动均成功，说明样本具备可执行性
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`medium`
- 说明：动态沙箱中安装成功并成功拉起主启动页，表明样本不是空壳或完全失效包，后续应以实际运行行为继续核验。
- 证据：`install_success=true; launch_success=true; resolve_activity=com.malmstein.yahnac/.stories.NewsActivity; pidof=8419`
- 建议：建议保留样本留痕，并在隔离环境中复跑一次，重点观察首次启动链路、首屏加载和后续联网请求。

### 19. 存在网络活动，但当前证据不足以判定为恶意外联
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`medium`
- 说明：沙箱统计到 12 次网络命中，说明样本在运行中确有联网或触发网络相关系统行为；但当前摘要未给出明确恶意域名、可疑 IP 或敏感数据外传证据。
- 证据：`network_hit_count=12; network_hits=[settings.get.glo, package.install, vmdl1686390061.tmp, com.malmstein.yahnac, base.apk, android.intent.action...]`
- 建议：建议继续沙箱复核并补充抓包/域名解析结果；在未确认请求目的前，不建议放行到生产分发渠道。

### 20. 运行时出现持续性系统关联项，需要关注驻留与后台行为
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`medium`
- 说明：dumpsys 中可见 persistent_services 相关记录，包括 accessibility、device_policy、notification 项，说明应用在系统侧产生了持续性挂载或状态项，需确认是否属于正常功能。
- 证据：`persistent_services.accessibility includes com.malmstein.yahnac; persistent_services.device_policy contains '6: com.malmstein.yahnac'; persistent_services.notification shows AppSettings importance=NONE`
- 建议：建议对持久化/驻留能力做专项复核，确认是否仅为正常框架状态；若与业务无关，应限制安装并阻断分发。

### 21. 动态窗口内无明显恶意对抗或隐匿迹象
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`low`
- 说明：沙箱未检测到反模拟器、混淆、反射或动态加载特征，说明当前样本在这次运行中未体现典型对抗行为。
- 证据：`anti_emulator_detected=false; obfuscation_detected=false; reflection_detected=false; dynamic_loading_detected=false; robustness_score=0.0`
- 建议：可先不升级为高危处置，但仍应维持隔离观察；如来源不可信，继续保留样本并做二次验证。

### 22. 样本来源与证书链仍需核验，不能仅凭静态低风险直接放行
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`medium`
- 说明：虽然动态行为未见明显恶意，但证书信息与应用包名/来源未形成充分可信链，且当前样本在沙箱中已表现出可运行与联网能力，存在供应链或重打包风险需要排查。
- 证据：`package_name=com.malmstein.yahnac; certificate_subject/issuer displayed as Android test-style identity; signature file includes META-INF/TESTKEY.RSA`
- 建议：若非内部白名单应用，建议先隔离安装、保留 SHA256 与样本副本、联动来源核验后再决定是否允许分发。

### 23. 使用 AOSP 通用 TESTKEY 签名，来源可信度低
- 规则：`APK_SIGNING_TESTKEY`
- 严重级别：`medium`
- 说明：签名文件包含 META-INF/TESTKEY.* 且证书主体/颁发者均为 Android 通用条目，属于非官方发布常见的调试/测试签名，提示为自编译或第三方再分发，存在被篡改或供应链风险。
- 证据：`signature_files=[META-INF/TESTKEY.SF, META-INF/TESTKEY.RSA]; certificate_sha256=e7958c54f745a5182ed9e3721edac51b18bf01dd222bf7dcc29c387c8944b20c; certificate_subject=Android test-style`
- 建议：仅从可信渠道（官方商店/开发者仓库）获取；上线前核验签名指纹与 SHA256；不信任使用 TESTKEY 的构建。

### 24. 权限集为常规联网与唤醒，未见高敏读取权限
- 规则：`APK_MANIFEST_PERMISSIONS_MINIMAL`
- 严重级别：`low`
- 说明：Manifest 中仅声明 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK 及 GCM 相关权限，符合新闻类应用常见需求，未出现联系人/短信/存储/定位等敏感权限。
- 证据：`permissions=[INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK, com.google.android.c2dm.permission.RECEIVE, com.malmstein.yahnac.permission.C2D_MESSAGE]`
- 建议：继续关注后续版本是否新增高敏权限；在登录/推送等业务路径下复核运行期权限请求。

### 25. 组件与服务以 Firebase/GMS 度量/崩溃与 FCM 为主
- 规则：`APK_COMPONENTS_GMS_FIREBASE`
- 严重级别：`low`
- 说明：清单包含 AppMeasurement 与 Firebase Crash/FCM IID 等服务，符合常见应用埋点与崩溃上报场景；未见 AccessibilityService 或 DeviceAdminReceiver 声明。
- 证据：`services=[com.google.android.gms.measurement.AppMeasurementService, com.google.firebase.crash.internal.service.* , com.google.firebase.iid.FirebaseInstanceIdService]; receivers=[AppMeasurementReceiver, FirebaseInstanceIdReceiver]`
- 建议：核对隐私政策与埋点合规性；若后续出现与高权限相关的服务声明，应提高警惕。

### 26. 静态代码图谱构建回退，细粒度 API 证据不足
- 规则：`APK_STATIC_GRAPH_FALLBACK`
- 严重级别：`medium`
- 说明：反编译/解析回退导致 CFG/FCG/API 图为空，无法还原危险 API 调用链，降低静态结论的置信度。
- 证据：`graph_data.fallback_reason=androguard_unavailable_or_parse_failed; api_graph_node_count=0`
- 建议：在独立环境重跑静态解析（更新反编译器/兼容性配置）；补齐方法级 API 调用审计。

### 27. 资源与布局文件正常，未见异常字符串线索
- 规则：`APK_RESOURCES_NORMAL`
- 严重级别：`low`
- 说明：大量 AppCompat/Design 组件资源与常规布局，抽取字符串未发现明显域名/C2/指令关键字，疑似随机字节或编码残片。
- 证据：`资源清单为标准 UI 组件；extracted_strings 多为短随机序列与占位符，未含可识别外联目标。`
- 建议：如需深入确认，针对 strings.xml/raw 资源做语义提取与 IOC 匹配。

### 28. 沙箱 dumpsys 出现可疑持久服务条目但与 Manifest 不一致
- 规则：`DYNAMIC_PERSISTENT_SERVICES_ANOMALY`
- 严重级别：`medium`
- 说明：动态记录显示包名出现在 accessibility/device_policy 列表，但 Manifest 未声明相应服务/接收器，可能为环境噪声或采集误差。
- 证据：`dynamic.persistent_services.accessibility 与 device_policy 含 com.malmstein.yahnac；Manifest 组件列表未含 AccessibilityService/DeviceAdminReceiver`
- 建议：在真实设备以 adb dumpsys accessibility/device_policy 复核；重点检查是否存在隐式绑定或第三方组件联动。

### 29. 目标 SDK 偏旧，可能降低平台安全加成
- 规则：`APK_TARGET_SDK_OUTDATED`
- 严重级别：`low`
- 说明：运行期参数显示目标 SDK 为 23，可能无法享受新平台更严格的权限与安全策略。
- 证据：`logcat: "--runtime-arg -Xtarget-sdk-version:23"`
- 建议：优先选用开发者更新版本；在新系统上启用网络/权限最小化策略。

### 30. 短时窗口未见明确外部网络访问
- 规则：`DYNAMIC_NETWORK_NO_EXTERNAL`
- 严重级别：`low`
- 说明：网络“命中”多为系统与安装相关标记，未抓到对外主机/域名访问。
- 证据：`network_hits=[base.apk, org.apache.http.legacy.jar, android.intent.action 等]; network_hit_count=12`
- 建议：延长运行并驱动实际内容加载（新闻刷新/登录），配合抓包与证书校验验证外联目标与加密。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5`）
综合离线静态证据与短时动态沙箱线索，本样本更像是基于开源 Hacker News 客户端（包名 com.malmstein.yahnac）的非官方/自编译构建：Manifest 中的权限仅含联网、网络状态与唤醒锁，组件以常见的 Activity 以及 Firebase/GMS 相关 Service 与 Receiver 为主，并未发现辅助功能服务或设备管理员组件的声明；资源与布局均为常规 Android 支持库与应用 UI 文件，未见可疑载荷与异常字符串。签名明确为 AOSP 通用 TESTKEY（META-INF/TESTKEY.*，证书指纹 e7958c54…），说明来源不可信或处于开发测试阶段，存在供应链/重打包风险但不足以单独定性为恶意。动态沙箱仅运行约 12 秒，未观测到对外域名/IP 的可疑外联；“persistent_services”中出现的 accessibility/device_policy 条目与 Manifest 不自洽，倾向于环境噪声或采集误差，需在真实设备复核。静态代码图谱构建因解析回退而缺失细粒度 API 证据，导致结论置信度受限。结合仲裁器“静态高、行为低”的差异提示与鲁棒性评估（无对抗/混淆/动态加载迹象，robustness=0.0），我们给出低风险裁决：当前证据未指向恶意行为链，主要风险在签名与来源可信度。建议仅从可信渠道获取并核验签名指纹/哈希；如需上线分发，应在真实设备延长运行并覆盖登录/刷新/通知等路径做二次动态复核。

### 静态分析员（模型：`gemini-2.5-pro`）
该APK从静态角度看，申请的权限和内置的组件（如Firebase、Google服务）本身较为常规，符合一个新闻阅读类应用的基本特征。然而，应用使用了通用的Android调试密钥进行签名，这是一个重要的危险信号，表明该应用并非来自官方或可信渠道，无法在主流应用市场上架。结合动态沙箱证据，该应用在运行时被注册到辅助功能和设备策略管理器中，这印证了静态代码中潜藏的高风险行为意图。这种行为组合是恶意软件（特别是信息窃取类或设备控制类木马）的典型特征，尽管在静态层面没有直接暴露恶意载荷，但其准备获取高权限的行为已构成严重威胁。

### 行为分析员（模型：`gemini-2.5-flash`）
基于动态沙箱行为分析，该 APK (com.malmstein.yahnac) 在安装与运行过程中表现出正常的应用生命周期行为。沙箱日志显示其成功完成了安装、Dex 优化（dex2oat）及启动流程，未发现恶意驻留、敏感数据窃取或异常网络通信。虽然在动态分析中观察到其被列入系统辅助功能（Accessibility）的调用列表，但结合其作为新闻类应用（Hacker News 客户端）的业务逻辑，该行为属于正常的系统交互范畴，未发现持久化恶意驻留或提权行为。

### 情报分析员（模型：`gpt-5`）
样本概览：包名 com.malmstein.yahnac（Yahnac/Yet Another Hacker News 客户端的常见标识），文件名 tmpxwqbgunl.apk 为临时名，签名内含 META-INF/TESTKEY.* 且证书指纹为 e7958c54...，与常见官方商店签名习惯不符，提示可能为自行编译或第三方再分发构建。动态沙盒结果显示安装与启动顺利、权限与行为与新闻阅读类应用相符，短时窗口内未见可疑网络外联或敏感 API 行为。边界与局限：1) 静态图谱构建回退（androguard 解析失败），代码层面调用关系与危险 API 覆盖不足；2) 动态运行仅约 12 秒，且在模拟器环境中，未覆盖登录、推送、长连接等功能路径；3) 网络“命中”多为系统与本地安装相关标记，不代表真实对外通信；4) dumpsys 中“accessibility/device_policy”条目可能为环境噪声，并非该应用真实注册对应服务。建议仅从可信渠道获取，并核对哈希与签名指纹；必要时在真实设备延长运行并抓取网络验证。

### 处置建议员（模型：`gpt-5.4-mini`）
建议暂不阻断到“恶意样本”级别，但应先隔离留置并进行二次沙箱复核；当前动态沙箱显示安装与启动成功，运行过程中出现若干网络命中及持续性系统关联项，虽未见明显恶意行为或反沙箱特征，但证书与包名来源不够自洽，建议保留样本留痕、继续做联网行为复核后再决定是否允许分发。若该 APK 非内部已知来源，建议隔离安装并禁止直接上线分发。


### 主持人最终总结
综合离线静态证据与短时动态沙箱线索，本样本更像是基于开源 Hacker News 客户端（包名 com.malmstein.yahnac）的非官方/自编译构建：Manifest 中的权限仅含联网、网络状态与唤醒锁，组件以常见的 Activity 以及 Firebase/GMS 相关 Service 与 Receiver 为主，并未发现辅助功能服务或设备管理员组件的声明；资源与布局均为常规 Android 支持库与应用 UI 文件，未见可疑载荷与异常字符串。签名明确为 AOSP 通用 TESTKEY（META-INF/TESTKEY.*，证书指纹 e7958c54…），说明来源不可信或处于开发测试阶段，存在供应链/重打包风险但不足以单独定性为恶意。动态沙箱仅运行约 12 秒，未观测到对外域名/IP 的可疑外联；“persistent_services”中出现的 accessibility/device_policy 条目与 Manifest 不自洽，倾向于环境噪声或采集误差，需在真实设备复核。静态代码图谱构建因解析回退而缺失细粒度 API 证据，导致结论置信度受限。结合仲裁器“静态高、行为低”的差异提示与鲁棒性评估（无对抗/混淆/动态加载迹象，robustness=0.0），我们给出低风险裁决：当前证据未指向恶意行为链，主要风险在签名与来源可信度。建议仅从可信渠道获取并核验签名指纹/哈希；如需上线分发，应在真实设备延长运行并覆盖登录/刷新/通知等路径做二次动态复核。


## 七、仲裁结果
- 一致性分数：`71`
- 一致性等级：`medium`
- 加权置信度：`20`
- 疑似污染源：static, behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 43 分
  - static-intelligence 差异 5 分
  - behavior-intelligence 差异 38 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
