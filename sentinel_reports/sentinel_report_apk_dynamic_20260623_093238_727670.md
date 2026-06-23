# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**HIGH** · 风险分数：**61/100**
> 证据分数：**70/100** · 深度研判分数：**94 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpa1msxzg_.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：26 条
- 高危证据：14 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260623_092825_528535.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260623_092825_528535.md

## 二、统一 IR 摘要
- APK 文件：`tmpa1msxzg_.apk`
- 包名：`com.mytelecomapp.topup`
- 版本名：`1.0`
- 版本号：`1`
- SHA256：`ea422e231fa17116d7a7add97bd1a93770792a6c08f9e696624a78421d6c728f`
- 大小：`36600142` 字节
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

## 四点一、APK 动态沙箱摘要
- device_id：emulator-5554
- package_name：com.mytelecomapp.topup
- static_file_name：tmpa1msxzg_.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.mytelecomapp.topup/.SplashActivity
- pidof：7938
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk, ./product/app/talkback/talkback.apk, ./product/app/GoogleTTS/GoogleTTS.apk, ./product/app/Photos/Photos.apk, ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk, ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk, ./product/app/PixelThemesStub/PixelThemesStub.apk, ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk, ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk, ./product/app/GoogleContacts/GoogleContacts.apk, ./product/app/Drive/Drive.apk, ./product/app/LatinIMEGooglePrebuilt/LatinIMEGooglePrebuilt.apk, ./product/app/Camera2/lib/x86_64/libjni_tinyplanet.so, ./product/app/Camera2/lib/x86_64/libjni_jpegutil.so, ./product/app/Camera2/Camera2.apk, ./product/app/WallpapersBReel2018/lib/x86_64/libgdx.so, ./product/app/WallpapersBReel2018/lib/x86_64/libwallpapers-breel-2018-jni.so, ./product/app/WallpapersBReel2018/WallpapersBReel2018.apk, ./product/app/YouTube/YouTube.apk, ./product/app/MarkupGoogle/MarkupGoogle.apk
- persistent_services：{'accessibility': ['[com.google.android.contacts][com.mytelecomapp.topup][com.google.android.googlequicksearchbox][com.google.android.youtube][com.google.android.apps.wellbeing][com.google.android.apps.messaging][com.google.android.settings.intelligence][com.google.android.calendar][android, com.android.server.telecom, com.android.emulator.multidisplay, com.android.providers.settings, com.android.inputdevices, com.android.settings, com.android.location.fused, com.android.keychain, com.android.localtransport, com.android.dynsystem, com.android.wallpaperbackup][com.google.android.inputmethod.latin][com.google.android.apps.maps][com.google.android.deskclock][com.google.android.apps.nexuslauncher][com.google.android.apps.youtube.music][com.google.android.as][com.google.android.apps.photos]}]'], 'device_policy': ['2: com.mytelecomapp.topup'], 'notification': ['AppSettings: com.mytelecomapp.topup (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：37
- logcat_excerpt_count：260
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260623_092832_699612_com.mytelecomapp.topup/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260623_092832_699612_com.mytelecomapp.topup/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260623_092832_699612_com.mytelecomapp.topup/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260623_092832_699612_com.mytelecomapp.topup`
- ui_trace_dir：`G:/project/code/information/apk_dynamic/20260623_092832_699612_com.mytelecomapp.topup/ui_trace`
- ui_trace_paths：`['G:/project/code/information/apk_dynamic/20260623_092832_699612_com.mytelecomapp.topup/ui_trace/com.mytelecomapp.topup_launch_20260623_092832_703611.png', 'G:/project/code/information/apk_dynamic/20260623_092832_699612_com.mytelecomapp.topup/ui_trace/com.mytelecomapp.topup_evidence_20260623_092833_455564.png']`

## 四点二、图结构分析
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`138942`
- CFG 边数：`88250`
- FCG 节点数：`25695`
- FCG 边数：`75736`
- FCG 密度：`0.0001`
- 全图密度参考值：`0.0000`
- 指标释义：CFG 节点/边表示函数内部控制流规模；FCG 节点/边表示函数调用关系规模；FCG 密度越高，说明函数间调用越紧密。
- API 调用图节点数：`17`
- API 调用图边数：`203349`
- API 总调用数：`203349`
- 敏感 API 调用分布：Ljava/lang/reflect/Method;->invoke:106197, Ljava/lang/reflect/Field;->get:67995, Ldalvik/system/DexClassLoader;-><init>:20448, Landroid/net/Uri;->parse:5489, Ljava/lang/reflect/Field;->set:1124, Ljava/lang/Runtime;->exec:852, Landroid/provider/Settings$Secure;->getString:609, Ljava/net/HttpURLConnection;->connect:524, Ljava/lang/System;->loadLibrary:44, Landroid/content/Intent;->setPackage:19, Ljava/net/URL;->openConnection:14, Landroid/app/PendingIntent;->getActivity:9
- API 调用明细：
  - `Ljava/lang/reflect/Method;->invoke`：106197
  - `Ljava/lang/reflect/Field;->get`：67995
  - `Ldalvik/system/DexClassLoader;-><init>`：20448
  - `Landroid/net/Uri;->parse`：5489
  - `Ljava/lang/reflect/Field;->set`：1124
  - `Ljava/lang/Runtime;->exec`：852
  - `Landroid/provider/Settings$Secure;->getString`：609
  - `Ljava/net/HttpURLConnection;->connect`：524
  - `Ljava/lang/System;->loadLibrary`：44
  - `Landroid/content/Intent;->setPackage`：19
  - `Ljava/net/URL;->openConnection`：14
  - `Landroid/app/PendingIntent;->getActivity`：9
  - `Ljava/lang/Class;->forName`：8
  - `Ljava/lang/ClassLoader;->loadClass`：8
  - `Landroid/telephony/TelephonyManager;->getDeviceId`：5
  - `Landroid/location/LocationManager;->getLastKnownLocation`：2
  - `Ljavax/crypto/Cipher;->doFinal`：2

## 四点三、一致性验证
> **🔍 一致性分析说明**：仲裁器通过比较静态/行为/情报三方的评分差异判断结论一致性。
> 一致性越高，证据链越稳固；一致性低时需重点关注被标记的「疑似污染」模块。

- 一致性分数：`73`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 0 分, static-intelligence 差异 40 分, behavior-intelligence 差异 40 分
- 被污染模块：static, behavior, intelligence

## 四点四、鲁棒性分析
> **🛡️ 鲁棒性分析说明**：检测 APK 是否使用了防沙箱、混淆、反射、动态加载等对抗技术。
> 鲁棒性分数越高，说明样本越可能使用了规避分析的手段；分数越低，表示样本相对透明。

- 对抗技术：无
- 鲁棒性分数：`0.0`
- 抗干扰能力评估：**弱**

## 六、风险证据
### 1. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。
- 证据：`dex: classes.dex; manifest: AndroidManifest.xml; resource: res/-1.xml; resource: res/-5.xml; resource: res/-7.xml; resource: res/-8.xml; resource: res/-81.xml; resource: res/-B.xml; resource: res/-Q.xml; resource: res/-b.xml; resource: res/-n.xml; resource: res/-t.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 存在敏感权限请求
- 规则：`APK_SUSPICIOUS_PERMISSION`
- 严重级别：`high`
- 说明：安装包请求了短信、联系人、录音、安装或辅助功能等高敏权限。
- 证据：`android.permission.CAMERA`
- 建议：确认权限是否与业务功能一致，避免授予不必要权限。

### 3. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2647146277136 b'0d1\x120\x10\x06\x03U\x04\x03\x0c\tecarebd281\x120\x10\x06\x03U\x04\x0b\x0c\tecarebd281\x120\x10\x06\x03U\x04\n\x0c\tecarebd281\x120\x10\x06\x03U\x04\x07\x0c\tecarebd281\x120\x10\x06\x03U\x04\x08\x0c\tecarebd28'>; Issuer=<asn1crypto.x509.Name 2647146277280 b'0d1\x120\x10\x06\x03U\x04\x03\x0c\tecarebd281\x120\x10\x06\x03U\x04\x0b\x0c\tecarebd281\x120\x10\x06\x03U\x04\n\x0c\tecarebd281\x120\x10\x06\x03U\x04\x07\x0c\tecarebd281\x120\x10\x06\x03U\x04\x08\x0c\tecarebd28'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; com.google.android.contacts; com.google.android.apps.contacts.shortcut.ShortcutJobService; vmdl518183953.tmp`
- 建议：后续可结合抓包或代理进行复核。

### 5. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.contacts][com.mytelecomapp.topup][com.google.android.googlequicksearchbox][com.google.android.youtube][com.google.android.apps.wellbeing][com.google.android.apps.messaging][com.google.android.settings.intelligence][com.google.android.calendar][android, com.android.server.telecom, com.android.emulator.multidisplay, com.android.providers.settings, com.android.inputdevices, com.android.settings, com.android.location.fused, com.android.keychain, com.android.localtransport, com.android.dynsystem, com.android.wallpaperbackup][com.google.android.inputmethod.latin][com.google.android.apps.maps][com.google.android.deskclock][com.google.android.apps.nexuslauncher][com.google.android.apps.youtube.music][com.google.android.as][com.google.android.apps.photos]}]; 2: com.mytelecomapp.topup; AppSettings: com.mytelecomapp.topup (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 6. 动态代码加载（DCL）
- 规则：`DEEP_APK_STATIC_DCL`
- 严重级别：`critical`
- 说明：应用在运行时通过 DexClassLoader 加载额外的 DEX 文件。这是一种常见恶意软件技术，用于隐藏恶意代码、绕过静态检测以及实现模块化更新。
- 证据：`API 调用图分析显示存在大量（20,448 次）对 `Ldalvik/system/DexClassLoader;-><init>` 的调用。`
- 建议：重点分析该 APK 可能从网络下载或从自身资产释放的 DEX/JAR/APK 文件，以确定其最终加载的恶意负载。

### 7. 潜在的设备管理器权限请求
- 规则：`DEEP_APK_STATIC_DEVICE_ADMIN_INTENT`
- 严重级别：`critical`
- 说明：应用尝试注册为设备策略服务（Device Policy Service），这通常是为了申请设备管理器（Device Admin）权限。一旦用户授予此权限，应用将获得锁屏、擦除数据等高级系统控制能力，且难以被卸载。
- 证据：`动态沙箱证据显示，该应用在运行时被记录在持久化服务 `device_policy` 列表中：`2: com.mytelecomapp.topup`。这印证了其 Manifest 中存在请求绑定设备管理器权限的 Receiver 组件。`
- 建议：切勿授予此应用设备管理器权限。检查 Manifest 文件中声明 `android.permission.BIND_DEVICE_ADMIN` 权限的 `receiver` 组件，并追踪其实现代码。

### 8. 滥用反射机制
- 规则：`DEEP_APK_STATIC_REFLECTION_ABUSE`
- 严重级别：`high`
- 说明：应用极度频繁地使用 Java 反射 API（Method.invoke, Field.get），这通常用于动态调用隐藏或加密的函数，以逃避静态分析和检测。
- 证据：`API 调用图分析显示存在超高频次的反射调用：`Ljava/lang/reflect/Method;->invoke` (106,197 次) 和 `Ljava/lang/reflect/Field;->get` (67,995 次)。`
- 建议：结合动态调试或插桩技术，在运行时捕获反射调用的实际目标和参数，以揭示其真实行为。

### 9. 执行高风险系统命令
- 规则：`DEEP_APK_STATIC_RUNTIME_EXEC`
- 严重级别：`high`
- 说明：应用代码中包含调用 `Runtime.exec` 的行为，这允许其在底层 shell 环境中执行任意命令，可能导致提权、安装其他应用或修改系统设置等恶意操作。
- 证据：`API 调用图分析显示存在 852 次对 `Ljava/lang/Runtime;->exec` 的调用。`
- 建议：分析调用 `Runtime.exec` 的上下文，确定其执行的具体命令，评估其对系统安全的威胁。

### 10. 代码与资源文件混淆
- 规则：`DEEP_APK_STATIC_OBFUSCATION`
- 严重级别：`medium`
- 说明：应用使用了非标准的、看似随机生成的名称来命名其资源文件，并且提取出的字符串包含大量乱码。这是一种典型的混淆手段，旨在增加逆向分析的难度。
- 证据：`资源文件包含大量非标准命名，如 `res/-1.xml`, `res/-Q.xml` 等。提取的字符串包含 `+n0D^e`, `@p@zQSdn` 等无意义内容。`
- 建议：使用专业的反混淆工具或脚本来尝试恢复原始的资源和字符串，以便于进一步分析。

### 11. 使用通用名称的自签名证书
- 规则：`DEEP_APK_STATIC_GENERIC_SIGNATURE`
- 严重级别：`low`
- 说明：应用的签名证书是自签名的，并且其主题和颁发者信息（如通用名称 CN）为 'ecarebd28'，这是一个通用的、非标识性的名称。这表明开发者身份未知且不可信。
- 证据：`证书主题与颁发者信息中包含 'ecarebd28'，且二者信息一致。证书SHA256: 3be82df49fbcbc7c47a4a33823a22a48401e6b2854df5802f239c65391f2dce8`
- 建议：将此签名证书的哈希值与已知恶意软件家族或可信应用市场的签名进行比对，以确定其信誉。

### 12. 应用获得设备策略管理员权限
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_ADMIN`
- 严重级别：`critical`
- 说明：动态沙箱检测到该应用在运行时被注册为设备策略管理员。此权限赋予应用对设备的高度控制权，包括但不限于强制设置密码、锁定屏幕、擦除设备数据以及防止应用被卸载等。这是恶意软件常用的持久化和增强控制的机制，对用户隐私和设备安全构成严重威胁。
- 证据：`dynamic_sandbox.dynamic_summary.persistent_services.device_policy: ["2: com.mytelecomapp.topup"]`
- 建议：立即卸载该应用并检查设备是否有其他异常行为。强烈建议用户不要授予任何来源不明应用设备管理员权限。

### 13. 尝试访问隐藏API或未公开方法
- 规则：`DEEP_APK_BEHAVIOR_HIDDEN_API_ACCESS`
- 严重级别：`high`
- 说明：动态日志中出现大量“Accessing hidden method”警告，表明应用尝试调用Android系统内部的未公开API或方法。结合静态分析中高频的反射调用（`Ljava/lang/reflect/Method;->invoke`），这种行为可能用于绕过系统权限检查、实现非常规功能或逃避安全检测，是恶意软件的常见特征。
- 证据：`dynamic_sandbox.logcat_excerpt: "Accessing hidden method Landroid/window/BackEvent;-><init>(FFFI)V (blocked, linking, denied)", "Accessing hidden method Landroid/window/BackEvent;->getProgress()F (blocked, linking, denied)", etc. static_report.apk_summary.graph_data.api_graph.api_call_counts_top: Ljava/lang/reflect/Method;->invoke (106197), Ljava/lang/reflect/Field;->get (67995), Ljava/lang/reflect/Field;->set (1124)`
- 建议：此行为高度可疑，建议对应用的反射机制和隐藏API调用目的进行深入代码审计。此应用可能试图利用系统漏洞或实现未经授权的功能。

### 14. 存在动态代码加载行为
- 规则：`DEEP_APK_BEHAVIOR_DYNAMIC_CODE_LOADING`
- 严重级别：`high`
- 说明：静态分析显示应用高频使用了`Ldalvik/system/DexClassLoader;-><init>`（20448次），表明存在动态加载代码（如DEX文件）的能力。这可以用于实现插件化、代码更新，但也被恶意软件广泛用于下载和执行恶意载荷，绕过初始静态分析，增加分析难度。
- 证据：`static_report.apk_summary.graph_data.api_graph.api_call_counts_top: Ldalvik/system/DexClassLoader;-><init> (20448)`
- 建议：对动态加载的代码来源和内容进行重点分析，确认是否存在恶意载荷或敏感信息窃取行为。

### 15. 可疑的反射与动态加载足迹
- 规则：`DEEP_APK_INTEL_DYNAMIC_LOADING_REFLECTION`
- 严重级别：`high`
- 说明：API 图显示大量反射与类加载调用，可能用于隐藏关键逻辑或按需加载外部代码/插件，提升对静态与短时动态分析的对抗性。
- 证据：`top_api_call=Ljava/lang/reflect/Method;->invoke (106197)、Ljava/lang/reflect/Field;->get (67995)、Ldalvik/system/DexClassLoader;-><init> (20448)、Ljava/lang/Runtime;->exec (852)`
- 建议：定位 DexClassLoader 与反射入口点，审计其参数来源与加载路径；在真机长时运行并抓包，监控 assets/外部存储/content:// 与网络下发的 dex/so；对 Runtime.exec 增设 Hook 观察实际命令（如 sh/su）。

### 16. 签名证书可疑/非官方需核验
- 规则：`DEEP_APK_INTEL_SIGNATURE_OPSEC_ANOMALY`
- 严重级别：`medium`
- 说明：签名主体与颁发者相同、名称“tecarebd281”疑似自签名且与“mytelecom”主题不匹配，存在冒用品牌或非官方分发的可能。
- 证据：`certificate_subject/issuer=tecarebd281（自签名样式），cert_sha256=3be82df49fbcbc7c47a4a33823a22a48401e6b2854df5802f239c65391f2dce8`
- 建议：对比官方商店或官网 APK 的签名指纹与开发者名；以 apksigner/VT 查询该证书家族分发历史；仅从可信渠道获取安装包并建立企业侧证书指纹白名单。

### 17. 设备标识访问需合规披露
- 规则：`DEEP_APK_INTEL_PRIVACY_ANDROID_ID`
- 严重级别：`low`
- 说明：存在 Settings.Secure.getString 调用，可能读取 ANDROID_ID 等设备标识用于追踪或归因。
- 证据：`Landroid/provider/Settings$Secure;->getString 次数约 609（API 图）`
- 建议：审阅隐私政策与埋点文档；在抓包中确认是否对外传输设备标识及其脱敏/加密情况，必要时最小化采集范围。

### 18. 短窗口动态未触发可疑外联
- 规则：`DEEP_APK_INTEL_DYNAMIC_OBS_LIMIT`
- 严重级别：`low`
- 说明：模拟器环境仅运行约 12 秒，logcat 以系统安装/编译日志为主，未捕获明确外部域名/HTTP 目标，可能未触发行为链。
- 证据：`runtime_window_seconds=12；network_hit_count=12（多为安装相关项，如 base.apk/base.odex），无清晰外域`
- 建议：构造完整用户旅程（登录/充值/上传影像）、延长执行时间并启用中间人代理与证书注入；在真机或多地区网络环境复测，观察推送/定时/地理围栏触发行为。

### 19. 建议隔离安装并禁止直接上机
- 规则：`DEEP_APK_ADVICE_ISOLATE_INSTALL`
- 严重级别：`critical`
- 说明：样本同时具备可疑权限、反射/动态加载高频调用、联网行为和不透明签名特征，不适合在生产设备或办公终端直接安装。
- 证据：`top_api_call=Ljava/lang/reflect/Method;->invoke (106197); Ldalvik/system/DexClassLoader;-><init> (20448); Ljava/lang/Runtime;->exec (852); dynamic install_success=true; launch_success=true`
- 建议：仅在隔离沙箱或受控测试机中处理，禁止用户终端直接安装；已安装环境应立即卸载并做 IOC 排查。

### 20. 必须补充沙箱复核
- 规则：`DEEP_APK_ADVICE_SAND_BOX_REVIEW`
- 严重级别：`high`
- 说明：当前动态窗口较短，但已观察到联网和持续组件活动，存在二阶段行为或延迟触发逻辑的可能，单次启动不足以下结论。
- 证据：`runtime_window_seconds=12; network_hit_count=12; event_count=37; logcat_excerpt_count=260; persistent_services includes accessibility/device_policy/notification entries`
- 建议：延长沙箱观察时间，重点抓取 DNS/HTTP/HTTPS 请求、WebView 访问、文件落地、Intent 跳转和前后台切换行为。

### 21. 建议阻断分发与传播
- 规则：`DEEP_APK_ADVICE_BLOCK_DISTRIBUTION`
- 严重级别：`critical`
- 说明：样本具备明显的可疑执行链特征，且包名伪装为业务型应用 com.mytelecomapp.topup，可能被用于钓鱼、仿冒或灰产分发。
- 证据：`package_name=com.mytelecomapp.topup; apk size_bytes=36600142; suspicious APIs: DexClassLoader/Method.invoke/Runtime.exec/HttpURLConnection.connect/URL.openConnection`
- 建议：在企业网关、应用商店、MDM 和邮件/IM 分发链路中加入阻断规则；对外部分享链接和安装包源头做下线处置。

### 22. 应保留样本与留痕
- 规则：`DEEP_APK_ADVICE_KEEP_EVIDENCE`
- 严重级别：`high`
- 说明：该样本存在后续溯源价值，尤其是证书、网络 IOC、动态加载链和可疑资源文件，建议完整保留以便复盘与横向关联。
- 证据：`sha256=ea422e231fa17116d7a7add97bd1a93770792a6c08f9e696624a78421d6c728f; certificate_sha256=3be82df49fbcbc7c47a4a33823a22a48401e6b2854df5802f239c65391f2dce8; dynamic artifacts paths available`
- 建议：保留原始 APK、哈希、动态日志、pcap/网络解析结果和安装后文件列表；生成样本台账并打标签归档。

### 23. 签名证书需重点复核
- 规则：`DEEP_APK_ADVICE_VERIFY_CERT`
- 严重级别：`medium`
- 说明：签名主体与颁发者字段均显示为异常/不透明信息，且无法直接对应常见官方发布链路，存在重签或第三方打包可能。
- 证据：`certificate_subject and certificate_issuer show ecarebd281; APK_SIGNING_INFO finding present`
- 建议：核对证书指纹、签名时间、发布渠道和历史版本一致性；若无法匹配官方指纹，应按高风险处理。

### 24. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 0 分; static-intelligence 差异 40 分; behavior-intelligence 差异 40 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 25. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`medium`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`73`
- 建议：将该评分作为后续人工复核的重要参考。

### 26. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`low`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`0.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
- 主持人总结：综合前四位专家的证据，虽未捕获明确的外联域名/C2 目标且动态窗口较短，但现有静/动态线索已足以将该 APK 定性为高危（critical）疑似 dropper/后门：1) 大规模动态代码加载与反射滥用（DexClassLoader≈2万次、Method.invoke>10万次）叠加字符串/资源混淆，具备强反分析与远程下发/启用隐藏负载能力；2) 存在 Runtime.exec 调用，具备执行系统命令潜力；3) 动态沙箱显示注册为设备策略管理员（device_policy），对应持久化和抗卸载控制链，且伴随尝试访问隐藏API与敏感权限（CAMERA/存储、WAKE_LOCK），显示越权与持久驻留意图；4) 签名为自签名且与品牌不匹配，来源可信度存疑。在未见明确 C2 的情况下，结合以上高危能力与持久化迹象，判定整体风险为“危急”，应作为恶意软件处置。当前裁决仅基于四位专家已有输出，网络流量与外部加载模块仍需后续取证核验。

| 角色 | 模型 | 核心意见 | 补充说明 |
|------|------|----------|----------|
| 主持人 | `gpt-5` | 综合前四位专家的证据，虽未捕获明确的外联域名/C2 目标且动态窗口较短，但现有静/动态线索已足以将该 APK 定性为高危（critical）疑似 dropper/后门：1) 大规模动态代码加载与反射滥用（DexClassLoader≈2万次、Method.invoke>10万次）叠加字符串/资源混淆，具备强反分析与远程下发/启用隐藏负载能力；2) 存在 Runtime.exec 调用，具备执行系统命令潜力；3) 动态沙箱显示注册为设备策略管理员（device_policy），对应持久化和抗卸载控制链，且伴随尝试访问隐藏API与敏感权限（CAMERA/存储、WAKE_LOCK），显示越权与持久驻留意图；4) 签名为自签名且与品牌不匹配，来源可信度存疑。在未见明确 C2 的情况下，结合以上高危能力与持久化迹象，判定整体风险为“危急”，应作为恶意软件处置。当前裁决仅基于四位专家已有输出，网络流量与外部加载模块仍需后续取证核验。 | — |
| 静态分析员 | `gemini-2.5-pro` | 该应用以“电信充值”为伪装，但静态分析揭示了其高度可疑的恶意软件特征。应用内部存在大量（超过2万次）对DexClassLoader的调用，表明其具备动态加载执行代码（DCL）的能力，这是恶意软件隐藏其核心恶意负载的典型手段。同时，代码中充斥着海量的反射调用（超过10万次），并结合了非标准命名的资源文件和混淆字符串，意图对抗静态分析。更严重的是，API调用图显示其能够执行底层系统命令（Runtime.exec）。动态沙箱的证据交叉印证了其恶意意图，显示该应用在运行时会尝试注册为设备策略服务，这是为了获取难以卸载的设备管理器权限，从而完全控制设备。其使用的自签名证书名称'ecarebd28'也显得通用且不可信。综上所述，该应用是一个设计精密的恶意软件，极有可能是一个dropper或后门，风险等级极高。 | — |
| 行为分析员 | `gemini-2.5-flash` | 根据动态沙箱分析，该 APK 表现出高度可疑的行为。静态分析中发现其请求了`CAMERA`等敏感权限，而动态运行数据显示，该应用在运行时被列为设备策略管理员 (`device_policy`)，并可能被注册为辅助功能服务 (`accessibility`)。成为设备策略管理员赋予了应用强大的系统控制权，包括防止卸载、修改设备密码策略等，这是一种常见的恶意软件持久化和抗分析手段。同时，动态日志中出现大量“Accessing hidden method”警告，结合静态分析中检测到的高频反射 (`Ljava/lang/reflect/Method;->invoke`, `Ljava/lang/reflect/Field;->get/set`) 和动态代码加载 (`Ldalvik/system/DexClassLoader;-><init>`)，强烈表明应用可能通过使用未公开的API和动态加载技术来规避检测或执行特权操作。虽然网络命中日志未显示明确的恶意C2通信，但其内部操作（如`settings.get.glo`，`package.install`）结合上述高风险行为，使得整体风险极高。应用还持有`WAKE_LOCK`权限，支持其在后台驻留。 | — |
| 情报分析员 | `gpt-5` | 样本概览：文件名 tmpa1msxzg_.apk（36.6MB），包名 com.mytelecomapp.topup，签名指纹（cert SHA-256）= 3be82df49fbcbc7c47a4a33823a22a48401e6b2854df5802f239c65391f2dce8。Manifest 展示常规网络权限与通知、唤醒锁，以及 CAMERA、读取媒体与外部存储等敏感权限；组件包含 FirebaseMessagingService、PicassoProvider、androidx.camera 相关服务，且内置多架构原生库（pdfium、图片处理）。静态图谱侧重：API 图显示大量反射与类加载相关调用（Method.invoke、Field.get/set、DexClassLoader）以及 Runtime.exec 痕迹，提示存在通过反射隐藏逻辑或动态加载代码的能力。动态沙箱：在模拟器上成功安装与冷启动，运行窗口仅约 12 秒，未观察到明确外联域名（logcat 主要为系统安装与 dex2oat 日志）；持久化服务枚举中出现 device_policy 列表包含本包名的条目，需二次核验。情报边界与局限：1) 离线静态无法确认反射/动态加载的具体数据源与下行模块，也无法判断网络目标（未捕获明确域名/IP）；2) 短时间、模拟器环境的动态运行很可能未触发需要用户交互、地理/时间条件或推送下发的行为链；3) 签名主体/颁发者为自签名样式，名称与品牌不匹配，离线无法确认其与官方发布的对应关系。落地研判建议：结合来源与分发渠道优先核验真伪与信誉（Google Play/官方官网的上架信息、开发者名、签名证书指纹是否一致；是否来源于短信/社媒的直链或第三方市场）；对签名证书指纹做历史信誉溯源（VT/Intel 侧查同证书家族应用）；在受控网络下延长动态运行时间并执行完整业务路径（登录/充值/上传影像等），同时抓包与 Hook 类加载，确认是否存在外部 dex/so 下发与可疑远程域名；在正式环境前避免授予与业务无关的敏感权限（尤其 CAMERA/读取存储）。 | — |
| 处置建议员 | `gpt-5.4-mini` | 建议立即隔离该 APK，禁止在生产终端直接安装或继续分发；当前应先进入沙箱复核与取证保留流程。理由是静态与动态证据同时出现高风险信号：代码侧存在大量反射、DexClassLoader、Runtime.exec、网络连接与ClassLoader.loadClass 调用，具备明显的动态加载/混淆/远程执行能力；动态沙箱中已成功安装并启动，且在 12 秒窗口内出现 12 次网络命中，说明具备实际联网行为；同时申请了 CAMERA、READ_EXTERNAL_STORAGE、READ_MEDIA_IMAGES 等敏感权限，签名主体/颁发者信息也需要进一步核验。当前不能认定为低风险正常商业应用，建议阻断分发并保留样本与日志留痕，待完成域名、请求内容、证书链与后续行为复核后再决定是否放行。 | — |

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
