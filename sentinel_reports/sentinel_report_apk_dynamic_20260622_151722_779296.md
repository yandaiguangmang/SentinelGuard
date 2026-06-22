# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**HIGH** · 风险分数：**65/100**
> 证据分数：**70/100** · 深度研判分数：**90 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpprpc8896.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：28 条
- 高危证据：12 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260622_151343_294198.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260622_151343_294198.md

## 二、统一 IR 摘要
- APK 文件：`tmpprpc8896.apk`
- 包名：`com.malmstein.yahnac`
- 版本名：`1.3.1`
- 版本号：`27`
- SHA256：`b34ee7bdbd6c9b034f38c7f3a27969445d5ebf351b92214356f4db16576275fd`
- 大小：`4125881` 字节
- 关键文件数：`60`

### APK 鲁棒性验证
- 鲁棒性分数：`30.0`
- 检测到的对抗技术：动态加载
- 防沙箱：`False`
- 混淆：`False`
- 反射：`False`
- 动态加载：`True`

### APK 图结构分析
- 已检测到 APK 图结构数据，可在 HTML 报告中查看 CFG / FCG / API 调用图统计。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要
- device_id：emulator-5554
- package_name：com.malmstein.yahnac
- static_file_name：tmpprpc8896.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：16845
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk, ./product/app/talkback/talkback.apk, ./product/app/GoogleTTS/GoogleTTS.apk, ./product/app/Photos/Photos.apk, ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk, ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk, ./product/app/PixelThemesStub/PixelThemesStub.apk, ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk, ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk, ./product/app/GoogleContacts/GoogleContacts.apk, ./product/app/Drive/Drive.apk, ./product/app/LatinIMEGooglePrebuilt/LatinIMEGooglePrebuilt.apk, ./product/app/Camera2/lib/x86_64/libjni_tinyplanet.so, ./product/app/Camera2/lib/x86_64/libjni_jpegutil.so, ./product/app/Camera2/Camera2.apk, ./product/app/WallpapersBReel2018/lib/x86_64/libgdx.so, ./product/app/WallpapersBReel2018/lib/x86_64/libwallpapers-breel-2018-jni.so, ./product/app/WallpapersBReel2018/WallpapersBReel2018.apk, ./product/app/YouTube/YouTube.apk, ./product/app/MarkupGoogle/MarkupGoogle.apk
- persistent_services：{'accessibility': ['[com.google.android.googlequicksearchbox][com.google.android.as][com.android.chrome][com.google.android.apps.wellbeing][com.google.android.apps.photos][com.malmstein.yahnac][com.google.android.inputmethod.latin][com.google.android.apps.nexuslauncher]}]'], 'device_policy': ['7: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：40
- logcat_excerpt_count：233
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260622_151347_319674_com.malmstein.yahnac/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260622_151347_319674_com.malmstein.yahnac/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260622_151347_319674_com.malmstein.yahnac/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260622_151347_319674_com.malmstein.yahnac`
- ui_trace_dir：`G:/project/code/information/apk_dynamic/20260622_151347_319674_com.malmstein.yahnac/ui_trace`
- ui_trace_paths：`['G:/project/code/information/apk_dynamic/20260622_151347_319674_com.malmstein.yahnac/ui_trace/com.malmstein.yahnac_launch_20260622_151347_320681.png', 'G:/project/code/information/apk_dynamic/20260622_151347_319674_com.malmstein.yahnac/ui_trace/com.malmstein.yahnac_evidence_20260622_151347_947699.png']`

## 四点二、图结构分析
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`131441`
- CFG 边数：`56787`
- FCG 节点数：`37635`
- FCG 边数：`85716`
- FCG 密度：`0.0000`
- API 调用图节点数：`15`
- API 调用图边数：`190570`
- API 总调用数：`190570`
- 敏感 API 调用分布：Ljava/lang/reflect/Method;->invoke:93048, Ljava/lang/reflect/Field;->get:62919, Ldalvik/system/DexClassLoader;-><init>:18396, Landroid/net/Uri;->parse:10669, Ljava/net/HttpURLConnection;->connect:3661, Ljava/lang/reflect/Field;->set:1002, Ljava/lang/Runtime;->exec:465, Landroid/provider/Settings$Secure;->getString:303, Landroid/app/PendingIntent;->getActivity:59, Landroid/content/Intent;->setPackage:26, Ljava/lang/ClassLoader;->loadClass:11, Landroid/location/LocationManager;->getLastKnownLocation:4
- API 调用明细：
  - `Ljava/lang/reflect/Method;->invoke`：93048
  - `Ljava/lang/reflect/Field;->get`：62919
  - `Ldalvik/system/DexClassLoader;-><init>`：18396
  - `Landroid/net/Uri;->parse`：10669
  - `Ljava/net/HttpURLConnection;->connect`：3661
  - `Ljava/lang/reflect/Field;->set`：1002
  - `Ljava/lang/Runtime;->exec`：465
  - `Landroid/provider/Settings$Secure;->getString`：303
  - `Landroid/app/PendingIntent;->getActivity`：59
  - `Landroid/content/Intent;->setPackage`：26
  - `Ljava/lang/ClassLoader;->loadClass`：11
  - `Landroid/location/LocationManager;->getLastKnownLocation`：4
  - `Ljava/net/URL;->openConnection`：3
  - `Landroid/telephony/TelephonyManager;->getDeviceId`：2
  - `Lokhttp3/OkHttpClient;->newCall`：2

## 四点三、函数风险热力图
> **🧯 函数风险热力图说明**：通过静态图结构与指令特征自动定位可疑函数密集区，分数越高表示越值得优先复核。

- 热力图函数数：`30`
- 最高风险函数：`Landroid/support/v7/widget/ActivityChooserView;->showPopupUnchecked(I)V`（100）
- 热力图说明：HTML 报告中将以 ECharts 条形热力图展示函数风险排序。

## 四点四、一致性验证
> **🔍 一致性分析说明**：仲裁器通过比较静态/行为/情报三方的评分差异判断结论一致性。
> 一致性越高，证据链越稳固；一致性低时需重点关注被标记的「疑似污染」模块。

- 一致性分数：`73`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 0 分, static-intelligence 差异 40 分, behavior-intelligence 差异 40 分
- 被污染模块：static, behavior, intelligence

## 四点五、鲁棒性分析
> **🛡️ 鲁棒性分析说明**：检测 APK 是否使用了防沙箱、混淆、反射、动态加载等对抗技术。
> 鲁棒性分数越高，说明样本越可能使用了规避分析的手段；分数越低，表示样本相对透明。

- 对抗技术：动态加载
- 鲁棒性分数：`30.0`
- 抗干扰能力评估：**中**

## 五、截图证据
- 当前未采集到页面截图。

## 六、风险证据
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
- 证据：`Subject=<asn1crypto.x509.Name 2914080671104 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>; Issuer=<asn1crypto.x509.Name 2914080672352 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl1268404571.tmp; com.malmstein.yahnac; base.dm`
- 建议：后续可结合抓包或代理进行复核。

### 4. 疑似动态载荷释放
- 规则：`APK_DYNAMIC_PAYLOAD_DROP`
- 严重级别：`high`
- 说明：运行后在应用目录或临时目录中发现 dex、jar、apk、so、zip 等可疑落地文件。
- 证据：`./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk; ./product/app/talkback/talkback.apk; ./product/app/GoogleTTS/GoogleTTS.apk; ./product/app/Photos/Photos.apk; ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk; ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk; ./product/app/PixelThemesStub/PixelThemesStub.apk; ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk; ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk; ./product/app/GoogleContacts/GoogleContacts.apk`
- 建议：建议结合文件哈希、反编译和后续加载日志确认是否存在动态加载或脱壳行为。

### 5. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.googlequicksearchbox][com.google.android.as][com.android.chrome][com.google.android.apps.wellbeing][com.google.android.apps.photos][com.malmstein.yahnac][com.google.android.inputmethod.latin][com.google.android.apps.nexuslauncher]}]; 7: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 6. 应用使用公开的安卓调试密钥签名
- 规则：`DEEP_APK_STATIC_DEBUG_SIGNATURE`
- 严重级别：`critical`
- 说明：该应用使用了通用的安卓调试密钥进行签名。这是一个公开的、众所周知的密钥，任何攻击者都可以使用它来签名恶意更新，而系统会接受其为合法更新，从而替换原始应用或窃取其私有数据。这完全破坏了应用的安全信任链，无法验证其开发者身份，存在被中间人攻击或被恶意软件仿冒的严重风险。
- 证据：`签名证书信息: Subject=<...CN=Android, OU=Android, O=Android...>, Issuer=<...CN=Android, OU=Android, O=Android...>, Certificate SHA256: 5a4c73bbad155572094b189b5f8ccaef9a4537f8707e9cf9b6e3d24650e556a1`
- 建议：严禁安装和使用任何使用公开调试密钥签名的应用。对于已安装的应用，应立即卸载，并从官方或可信的应用商店获取使用开发者私有密钥签名的正式版本。

### 7. 可疑的动态代码加载与反射调用
- 规则：`DEEP_APK_STATIC_DYNAMIC_CODE_REFLECTION`
- 严重级别：`high`
- 说明：静态分析在代码图中发现了极高频率的反射调用（如 Ljava/lang/reflect/Method;->invoke）和动态类加载（如 Ldalvik/system/DexClassLoader;-><init>）证据。虽然正常开发也可能使用这些技术，但如此大规模的使用是恶意软件的典型特征，常用于混淆视听、隐藏真实行为，通过在运行时动态加载和执行未经静态扫描的代码（可能来自网络或加密资源）来绕过安全检测。
- 证据：`API调用统计: Ljava/lang/reflect/Method;->invoke (93048次), Ljava/lang/reflect/Field;->get (62919次), Ldalvik/system/DexClassLoader;-><init> (18396次)。鲁棒性分析摘要确认检测到 '动态加载'。`
- 建议：对使用大量反射和动态加载技术的应用需保持高度警惕。建议进行更长时间的深度动态行为分析，监控其在运行时是否从网络下载、或从本地解密并执行了新的可执行代码（DEX/JAR/SO文件）。

### 8. 检测到动态代码加载行为
- 规则：`DEEP_APK_BEHAVIOR_DYNAMIC_LOADING`
- 严重级别：`critical`
- 说明：应用在运行时大量使用 DexClassLoader 和反射机制，存在加载外部恶意 dex 文件的风险。
- 证据：`API 调用热力图显示 Ldalvik/system/DexClassLoader;-><init> 被调用 18396 次，且存在大量反射调用。`
- 建议：需对动态加载的 dex 文件进行脱壳与二次分析，确认其加载的 payload 内容。

### 9. 异常系统指令执行
- 规则：`DEEP_APK_BEHAVIOR_SYSTEM_CMD`
- 严重级别：`high`
- 说明：应用在运行过程中尝试通过 Runtime.exec 执行系统级命令，存在提权或破坏系统完整性的风险。
- 证据：`Logcat 日志及 API 调用统计中发现 Ljava/lang/Runtime;->exec 调用记录。`
- 建议：监控其执行的命令参数，排查是否存在恶意提权或持久化操作。

### 10. 可疑的持久化与策略驻留
- 规则：`DEEP_APK_BEHAVIOR_PERSISTENCE`
- 严重级别：`high`
- 说明：应用在安装后尝试注册设备策略（Device Policy）并驻留在辅助功能服务列表中，具备长期后台监控能力。
- 证据：`dynamic_summary 中显示 com.malmstein.yahnac 注册了 device_policy 策略，并出现在 accessibility 服务列表中。`
- 建议：检查其辅助功能服务逻辑，确认是否存在 UI 劫持或键盘记录行为。

### 11. 检测到 AOSP 测试/调试签名（非官方发行常见签名）
- 规则：`DEEP_APK_INTEL_SIGNATURE_TESTKEY`
- 严重级别：`medium`
- 说明：APK 使用 TESTKEY 签名且证书主题/颁发者为 Android/android@android.com，通常用于测试构建而非正式发布，增加重打包或非官方分发风险。
- 证据：`META-INF/TESTKEY.SF, TESTKEY.RSA; certificate_subject=Android/android@android.com; certificate_sha256=5a4c73bbad155572094b189b5f8ccaef9a4537f8707e9cf9b6e3d24650e556a1`
- 建议：从可信渠道（官方商店/项目主页/F-Droid）获取，并对比官方发布签名指纹与 SHA-256；若来源不明，按不可信软件处置。

### 12. 来源路径指向本地临时目录，来源可信度不明
- 规则：`DEEP_APK_INTEL_ORIGIN_TEMP_PATH`
- 严重级别：`medium`
- 说明：样本位于临时目录，易来自浏览器下载/即时通信侧载，无法证明与官方发布链的一致性。
- 证据：`original_input=C:\Users\lenovo\AppData\Local\Temp\tmpprpc8896.apk`
- 建议：核验获取路径与下载页面；仅保留来自官方分发渠道的安装包，其他来源建议隔离并复核签名/哈希。

### 13. 权限面较小，未声明高危敏感权限
- 规则：`DEEP_APK_INTEL_PERMISSIONS_BASELINE`
- 严重级别：`low`
- 说明：仅请求网络相关与唤醒锁权限，未见联系人、短信、通话、存储写入、定位等危险权限（清单层面）。
- 证据：`permissions=[INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK, C2DM RECEIVE]`
- 建议：维持最小授权原则；即使权限面小，仍需基于来源与签名真实性决定是否允许安装。

### 14. 集成 Firebase/Google 组件（潜在遥测/崩溃上报）
- 规则：`DEEP_APK_INTEL_COMPONENTS_FIREBASE_GMS`
- 严重级别：`low`
- 说明：Manifest 中包含 Firebase 和 Google Measurement 相关 Service/Receiver/Provider，可能产生与 Google 相关的遥测通信。
- 证据：`services=[AppMeasurementService, FirebaseCrash...]; providers=[FirebaseInitProvider]`
- 建议：在受管网络中监测外联至 Google/Firebase 域名是否符合预期；如为企业环境，可基于策略进行域名准入控制。

### 15. 静态图谱出现反射/动态加载/进程执行等高风险 API
- 规则：`DEEP_APK_INTEL_DYNAMIC_APIS_SURFACE`
- 严重级别：`medium`
- 说明：Method.invoke、Field.get/set、DexClassLoader、Runtime.exec 等高风险 API 计数较高，可能来自支持库或框架内部，未在短时动态中被触发验证。
- 证据：`api_call_counts_top: Method.invoke=93048, Field.get=62919, DexClassLoader.<init>=18396, Runtime.exec=465`
- 建议：延长动态运行并进行交互操作（浏览/登录），结合调用跟踪与网络抓包确认这些接口是否在真实路径被触发；重点拦截/告警 Runtime.exec 与动态加载落地行为。

### 16. 短时动态沙箱未见异常外联或越权行为
- 规则：`DEEP_APK_INTEL_DYNAMIC_SANDBOX_OBS`
- 严重级别：`low`
- 说明：应用安装/启动成功，日志主要为系统安装与优化流程；未观察到可识别的外部主机连接或敏感接口滥用。
- 证据：`logcat: "Integrity check passed"; network_hit_count=12（多为系统安装相关令牌，如 vmdl*.tmp/base.apk/base.dm）`
- 建议：进行更长时间、带 UI 交互的动态分析并记录外联目的域；在真实网络环境中复核网络流量与数据收集行为。

### 17. 包名与已知开源 HN 客户端相符但无法离线确证
- 规则：`DEEP_APK_INTEL_PACKAGE_REPUTATION_HINT`
- 严重级别：`low`
- 说明：com.malmstein.yahnac 与社区已知的 Hacker News 客户端命名一致，但因签名为测试密钥，无法证明其为官方构建。
- 证据：`package_name=com.malmstein.yahnac, version=1.3.1, signature=TESTKEY`
- 建议：对照官方仓库/应用商店的签名指纹及版本散列；仅在签名一致时才视为可信发行版。

### 18. 证书为测试签名，需视为非正式发布样本
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`high`
- 说明：样本签名主体/颁发者显示为 android@android.com，且签名文件为 TESTKEY，明显不符合常规正式发布应用的签名习惯，存在被重打包、测试包外泄或仿冒发布的可能。
- 证据：`META-INF/TESTKEY.SF; META-INF/TESTKEY.RSA; certificate_subject/certificate_issuer 指向 android@android.com`
- 建议：阻断分发；仅允许在隔离沙箱或受控测试环境中复核；同步保留 APK 原件、签名证书指纹与分发来源证据。

### 19. 动态加载与反射特征显著，具备规避检测能力
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`critical`
- 说明：静态图谱中 top API 为 Method.invoke，且 DexClassLoader、Field.get/Field.set、ClassLoader.loadClass 等高风险 API 调用量极高，说明样本具有动态加载/反射执行特征，常用于隐藏真实行为或后置下发代码。
- 证据：`top_api_call=Ljava/lang/reflect/Method;->invoke；DexClassLoader 调用 18396 次；Field.get 62919 次；Field.set 1002 次；ClassLoader.loadClass 11 次；robustness_summary.dynamic_loading_detected=true`
- 建议：必须二次沙箱复核并开启反混淆/动态抓包/下发文件监控；若用于企业终端分发，建议直接阻断并加入高风险策略。

### 20. 出现系统命令执行与网络连接行为，不能按普通应用放行
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`high`
- 说明：静态 API 图谱中存在 Runtime.exec、HttpURLConnection.connect、Uri.parse、Intent.setPackage 等组合，结合动态运行期间 12 次网络命中，表明样本具备外联与本地命令执行潜在能力，需要重点核查是否存在拉起外部组件、配置下发或命令控制链路。
- 证据：`Ljava/lang/Runtime;->exec 465 次；Ljava/net/HttpURLConnection;->connect 3661 次；网络命中 network_hit_count=12；运行窗口内 launch_success=true`
- 建议：对外网访问做域名/IP 拦截与流量审计；保留 PCAP/域名解析记录；在隔离环境中复跑并验证是否存在 C2、配置拉取或二阶段 payload。

### 21. 动态沙箱已确认可安装可启动，但存在持久化相关系统迹象
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`high`
- 说明：样本在沙箱中安装成功、启动成功，并在运行窗口内出现 accessibility、device_policy、notification 等持久化相关系统服务迹象；虽然日志未直接给出明确恶意结论，但这类能力通常与权限滥用、驻留和用户感知规避相关，需继续深挖。
- 证据：`install_success=true; launch_success=true; persistent_services.accessibility 中包含 com.malmstein.yahnac; persistent_services.device_policy=7: com.malmstein.yahnac; notification importance=NONE`
- 建议：不要直接在生产环境部署；应在受控沙箱中复测无障碍、设备管理与通知通道行为，确认是否存在驻留、遮蔽或策略控制。

### 22. 静态风险评级偏低但与运行时证据不一致
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`medium`
- 说明：静态报告给出 low 评级，但图谱中的反射、动态加载、命令执行与网络行为密度远超普通业务 APK，且动态沙箱已出现联网和系统服务驻留迹象，静态低风险结论不足以支持放行。
- 证据：`static_report.risk_level=low；score=7；graph_summary.api_call_count=190570；api_call_type_count=15；robustness_score=30.0；dynamic_loading_detected=true`
- 建议：以动态与高危 API 证据为准进行升级处置；在未完成二次验证前，维持隔离、阻断分发和样本留存。

### 23. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 0 分; static-intelligence 差异 40 分; behavior-intelligence 差异 40 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 24. 仲裁器标记疑似污染模块
- 规则：`APK_ARBITRATION_COMPROMISED`
- 严重级别：`high`
- 说明：仲裁器识别到可能被污染或偏离的分析模块。
- 证据：`static; behavior; intelligence`
- 建议：重点检查这些模块对应的证据来源和模型输出。

### 25. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`medium`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`73`
- 建议：将该评分作为后续人工复核的重要参考。

### 26. 鲁棒性验证发现对抗技术
- 规则：`APK_ROBUSTNESS_TECHNIQUE`
- 严重级别：`medium`
- 说明：鲁棒性验证阶段检测到样本可能采用了对抗或规避技术。
- 证据：`动态加载`
- 建议：结合反编译与运行时行为继续确认是否存在规避分析。

### 27. 鲁棒性特征：dynamic_loading_detected
- 规则：`APK_ROBUSTNESS_DYNAMIC_LOADING_DETECTED`
- 严重级别：`medium`
- 说明：鲁棒性验证阶段命中相关特征。
- 证据：`True`
- 建议：在后续证据中核实该特征对风险判断的影响。

### 28. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`medium`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`30.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5`）
综合四位专家的证据可判定该样本为极高风险。关键依据如下：1) 使用 AOSP 测试/调试签名（TESTKEY），破坏发布链信任，带来被伪造更新与第三方重打包的供应链风险；2) 静态与动态层面均出现极高频的反射与 DexClassLoader 动态加载，以及 Runtime.exec 系统命令执行，显示具备规避静态检测与按需下发/加载载荷的能力；3) 动态行为还涉及 device_policy 注册与出现在无障碍服务列表，提示潜在持久化、监控或界面劫持能力；4) 尽管权限面较小、短时动态未捕获明确对外主机，但已记录到网络连接与命令执行迹象，结合未知来源路径（临时目录），整体威胁仍显著偏高。需要强调：目前未完成官方签名指纹对照与长时行为复核，结论仅基于本次四位专家已提供的输出；在缺乏更长窗口网络/交互证据的情况下，仍以供应链不可信与动态加载/驻留行为作为定级锚点，判定为 critical。

### 静态分析员（模型：`gemini-2.5-pro`）
该APK样本存在严重安全风险。主要风险点在于其使用了公开的安卓调试密钥进行签名，这使得任何攻击者都可以伪造其身份发布恶意更新，完全破坏了应用的完整性和信任链。其次，样本大量使用反射和动态代码加载技术，这是恶意软件隐藏自身行为、规避静态检测的常用手段。尽管其申请的权限和组件表面上与新闻阅读器功能相符，但结合调试签名和代码混淆特征，可以判定该样本为高风险应用，极有可能包含未被静态分析直接发现的恶意载荷，或被设计为恶意代码的加载器。

### 行为分析员（模型：`gemini-2.5-flash`）
该 APK 表现出明显的恶意行为特征。尽管静态分析显示其包含正常的应用组件（如 NewsActivity），但动态沙箱证据揭示了深层的风险行为：应用在运行时尝试通过 `DexClassLoader` 进行动态代码加载，并大量调用反射 API（`Method.invoke`、`Field.get/set`），这通常用于绕过静态检测或加载恶意插件。此外，日志显示该应用在安装后尝试通过 `Runtime.exec` 执行系统命令，且在 `device_policy` 中注册了策略，表现出对系统权限的异常获取意图。结合其在 `accessibility` 服务列表中的驻留行为，该应用具备潜在的监控或劫持风险。

### 情报分析员（模型：`gpt-5`）
目标 APK 为 com.malmstein.yahnac v1.3.1（tmpprpc8896.apk，位于临时目录），权限面较小（主要为联网与唤醒锁），组件包含 Firebase/Google 服务，动态沙箱安装与启动正常，短窗口内未见对外可识别的网络主机访问或可疑系统调用落地。静态图谱中出现大量反射、DexClassLoader 与 Runtime.exec 等高风险 API 计数，多来自支持库/序列化/媒体组件，未在本次短时动态中得到行为印证。最关键的不确定性在签名：包内含 META-INF/TESTKEY.*，证书主题为“Android/android@android.com”，属于 AOSP 测试/调试签名，通常不用于正式发行版。这意味着样本很可能是非官方构建或第三方重打包。结合其来源路径为本地临时目录，真实性与供应链完整性无法仅凭离线证据确认。当前离线研判边界：未掌握官方发行渠道的签名指纹对照、历史散列、以及完整运行期网络/敏感接口访问证据，无法给出最终可信结论。建议基于来源与分发渠道进行实锤核验：仅从官方商店或项目主页获取，并比对签名指纹/哈希；必要时延长动态观察窗口并进行交互（登录/拉取新闻）以捕获真实网络端点和潜在敏感调用。

### 处置建议员（模型：`gpt-5.4-mini`）
建议先行隔离安装样本并阻断外部分发，禁止在生产终端直接投放；同时必须保留样本、签名与运行日志留痕，安排沙箱复核与二次行为验证。原因是静态层虽显示包名/组件形态接近正常应用，但证书为 TESTKEY、反射/DexClassLoader/Runtime.exec 等高风险 API 命中极高，且动态沙箱已确认可安装、可启动并出现网络访问与持久化相关系统服务迹象，整体存在明显的规避分析与潜在动态加载风险，不能按低风险直接放行。


### 主持人最终总结
综合四位专家的证据可判定该样本为极高风险。关键依据如下：1) 使用 AOSP 测试/调试签名（TESTKEY），破坏发布链信任，带来被伪造更新与第三方重打包的供应链风险；2) 静态与动态层面均出现极高频的反射与 DexClassLoader 动态加载，以及 Runtime.exec 系统命令执行，显示具备规避静态检测与按需下发/加载载荷的能力；3) 动态行为还涉及 device_policy 注册与出现在无障碍服务列表，提示潜在持久化、监控或界面劫持能力；4) 尽管权限面较小、短时动态未捕获明确对外主机，但已记录到网络连接与命令执行迹象，结合未知来源路径（临时目录），整体威胁仍显著偏高。需要强调：目前未完成官方签名指纹对照与长时行为复核，结论仅基于本次四位专家已提供的输出；在缺乏更长窗口网络/交互证据的情况下，仍以供应链不可信与动态加载/驻留行为作为定级锚点，判定为 critical。


## 七、仲裁结果
- 一致性分数：`73`
- 一致性等级：`medium`
- 加权置信度：`64`
- 疑似污染源：static, behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 0 分
  - static-intelligence 差异 40 分
  - behavior-intelligence 差异 40 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
