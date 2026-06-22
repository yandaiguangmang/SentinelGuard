# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**HIGH** · 风险分数：**60/100**
> 证据分数：**70/100** · 深度研判分数：**75 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpvaur8oj3.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：24 条
- 高危证据：6 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260622_182241_105720.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260622_182241_105720.md

## 二、统一 IR 摘要
- APK 文件：`tmpvaur8oj3.apk`
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
- static_file_name：tmpvaur8oj3.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：25939
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk, ./product/app/talkback/talkback.apk, ./product/app/GoogleTTS/GoogleTTS.apk, ./product/app/Photos/Photos.apk, ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk, ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk, ./product/app/PixelThemesStub/PixelThemesStub.apk, ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk, ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk, ./product/app/GoogleContacts/GoogleContacts.apk, ./product/app/Drive/Drive.apk, ./product/app/LatinIMEGooglePrebuilt/LatinIMEGooglePrebuilt.apk, ./product/app/Camera2/lib/x86_64/libjni_tinyplanet.so, ./product/app/Camera2/lib/x86_64/libjni_jpegutil.so, ./product/app/Camera2/Camera2.apk, ./product/app/WallpapersBReel2018/lib/x86_64/libgdx.so, ./product/app/WallpapersBReel2018/lib/x86_64/libwallpapers-breel-2018-jni.so, ./product/app/WallpapersBReel2018/WallpapersBReel2018.apk, ./product/app/YouTube/YouTube.apk, ./product/app/MarkupGoogle/MarkupGoogle.apk
- persistent_services：{'accessibility': ['[com.google.android.googlequicksearchbox][com.google.android.as][com.google.android.apps.wellbeing][com.google.android.youtube][com.google.android.apps.photos][com.google.android.calendar][com.google.android.inputmethod.latin][com.malmstein.yahnac][com.google.android.apps.nexuslauncher]}]'], 'device_policy': ['8: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：40
- logcat_excerpt_count：431
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260622_182247_778884_com.malmstein.yahnac/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260622_182247_778884_com.malmstein.yahnac/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260622_182247_778884_com.malmstein.yahnac/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260622_182247_778884_com.malmstein.yahnac`
- ui_trace_dir：`G:/project/code/information/apk_dynamic/20260622_182247_778884_com.malmstein.yahnac/ui_trace`
- ui_trace_paths：`['G:/project/code/information/apk_dynamic/20260622_182247_778884_com.malmstein.yahnac/ui_trace/com.malmstein.yahnac_launch_20260622_182247_780866.png', 'G:/project/code/information/apk_dynamic/20260622_182247_778884_com.malmstein.yahnac/ui_trace/com.malmstein.yahnac_evidence_20260622_182248_527039.png']`

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
- 分歧点：static-behavior 差异 15 分, static-intelligence 差异 25 分, behavior-intelligence 差异 40 分
- 被污染模块：behavior, intelligence

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
- 证据：`Subject=<asn1crypto.x509.Name 2234933793840 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>; Issuer=<asn1crypto.x509.Name 2234933793696 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`https://play.googleapis.com/play/log; https://play.googleapis.com/play/log/timestamp; settings.get.glo; package.install; vmdl1426378183.tmp`
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
- 证据：`[com.google.android.googlequicksearchbox][com.google.android.as][com.google.android.apps.wellbeing][com.google.android.youtube][com.google.android.apps.photos][com.google.android.calendar][com.google.android.inputmethod.latin][com.malmstein.yahnac][com.google.android.apps.nexuslauncher]}]; 8: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 6. 应用使用通用安卓调试密钥签名
- 规则：`DEEP_APK_STATIC_DEBUG_SIGNATURE`
- 严重级别：`high`
- 说明：该APK使用了标准的安卓调试密钥（testkey）进行签名。这意味着它并非来自官方发布渠道，其完整性和来源无法保证。任何人都可能修改原始应用后用此密钥重新打包，这极大地增加了应用被植入恶意代码（如后门、信息窃取模块）的风险。
- 证据：`签名证书主体和颁发者均为 'CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US'，证书SHA256哈希为 '52c28a0dd0d60ae5b9d87dd22c293d87f4993d68b7e93d73481b5db1caa1b591'。签名文件名包含 'META-INF/TESTKEY.RSA'。`
- 建议：立即停止使用并卸载此应用。务必从官方应用商店或项目官方网站等可信渠道获取应用，并验证其签名是否为开发者官方签名。

### 7. 应用包含动态代码加载和命令执行能力
- 规则：`DEEP_APK_STATIC_DYNAMIC_CODE_EXECUTION`
- 严重级别：`medium`
- 说明：静态代码分析显示，该应用具备调用`DexClassLoader`和`Runtime.exec`的能力。`DexClassLoader`可用于在运行时从外部文件（如APK、JAR、DEX）加载并执行代码，是恶意软件隐藏和更新恶意逻辑的常用手段。`Runtime.exec`则能执行底层系统命令。结合该应用使用了不安全的调试签名，这些功能构成了严重的安全隐患，可能被用于执行未知的恶意操作。
- 证据：`API调用图（api_graph）显示存在对 'Ldalvik/system/DexClassLoader;-><init>' (18396次) 和 'Ljava/lang/Runtime;->exec' (465次) 的潜在调用路径。健壮性分析（robustness_summary）标记了'动态加载'（dynamic_loading_detected）对抗技术。`
- 建议：鉴于存在动态加载和命令执行的风险，且应用签名不可信，建议将此应用视为恶意软件。需要进行深入的逆向工程分析，以追踪这些高危API的具体调用逻辑和意图。

### 8. 获取设备管理员权限
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_ADMIN_PRIVILEGE`
- 严重级别：`critical`
- 说明：动态沙箱检测到该应用在运行时注册并获取了设备管理员权限。此权限赋予应用对设备强大的控制能力，包括但不限于强制设置密码、锁定屏幕、擦除数据或阻止用户卸载应用。对于一个普通新闻客户端而言，此权限是非必要且具有高风险的。
- 证据：`dynamic_sandbox.dynamic_summary.persistent_services.device_policy: ['8: com.malmstein.yahnac']`
- 建议：此行为高度可疑，强烈建议对应用进行彻底的安全分析。用户应避免授予此类非必要权限，并谨慎安装未知来源的应用。

### 9. 安装后异常的包移除行为
- 规则：`DEEP_APK_BEHAVIOR_UNUSUAL_PACKAGE_REMOVAL`
- 严重级别：`high`
- 说明：动态沙箱日志显示，在应用安装和 DEX 优化完成后不久，系统记录了 'Force stopping com.malmstein.yahnac ... pkg removed'。这种在短时间内自行或被系统移除包的行为，可能是应用为了隐藏自身、逃避检测或触发后续恶意载荷的一种反分析机制。
- 证据：`dynamic_sandbox.logcat_excerpt: 'I/ActivityManager(  525): Force stopping com.malmstein.yahnac appid=10174 user=0: pkg removed'`
- 建议：结合其他可疑行为（如获取设备管理员权限），此行为进一步增加了应用的恶意可能性。需进一步分析应用代码，探究其在包移除前后是否存在其他隐藏操作或与服务器的通信。

### 10. 检测到动态代码加载
- 规则：`DEEP_APK_BEHAVIOR_DYNAMIC_CODE_LOADING`
- 严重级别：`medium`
- 说明：静态分析的健壮性摘要显示该应用使用了动态代码加载技术（Dynamic Loading）。API 图中的高频调用 `Ldalvik/system/DexClassLoader;-><init>` 和 `Ljava/lang/reflect/Method;->invoke` 证实了这一点。动态加载本身不一定是恶意的，但常被恶意软件利用来在运行时加载加密或混淆的恶意载荷，以逃避静态分析和早期检测。
- 证据：`apk_ir.graph_data.robustness_summary.dynamic_loading_detected: true; apk_ir.graph_data.api_graph.api_call_counts_top: {'Ldalvik/system/DexClassLoader;-><init>': 18396, 'Ljava/lang/reflect/Method;->invoke': 93048}`
- 建议：需警惕应用是否在运行时下载并执行外部代码。结合其获取的设备管理员权限，动态加载可能被用于执行更深层次的恶意功能。

### 11. 使用 AOSP 测试证书签名，非官方发行构建
- 规则：`DEEP_APK_INTEL_SIGNING_TESTKEY`
- 严重级别：`medium`
- 说明：证书主题与颁发者均为 Android 测试证书（AOSP testkey），且包内包含 META-INF/TESTKEY.*，通常仅用于开发/测试或第三方重签名，不符合正式发行习惯。
- 证据：`certificate_subject=Android, android@android.com；certificate_sha256=52c28a0dd0d60ae5...; META-INF/TESTKEY.SF / TESTKEY.RSA 存在`
- 建议：将样本 SHA256=b34ee7bdbd6c9b034f38c7f3a27969445d5ebf351b92214356f4db16576275fd 与官方渠道（Google Play/F-Droid/GitHub Release）版本签名指纹与哈希比对；优先从可信商店获取同版本，避免使用测试/重签名构建。

### 12. 来源不明的临时路径样本，供应链可信度待核验
- 规则：`DEEP_APK_INTEL_PROVENANCE_UNKNOWN`
- 严重级别：`medium`
- 说明：样本来自本地临时目录，缺失下载链接与商店元数据，无法建立发行链与开发者身份绑定。
- 证据：`original_input=C:\Users\lenovo\AppData\Local\Temp\tmpvaur8oj3.apk；url=null`
- 建议：结合获取途径与分发渠道判断：仅接受来自官方市场或开发者官方仓库的下载；核验开发者签名长期一致性与历史信誉（如 Play 上 com.malmstein.yahnac 的签名证书指纹）。

### 13. 权限画像以网络为主，未声明敏感高危权限
- 规则：`DEEP_APK_INTEL_PERMISSION_MINIMAL`
- 严重级别：`low`
- 说明：仅请求 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK 与 GCM/FCM 相关自定义权限，符合新闻客户端的常规最小权限画像。
- 证据：`permissions=[INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK, com.google.android.c2dm.permission.RECEIVE, com.malmstein.yahnac.permission.C2D_MESSAGE]`
- 建议：从隐私合规角度关注 Firebase/测量组件的数据传输；继续监测运行期是否额外请求动态权限或出现超出画像的行为。

### 14. 短时动态运行未见可疑外链或异常行为
- 规则：`DEEP_APK_INTEL_DYNAMIC_BEHAVIOR_BENIGN`
- 严重级别：`low`
- 说明：应用成功安装启动，窗口期 12 秒内主要访问 Google Play 日志端点，Logcat 多为安装/优化流程日志，未观察到可疑命令执行或恶意 C2 连接。
- 证据：`launch_success=true; network_hits≈[https://play.googleapis.com/play/log,...]; resolve_activity=com.malmstein.yahnac/.stories.NewsActivity; logcat 安装/DEX 优化日志`
- 建议：延长动态观测时间并进行真实交互（浏览/登录/评论等），抓取完整网络流量（如 Hacker News API/内容域名），同时在具备用户行为与推送触发条件下复测。

### 15. 静态图谱反射与动态加载调用计数高，需结合上下文判读
- 规则：`DEEP_APK_INTEL_REFLECTION_DYNAMIC_LOADING`
- 严重级别：`medium`
- 说明：Method.invoke/Field.get/DexClassLoader 计数高，多见于 Android 兼容支持库/JSON 序列化/媒体支持等路径；静态存在不代表必然在运行期触发，但在重签名或非官方构建情景下值得二次核查。
- 证据：`api_call_counts_top: Method.invoke=93048, Field.get=62919, DexClassLoader.<init>=18396, HttpURLConnection.connect=3661`
- 建议：进行针对性代码审计与覆盖式动态触发：定位 DexClassLoader 与 Runtime.exec 的可达路径（如特定设置/调试/隐蔽入口），在真实机上 Hook/Trace 关键 API 以确认是否被实际调用。

### 16. 存在对 Runtime.exec 的引用但未在短时沙箱中触发
- 规则：`DEEP_APK_INTEL_RUNTIME_EXEC_REFERENCES`
- 严重级别：`medium`
- 说明：静态聚合显示 Runtime.exec 参考计数（465），但 12 秒动态窗口未见对应调用或异常行为，可能来源于三方库的通用代码路径或异常分支。
- 证据：`api_call_counts_top: Runtime.exec=465；动态日志未见可疑子进程/命令`
- 建议：扩大行为覆盖（网络异常、登录失败、调试开关等场景）并监控子进程创建与命令行；在源代码或反编译基础上确认这些引用的条件分支与输入来源。

### 17. 模拟器环境枚举项可能产生噪声，需与 Manifest 交叉验证
- 规则：`DEEP_APK_INTEL_SANDBOX_NOISE_VALIDATION`
- 严重级别：`low`
- 说明：动态摘要出现 device_policy/accessibility 枚举包含目标包，但 Manifest 未见对应 DeviceAdminReceiver/AccessibilityService 声明，疑为环境噪声。
- 证据：`persistent_services.device_policy=["8: com.malmstein.yahnac"]; components 未包含设备管理/无障碍服务`
- 建议：在真机或不同沙箱复测，并直接查询设备管理员/无障碍服务注册状态；以 Manifest/运行时注册证据为准，避免误判。

### 18. 存在动态加载与反射链路，需重点复核
- 规则：`DEEP_APK_ADVICE_DYNAMIC_LOADING_REVIEW`
- 严重级别：`high`
- 说明：静态图谱显示 DexClassLoader、Method.invoke、Field.get/Field.set 调用频繁，具备通过反射和动态加载隐藏真实逻辑的能力，增加规避静态检测与后续载荷更新风险。
- 证据：`top_api_call=Ljava/lang/reflect/Method;->invoke；api_call_counts_top 包含 Ldalvik/system/DexClassLoader;-><init>=18396、Ljava/lang/reflect/Method;->invoke=93048、Ljava/lang/reflect/Field;->get=62919、Ljava/lang/reflect/Field;->set=1002；robustness_summary.dynamic_loading_detected=true`
- 建议：建议进入隔离沙箱二次复核，重点跟踪类加载、反射目标、远程配置与后续下载链路；在确认无隐藏载荷前，不建议放行安装。

### 19. 运行时已产生网络行为，需核验通信目的与数据内容
- 规则：`DEEP_APK_ADVICE_NETWORK_BEHAVIOR_CHECK`
- 严重级别：`medium`
- 说明：动态沙箱在 12 秒窗口内记录到 12 次网络命中，说明应用启动后存在联网行为；结合 HttpURLConnection、Uri.parse 等调用，需确认是否为正常业务通信或隐蔽拉取内容。
- 证据：`dynamic_summary.network_hit_count=12；network_hits 包含 https://play.googleapis.com/play/log、https://play.googleapis.com/play/log/timestamp、settings.get.glo、package.install；api_call_counts_top 包含 java/net/HttpURLConnection;->connect=3661、android/net/Uri;->parse=10669`
- 建议：建议继续沙箱抓包复核域名、请求路径、参数与响应体，判断是否存在配置下发、统计外联或隐蔽下载；未完成核验前应阻断对外分发。

### 20. 安装可成功但来源与证书需控管
- 规则：`DEEP_APK_ADVICE_INSTALLATION_SCOPE_CONTROL`
- 严重级别：`medium`
- 说明：样本在沙箱中安装与启动均成功，说明载体完整且可执行；证书主体/颁发者信息呈现 Android 测试样式，且静态报告已提示签名信息需复核，来源可信度不足。
- 证据：`install_success=true；launch_success=true；certificate_subject/issuer 显示 android@android.com 风格信息；static_report findings 包含 APK_SIGNING_INFO`
- 建议：对外部来源版本先隔离留样并核验签名链、发布渠道与历史版本一致性；未确认签名可信前，不建议在生产终端安装。

### 21. 应保留样本与运行痕迹以便追溯
- 规则：`DEEP_APK_ADVICE_PRESERVE_EVIDENCE`
- 严重级别：`low`
- 说明：当前已获得 APK 哈希、动态日志与网络命中信息，具备完整留痕条件。为支持后续溯源和复盘，样本及其动态产物应保留。
- 证据：`sha256=b34ee7bdbd6c9b034f38c7f3a27969445d5ebf351b92214356f4db16576275fd；dynamic_logcat_path 与 dynamic_json_path 已生成；event_count=40、logcat_excerpt_count=431`
- 建议：保留原始 APK、SHA256、动态日志、抓包结果和沙箱输出目录；同时记录处置时间、分析环境与结论，便于后续关联分析。

### 22. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 15 分; static-intelligence 差异 25 分; behavior-intelligence 差异 40 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 23. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`medium`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`73`
- 建议：将该评分作为后续人工复核的重要参考。

### 24. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`medium`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`30.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5`）
综合四位专家意见：样本为开源 Hacker News 客户端的非官方构建，使用 AOSP 测试证书/通用调试密钥签名，信任链断裂且来源不明，存在被重签名或篡改的显著供应链风险。静态层面检测到 DexClassLoader、反射与 Runtime.exec 等能力，具备动态加载与潜在远程载荷执行的条件；在不可信签名前提下，这一能力组合构成结构性高风险。动态沙箱短时窗口内未观测到明显恶意外联（主要为 Google Play 日志端点），“设备管理员权限”与“安装后包被移除”的迹象存在争议：情报分析指出 Manifest 未见对应组件，可能为环境噪声，因而不足以据此定性为已实施恶意行为。基于当前证据，倾向判定为高风险的可疑样本（疑似被重签名且具备动态加载执行能力），不建议信任或分发，应先隔离留样、校验证书与来源并延长动态观测后再作处置。上述结论仅基于当前四位专家提供的静/动态与情报/处置意见，缺乏更长时间运行与官方签名链校验的确证支撑。

### 静态分析员（模型：`gemini-2.5-pro`）
该应用（com.malmstein.yahnac）是一款基于开源项目的新闻阅读器，但此样本存在严重安全风险。主要问题在于它使用了通用的安卓调试密钥进行签名，这表明它并非官方发布版本，极有可能被第三方篡改并植入了恶意代码。静态分析进一步发现了动态代码加载（DexClassLoader）和命令执行（Runtime.exec）等高风险行为能力，虽然这些可能源于其集成的第三方库，但结合不安全的签名，使得应用在运行时下载和执行任意代码成为可能。尽管应用申请的权限与其功能基本相符，且动态沙箱的短期运行未观察到明显恶意行为，但其静态层面的结构性风险已构成重大威胁，不应被信任。

### 行为分析员（模型：`gemini-2.5-flash`）
根据动态沙箱执行日志和产物分析，该 APK (com.malmstein.yahnac) 在安装后表现出异常行为。应用成功安装并启动，但在短时间内被系统记录为“pkg removed”，这可能是一种反分析或隐藏自身存在的尝试。更重要的是，动态摘要显示该应用注册了设备管理员权限（device_policy），这对于一个声称是新闻客户端的应用来说，是高度可疑和不必要的，赋予了其强大的系统控制能力，包括防止卸载、修改密码等。此外，静态分析也检测到该应用使用了动态代码加载 (Dynamic Loading) 和反射机制 (Reflection)，这通常被恶意软件用来加载混淆或加密的恶意载荷，以规避静态检测。

### 情报分析员（模型：`gpt-5`）
目标 APK 文件名为 tmpvaur8oj3.apk，包名 com.malmstein.yahnac（开源 Hacker News 客户端 Yahnac 的已知包名）。签名显示为 AOSP 测试证书（Subject/Issuer=Android, android@android.com；且存在 META-INF/TESTKEY.*），说明该样本并非官方商店签名构建，属于侧载/重签名或开发构建，信任链不明。静态权限仅为网络与唤醒锁，组件中包含 Firebase/GMS 常见服务，未见越权声明；静态图谱中反射与 DexClassLoader 调用计数高，更多源自支持库/三方库的兼容性与序列化路径，不能单凭计数判定恶意。动态沙箱在 12 秒窗口内正常安装启动，主要网络访问为 Google Play 日志端点，未见可疑外连或执行异常；“device_policy”“accessibility”持久化枚举疑似模拟器噪声，Manifest 并未显示对应组件。离线研判边界：缺乏官方分发渠道与开发者签名链校验、应用市场元数据与历史信誉，且动态运行时间短、交互有限，无法证实或排除隐藏行为。总体倾向为开源应用的非官方构建样本，技术风险低但供应链/来源风险需重视，建议以来源与分发渠道最终判定。

### 处置建议员（模型：`gpt-5.4-mini`）
建议暂不按恶意样本直接阻断分发，但必须先隔离留样并做二次沙箱复核。当前动态沙箱已确认可正常安装、可启动，运行窗口内出现 12 次网络命中，且静态图谱中存在高频反射、DexClassLoader、HttpURLConnection、Runtime.exec 等高风险能力特征，说明样本具备动态加载与远程通信的可疑基础；同时未见明确落地的恶意行为证据，因此不宜直接定性为已确认恶意，但也绝不建议直接放行安装或继续大范围分发。处置上应对该 APK 先隔离保存原样、保留哈希与日志留痕，阻断未知来源分发/二次传播，并在受控环境中复核其网络访问、动态加载及反射调用链。


### 主持人最终总结
综合四位专家意见：样本为开源 Hacker News 客户端的非官方构建，使用 AOSP 测试证书/通用调试密钥签名，信任链断裂且来源不明，存在被重签名或篡改的显著供应链风险。静态层面检测到 DexClassLoader、反射与 Runtime.exec 等能力，具备动态加载与潜在远程载荷执行的条件；在不可信签名前提下，这一能力组合构成结构性高风险。动态沙箱短时窗口内未观测到明显恶意外联（主要为 Google Play 日志端点），“设备管理员权限”与“安装后包被移除”的迹象存在争议：情报分析指出 Manifest 未见对应组件，可能为环境噪声，因而不足以据此定性为已实施恶意行为。基于当前证据，倾向判定为高风险的可疑样本（疑似被重签名且具备动态加载执行能力），不建议信任或分发，应先隔离留样、校验证书与来源并延长动态观测后再作处置。上述结论仅基于当前四位专家提供的静/动态与情报/处置意见，缺乏更长时间运行与官方签名链校验的确证支撑。


## 七、仲裁结果
- 一致性分数：`73`
- 一致性等级：`medium`
- 加权置信度：`60`
- 疑似污染源：behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 15 分
  - static-intelligence 差异 25 分
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
