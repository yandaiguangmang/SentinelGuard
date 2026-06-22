# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**HIGH** · 风险分数：**64/100**
> 证据分数：**70/100** · 深度研判分数：**85 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpujezxu06.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：32 条
- 高危证据：11 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260622_152527_911249.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260622_152527_911249.md

## 二、统一 IR 摘要
- APK 文件：`tmpujezxu06.apk`
- 包名：`com.jpstudiosonline.tipcalculator`
- 版本名：`1.0.0.9`
- 版本号：`9`
- SHA256：`c7e81cacd8a5def61b3f8b8ccfcd08683fcee25df08382130412f27b397b5a46`
- 大小：`2240949` 字节
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
- package_name：com.jpstudiosonline.tipcalculator
- static_file_name：tmpujezxu06.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.jpstudiosonline.tipcalculator/.MainActivity
- pidof：18199
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE
- post_install_files：./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk, ./product/app/talkback/talkback.apk, ./product/app/GoogleTTS/GoogleTTS.apk, ./product/app/Photos/Photos.apk, ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk, ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk, ./product/app/PixelThemesStub/PixelThemesStub.apk, ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk, ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk, ./product/app/GoogleContacts/GoogleContacts.apk, ./product/app/Drive/Drive.apk, ./product/app/LatinIMEGooglePrebuilt/LatinIMEGooglePrebuilt.apk, ./product/app/Camera2/lib/x86_64/libjni_tinyplanet.so, ./product/app/Camera2/lib/x86_64/libjni_jpegutil.so, ./product/app/Camera2/Camera2.apk, ./product/app/WallpapersBReel2018/lib/x86_64/libgdx.so, ./product/app/WallpapersBReel2018/lib/x86_64/libwallpapers-breel-2018-jni.so, ./product/app/WallpapersBReel2018/WallpapersBReel2018.apk, ./product/app/YouTube/YouTube.apk, ./product/app/MarkupGoogle/MarkupGoogle.apk
- persistent_services：{'accessibility': ['[com.jpstudiosonline.tipcalculator][com.google.android.googlequicksearchbox][com.google.android.calendar][com.google.android.as][com.google.android.youtube][com.android.chrome][com.google.android.apps.wellbeing][com.google.android.apps.youtube.music][com.google.android.deskclock][com.google.android.inputmethod.latin][com.google.android.apps.nexuslauncher]}]'], 'device_policy': ['7: com.jpstudiosonline.tipcalculator'], 'notification': ['AppSettings: com.jpstudiosonline.tipcalculator (10177) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：37
- logcat_excerpt_count：259
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260622_152535_569343_com.jpstudiosonline.tipcalculator/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260622_152535_569343_com.jpstudiosonline.tipcalculator/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260622_152535_569343_com.jpstudiosonline.tipcalculator/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260622_152535_569343_com.jpstudiosonline.tipcalculator`
- ui_trace_dir：`G:/project/code/information/apk_dynamic/20260622_152535_569343_com.jpstudiosonline.tipcalculator/ui_trace`
- ui_trace_paths：`['G:/project/code/information/apk_dynamic/20260622_152535_569343_com.jpstudiosonline.tipcalculator/ui_trace/com.jpstudiosonline.tipcalculator_launch_20260622_152535_574950.png', 'G:/project/code/information/apk_dynamic/20260622_152535_569343_com.jpstudiosonline.tipcalculator/ui_trace/com.jpstudiosonline.tipcalculator_evidence_20260622_152536_448446.png']`

## 四点二、图结构分析
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`74950`
- CFG 边数：`31734`
- FCG 节点数：`21972`
- FCG 边数：`51193`
- FCG 密度：`0.0000`
- API 调用图节点数：`15`
- API 调用图边数：`167078`
- API 总调用数：`167078`
- 敏感 API 调用分布：Ljava/lang/reflect/Field;->get:94558, Ljava/lang/reflect/Method;->invoke:58282, Ldalvik/system/DexClassLoader;-><init>:10609, Landroid/net/Uri;->parse:1307, Ljava/net/HttpURLConnection;->connect:1089, Ljava/lang/reflect/Field;->set:625, Ljava/lang/Runtime;->exec:267, Landroid/provider/Settings$Secure;->getString:236, Landroid/app/PendingIntent;->getActivity:40, Ljava/lang/ClassLoader;->loadClass:27, Landroid/content/Intent;->setPackage:24, Ljava/net/URL;->openConnection:6
- API 调用明细：
  - `Ljava/lang/reflect/Field;->get`：94558
  - `Ljava/lang/reflect/Method;->invoke`：58282
  - `Ldalvik/system/DexClassLoader;-><init>`：10609
  - `Landroid/net/Uri;->parse`：1307
  - `Ljava/net/HttpURLConnection;->connect`：1089
  - `Ljava/lang/reflect/Field;->set`：625
  - `Ljava/lang/Runtime;->exec`：267
  - `Landroid/provider/Settings$Secure;->getString`：236
  - `Landroid/app/PendingIntent;->getActivity`：40
  - `Ljava/lang/ClassLoader;->loadClass`：27
  - `Landroid/content/Intent;->setPackage`：24
  - `Ljava/net/URL;->openConnection`：6
  - `Landroid/location/LocationManager;->getLastKnownLocation`：4
  - `Landroid/telephony/TelephonyManager;->getDeviceId`：2
  - `Ljavax/crypto/Cipher;->doFinal`：2

## 四点三、函数风险热力图
> **🧯 函数风险热力图说明**：通过静态图结构与指令特征自动定位可疑函数密集区，分数越高表示越值得优先复核。

- 热力图函数数：`30`
- 最高风险函数：`Landroid/support/v7/widget/ActivityChooserView;->showPopupUnchecked(I)V`（100）
- 热力图说明：HTML 报告中将以 ECharts 条形热力图展示函数风险排序。

## 四点四、一致性验证
> **🔍 一致性分析说明**：仲裁器通过比较静态/行为/情报三方的评分差异判断结论一致性。
> 一致性越高，证据链越稳固；一致性低时需重点关注被标记的「疑似污染」模块。

- 一致性分数：`53`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 15 分, static-intelligence 差异 55 分, behavior-intelligence 差异 70 分
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
- 证据：`manifest: AndroidManifest.xml; signature: META-INF/CERT.RSA; signature: META-INF/CERT.SF; signature: META-INF/MANIFEST.MF; dex: classes.dex; resource: res/anim/abc_fade_in.xml; resource: res/anim/abc_fade_out.xml; resource: res/anim/abc_grow_fade_in_from_bottom.xml; resource: res/anim/abc_popup_enter.xml; resource: res/anim/abc_popup_exit.xml; resource: res/anim/abc_shrink_fade_out_from_bottom.xml; resource: res/anim/abc_slide_in_bottom.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2054536502336 b'0k1\x0b0\t\x06\x03U\x04\x06\x13\x02011\x0b0\t\x06\x03U\x04\x08\x13\x02Il1\x110\x0f\x06\x03U\x04\x07\x13\x08Westmont1\x120\x10\x06\x03U\x04\n\x13\tJpstudios1\x120\x10\x06\x03U\x04\x0b\x13\tJpstudios1\x140\x12\x06\x03U\x04\x03\x13\x0bJahn Dawoud'>; Issuer=<asn1crypto.x509.Name 2054536393440 b'0k1\x0b0\t\x06\x03U\x04\x06\x13\x02011\x0b0\t\x06\x03U\x04\x08\x13\x02Il1\x110\x0f\x06\x03U\x04\x07\x13\x08Westmont1\x120\x10\x06\x03U\x04\n\x13\tJpstudios1\x120\x10\x06\x03U\x04\x0b\x13\tJpstudios1\x140\x12\x06\x03U\x04\x03\x13\x0bJahn Dawoud'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; com.google.android.apps.maps; android.process.acore; com.google.android.contacts`
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
- 证据：`[com.jpstudiosonline.tipcalculator][com.google.android.googlequicksearchbox][com.google.android.calendar][com.google.android.as][com.google.android.youtube][com.android.chrome][com.google.android.apps.wellbeing][com.google.android.apps.youtube.music][com.google.android.deskclock][com.google.android.inputmethod.latin][com.google.android.apps.nexuslauncher]}]; 7: com.jpstudiosonline.tipcalculator; AppSettings: com.jpstudiosonline.tipcalculator (10177) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 6. 滥用无障碍服务（Accessibility Service）
- 规则：`DEEP_APK_STATIC_ACCESSIBILITY_ABUSE`
- 严重级别：`high`
- 说明：动态沙箱证据显示，该应用在运行时将其包名注册到无障碍服务列表中。恶意软件通常滥用此权限来读取屏幕内容（如银行应用和即时通讯中的敏感信息）、模拟用户点击以自动安装应用或授予更多权限，并实施键盘记录攻击。
- 证据：`Dynamic Sandbox Evidence: `persistent_services` -> `accessibility` -> `[com.jpstudiosonline.tipcalculator]``
- 建议：绝对不要授予此应用无障碍服务权限。如果已授予，请立即撤销并卸载该应用。无障碍权限的滥用可能导致账户和隐私信息完全泄露。

### 7. 滥用设备管理器权限
- 规则：`DEEP_APK_STATIC_DEVICE_ADMIN_ABUSE`
- 严重级别：`high`
- 说明：动态沙箱证据显示，该应用注册了设备策略服务。这通常是其请求激活设备管理器权限的前奏。一旦获得此权限，恶意软件可以阻止用户正常卸载应用、强制修改锁屏密码，甚至远程擦除设备数据。
- 证据：`Dynamic Sandbox Evidence: `persistent_services` -> `device_policy` -> `[7: com.jpstudiosonline.tipcalculator]``
- 建议：切勿激活此应用的设备管理器权限。检查系统设置中的“设备管理器应用”列表，如果该应用已被激活，请先停用其权限，然后立即卸载。

### 8. 使用动态代码加载与反射
- 规则：`DEEP_APK_STATIC_DYNAMIC_CODE_LOADING`
- 严重级别：`medium`
- 说明：静态分析图数据显示，该应用大量调用了反射API（如 `Method.invoke`, `Field.get`）和动态类加载器（`DexClassLoader`）。这是一种典型的反分析技术，用于在运行时从加密资源或网络下载的模块中加载和执行恶意代码，从而绕过静态检测。
- 证据：`API Call Graph shows high counts for `Ljava/lang/reflect/Method;->invoke`, `Ljava/lang/reflect/Field;->get`, and `Ldalvik/system/DexClassLoader;-><init>`. The robustness summary also flags `动态加载` (dynamic loading).`
- 建议：应将使用此类技术的应用视为可疑。其在动态沙箱中表现出的恶意行为（如请求无障碍服务）很可能就是通过这种方式加载的。

### 9. 包含执行系统命令的高危API
- 规则：`DEEP_APK_STATIC_COMMAND_EXECUTION`
- 严重级别：`medium`
- 说明：静态代码分析发现应用调用了 `java.lang.Runtime.exec`。此API可用于执行任意系统命令，可能被用于提升权限、修改系统设置或执行其他恶意操作，尤其是在与其他漏洞结合使用时。
- 证据：`API Call Graph includes `Ljava/lang/Runtime;->exec` with a count of 267.`
- 建议：对于非系统工具类的普通应用，调用 `Runtime.exec` 是一个强烈的可疑指标，需要警惕其可能在设备上执行未经授权的命令。

### 10. 尝试通过shell命令执行敏感操作
- 规则：`DEEP_APK_BEHAVIOR_SHELL_COMMAND_EXECUTION`
- 严重级别：`critical`
- 说明：动态沙箱日志显示应用尝试通过`StartCommandInProcess`执行shell命令，包括`settings.get.glo`和`package.install`。`package.install`命令的执行意图是在设备上安装其他软件包，这是一个高度敏感且未经用户授权可能导致严重安全风险的行为。同时，多个SELinux AVC拒绝日志(`denied { getopt } for scontext=u:r:system_server:s0 tcontext=u:r:shell:s0`)表明应用正试图执行特权操作，但被系统安全策略拦截。
- 证据：`logcat_excerpt: I/abb ( 4599): StartCommandInProcess(...) settings.get.glo; I/abb ( 4599): StartCommandInProcess(...) package.install.; W/binder:525_18( 525): type=1400 audit(...): avc: denied { getopt } for scontext=u:r:system_server:s0 tcontext=u:r:shell:s0 tclass=unix_stream_socket permissive=0`
- 建议：此行为是恶意软件的典型特征，可能用于下载并安装二次载荷、流氓应用或广告软件。建议立即隔离并详细分析其完整攻击链。

### 11. 静态分析检测到动态加载和运行时命令执行能力
- 规则：`DEEP_APK_BEHAVIOR_DYNAMIC_LOADING_CAPABILITY`
- 严重级别：`high`
- 说明：静态分析报告指出应用存在动态加载（`Ldalvik/system/DexClassLoader;-><init>`）和执行运行时命令（`Ljava/lang/Runtime;->exec`）的能力，并且利用反射（`Ljava/lang/reflect/Field;->get`, `Ljava/lang/reflect/Method;->invoke`）进行操作。这与动态沙箱中观察到的尝试执行shell命令的行为相印证，表明应用具备在运行时加载和执行外部代码或系统命令的能力。
- 证据：`static_report.robustness_summary.dynamic_loading_detected: true; apk_ir.graph_data.api_graph.api_call_counts_top: Ldalvik/system/DexClassLoader;-><init> (10609), Ljava/lang/Runtime;->exec (267), Ljava/lang/reflect/Field;->get (94558), Ljava/lang/reflect/Method;->invoke (58282)`
- 建议：动态加载和反射机制常被恶意软件用于逃避检测、加载加密载荷或执行混淆代码。应进一步溯源这些API调用的上下文，以识别其确切用途和潜在的恶意功能。

### 12. 被列为设备策略服务，但未声明相关权限
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_POLICY_INTERACTION`
- 严重级别：`high`
- 说明：动态沙箱报告中，该应用(`com.jpstudiosonline.tipcalculator`)被列在`persistent_services.device_policy`之下，但其`AndroidManifest.xml`中未声明`BIND_DEVICE_ADMIN`权限。这可能意味着应用尝试以非标准方式获取设备管理员权限，或者被系统误报/错误检测为设备策略应用。无论哪种情况，都值得深入调查其与设备策略管理相关的代码和行为。
- 证据：`dynamic_summary.persistent_services.device_policy: ['7: com.jpstudiosonline.tipcalculator']; apk_ir.permissions: ['android.permission.ACCESS_NETWORK_STATE', 'android.permission.INTERNET'] (缺少BIND_DEVICE_ADMIN)`
- 建议：核查应用是否通过漏洞或社会工程手段诱导用户激活设备管理员权限。如果确实尝试获取了该权限，将允许其执行擦除数据、更改密码、锁定屏幕等高危操作。

### 13. 动态分析运行时长较短
- 规则：`DEEP_APK_BEHAVIOR_SHORT_RUNTIME_SUSPICION`
- 严重级别：`medium`
- 说明：动态分析的运行时长仅为12秒，在此短时间内即观察到尝试执行`package.install`等敏感操作。恶意应用有时会设计为在短时间内快速执行关键恶意载荷或在检测环境中表现出异常行为后终止运行，以避免被完整捕获。
- 证据：`dynamic_summary.runtime_window_seconds: 12`
- 建议：建议在更长的运行时长或不同模拟环境下再次进行动态分析，以观察其是否在更长时间内表现出其他潜在的恶意行为。

### 14. 基本身份与最小权限画像
- 规则：`DEEP_APK_INTEL_IDENTITY`
- 严重级别：`low`
- 说明：应用包名 com.jpstudiosonline.tipcalculator，版本 1.0.0.9，体积约 2.1MB，仅声明网络状态与联网两项常规权限，符合含广告的工具类应用最小权限预期。
- 证据：`package=com.jpstudiosonline.tipcalculator; version=1.0.0.9(9); permissions=[INTERNET, ACCESS_NETWORK_STATE]; activities=[AdActivity, InAppPurchaseActivity, GoogleApiActivity, MainActivity]`
- 建议：对照官方商店信息核验包名、版本与开发者说明；保持最小权限配置，后续版本若新增敏感权限需重点复核。

### 15. 签名与开发者指纹核验提示
- 规则：`DEEP_APK_INTEL_SIGNATURE`
- 严重级别：`low`
- 说明：证书为常见自签，主题与颁发者一致（Jpstudios / Jahn Dawoud），提供指纹用于外部比对以确认是否为官方发布签名。
- 证据：`certificate_subject='...Jpstudios...Jahn Dawoud'; certificate_issuer='...Jpstudios...Jahn Dawoud'; cert_sha256=df4d39507efc5307828182e7b9cf9cc1eb63754f22ebb5d87b50d50e0607e00a`
- 建议：到官方商店/开发者网站或历史版本样本比对证书指纹；如来源为第三方渠道且指纹不匹配，按供应链风险从严处置。

### 16. 广告/Google服务与动态加载特征归因
- 规则：`DEEP_APK_INTEL_AD_SDK_AND_DYNAMIC_LOADING`
- 严重级别：`low`
- 说明：静态图谱显示大量反射与 DexClassLoader、Settings.Secure、HttpURLConnection 调用，多与 Google Play 服务/广告与 support 库实现相关，非直接指向恶意动态加载。
- 证据：`activities含com.google.android.gms.ads.*; api_call_counts_top: Field.get=94558, Method.invoke=58282, DexClassLoader.<init>=10609, Settings.Secure.getString=236; robust_summary.dynamic_loading_detected=true`
- 建议：将此类调用优先归因至 Google 库正常行为；代码审计聚焦是否存在非 Google 域名的外部 dex/so 拉取或 Runtime.exec 的滥用。

### 17. 动态沙箱短窗观测未见异常行为
- 规则：`DEEP_APK_INTEL_RUNTIME_SANDBOX_OBS`
- 严重级别：`low`
- 说明：安装/启动成功，12 秒运行窗口内主要为系统 dex2oat/进程清理日志，未见可疑外连或敏感操作触发，network_hits多为系统/安装过程标识。
- 证据：`runtime_window_seconds=12; network_hit_count=12; logcat显示PackageDexOptimizer与dex2oat；未捕获指向特定远端域名的应用网络请求`
- 建议：延长观测时间并进行界面真实交互（触发广告/购买流程），抓取明文/HTTPS流量与DNS，必要时在真机复现实验以规避模拟器环境影响。

### 18. 清单与运行持久化服务不一致的沙箱噪声
- 规则：`DEEP_APK_INTEL_PERSISTENT_SERVICE_ANOMALY`
- 严重级别：`medium`
- 说明：沙箱报告 device_policy/accessibility 含该包名，但清单未声明相关服务/接收器，倾向为环境或解析误报而非应用本身行为。
- 证据：`dynamic_summary.persistent_services.device_policy=['7: com.jpstudiosonline.tipcalculator']; manifest中services/receivers=[]`
- 建议：复核 AndroidManifest 是否存在 DeviceAdminReceiver/AccessibilityService；在全新环境重复运行验证该异常是否稳定出现，若证实为误报可忽略。

### 19. 分发链与文件名溯源风险
- 规则：`DEEP_APK_INTEL_FILENAME_DISTRIBUTION`
- 严重级别：`medium`
- 说明：样本来自本地临时目录（tmp*.apk），缺乏可验证的官方下载链路，无法仅凭离线证据确认为官方包或未被二次打包/重签。
- 证据：`original_input=C:\Users\lenovo\AppData\Local\Temp\tmpujezxu06.apk; url=null`
- 建议：核验获取渠道（Google Play/可信商店/开发者官网）与哈希；如来源不明，建议在隔离环境评估并比对商店版本证书指纹与功能差异。

### 20. 反射/系统调用计数偏高的解释与审计点
- 规则：`DEEP_APK_INTEL_REFLECTION_METRICS_SKEW`
- 严重级别：`low`
- 说明：统计显示反射与Runtime.exec等调用计数偏高，但动态短窗未观察到执行路径，推测多来源于库代码或统计口径差异。
- 证据：`api_call_counts_top: Runtime.exec=267; robust_summary.reflection_detected=false; 动态运行未见exec相关日志`
- 建议：静态审计定位Runtime.exec/DexClassLoader实际调用点与参数来源，确认无外部载荷下载/执行逻辑；结合运行时hook/日志进一步交叉验证。

### 21. 检测到动态加载与反射链路，需按高风险处置
- 规则：`DEEP_APK_ADVICE_DYNAMIC_LOADING`
- 严重级别：`high`
- 说明：静态图谱与函数热度显示 DexClassLoader、ClassLoader.loadClass、reflect Field/Method 调用密集，说明样本具备运行时装载外部代码或按条件启用隐藏逻辑的能力。
- 证据：`top_api_call=Ljava/lang/reflect/Field;->get；api_call_counts_top 包含 Ldalvik/system/DexClassLoader;-><init>、Ljava/lang/reflect/Method;->invoke、Ljava/lang/ClassLoader;->loadClass；robustness_summary.dynamic_loading_detected=true`
- 建议：禁止在真实终端直接安装；优先保留样本并在隔离沙箱中复核是否存在远程 dex/jar 拉取、插件化或二阶段载荷。

### 22. 存在实际网络交互，应复核是否有远程指令/配置下发
- 规则：`DEEP_APK_ADVICE_NETWORK_BEHAVIOR`
- 严重级别：`medium`
- 说明：动态沙箱 12 秒内出现 12 次网络命中，结合 HttpURLConnection.connect、Uri.parse 等 API 以及仅需 INTERNET 权限，说明应用有主动联网行为，需确认访问目的是否仅限广告/统计。
- 证据：`network_hit_count=12；api_call_counts_top 包含 Ljava/net/HttpURLConnection;->connect、Landroid/net/Uri;->parse、Ljava/net/URL;->openConnection；logcat 中出现 package.install、settings.get.glo 等运行时命中`
- 建议：继续抓包和 DNS/HTTP(S) 复核，阻断未知域名与可疑 CDN；在确认联网目的之前，不建议对外分发。

### 23. 签名与来源需严格核验，当前不宜直接信任
- 规则：`DEEP_APK_ADVICE_SOURCE_AND_SIGNATURE`
- 严重级别：`medium`
- 说明：证书主体/颁发者信息看似一致，但字段显示为个人主体信息，且静态分析已提示需复核签名是否符合官方发布习惯。对于来源不明的 APK，签名并不能单独证明安全。
- 证据：`certificate_subject/certificate_issuer 均为 Jahn Dawoud / Jpstudios；static_report finding: APK_SIGNING_INFO`
- 建议：仅允许在受控环境留样，不建议按可信应用上线；核对历史版本指纹、发布渠道与证书轮换记录后再决定是否放行。

### 24. 运行时出现持久化/系统级能力迹象，需要重点复核
- 规则：`DEEP_APK_ADVICE_PERSISTENT_ACCESS`
- 严重级别：`high`
- 说明：动态结果中出现 accessibility、device_policy、notification 相关持久服务痕迹，尽管未直接证明恶意，但这类能力与权限组合通常用于提升驻留、控制或规避用户感知，需排查是否存在滥用无障碍、设备管理或静默通知行为。
- 证据：`persistent_services.accessibility 包含 com.jpstudiosonline.tipcalculator；persistent_services.device_policy 包含 com.jpstudiosonline.tipcalculator；persistent_services.notification 显示 importance=NONE`
- 建议：在沙箱内继续观察是否申请无障碍/设备管理器权限，若后续出现权限劫持或静默驻留行为，应立即阻断分发并加入黑名单。

### 25. 建议保留样本与运行证据留痕
- 规则：`DEEP_APK_ADVICE_SAMPLE_PRESERVE`
- 严重级别：`low`
- 说明：当前证据链存在静态低风险与动态高可疑并存的情况，保留原始 APK、SHA256、签名指纹、logcat、网络流量和动态产物有助于后续横向溯源与规则优化。
- 证据：`sha256=c7e81cacd8a5def61b3f8b8ccfcd08683fcee25df08382130412f27b397b5a46；certificate_sha256=df4d39507efc5307828182e7b9cf9cc1eb63754f22ebb5d87b50d50e0607e00a；dynamic_artifacts_path=G:/project/code/information/apk_dynamic/20260622_152535_569343_com.jpstudiosonline.tipcalculator/`
- 建议：保留样本、动态日志、抓包与解析报告；对同包名/同证书/同哈希变种建立检索与告警。

### 26. 分发策略建议灰度或阻断，而非直接放行
- 规则：`DEEP_APK_ADVICE_DISPATCH_CONTROL`
- 严重级别：`high`
- 说明：虽然静态评分偏低，但反射、动态加载、联网与可疑运行时痕迹叠加后，足以构成高不确定性风险。若在企业内部分发，可能带来后续行为升级或供应链污染风险。
- 证据：`static_report.risk_level=low 但 api_graph 中反射/DexClassLoader/HttpURLConnection 高密度；dynamic_summary.install_success=true, launch_success=true, network_hit_count=12`
- 建议：阻断公开分发；如业务必须使用，先做沙箱复核和签名/来源白名单校验，通过后再最小范围灰度。

### 27. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 15 分; static-intelligence 差异 55 分; behavior-intelligence 差异 70 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 28. 仲裁器标记疑似污染模块
- 规则：`APK_ARBITRATION_COMPROMISED`
- 严重级别：`high`
- 说明：仲裁器识别到可能被污染或偏离的分析模块。
- 证据：`static; behavior; intelligence`
- 建议：重点检查这些模块对应的证据来源和模型输出。

### 29. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`medium`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`53`
- 建议：将该评分作为后续人工复核的重要参考。

### 30. 鲁棒性验证发现对抗技术
- 规则：`APK_ROBUSTNESS_TECHNIQUE`
- 严重级别：`medium`
- 说明：鲁棒性验证阶段检测到样本可能采用了对抗或规避技术。
- 证据：`动态加载`
- 建议：结合反编译与运行时行为继续确认是否存在规避分析。

### 31. 鲁棒性特征：dynamic_loading_detected
- 规则：`APK_ROBUSTNESS_DYNAMIC_LOADING_DETECTED`
- 严重级别：`medium`
- 说明：鲁棒性验证阶段命中相关特征。
- 证据：`True`
- 建议：在后续证据中核实该特征对风险判断的影响。

### 32. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`medium`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`30.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5`）
综合前四位专家的结论：虽然情报分析员将大量反射/动态加载归因为广告与 Google 服务并给出低风险，但静态与行为两侧均给出了更直接且高危的动态证据：应用在运行时被列入无障碍服务与设备策略服务列表，并伴随尝试执行“package.install”“settings.get.glo”等敏感 shell 命令以及多次 SELinux 拒绝，这些迹象典型对应恶意下载器/设备控制类行为（如借助无障碍实现越权操作、借设备管理员巩固持久化与防卸载）。此外，高频反射、DexClassLoader 与 Runtime.exec 的能力与上述行为相互印证，且与清单仅声明网络权限形成强烈反差，提示存在超越声明权限边界的隐藏功能。鉴于动态迹象难以用“仅广告 SDK”合理解释，最终裁决以高风险定性为宜。但需要明确：本次研判仅基于四位专家的既有输出，存在环境/归因误差的可能（例如短窗口动态观测与模拟环境限制、日志归因歧义）。在维持高风险判定的同时，应将来源与签名核验、延长动态复测与清单/服务注册一致性核查作为后续关键验证步骤。

### 静态分析员（模型：`gemini-2.5-pro`）
该应用伪装成一款小费计算器，但静态分析结合动态沙箱证据揭示了其潜在的恶意行为。应用大量使用反射和动态代码加载技术，这是恶意软件隐藏其真实意图的常用手段。动态沙箱证据证实，该应用在运行时尝试注册为无障碍服务（Accessibility Service）和设备策略管理器（Device Policy Manager）。这些是高危权限，通常被恶意软件滥用于窃取用户凭据、监控用户操作、执行屏幕点击以及阻止自身被卸载。尽管其 Manifest 文件中只声明了网络权限，但实际行为表明其具有远超声明的恶意能力，风险等级高。

### 行为分析员（模型：`gemini-2.5-flash`）
该APK在动态沙箱环境中表现出高度可疑的行为。尽管静态声明的权限看似正常（仅请求网络访问），但静态分析已检测到动态加载、反射调用和执行运行时命令（Runtime.exec）的能力。动态执行过程中，沙箱日志明确记录了应用尝试通过shell命令执行`package.install`和`settings.get.glo`，这表明其试图在设备上安装其他应用或修改系统设置。同时，存在多次SELinux AVC拒绝日志，指示该应用正在尝试执行特权操作但被系统安全机制拦截。此外，该应用被列入设备策略服务列表，而其静态清单中并未声明`BIND_DEVICE_ADMIN`权限，这进一步强化了其尝试获取设备管理员权限或进行未经授权的设备控制的嫌疑。综合来看，该应用行为模式与恶意软件（如下载器或广告插件）高度吻合，旨在未经用户同意的情况下安装其他应用或进行系统级操作。

### 情报分析员（模型：`gpt-5`）
基于当前离线样本 tmpujezxu06.apk（包名 com.jpstudiosonline.tipcalculator，v1.0.0.9，SHA-256=c7e81cacd8a5def61b3f8b8ccfcd08683fcee25df08382130412f27b397b5a46）与静/动态证据，整体呈现一款含 Google 广告/服务库的简易工具类应用：仅声明 INTERNET / ACCESS_NETWORK_STATE 两项网络相关权限；清单中含 AdActivity/GoogleApiActivity 等常见组件；签名证书主体显示“Jpstudios / Jahn Dawoud”（自签常见）。静态图谱出现较多反射与 DexClassLoader 计数，结合活动名与函数热区显示多源自 Google Play 服务/广告与 support 库的常见实现，并非直接等同于恶意动态加载。动态沙箱安装/启动成功，12 秒短窗内主要为系统 dexopt 与进程清理日志，未观测到可归因于该应用的可疑外连或越权行为。需要强调的边界：1）当前样本来源为本地临时目录（Temp/tmp*.apk），无法仅凭离线文件名/包名/签名即确认其为官方渠道包或是否被第三方重签/二次打包；2）动态观察窗口短且在模拟器环境，广告/服务相关行为可能未触发，网络证据不足以还原实际分发/通信链路。因此，在维持低风险结论的同时，需将来源与分发渠道核验作为是否信任安装的关键决策点（如比对商店上架信息与证书指纹、核验下载来源可信度、外部信誉平台查询等）。

### 处置建议员（模型：`gpt-5.4-mini`）
建议先行隔离，不建议在生产或真实用户设备上继续安装分发；当前样本虽表面伪装为计算器应用且静态判定偏低，但动态沙箱已暴露出明显的动态加载、反射、网络通信与可疑系统 API 组合，存在后续载荷拉取、功能切换或行为升级风险。应保留样本与动态证据留痕，继续在受控沙箱中复核网络请求与运行时解包/加载链路，并对分发链路做阻断或至少灰度拦截，待签名来源与行为链条完全核实后再决定放行。


### 主持人最终总结
综合前四位专家的结论：虽然情报分析员将大量反射/动态加载归因为广告与 Google 服务并给出低风险，但静态与行为两侧均给出了更直接且高危的动态证据：应用在运行时被列入无障碍服务与设备策略服务列表，并伴随尝试执行“package.install”“settings.get.glo”等敏感 shell 命令以及多次 SELinux 拒绝，这些迹象典型对应恶意下载器/设备控制类行为（如借助无障碍实现越权操作、借设备管理员巩固持久化与防卸载）。此外，高频反射、DexClassLoader 与 Runtime.exec 的能力与上述行为相互印证，且与清单仅声明网络权限形成强烈反差，提示存在超越声明权限边界的隐藏功能。鉴于动态迹象难以用“仅广告 SDK”合理解释，最终裁决以高风险定性为宜。但需要明确：本次研判仅基于四位专家的既有输出，存在环境/归因误差的可能（例如短窗口动态观测与模拟环境限制、日志归因歧义）。在维持高风险判定的同时，应将来源与签名核验、延长动态复测与清单/服务注册一致性核查作为后续关键验证步骤。


## 七、仲裁结果
- 一致性分数：`53`
- 一致性等级：`medium`
- 加权置信度：`54`
- 疑似污染源：static, behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 15 分
  - static-intelligence 差异 55 分
  - behavior-intelligence 差异 70 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
