# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**LOW** · 风险分数：**29/100**
> 证据分数：**50/100** · 深度研判分数：**60 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpr5q3f06g.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：30 条
- 高危证据：2 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260620_233450_186559.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260620_233450_186559.md

## 二、统一 IR 摘要
- APK 文件：`tmpr5q3f06g.apk`
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
- static_file_name：tmpr5q3f06g.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：23406
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：无
- persistent_services：{'accessibility': ['[com.google.android.as][com.google.android.inputmethod.latin][com.google.android.apps.nexuslauncher][com.malmstein.yahnac][com.google.android.apps.wellbeing][com.google.android.googlequicksearchbox]}]'], 'device_policy': ['6: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：37
- logcat_excerpt_count：221
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260620_233451_669650_com.malmstein.yahnac/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260620_233451_669650_com.malmstein.yahnac/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260620_233451_669650_com.malmstein.yahnac/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260620_233451_669650_com.malmstein.yahnac`

## 四点二、图结构分析
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`131441`
- CFG 边数：`56787`
- FCG 节点数：`37635`
- FCG 边数：`85716`
- FCG 密度：`0.0000`
- API 调用图节点数：`14`
- API 调用图边数：`288`
- API 总调用数：`288`
- 敏感 API 调用分布：Ljava/lang/reflect/Method;->invoke:81, Ljava/lang/reflect/Field;->get:74, Ljava/lang/reflect/Field;->set:33, Ljava/lang/Class;->forName:32, Landroid/net/Uri;->parse:23, Landroid/content/Intent;->setPackage:18, Ljava/lang/ClassLoader;->loadClass:11, Landroid/app/PendingIntent;->getActivity:5, Ljava/net/URL;->openConnection:3, Landroid/provider/Settings$Secure;->getString:2, Ljava/net/HttpURLConnection;->connect:2, Ljava/net/Socket;->connect:2
- API 调用明细：
  - `Ljava/lang/reflect/Method;->invoke`：81
  - `Ljava/lang/reflect/Field;->get`：74
  - `Ljava/lang/reflect/Field;->set`：33
  - `Ljava/lang/Class;->forName`：32
  - `Landroid/net/Uri;->parse`：23
  - `Landroid/content/Intent;->setPackage`：18
  - `Ljava/lang/ClassLoader;->loadClass`：11
  - `Landroid/app/PendingIntent;->getActivity`：5
  - `Ljava/net/URL;->openConnection`：3
  - `Landroid/provider/Settings$Secure;->getString`：2
  - `Ljava/net/HttpURLConnection;->connect`：2
  - `Ljava/net/Socket;->connect`：2
  - `Landroid/location/LocationManager;->getLastKnownLocation`：1
  - `Lorg/apache/http/client/HttpClient;->execute`：1

## 四点三、一致性验证
- 一致性分数：`65`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 43 分, static-intelligence 差异 53 分, behavior-intelligence 差异 10 分
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
- 证据：`Subject=<asn1crypto.x509.Name 1697519202416 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>; Issuer=<asn1crypto.x509.Name 1697519206208 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl2056526158.tmp; com.malmstein.yahnac; base.dm`
- 建议：后续可结合抓包或代理进行复核。

### 4. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.as][com.google.android.inputmethod.latin][com.google.android.apps.nexuslauncher][com.malmstein.yahnac][com.google.android.apps.wellbeing][com.google.android.googlequicksearchbox]}]; 6: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 5. 应用使用调试证书签名
- 规则：`DEEP_APK_STATIC_DEBUG_SIGNATURE`
- 严重级别：`high`
- 说明：该APK文件使用了标准的Android调试证书进行签名。使用调试证书发布的应用程序存在严重安全风险，因为它允许任何人创建并安装该应用的恶意更新版本，从而可能窃取用户数据或控制设备。这表明该应用可能是一个未经官方发布的开发版本，或者已被恶意重打包。
- 证据：`Certificate Subject/Issuer: CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US, Email=android@android.com`
- 建议：绝对不要安装和使用以来源不明的渠道、并使用调试证书签名的应用。如果需要使用该应用，请务必从官方或可信的应用商店下载，并验证其签名是否为开发者官方签名。

### 6. 代码中检测到反射调用
- 规则：`DEEP_APK_STATIC_REFLECTION_USAGE`
- 严重级别：`low`
- 说明：代码中检测到多处使用Java反射API（如 `Method.invoke`, `Class.forName`）。虽然反射是正常开发技术，常用于框架和库中，但也可能被恶意软件用于隐藏恶意行为、动态加载代码或绕过静态检测。在此样本中，多数反射调用与Android支持库相关，未直接发现恶意意图，但该技术本身值得关注。
- 证据：`API Calls: Ljava/lang/reflect/Method;->invoke (81 times), Ljava/lang/reflect/Field;->get (74 times), Ljava/lang/Class;->forName (32 times)`
- 建议：当应用同时存在反射调用和可疑行为（如动态代码加载、连接未知服务器）时，应重点审查反射调用的上下文，以确定其真实目的。

### 7. 第三方 SDK 行为特征
- 规则：`DEEP_APK_BEHAVIOR_NORMAL_SDK_INTEGRATION`
- 严重级别：`low`
- 说明：应用集成了 Google Firebase 和 Android Support 库，运行时产生的反射调用和网络请求属于 SDK 正常功能范围。
- 证据：`动态日志显示 FirebaseCrashReceiverService 和 AppMeasurementService 正常初始化；静态分析显示大量反射调用指向 Android Support 库。`
- 建议：无需特殊处置，属于常规应用行为。

### 8. 运行时环境兼容性告警
- 规则：`DEEP_APK_BEHAVIOR_RUNTIME_STABILITY`
- 严重级别：`low`
- 说明：在沙箱运行期间，dex2oat 进程报告了 CPU 变体不匹配及部分系统权限拒绝（getopt），这属于模拟器环境下的常见兼容性问题，非恶意行为。
- 证据：`logcat 中出现 'Unexpected CPU variant for x86' 及 'avc: denied { getopt }' 审计日志。`
- 建议：忽略此类环境适配告警。

### 9. 敏感权限合规性
- 规则：`DEEP_APK_BEHAVIOR_PERMISSION_USAGE`
- 严重级别：`low`
- 说明：应用申请的权限（INTERNET, WAKE_LOCK 等）与其作为新闻阅读类应用的业务逻辑相符。
- 证据：`动态沙箱中已授权权限列表与 Manifest 声明一致，未发现越权行为。`
- 建议：保持常规监控。

### 10. 检测到 TESTKEY/非生产签名，需确认来源可信度
- 规则：`DEEP_APK_INTEL_TESTKEY_SIGNATURE`
- 严重级别：`medium`
- 说明：APK 使用默认测试/非生产证书签名（META-INF/TESTKEY.*，证书主体为通用 Android），与官方商店发布习惯不符，存在第三方重打包或非官方构建的供应链风险。
- 证据：`META-INF/TESTKEY.SF, META-INF/TESTKEY.RSA; certificate_subject=Android/android@android.com; certificate_sha256=c5375e7bef9b109995f75a87d719eddc38e88ce6f21b74f66258841e36e51d39`
- 建议：仅信任来自官方渠道（Google Play/开发者官网/GitHub Release/FDroid）的安装包；以证书 SHA-256 指纹比对历史可信版本；企业环境可对 TESTKEY 签名应用设为阻断或隔离策略。

### 11. 权限基线为网络与唤醒类，未声明高危隐私权限
- 规则：`DEEP_APK_INTEL_PERMISSIONS_BASELINE`
- 严重级别：`low`
- 说明：仅请求 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK 及 GCM/自定义消息权限，符合新闻类应用常见最小权限集，未见存取联系人、短信、通话记录、文件系统或定位权限声明。
- 证据：`permissions=[INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK, com.google.android.c2dm.permission.RECEIVE, com.malmstein.yahnac.permission.C2D_MESSAGE]`
- 建议：保持按需授权与网络访问最小化审计；结合动态抓包核验是否存在越权数据收集。

### 12. 包含 Firebase Crash/Measurement 组件，可能收集设备标识
- 规则：`DEEP_APK_INTEL_FIREBASE_ANALYTICS`
- 严重级别：`low`
- 说明：存在 Firebase Crash/Measurement 服务与 Provider，API 图谱出现 Settings.Secure.getString（可能用于 ANDROID_ID）。属常见分析/崩溃上报行为，但应关注隐私合规与告知。
- 证据：`services=[AppMeasurementService, FirebaseCrashReceiverService, FirebaseCrashSenderService]; providers=[FirebaseInitProvider]; API: Settings.Secure.getString x2`
- 建议：核查隐私政策与用户告知；如在企业网络，按需限制相关域名外连或启用基线流量监控。

### 13. 动态沙箱观测窗口较短且为模拟器环境，证据有限
- 规则：`DEEP_APK_INTEL_DYNAMIC_WINDOW_LIMITED`
- 严重级别：`low`
- 说明：仅在模拟器运行约 12 秒，未捕获明确外联域名，日志多为安装与 dex 优化过程，无法排除延时触发或深层交互路径的网络行为。
- 证据：`runtime_window_seconds=12; network_hit_count=12（多为系统安装产物，如 base.apk/base.odex 等）; logcat_path=.../logcat_excerpt.txt`
- 建议：延长动态观测至 3–5 分钟以上，模拟登录/浏览/通知交互并抓取 DNS/HTTP(S) 流量；必要时在真机环境复测。

### 14. 自定义 ContentProvider 暴露面需复核
- 规则：`DEEP_APK_INTEL_PROVIDER_EXPORTED_REVIEW`
- 严重级别：`low`
- 说明：应用包含自有 Provider（com.malmstein.yahnac.data.HNewsProvider），当前离线证据未给出 exported 与读写权限配置，如配置不当可能导致数据被越权访问。
- 证据：`providers=[com.malmstein.yahnac.data.HNewsProvider]; manifest 文件已提取但未见导出属性细节`
- 建议：复查 AndroidManifest.xml 中 Provider 的 exported、grantUriPermissions、读写权限；使用 adb content query 进行本地访问测试以验证访问控制。

### 15. 沙箱列出 device_policy/accessibility 项含本包名，疑似噪声需核验
- 规则：`DEEP_APK_INTEL_SANDBOX_DEVICE_POLICY_ANOMALY`
- 严重级别：`medium`
- 说明：动态摘要在 device_policy/accessibility 清单中包含 com.malmstein.yahnac，但 Manifest 未见对应 DeviceAdminReceiver/AccessibilityService 及相关权限，可能为沙箱侧枚举误差或环境噪声。
- 证据：`persistent_services.device_policy=['6: com.malmstein.yahnac']; permissions 未含 BIND_DEVICE_ADMIN/BIND_ACCESSIBILITY_SERVICE；组件清单未见对应服务`
- 建议：在目标设备执行 adb shell dumpsys device_policy 与 dumpsys accessibility 交叉核验；审阅 Manifest 及代码是否注册 DeviceAdminReceiver/AccessibilityService；如未发现对应实现，则可判定为误报。

### 16. 需结合来源与分发渠道完成信誉核验
- 规则：`DEEP_APK_INTEL_SOURCE_CHAIN_VALIDATION`
- 严重级别：`low`
- 说明：包名与开源新闻客户端命名一致，但签名为 TESTKEY，存在非官方构建的可能。未进行线上信誉与商店签名比对，离线无法最终定性。
- 证据：`package_name=com.malmstein.yahnac; certificate_sha256=c5375e7b...; 文件名为临时名 tmpr5q3f06g.apk（非官方发布命名习惯）`
- 建议：从官方商店或开发者发布页获取安装包；比对开发者签名指纹/历史版本签名一致性；用 sha256 在威胁情报平台（如 VirusTotal）与商店后端校验；企业侧对未知来源侧载设置拦截或额外审计。

### 17. 动态沙箱未见明确恶意行为，但存在持续联网访问
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`medium`
- 说明：样本在沙箱中安装、启动成功，运行窗口内产生网络访问，但未见明显恶意落地、破坏或权限滥用证据。鉴于应用具备联网能力且存在多次网络命中，仍建议进一步复核流量目的与域名信誉。
- 证据：`install_success=true; launch_success=true; event_count=37; runtime_window_seconds=12; network_hit_count=12; logcat显示安装与dexopt正常完成，未见异常报错或明显恶意动作。`
- 建议：保留样本并在隔离沙箱中复测；抓取完整网络流量、DNS 与证书链，确认访问目的后再决定是否放行。

### 18. 反射调用较多，需警惕隐藏逻辑
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`medium`
- 说明：静态图谱显示反射相关 API 调用较多，top API 包含 Method.invoke、Field.get、Field.set、Class.forName、ClassLoader.loadClass。虽然当前未检测到动态加载或混淆，但这类模式可能用于延迟装载、兼容适配或隐藏业务逻辑。
- 证据：`Ljava/lang/reflect/Method;->invoke=81; Ljava/lang/reflect/Field;->get=74; Ljava/lang/reflect/Field;->set=33; Ljava/lang/Class;->forName=32; Ljava/lang/ClassLoader;->loadClass=11; robustness_summary显示reflection_detected=false、dynamic_loading_detected=false。`
- 建议：建议进行二次静态复核与符号级代码审查，重点检查反射调用目标是否固定、是否存在远程配置驱动执行路径。

### 19. 签名证书需要来源核验
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`medium`
- 说明：证书主体与颁发者信息显示为 Android 测试证书风格，且静态报告提示需复核签名证书是否符合官方发布习惯。若该包本应来自正式市场或厂商渠道，则签名可信度不足。
- 证据：`certificate_subject/certificate_issuer 均显示 android@android.com 风格信息；static_report 中 APK_SIGNING_INFO 提示“签名证书信息需复核”。`
- 建议：若来源不是明确可信渠道，应阻断分发；对比官方包的证书指纹与包名版本，确认是否为重打包或测试构建。

### 20. 当前证据不足以直接判定恶意，适合隔离复核而非直接拦截
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`low`
- 说明：包名、组件结构、权限集合与 Firebase/Google 相关服务更像常规应用构成，动态也未见异常持久化服务、可疑文件写入或敏感权限滥用。综合看风险偏中低，但证据链尚不足以完全排除供应链或来源风险。
- 证据：`package_name=com.malmstein.yahnac; permissions仅含 INTERNET/NETWORK/WIFI/WAKE_LOCK/FCM相关; activities/services/providers 与常规应用一致; post_install_files为空; persistent_services未见异常系统级持久化。`
- 建议：建议先在隔离环境继续观察，生产环境暂缓安装；完成来源、签名与流量三项核验后再决定是否允许分发。

### 21. 建议保留样本留痕并建立 IOC 记录
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`low`
- 说明：样本已形成可追溯哈希、证书指纹、包名、版本号与动态目录证据，适合纳入留痕与复检体系。即使当前未达恶意结论，也应保留用于后续情报比对。
- 证据：`sha256=b34ee7bdbd6c9b034f38c7f3a27969445d5ebf351b92214356f4db16576275fd; certificate_sha256=c5375e7bef9b109995f75a87d719eddc38e88ce6f21b74f66258841e36e51d39; dynamic_artifacts_path已生成。`
- 建议：保存原始 APK、静态/动态报告、哈希、证书指纹、日志与抓包结果，纳入 IOC 库并用于后续同源样本关联。

### 22. 代码中检测到反射调用
- 规则：`DEEP_APK_STATIC_REFLECTION_USAGE`
- 严重级别：`low`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`API Calls: Method.invoke=81, Field.get=74, Class.forName=32`
- 建议：结合静态报告进一步复核。

### 23. 第三方 SDK 行为特征
- 规则：`DEEP_APK_BEHAVIOR_NORMAL_SDK_INTEGRATION`
- 严重级别：`low`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`FirebaseCrashReceiverService 与 AppMeasurementService 正常初始化；反射调用指向支持库`
- 建议：结合静态报告进一步复核。

### 24. 运行时环境兼容性告警
- 规则：`DEEP_APK_BEHAVIOR_RUNTIME_STABILITY`
- 严重级别：`low`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`logcat: 'Unexpected CPU variant for x86', 'avc: denied { getopt }'`
- 建议：结合静态报告进一步复核。

### 25. 敏感权限合规性
- 规则：`DEEP_APK_BEHAVIOR_PERMISSION_USAGE`
- 严重级别：`low`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`动态已授权权限与 Manifest 声明一致，未见越权`
- 建议：结合静态报告进一步复核。

### 26. 权限基线为网络与唤醒类，未声明高危隐私权限
- 规则：`DEEP_APK_INTEL_PERMISSIONS_BASELINE`
- 严重级别：`low`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`permissions=[INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK, C2DM 相关权限]`
- 建议：结合静态报告进一步复核。

### 27. 包含 Firebase Crash/Measurement 组件，可能收集设备标识
- 规则：`DEEP_APK_INTEL_FIREBASE_ANALYTICS`
- 严重级别：`low`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`AppMeasurementService, FirebaseCrashReceiverService, FirebaseInitProvider; Settings.Secure.getString x2`
- 建议：结合静态报告进一步复核。

### 28. 动态沙箱未见明确恶意行为，但存在持续联网访问
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`install_success=true; launch_success=true; runtime_window_seconds=12; network_hit_count=12`
- 建议：结合静态报告进一步复核。

### 29. 反射调用较多，需警惕隐藏逻辑
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`Method.invoke=81; Field.get=74; Field.set=33; Class.forName=32; ClassLoader.loadClass=11；未检出动态加载`
- 建议：结合静态报告进一步复核。

### 30. 签名证书需要来源核验
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`证书主体/颁发者均为 android@android.com 风格；提示签名证书信息需复核`
- 建议：结合静态报告进一步复核。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5`）
综合四位专家结论：该样本在功能、权限与短时动态行为上均符合正常的新闻客户端画像，未见越权、恶意落地或后门迹象；大量反射调用主要归因于支持库/第三方 SDK 的常见用法，缺乏动态加载与隐藏恶意逻辑的直接证据。当前唯一且关键的高影响风险在于签名不合规——检测到使用 TESTKEY/调试证书（Android 通用测试证书），这会显著降低分发与更新的信任边界，存在被第三方重打包仿冒、通过“合法更新”渠道投递恶意版本的供应链安全风险，因此不建议在生产环境中使用或放行。综合判断为“中风险”：样本本身未表现出恶意，但签名安全性严重不达标，需以来源核验与证书指纹比对作为前置条件，仅建议在隔离/测试环境继续观察与复核。注意：本结论仅基于现有四位专家的输出，且受限于短时（约12秒）沙箱窗口、模拟器环境与未核验分发渠道/证书指纹，仍存在不确定性。

### 静态分析员（模型：`gemini-2.5-pro`）
静态分析显示，该应用（com.malmstein.yahnac）从功能上看是一个Hacker News客户端，其申请的权限（网络、唤醒锁）与此功能相符。代码层面使用了Google Firebase服务用于崩溃分析和消息推送，属于常规开发实践。然而，最严重的安全风险在于该APK使用了通用的Android调试证书进行签名。这意味着任何人都可能创建该应用的恶意更新版本，并被系统接受安装，从而导致严重的安全漏洞。虽然动态沙箱在短时运行中未发现明显恶意行为，但基于该签名漏洞，此APK不应被信任或在生产环境中使用。

### 行为分析员（模型：`gemini-2.5-flash`）
基于动态沙箱行为分析，该 APK (com.malmstein.yahnac) 表现为正常的应用生命周期行为。动态运行日志显示其主要执行了包安装、Dex 优化（dex2oat）及正常的组件初始化。虽然存在反射调用（Method.invoke, Field.get/set）和网络连接行为，但结合静态分析中的 Android Support 库及 Firebase 组件特征，这些行为符合典型 Android 应用集成第三方 SDK（如 Firebase Crashlytics、Google Analytics）的常规特征。沙箱中未发现恶意落地文件、敏感数据外泄或持久化后门行为，设备策略与辅助功能注册均在正常应用范畴内。

### 情报分析员（模型：`gpt-5`）
样本为 Android 应用 com.malmstein.yahnac（v1.3.1，sha256=b34ee7bdbd6c9b034f38c7f3a27969445d5ebf351b92214356f4db16576275fd，文件名 tmpr5q3f06g.apk）。静态侧：仅声明网络与唤醒类常规权限，组件包含 Firebase Crash/Measurement 与自有 ContentProvider；API 图谱中反射调用较多，但主要来自 Android Support/Design 库的常见用法，未见明显恶意指令或动态加载迹象。签名侧：APK 内含 META-INF/TESTKEY.*，证书主体为通用“Android”信息，显示为测试/非生产签名，这与官方商店分发习惯不符，增加被第三方重打包或非官方构建的风险。动态侧：沙箱在模拟器中成功安装/启动，12 秒观测窗口内未捕获对外可辨识的网络域名访问，日志主要为系统安装与优化流程；沙箱将应用列入“device_policy/accessibility”清单，但 Manifest 未见对应高风险组件与权限，倾向为沙箱侧噪声或解析偏差，需复核。整体判断：功能与权限画像符合新闻客户端，未发现明确恶意行为迹象，但签名为 TESTKEY 与分发可信度是当前主要不确定性。离线分析边界：1) 我方未核验外部分发源（Google Play/开发者官网/GitHub/FDroid 等）与开发者指纹；2) 动态观测时间短且在模拟器环境，不能替代真实用户长时交互；3) 未进行联网抓包与基于域名/IP 的威胁情报交叉。建议结合来源与分发渠道复核：仅从官方商店或开发者可信发布页获取；以证书 SHA-256 指纹比对历史版本或公开指纹；用样本哈希在威胁情报平台（如 VT）与商店后端校验；企业场景可通过 MDM/零信任策略限制可疑来源的侧载。

### 处置建议员（模型：`gpt-5.4-mini`）
该 APK 当前更符合正常应用样本而非明确恶意样本：静态上未见明显加壳、反射/动态加载痕迹虽存在但更像框架或兼容代码，动态沙箱中安装与启动均成功，未观察到落地可疑文件、明显恶意权限滥用或异常持久化行为。建议允许隔离环境内继续观察，不建议直接在生产终端放行；若来源非官方或签名不可信，应阻断分发并保留样本留痕。


### 主持人最终总结
综合四位专家结论：该样本在功能、权限与短时动态行为上均符合正常的新闻客户端画像，未见越权、恶意落地或后门迹象；大量反射调用主要归因于支持库/第三方 SDK 的常见用法，缺乏动态加载与隐藏恶意逻辑的直接证据。当前唯一且关键的高影响风险在于签名不合规——检测到使用 TESTKEY/调试证书（Android 通用测试证书），这会显著降低分发与更新的信任边界，存在被第三方重打包仿冒、通过“合法更新”渠道投递恶意版本的供应链安全风险，因此不建议在生产环境中使用或放行。综合判断为“中风险”：样本本身未表现出恶意，但签名安全性严重不达标，需以来源核验与证书指纹比对作为前置条件，仅建议在隔离/测试环境继续观察与复核。注意：本结论仅基于现有四位专家的输出，且受限于短时（约12秒）沙箱窗口、模拟器环境与未核验分发渠道/证书指纹，仍存在不确定性。


## 七、仲裁结果
- 一致性分数：`65`
- 一致性等级：`medium`
- 加权置信度：`29`
- 疑似污染源：static, behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 43 分
  - static-intelligence 差异 53 分
  - behavior-intelligence 差异 10 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
