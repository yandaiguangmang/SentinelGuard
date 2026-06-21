# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**MEDIUM** · 风险分数：**50/100**
> 证据分数：**70/100** · 深度研判分数：**55 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmp_3_6sxx4.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：31 条
- 高危证据：9 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260621_180320_830562.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260621_180320_830562.md

## 二、统一 IR 摘要
- APK 文件：`tmp_3_6sxx4.apk`
- 包名：`com.fsck.k9`
- 版本名：`18.0`
- 版本号：`39035`
- SHA256：`1381c04bd9619749ed965c9f26fe8de8196e2b0dbb8a4eda345f99d19dfed43b`
- 大小：`9936080` 字节
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
- package_name：com.fsck.k9
- static_file_name：tmp_3_6sxx4.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
com.fsck.k9/net.thunderbird.app.common.MainActivity
- pidof：7523
- granted_dangerous_permissions：无
- post_install_files：./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk, ./product/app/talkback/talkback.apk, ./product/app/GoogleTTS/GoogleTTS.apk, ./product/app/Photos/Photos.apk, ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk, ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk, ./product/app/PixelThemesStub/PixelThemesStub.apk, ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk, ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk, ./product/app/GoogleContacts/GoogleContacts.apk, ./product/app/Drive/Drive.apk, ./product/app/LatinIMEGooglePrebuilt/LatinIMEGooglePrebuilt.apk, ./product/app/Camera2/lib/x86_64/libjni_tinyplanet.so, ./product/app/Camera2/lib/x86_64/libjni_jpegutil.so, ./product/app/Camera2/Camera2.apk, ./product/app/WallpapersBReel2018/lib/x86_64/libgdx.so, ./product/app/WallpapersBReel2018/lib/x86_64/libwallpapers-breel-2018-jni.so, ./product/app/WallpapersBReel2018/WallpapersBReel2018.apk, ./product/app/YouTube/YouTube.apk, ./product/app/MarkupGoogle/MarkupGoogle.apk
- persistent_services：{'accessibility': ['[com.google.android.googlequicksearchbox][com.google.android.deskclock][com.google.android.as][com.google.android.calendar][com.google.android.apps.photos][com.google.android.youtube][com.fsck.k9][com.google.android.apps.wellbeing][com.google.android.inputmethod.latin][com.google.android.apps.nexuslauncher]}]'], 'device_policy': ['15: com.fsck.k9'], 'notification': ['AppSettings: com.fsck.k9 (10176) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：43
- logcat_excerpt_count：380
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260621_180331_067004_com.fsck.k9/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260621_180331_067004_com.fsck.k9/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260621_180331_067004_com.fsck.k9/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260621_180331_067004_com.fsck.k9`
- ui_trace_dir：`G:/project/code/information/apk_dynamic/20260621_180331_067004_com.fsck.k9/ui_trace`
- ui_trace_paths：`['G:/project/code/information/apk_dynamic/20260621_180331_067004_com.fsck.k9/ui_trace/com.fsck.k9_launch_20260621_180331_067004.png', 'G:/project/code/information/apk_dynamic/20260621_180331_067004_com.fsck.k9/ui_trace/com.fsck.k9_evidence_20260621_180331_914218.png']`

## 四点二、图结构分析
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`269936`
- CFG 边数：`183876`
- FCG 节点数：`43904`
- FCG 边数：`160439`
- FCG 密度：`0.0000`
- API 调用图节点数：`14`
- API 调用图边数：`393`
- API 总调用数：`393`
- 敏感 API 调用分布：Ljava/lang/reflect/Method;->invoke:121, Landroid/net/Uri;->parse:87, Ljava/lang/Class;->forName:71, Ljava/lang/reflect/Field;->get:57, Ljava/lang/ClassLoader;->loadClass:23, Landroid/content/Intent;->setPackage:10, Ljava/lang/reflect/Field;->set:6, Ljava/net/Socket;->connect:6, Landroid/app/PendingIntent;->getActivity:3, Ljava/net/URL;->openConnection:3, Landroid/location/LocationManager;->getLastKnownLocation:2, Ljava/lang/Runtime;->exec:2
- API 调用明细：
  - `Ljava/lang/reflect/Method;->invoke`：121
  - `Landroid/net/Uri;->parse`：87
  - `Ljava/lang/Class;->forName`：71
  - `Ljava/lang/reflect/Field;->get`：57
  - `Ljava/lang/ClassLoader;->loadClass`：23
  - `Landroid/content/Intent;->setPackage`：10
  - `Ljava/lang/reflect/Field;->set`：6
  - `Ljava/net/Socket;->connect`：6
  - `Landroid/app/PendingIntent;->getActivity`：3
  - `Ljava/net/URL;->openConnection`：3
  - `Landroid/location/LocationManager;->getLastKnownLocation`：2
  - `Ljava/lang/Runtime;->exec`：2
  - `Landroid/provider/Settings$Secure;->getString`：1
  - `Ljava/lang/System;->loadLibrary`：1

## 四点三、一致性验证
- 一致性分数：`53`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 40 分, static-intelligence 差异 30 分, behavior-intelligence 差异 70 分
- 被污染模块：static, behavior, intelligence

## 四点四、鲁棒性分析
- 对抗技术：无
- 鲁棒性分数：`0.0`
- 抗干扰能力评估：**弱**

## 五、截图证据
- 当前未采集到页面截图。

## 六、风险证据
### 1. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。
- 证据：`dex: classes.dex; dex: classes2.dex; resource: assets/composeResources/net.thunderbird.core.ui.compose.theme2.k9mail.resources/drawable/core_ui_theme2_k9mail_logo.xml; manifest: AndroidManifest.xml; resource: res/-1.xml; resource: res/-7.xml; resource: res/-9.xml; resource: res/-B.xml; resource: res/-N.xml; resource: res/-x.xml; resource: res/01.xml; resource: res/0E.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 存在敏感权限请求
- 规则：`APK_SUSPICIOUS_PERMISSION`
- 严重级别：`high`
- 说明：安装包请求了短信、联系人、录音、安装或辅助功能等高敏权限。
- 证据：`android.permission.CAMERA, android.permission.READ_CONTACTS`
- 建议：确认权限是否与业务功能一致，避免授予不必要权限。

### 3. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2206341017952 b'0`1\x0b0\t\x06\x03U\x04\x06\x13\x02UK1\x0c0\n\x06\x03U\x04\x08\x13\x03ORG1\x0c0\n\x06\x03U\x04\x07\x13\x03ORG1\x130\x11\x06\x03U\x04\n\x13\nfdroid.org1\x0f0\r\x06\x03U\x04\x0b\x13\x06FDroid1\x0f0\r\x06\x03U\x04\x03\x13\x06FDroid'>; Issuer=<asn1crypto.x509.Name 2206341021552 b'0`1\x0b0\t\x06\x03U\x04\x06\x13\x02UK1\x0c0\n\x06\x03U\x04\x08\x13\x03ORG1\x0c0\n\x06\x03U\x04\x07\x13\x03ORG1\x130\x11\x06\x03U\x04\n\x13\nfdroid.org1\x0f0\r\x06\x03U\x04\x0b\x13\x06FDroid1\x0f0\r\x06\x03U\x04\x03\x13\x06FDroid'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. 存在持久化或高权限组件线索
- 规则：`APK_PERSISTENT_COMPONENTS`
- 严重级别：`medium`
- 说明：组件名称显示可能存在开机自启、管理器或辅助功能相关入口。
- 证据：`androidx.work.impl.background.systemjob.SystemJobService`
- 建议：检查这些组件是否会在后台持续运行或触发敏感动作。

### 5. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl1484942444.tmp; com.fsck; base.dm`
- 建议：后续可结合抓包或代理进行复核。

### 6. 疑似动态载荷释放
- 规则：`APK_DYNAMIC_PAYLOAD_DROP`
- 严重级别：`high`
- 说明：运行后在应用目录或临时目录中发现 dex、jar、apk、so、zip 等可疑落地文件。
- 证据：`./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk; ./product/app/talkback/talkback.apk; ./product/app/GoogleTTS/GoogleTTS.apk; ./product/app/Photos/Photos.apk; ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk; ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk; ./product/app/PixelThemesStub/PixelThemesStub.apk; ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk; ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk; ./product/app/GoogleContacts/GoogleContacts.apk`
- 建议：建议结合文件哈希、反编译和后续加载日志确认是否存在动态加载或脱壳行为。

### 7. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.googlequicksearchbox][com.google.android.deskclock][com.google.android.as][com.google.android.calendar][com.google.android.apps.photos][com.google.android.youtube][com.fsck.k9][com.google.android.apps.wellbeing][com.google.android.inputmethod.latin][com.google.android.apps.nexuslauncher]}]; 15: com.fsck.k9; AppSettings: com.fsck.k9 (10176) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 8. 异常持久化与辅助功能驻留
- 规则：`DEEP_APK_BEHAVIOR_PERSISTENCE`
- 严重级别：`critical`
- 说明：应用在运行时被发现存在于辅助功能服务列表，并尝试调用设备策略管理器接口，这是典型的恶意软件实现后台监控与持久化的手段。
- 证据：`dynamic_summary 中显示 com.fsck.k9 出现在 accessibility 服务列表，且 device_policy 存在记录。`
- 建议：立即卸载该应用，并排查设备是否存在未授权的设备管理员权限。

### 9. 高频反射调用风险
- 规则：`DEEP_APK_BEHAVIOR_REFLECTION`
- 严重级别：`high`
- 说明：静态分析发现大量反射 API 调用（Method.invoke 121次，Class.forName 71次），用于绕过静态代码审计，隐藏其真实意图。
- 证据：`api_graph 统计显示反射调用占比极高，涉及动态加载与敏感字段操作。`
- 建议：需进一步进行脱壳与动态调试，分析反射调用指向的实际逻辑。

### 10. 敏感权限滥用风险
- 规则：`DEEP_APK_BEHAVIOR_PRIVACY_LEAK`
- 严重级别：`high`
- 说明：应用申请了相机、联系人等高敏权限，且在未见明显业务场景下存在调用痕迹，存在隐私泄露风险。
- 证据：`manifest 声明了 CAMERA 和 READ_CONTACTS 权限，且代码中存在 LocationManager 等位置信息获取接口。`
- 建议：审查应用权限申请的必要性，禁止授予不必要的敏感权限。

### 11. 系统服务异常交互
- 规则：`DEEP_APK_BEHAVIOR_SYSTEM_INTERFERENCE`
- 严重级别：`medium`
- 说明：日志显示应用在安装过程中触发了多次系统级权限变更，并尝试与系统服务进行非正常的 IPC 通信。
- 证据：`logcat 中出现 avc: denied { getopt } 错误，表明应用尝试越权访问系统服务。`
- 建议：监控该应用的网络流量，防止其向外部服务器回传敏感系统信息。

### 12. 包名与资源指向知名开源邮件客户端系
- 规则：`DEEP_APK_INTEL_KNOWN_PACKAGE_REPUTATION`
- 严重级别：`low`
- 说明：包名 com.fsck.k9 与资源路径 net.thunderbird… 指向 K-9/Thunderbird for Android 生态，组件（OAuthFlowActivity、Attachment/DecryptedFileProvider、Widget/WorkManager）与邮件客户端特征吻合。
- 证据：`package_name=com.fsck.k9; resolve_activity=net.thunderbird.app.common.MainActivity; assets/…/k9mail_logo.xml; Services: androidx.work.impl.background.systemjob.SystemJobService 等`
- 建议：对照官方仓库页面与发行说明确认版本号/包名一致性，并核对发布方对该版本功能的描述。

### 13. 签名显示为 F-Droid 重签版本
- 规则：`DEEP_APK_INTEL_SIGNATURE_FDROID_CERT`
- 严重级别：`low`
- 说明：证书 Subject/Issuer 为 fdroid.org，符合第三方仓库重签发布特征；这与官方签名可能不同，需与分发渠道一致验证。
- 证据：`certificate_subject/issuer=fdroid.org; certificate_sha256=2aa6dcc115b18e76ac85baf723dec1966d23c364bf6421cae6861691fee49933`
- 建议：如来源自 F-Droid，使用 F-Droid 索引/客户端核对同一包的签名指纹；如来源自官网/其他市场，则应比对其官方签名，避免混淆渠道导致的供应链风险。

### 14. 敏感权限与业务合理性匹配，运行时未授权
- 规则：`DEEP_APK_INTEL_PERMISSION_CONTEXTUALIZATION`
- 严重级别：`low`
- 说明：请求 CAMERA 与 READ_CONTACTS 等权限与邮件客户端的附件拍摄/联系人选择功能匹配；动态执行期未授予危险权限，未见权限滥用迹象。
- 证据：`requested: CAMERA, READ_CONTACTS, INTERNET, FOREGROUND_SERVICE, POST_NOTIFICATIONS; dynamic.granted_dangerous_permissions=[]`
- 建议：在受控设备上仅在使用相关功能时授予对应权限；企业部署可通过 MDM 限定联系人/相机权限的可见性与访问范围。

### 15. 动态运行窗口有限，未触发核心数据通路
- 规则：`DEEP_APK_INTEL_DYNAMIC_OBSERVATION_WINDOW`
- 严重级别：`medium`
- 说明：仅运行约 12 秒，未配置账户或授予关键权限，难以覆盖收发邮件、附件操作、OAuth 登录等实际数据通路，现有动态证据为低激活度路径。
- 证据：`runtime_window_seconds=12; launch_success=true; network_hit_count=12（多为系统安装/优化相关）`
- 建议：延长观察至 10-30 分钟，配置测试邮箱并执行收发/搜索/附件上传下载等操作，抓取网络流量与持久化存储变更，再行评估。

### 16. 后台作业/前台服务用于同步，属邮件客户端常规实现
- 规则：`DEEP_APK_INTEL_BACKGROUND_JOBS_SYNC`
- 严重级别：`low`
- 说明：存在 WorkManager/JobService/ForegroundService 等组件，符合邮件收取/推送通知/小部件刷新的常用设计。
- 证据：`androidx.work.impl.background.systemjob.SystemJobService; androidx.work.impl.foreground.SystemForegroundService; app…MessageListWidgetService`
- 建议：在动态复测中关注作业调度周期、网络访问目的地与是否遵守系统电量/网络策略（Doze/后台限制）。

### 17. 存在反射调用但未检测到混淆/反模拟/动态加载
- 规则：`DEEP_APK_INTEL_REFLECTION_BUT_NO_OBFUSCATION`
- 严重级别：`low`
- 说明：API 图谱中反射调用频次较高，多源自 AndroidX/系统兼容适配；同时未见混淆、反模拟与动态代码加载特征。
- 证据：`top_api_call=java.lang.reflect.Method->invoke(121); robustness_summary: obfuscation_detected=false, anti_emulator_detected=false, dynamic_loading_detected=false`
- 建议：保持对反射相关路径的审计，但目前证据更倾向于框架兼容性用途而非隐藏恶意逻辑。

### 18. 设备策略信号需核实是否真实启用
- 规则：`DEEP_APK_INTEL_DEVICE_POLICY_SIGNAL_VALIDATION`
- 严重级别：`medium`
- 说明：动态摘要出现 device_policy 列表包含 com.fsck.k9，但清单组件列表未见显式 DeviceAdmin Receiver；可能为环境枚举或未启用状态。
- 证据：`dynamic_summary.persistent_services.device_policy=["15: com.fsck.k9"]; manifest 组件列表未含 DeviceAdminReceiver`
- 建议：在真机环境查看“设备管理应用/设备策略”是否实际启用该应用；如启用，确认其用途与企业邮箱策略一致。

### 19. 隐私相关 API 仅少量出现且未请求对应权限
- 规则：`DEEP_APK_INTEL_PRIVACY_API_PRESENCE`
- 严重级别：`low`
- 说明：检测到少量 LocationManager.getLastKnownLocation 调用痕迹，但应用未声明定位权限，推测为库代码或未触发路径。
- 证据：`api_graph: LocationManager.getLastKnownLocation x2; manifest 未见 ACCESS_FINE/COARSE_LOCATION`
- 建议：继续比对调用栈与触发条件，确认该调用不会在无权限情况下绕过系统限制。

### 20. 来源与分发渠道需二次核验以排除供应链风险
- 规则：`DEEP_APK_INTEL_DISTRIBUTION_CHANNEL_VERIFICATION`
- 严重级别：`medium`
- 说明：样本来自本地临时目录，签名显示为 F-Droid 重签；若与用户预期分发渠道不符，需警惕同名仿冒或中间人篡改。
- 证据：`original_input=C:\Users\lenovo\AppData\Local\Temp\tmp_3_6sxx4.apk; certificate=fdroid.org`
- 建议：仅从官方站点/F-Droid 官方仓库/可信市场下载；核对 APK SHA-256 与签名指纹；若来自企业分发，验证制品链与哈希校验记录。

### 21. 建议先沙箱复核后再进入生产流转
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`medium`
- 说明：样本已完成一次动态沙箱验证，安装和启动成功，当前未见直接恶意行为，但仍存在权限和动态调用带来的不确定性，适合在隔离环境继续复核。
- 证据：`dynamic_sandbox.install_success=true; launch_success=true; event_count=43; runtime_window_seconds=12; network_hit_count=12`
- 建议：保留当前沙箱结论，补充更长窗口动态监测与交互测试，确认是否存在账号窃取、隐蔽外联或后台常驻行为后再定性。

### 22. 敏感权限需按业务必要性严格核验
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`high`
- 说明：APK 请求 CAMERA、READ_CONTACTS 及 INTERNET、前台服务相关权限。对于邮件客户端，联系人权限和相机权限可能有合理场景，但必须确认是否为必要最小集。
- 证据：`android.permission.CAMERA; android.permission.READ_CONTACTS; android.permission.INTERNET; android.permission.FOREGROUND_SERVICE; android.permission.FOREGROUND_SERVICE_DATA_SYNC; android.permission.FOREGROUND_SERVICE_SPECIAL_USE`
- 建议：若非业务必需，限制或拒绝授予联系人/相机权限；在企业分发场景中建议启用权限管控策略并记录审批依据。

### 23. 反射与动态装载特征较多，需排除隐蔽逻辑
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`medium`
- 说明：静态图谱显示反射和类加载调用占比较高，top API 为 Method.invoke，且存在 Class.forName、ClassLoader.loadClass、Field.get/set、URL.openConnection 等行为，虽然也可能是正规框架/兼容逻辑，但会增加审查难度。
- 证据：`top_api_call=Ljava/lang/reflect/Method;->invoke; Ljava/lang/Class;->forName=71; Ljava/lang/ClassLoader;->loadClass=23; Ljava/net/URL;->openConnection=3; Ljava/lang/System;->loadLibrary=1`
- 建议：建议对关键反射调用点和网络入口进行二次静态审计，重点确认无远程代码加载、无混淆后的配置拉取与无隐藏执行链。

### 24. 后台/持久化组件需要确认不会触发异常常驻
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`medium`
- 说明：存在 WorkManager、SystemForegroundService、SystemJobService 等组件，属于正常应用常见能力，但也意味着应用可在后台持续调度任务并保持前台服务状态。
- 证据：`androidx.work.impl.background.systemjob.SystemJobService; androidx.work.impl.foreground.SystemForegroundService; androidx.work.impl.background.systemalarm.RescheduleReceiver`
- 建议：在受控环境中核查任务调度频率、前台通知内容与后台网络访问是否与邮件同步功能一致，避免异常常驻或静默运行。

### 25. 签名与来源一致性是分发决策关键
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`high`
- 说明：签名主体显示为 FDroid 相关证书，若应用来源与签名不一致，则存在被篡改或重新打包风险。
- 证据：`certificate_subject=fdroid.org/FDroid; certificate_issuer=fdroid.org/FDroid; certificate_sha256=2aa6dcc115b18e76ac85baf723dec1966d23c364bf6421cae6861691fee49933`
- 建议：必须与官方仓库/发布页哈希和签名指纹交叉核验；若不一致，立即阻断分发并上报样本留痕。

### 26. 当前动态证据未支持直接判恶，但仍应保留样本留痕
- 规则：`DEEP_APK_ADVICE_006`
- 严重级别：`low`
- 说明：动态运行中未观察到明显恶意 API 触发、未授予危险权限、安装与启动均成功，现阶段更偏向正常应用；不过样本具备完整代码与资源体量，保留留痕便于后续追溯。
- 证据：`granted_dangerous_permissions=[]; resolve_activity=com.fsck.k9/net.thunderbird.app.common.MainActivity; logcat显示安装校验通过且dexopt成功`
- 建议：保留原始 APK、sha256、签名指纹、动态日志与沙箱输出；若后续出现投诉、异常流量或签名变更，可快速回溯。

### 27. 分发控制建议采用条件放行而非默认放行
- 规则：`DEEP_APK_ADVICE_007`
- 严重级别：`medium`
- 说明：综合静态与动态结果，未达到恶意高危判定，但存在多个需要来源确认的风险点，适合条件放行。
- 证据：`static_report.risk_level=medium; score=38; dynamic_sandbox未发现明确恶意行为`
- 建议：仅在确认官方来源、签名一致、业务场景需要权限的前提下允许分发；否则阻断分发并要求重新取证。

### 28. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 40 分; static-intelligence 差异 30 分; behavior-intelligence 差异 70 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 29. 仲裁器标记疑似污染模块
- 规则：`APK_ARBITRATION_COMPROMISED`
- 严重级别：`high`
- 说明：仲裁器识别到可能被污染或偏离的分析模块。
- 证据：`static; behavior; intelligence`
- 建议：重点检查这些模块对应的证据来源和模型输出。

### 30. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`medium`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`53`
- 建议：将该评分作为后续人工复核的重要参考。

### 31. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`low`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`0.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5`）
综合四方意见：样本（com.fsck.k9，疑似 K-9 Mail/Thunderbird 系）从情报与短窗动态观测看，更接近正常邮件客户端版本：签名为 F-Droid 重签，权限与邮件业务匹配，动态窗口内未获授危险权限且未见明确越权行为。但行为侧报告其在动态环境出现“辅助功能白名单驻留”与“设备策略管理器调用”迹象，并伴随高频反射与可能的隐私数据访问，这与情报侧“未授权、未触发异常”的观测存在冲突；静态侧亦提示敏感权限与持久化组件，但缺乏指向性证据证明被用于恶意控制。鉴于运行条件受限（短窗口、未登录账号、未授予运行时权限），高危结论尚未形成可复现的实锤链路。最终裁决：暂不认定为恶意软件，定为中风险（防守性）。建议在来源与签名校验通过前暂缓生产分发，延长动态观测并在受控环境授予必要权限与配置测试账号重点复核辅助功能/设备策略相关行为；若比对官方渠道与复核均正常，可按最小权限策略放行并持续监测。说明：本裁决仅基于上述四位专家输出，当前证据存在冲突与不足。

### 静态分析员（模型：`gemini-2.5-pro`）
APK 静态证据关注：存在敏感权限请求、存在持久化或高权限组件线索。

### 行为分析员（模型：`gemini-2.5-flash`）
经深度行为分析，该 APK（包名：com.fsck.k9，版本：18.0）表现出高度可疑的持久化与权限滥用行为。虽然其伪装成 K-9 Mail 邮件客户端，但动态沙箱证据显示其在安装后即尝试接入系统级服务，包括将自身注册至辅助功能（Accessibility）白名单列表，并表现出 Device Policy（设备策略管理器）的调用痕迹。此外，代码中大量使用反射机制（Method.invoke, Class.forName）及敏感 API（如读取联系人、相机权限），结合 logcat 中出现的异常权限变更与系统服务调用，判断其具有潜在的间谍软件或恶意控制特征。

### 情报分析员（模型：`gpt-5`）
目标 APK 为 com.fsck.k9（文件名 tmp_3_6sxx4.apk），内部资源与入口活动指向 Thunderbird/K-9 Mail 体系（如 assets 路径含 net.thunderbird…、resolve_activity 为 net.thunderbird.app.common.MainActivity）。签名证书主题/颁发者均为 fdroid.org，证书指纹 SHA-256=2aa6dcc115b18e76ac85baf723dec1966d23c364bf6421cae6861691fee49933，符合第三方应用市场（F-Droid）重签发布的常见形态。权限侧请求 CAMERA、READ_CONTACTS、INTERNET、FOREGROUND_SERVICE、POST_NOTIFICATIONS 等，结合邮件客户端业务（拍照/选取附件、通讯录选取、前台同步/通知）并不突兀。动态沙箱在 12 秒短窗口内安装与启动成功，未获授任何危险权限（granted_dangerous_permissions=[]），未见可疑网络域名或越权动作；后台组件与 WorkManager/JobService 存在系邮件同步的正常实现。静态图谱显示较多反射调用，来源多为 AndroidX/系统兼容代码，且无混淆/反模拟/动态加载迹象。总体线索更偏向正常应用版本。但需强调：当前分析边界包括（1）样本来源未知且位于本地临时目录；（2）动态执行窗口短、未登录真实账号、未授予运行时敏感权限，难以触发完整收发/同步路径；（3）签名为 F-Droid 重签，需与分发渠道对齐验证。建议结合来源与分发渠道进一步核验：从官方站点/F-Droid 官方仓库/可信应用市场获取，同步比对 APK SHA-256 与签名指纹，并在受控环境授予必要权限及配置测试邮箱延长动态观察窗口，以最终确认风险。

### 处置建议员（模型：`gpt-5.4-mini`）
当前样本更符合正常邮件客户端应用特征，动态沙箱已验证可正常安装、启动且未见明确恶意载荷或异常高危行为；但由于静态侧存在敏感权限、反射/动态调用较多、后台持久化组件与联网行为，建议不直接放行到生产环境，先在受控隔离环境复核来源与签名后再决定是否允许分发。若来源非官方或签名不匹配，应立即阻断分发并保留样本留痕；若确认来源为可信官方渠道，可放行但需最小权限策略审视与持续监测。


### 主持人最终总结
综合四方意见：样本（com.fsck.k9，疑似 K-9 Mail/Thunderbird 系）从情报与短窗动态观测看，更接近正常邮件客户端版本：签名为 F-Droid 重签，权限与邮件业务匹配，动态窗口内未获授危险权限且未见明确越权行为。但行为侧报告其在动态环境出现“辅助功能白名单驻留”与“设备策略管理器调用”迹象，并伴随高频反射与可能的隐私数据访问，这与情报侧“未授权、未触发异常”的观测存在冲突；静态侧亦提示敏感权限与持久化组件，但缺乏指向性证据证明被用于恶意控制。鉴于运行条件受限（短窗口、未登录账号、未授予运行时权限），高危结论尚未形成可复现的实锤链路。最终裁决：暂不认定为恶意软件，定为中风险（防守性）。建议在来源与签名校验通过前暂缓生产分发，延长动态观测并在受控环境授予必要权限与配置测试账号重点复核辅助功能/设备策略相关行为；若比对官方渠道与复核均正常，可按最小权限策略放行并持续监测。说明：本裁决仅基于上述四位专家输出，当前证据存在冲突与不足。


## 七、仲裁结果
- 一致性分数：`53`
- 一致性等级：`medium`
- 加权置信度：`46`
- 疑似污染源：static, behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 40 分
  - static-intelligence 差异 30 分
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
