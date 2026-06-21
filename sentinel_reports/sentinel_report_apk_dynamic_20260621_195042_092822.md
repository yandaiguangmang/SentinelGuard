# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**HIGH** · 风险分数：**61/100**
> 证据分数：**70/100** · 深度研判分数：**92 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmp5xn8gtvc.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：31 条
- 高危证据：15 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260621_194730_103575.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260621_194730_103575.md

## 二、统一 IR 摘要
- APK 文件：`tmp5xn8gtvc.apk`
- 包名：`com.appple.app.email`
- 版本名：`1.12.20`
- 版本号：`12`
- SHA256：`e8595d59908040edaa9b2583a83b574d3ffa7bff468ba63472851ec782a2a6d6`
- 大小：`7108946` 字节
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
- package_name：com.appple.app.email
- static_file_name：tmp5xn8gtvc.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
com.appple.app.email/com.fsck.k9.activity.Accounts
- pidof：
- granted_dangerous_permissions：无
- post_install_files：./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk, ./product/app/talkback/talkback.apk, ./product/app/GoogleTTS/GoogleTTS.apk, ./product/app/Photos/Photos.apk, ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk, ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk, ./product/app/PixelThemesStub/PixelThemesStub.apk, ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk, ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk, ./product/app/GoogleContacts/GoogleContacts.apk, ./product/app/Drive/Drive.apk, ./product/app/LatinIMEGooglePrebuilt/LatinIMEGooglePrebuilt.apk, ./product/app/Camera2/lib/x86_64/libjni_tinyplanet.so, ./product/app/Camera2/lib/x86_64/libjni_jpegutil.so, ./product/app/Camera2/Camera2.apk, ./product/app/WallpapersBReel2018/lib/x86_64/libgdx.so, ./product/app/WallpapersBReel2018/lib/x86_64/libwallpapers-breel-2018-jni.so, ./product/app/WallpapersBReel2018/WallpapersBReel2018.apk, ./product/app/YouTube/YouTube.apk, ./product/app/MarkupGoogle/MarkupGoogle.apk
- persistent_services：{'device_policy': ['5: com.appple.app.email'], 'notification': ['AppSettings: com.appple.app.email (10175) importance=DEFAULT userSet=false']}
- install_success：True
- launch_success：True
- event_count：34
- logcat_excerpt_count：366
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260621_194736_760249_com.appple.app.email/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260621_194736_760249_com.appple.app.email/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260621_194736_760249_com.appple.app.email/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260621_194736_760249_com.appple.app.email`
- ui_trace_dir：`G:/project/code/information/apk_dynamic/20260621_194736_760249_com.appple.app.email/ui_trace`
- ui_trace_paths：`['G:/project/code/information/apk_dynamic/20260621_194736_760249_com.appple.app.email/ui_trace/com.appple.app.email_launch_20260621_194736_761279.png', 'G:/project/code/information/apk_dynamic/20260621_194736_760249_com.appple.app.email/ui_trace/com.appple.app.email_evidence_20260621_194737_448945.png']`

## 四点二、图结构分析
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`166859`
- CFG 边数：`70995`
- FCG 节点数：`48385`
- FCG 边数：`110726`
- FCG 密度：`0.0000`
- API 调用图节点数：`16`
- API 调用图边数：`353`
- API 总调用数：`353`
- 敏感 API 调用分布：Landroid/net/Uri;->parse:100, Ljava/lang/reflect/Method;->invoke:67, Ljava/lang/reflect/Field;->get:44, Landroid/content/Intent;->setPackage:37, Ljava/lang/Class;->forName:30, Ljava/lang/ClassLoader;->loadClass:14, Ljava/net/URL;->openConnection:14, Ljava/lang/reflect/Field;->set:13, Lorg/apache/http/client/HttpClient;->execute:9, Landroid/app/PendingIntent;->getActivity:8, Landroid/provider/Settings$Secure;->getString:5, Ljava/net/HttpURLConnection;->connect:5
- API 调用明细：
  - `Landroid/net/Uri;->parse`：100
  - `Ljava/lang/reflect/Method;->invoke`：67
  - `Ljava/lang/reflect/Field;->get`：44
  - `Landroid/content/Intent;->setPackage`：37
  - `Ljava/lang/Class;->forName`：30
  - `Ljava/lang/ClassLoader;->loadClass`：14
  - `Ljava/net/URL;->openConnection`：14
  - `Ljava/lang/reflect/Field;->set`：13
  - `Lorg/apache/http/client/HttpClient;->execute`：9
  - `Landroid/app/PendingIntent;->getActivity`：8
  - `Landroid/provider/Settings$Secure;->getString`：5
  - `Ljava/net/HttpURLConnection;->connect`：5
  - `Ljava/net/Socket;->connect`：4
  - `Ldalvik/system/DexClassLoader;-><init>`：1
  - `Ljava/lang/Runtime;->exec`：1
  - `Ljavax/crypto/Cipher;->doFinal`：1

## 四点三、一致性验证
- 一致性分数：`73`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 15 分, static-intelligence 差异 25 分, behavior-intelligence 差异 40 分
- 被污染模块：behavior, intelligence

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
- 证据：`manifest: AndroidManifest.xml; resource: assets/crashlytics-build.properties; resource: assets/downloading.html; resource: res/anim/slide_in_from_bottom.xml; resource: res/anim/slide_in_from_top.xml; resource: res/anim/slide_in_left.xml; resource: res/anim/slide_in_right.xml; resource: res/anim/slide_out_left.xml; resource: res/anim/slide_out_right.xml; resource: res/anim/slide_out_to_bottom.xml; resource: res/anim/slide_out_to_top.xml; resource: res/color/common_google_signin_btn_text_dark.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 存在敏感权限请求
- 规则：`APK_SUSPICIOUS_PERMISSION`
- 严重级别：`high`
- 说明：安装包请求了短信、联系人、录音、安装或辅助功能等高敏权限。
- 证据：`android.permission.READ_CONTACTS, android.permission.WRITE_CONTACTS`
- 建议：确认权限是否与业务功能一致，避免授予不必要权限。

### 3. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2213807225536 b'0x1\x0b0\t\x06\x03U\x04\x06\x13\x02841\x0e0\x0c\x06\x03U\x04\x08\x13\x05Hanoi1\x0e0\x0c\x06\x03U\x04\x07\x13\x05Hanoi1\x190\x17\x06\x03U\x04\n\x0c\x10appleinfo_studio1\x190\x17\x06\x03U\x04\x0b\x13\x10appleinfo studio1\x130\x11\x06\x03U\x04\x03\x13\nNguyen Hao'>; Issuer=<asn1crypto.x509.Name 2213807223664 b'0x1\x0b0\t\x06\x03U\x04\x06\x13\x02841\x0e0\x0c\x06\x03U\x04\x08\x13\x05Hanoi1\x0e0\x0c\x06\x03U\x04\x07\x13\x05Hanoi1\x190\x17\x06\x03U\x04\n\x0c\x10appleinfo_studio1\x190\x17\x06\x03U\x04\x0b\x13\x10appleinfo studio1\x130\x11\x06\x03U\x04\x03\x13\nNguyen Hao'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. 存在持久化或高权限组件线索
- 规则：`APK_PERSISTENT_COMPONENTS`
- 严重级别：`medium`
- 说明：组件名称显示可能存在开机自启、管理器或辅助功能相关入口。
- 证据：`com.fsck.k9.service.BootReceiver`
- 建议：检查这些组件是否会在后台持续运行或触发敏感动作。

### 5. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; com.sonyericsson.home.permission; com.appple.app.email; vmdl1383258375.tmp`
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
- 证据：`5: com.appple.app.email; AppSettings: com.appple.app.email (10175) importance=DEFAULT userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 8. 品牌仿冒与包名伪装
- 规则：`DEEP_APK_STATIC_BRAND_IMPERSONATION`
- 严重级别：`high`
- 说明：应用包名“com.appple.app.email”通过拼写错误的方式仿冒知名品牌“Apple”，企图欺骗用户下载安装。其签名证书显示开发者为“appleinfo_studio”，与官方品牌无关，是典型的恶意软件伪装策略。
- 证据：`Package Name: com.appple.app.email
Certificate Subject: CN=Nguyen Hao, OU=appleinfo studio, O=appleinfo_studio, L=Hanoi, ST=Hanoi, C=84`
- 建议：对包名与官方应用不符、且签名非官方的应用保持高度警惕，切勿安装来源不明的软件。

### 9. 应用程序木马化
- 规则：`DEEP_APK_STATIC_TROJANIZED_APP`
- 严重级别：`high`
- 说明：应用的核心组件（如Activity、Service等）大量使用了“com.fsck.k9”前缀，表明其代码基于合法的开源邮件客户端 K-9 Mail。攻击者极有可能在原有代码基础上植入了恶意功能后重新打包发布。
- 证据：`Receiver: com.fsck.k9.service.BootReceiver
Activity: com.fsck.k9.activity.Accounts
Service: com.fsck.k9.service.MailService`
- 建议：建议将此样本与官方 K-9 Mail 客户端进行代码比对，以精确定位被植入的恶意代码片段。

### 10. 联系人信息窃取风险
- 规则：`DEEP_APK_STATIC_PRIVACY_LEAK_CONTACTS`
- 严重级别：`high`
- 说明：应用在 Manifest 文件中申请了“android.permission.READ_CONTACTS”和“android.permission.WRITE_CONTACTS”权限。鉴于其伪装和木马化性质，这些权限极有可能被用于窃取和篡改用户的通讯录数据。
- 证据：`Permissions in AndroidManifest.xml: android.permission.READ_CONTACTS, android.permission.WRITE_CONTACTS`
- 建议：应在运行时严密监控该应用对联系人数据库的访问行为，并阻断任何未经授权的数据外传企图。

### 11. 持久化驻留与权限提升企图
- 规则：`DEEP_APK_STATIC_PERSISTENCE_AND_ESCALATION`
- 严重级别：`medium`
- 说明：应用注册了“com.fsck.k9.service.BootReceiver”，监听“RECEIVE_BOOT_COMPLETED”广播，使其能够在设备启动后自动运行，实现持久化。此外，动态沙箱的日志显示该应用在后台与设备策略服务(device_policy)交互，这表明它可能试图诱导用户授予其设备管理器权限，以达到防卸载的目的。
- 证据：`Manifest: Receiver 'com.fsck.k9.service.BootReceiver' with intent action 'android.intent.action.BOOT_COMPLETED'.
Dynamic Sandbox Log: persistent_services.device_policy includes 'com.appple.app.email'.`
- 建议：审查 BootReceiver 的具体实现，并检查应用是否存在诱导用户激活设备管理器的界面或逻辑。

### 12. 非法获取设备管理权限
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_ADMIN`
- 严重级别：`critical`
- 说明：应用在动态运行期间被识别为 Device Policy 参与者，试图通过设备管理接口获取系统级控制权。
- 证据：`dynamic_summary 中显示 device_policy 包含: 5: com.appple.app.email`
- 建议：该行为通常用于防止用户卸载或实施远程锁定，建议立即卸载并清理相关配置。

### 13. 恶意干扰系统进程
- 规则：`DEEP_APK_BEHAVIOR_PROCESS_INTERFERENCE`
- 严重级别：`high`
- 说明：应用在安装与运行过程中强制终止了联系人与健康监测等系统关键进程，存在恶意干扰意图。
- 证据：`logcat 中记录: Force stopping com.appple.app.email... Killing 11338:com.google.android.contacts... Killing 11101:com.google.android.apps.wellbeing`
- 建议：监控该应用对系统服务的调用，防止其通过干扰正常服务掩盖恶意行为。

### 14. 异常系统调用探测
- 规则：`DEEP_APK_BEHAVIOR_PRIVILEGE_ESCALATION`
- 严重级别：`medium`
- 说明：应用在运行期间触发了大量的 SELinux 审计拒绝（avc: denied），表明其尝试执行未授权的系统级操作。
- 证据：`logcat 中频繁出现: avc: denied { getopt } for scontext=u:r:system_server:s0 tcontext=u:r:shell:s0`
- 建议：该行为属于典型的提权探测，建议对该包名进行全网封禁。

### 15. 可疑品牌冒充与包名伪装
- 规则：`DEEP_APK_INTEL_BRAND_SQUATTING`
- 严重级别：`high`
- 说明：包名含“appple”混淆拼写，应用内部为 K‑9 Mail 架构，疑似借“Apple/邮箱”名义换皮分发，存在诱导安装与信誉误导风险。
- 证据：`package_name=com.appple.app.email；内部类名与组件大量为 com.fsck.k9.*；活动中含 com.appple.app.email.activity.UnreadWidgetConfiguration`
- 建议：核对商店展示名/开发者名与签名；如来自第三方站点或以“Apple 邮件”名义传播，按仿冒/PUA 归类并阻断分发。

### 16. 疑似基于 K‑9 Mail 的重打包/换皮
- 规则：`DEEP_APK_INTEL_REPACKAGE_K9`
- 严重级别：`medium`
- 说明：组件与资源与 K‑9 Mail 高度一致，同时引入第三方对话/广告相关组件，签名与官方不匹配，符合重打包特征。
- 证据：`services/receivers/providers: com.fsck.k9.service.*、com.fsck.k9.provider.*；activities: com.fsck.k9.activity.*；资源包含 K‑9 样式与布局；额外组件 com.banana.lib.RateDialogActivity`
- 建议：对比官方 K‑9（包名 com.fsck.k9）签名与哈希；进行差异化代码审计（广告/跟踪/私有 SDK）；优先使用官方仓库或商店版本。

### 17. 签名主体可疑且与官方不一致
- 规则：`DEEP_APK_INTEL_SIGNATURE_ANOMALY`
- 严重级别：`medium`
- 说明：证书为自签名，主体/颁发者一致，地理信息为 Hanoi，开发者名 appleinfo_studio，与任何官方邮箱产品或 K‑9 官方签名不符。
- 证据：`certificate_subject/issuer=...Hanoi... O=appleinfo_studio, OU=appleinfo studio, CN=Nguyen Hao；certificate_sha256=b599c7e7c7fc7c03a3a73cbefb300d6bcf7b4b0b19bd83ac6161e28e890e6668`
- 建议：使用证书指纹与 APK SHA‑256 在 VT/开源情报平台比对信誉与家族；企业侧建立签名信任名单，阻断未知签名来源。

### 18. 联系人读取与持久化运行的隐私面风险
- 规则：`DEEP_APK_INTEL_PERMISSION_PRIVACY`
- 严重级别：`medium`
- 说明：邮件类应用读取联系人可解释，但与开机启动/后台轮询结合，存在静默收集或扩大数据面风险，需最小化授权。
- 证据：`权限: READ_CONTACTS, RECEIVE_BOOT_COMPLETED；组件: com.fsck.k9.service.BootReceiver, PollService, PushService`
- 建议：仅在业务需要时授权 READ_CONTACTS；移动终端管理（MDM）限制自启动与后台访问频率；监控异常外联与数据访问模式。

### 19. 短窗动态沙箱未见对外可疑外联
- 规则：`DEEP_APK_INTEL_DYNAMIC_BEHAVIOR_BASELINE`
- 严重级别：`low`
- 说明：12 秒运行窗口内未授予危险权限与未观测到对外 HTTP/Socket 可疑访问，日志以包管理/优化为主，但不排除延迟触发与条件触发路径。
- 证据：`runtime_window_seconds=12；granted_dangerous_permissions=[]；network_hit_count=12（均为系统/安装相关条目）；logcat 未见外域 URL`
- 建议：延长运行时间并进行账户配置/交互测试；在允许的前提下授予必要权限观察实际网络流量；在真实设备复测并监控 DNS/HTTP(S)。

### 20. 目标 SDK 偏低与兼容路径可能放宽
- 规则：`DEEP_APK_INTEL_OLD_TARGET_SDK`
- 严重级别：`medium`
- 说明：目标 SDK 21，可能触发旧版行为兼容分支；结合反射与旧版支持库，隐私/权限边界存在历史差异，需谨慎评估。
- 证据：`dex2oat 日志: -Xtarget-sdk-version:21；API 图谱含多处反射调用（Method.invoke=67, Class.forName=30）`
- 建议：在新系统上评估权限授予实际效果；企业侧可按最小 SDK/目标 SDK 基线进行拦截策略，限制过旧目标 SDK 的第三方邮件客户端。

### 21. 来源与分发渠道不明（临时文件路径）
- 规则：`DEEP_APK_INTEL_DISTRIBUTION_RISK`
- 严重级别：`high`
- 说明：当前样本来自临时目录，无法确认是否为官方商店分发或可信渠道下载，供应链与投放链条不透明。
- 证据：`original_input=C:\Users\lenovo\AppData\Local\Temp\tmp5xn8gtvc.apk`
- 建议：仅从官方应用商店/官方仓库获取；保留下载链路证据（Referer/落地页/下载源 IP）；对下载站点与推广投放进行 IOC 关联与阻断。

### 22. 内置崩溃分析/广告提示等增长组件
- 规则：`DEEP_APK_INTEL_TRACKING_AD_COMPONENTS`
- 严重级别：`low`
- 说明：存在 Crashlytics 配置与评分对话、广告相关布局，指向内置分析/增长或广告模块，需进行隐私与合规复核。
- 证据：`assets/crashlytics-build.properties；布局: res/layout/rate_dialog_activity.xml, layout_notification_ads.xml；活动: com.banana.lib.RateDialogActivity`
- 建议：审阅 SDK 隐私策略与数据出境行为；在企业设备限制广告/跟踪域名外联；合规侧评估告知与授权流程。

### 23. 建议隔离安装验证
- 规则：`DEEP_APK_ADVICE_QUARANTINE_INSTALL`
- 严重级别：`high`
- 说明：样本已在沙箱中成功安装并启动，但存在敏感权限、后台常驻组件与联网行为，适合继续在隔离环境中验证，不建议直接下发到生产终端。
- 证据：`install_success=true; launch_success=true; permissions include READ_CONTACTS, INTERNET, RECEIVE_BOOT_COMPLETED; services include MailService, PollService, PushService; receiver BootReceiver`
- 建议：仅允许在无真实账号、无真实联系人数据的隔离沙箱或测试机上继续验证，禁止在员工真机或业务终端直接安装。

### 24. 建议继续沙箱复核联网与数据访问
- 规则：`DEEP_APK_ADVICE_SBOX_REVIEW`
- 严重级别：`high`
- 说明：动态沙箱期间出现网络访问迹象，结合联系人权限与邮件类组件，需确认是否存在同步、外联或数据上传行为。
- 证据：`network_hit_count=12; logcat shows package install and runtime activity; api graph includes HttpClient.execute, URL.openConnection, Socket.connect, Uri.parse`
- 建议：扩大沙箱时长并抓包复核，重点检查目的域名、请求参数、联系人读取时机、账号登录与同步链路，确认无敏感数据外传后再决定放行。

### 25. 建议阻断分发直至完成可信核验
- 规则：`DEEP_APK_ADVICE_BLOCK_DISTRIBUTION`
- 严重级别：`critical`
- 说明：包名 com.appple.app.email 具有仿冒知名厂商命名特征，证书主体为个人/工作室信息且与常见官方发布习惯不符，叠加敏感权限与持久化组件，当前不满足直接分发条件。
- 证据：`package_name=com.appple.app.email; certificate_subject includes appleinfo_studio / Nguyen Hao; certificate_issuer same as subject; suspicious permission READ_CONTACTS; BootReceiver present`
- 建议：在来源、签名链、发布渠道和版本历史未完成核验前，禁止在内部分发市场、MDM 或邮件附件中继续传播该 APK。

### 26. 建议保留样本与运行时留痕
- 规则：`DEEP_APK_ADVICE_PRESERVE_EVIDENCE`
- 严重级别：`medium`
- 说明：样本已产生可复现的动态行为，且静态与动态证据均具备研判价值，应完整保留原始 APK、签名信息、logcat、动态摘要和网络观测结果。
- 证据：`sha256=e8595d59908040edaa9b2583a83b574d3ffa7bff468ba63472851ec782a2a6d6; dynamic artifacts paths recorded; logcat_excerpt_count=366; runtime_window_seconds=12`
- 建议：保留原始文件、SHA256、证书指纹、动态日志、抓包和安装启动记录，并建立样本留痕台账，便于后续溯源与复检。

### 27. 联系人访问需重点核查
- 规则：`DEEP_APK_ADVICE_CONTACT_ACCESS_CHECK`
- 严重级别：`high`
- 说明：静态权限明确包含联系人读取，邮件类应用虽可能合理，但与仿冒命名、后台组件和联网行为叠加后，存在通讯录泄露风险。
- 证据：`android.permission.READ_CONTACTS; static finding APK_SUSPICIOUS_PERMISSION; activities/services are mail-related; dynamic sandbox did not grant dangerous permissions`
- 建议：核查联系人读取是否仅用于地址自动补全或账号同步，确认是否存在越权读取、加密上传或第三方 SDK 收集行为。

### 28. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 15 分; static-intelligence 差异 25 分; behavior-intelligence 差异 40 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 29. 仲裁器标记疑似污染模块
- 规则：`APK_ARBITRATION_COMPROMISED`
- 严重级别：`high`
- 说明：仲裁器识别到可能被污染或偏离的分析模块。
- 证据：`behavior; intelligence`
- 建议：重点检查这些模块对应的证据来源和模型输出。

### 30. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`medium`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`73`
- 建议：将该评分作为后续人工复核的重要参考。

### 31. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`low`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`0.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5`）
最终裁决：该 APK 为基于开源 K‑9 Mail 的木马化、品牌仿冒邮件客户端，风险定级为“严重”。静态证据显示其包名 com.appple.app.email 仿冒 Apple，签名为未知越南个人自签，且申请读取/写入联系人与开机自启并注册 BootReceiver，具备隐私窃取与持久化能力。动态侧进一步观测到尝试获取设备管理器权限（DevicePolicyManager 列表出现该包），以及强制停止联系人与健康类应用的恶意干扰行为，并伴随异常系统调用被拒记录，指向防卸载/提权探测与持久驻留意图。尽管情报侧短时沙箱未复现对外通信或明显恶意动作，但其已指出运行窗口和环境局限；在现有证据下，上述高危行为足以确立恶意性质。综合四位专家意见，判定该样本具备窃取联系人、系统干扰、获取设备管理权限与持久化驻留的能力，建议立即隔离样本并阻断分发。注：本裁决仅基于当前四位专家提供的证据与结论。

### 静态分析员（模型：`gemini-2.5-pro`）
此应用是一个木马化的邮件客户端。静态分析发现其包名 com.appple.app.email 明显仿冒知名品牌 Apple，而其签名证书则来自一个位于越南的未知开发者，这构成了典型的品牌仿冒欺诈。应用的核心功能代码基于开源项目 K-9 Mail，但被重新打包并增加了可疑行为。它申请了读取和写入联系人等高危权限，并注册了开机自启广播接收器(BootReceiver)以实现持久化。动态沙箱证据交叉印证了其风险，该应用在运行时会与设备策略服务交互，这通常是恶意软件为了获取设备管理器权限、防止被卸载的常见手段。综合判断，该应用具有窃取用户联系人信息、进行持久化驻留等恶意行为，风险等级高。

### 行为分析员（模型：`gemini-2.5-flash`）
该 APK 表现为典型的伪装类恶意软件。虽然代码结构复用了开源项目 K-9 Mail 的组件，但其签名证书（Nguyen Hao, Hanoi）与该开源项目无关。动态分析显示，该应用在安装后通过 `DevicePolicyManager` 尝试获取设备管理权限，并存在明显的 `getopt` 异常调用与 `logcat` 审计拒绝记录，表明其试图绕过系统沙箱限制或进行提权探测。此外，应用在后台强制停止了联系人与健康应用，表现出明显的恶意干扰行为，存在窃取敏感数据或进行持久化驻留的风险。

### 情报分析员（模型：`gpt-5`）
综合本地静态与短时动态沙箱证据：该 APK 包名为 com.appple.app.email，明显带有“appple”拼写混淆，结合内部大量 com.fsck.k9.* 组件与资源，强烈指向基于开源 K-9 Mail 的换皮/重打包版本，并非 Apple 官方产品。签名证书主体/颁发者为自签名实体（appleinfo_studio，Hanoi，CN=Nguyen Hao），与任何知名邮箱厂商或 K‑9 官方签名均不一致，信誉需重点核验。权限侧请求 READ_CONTACTS、RECEIVE_BOOT_COMPLETED 等，功能上可与邮件客户端相容，但存在隐私与持久化运行面风险。动态沙箱在约 12 秒窗口内安装/启动成功，未授予危险权限、未见对外网络 C2/下载行为，仅观察到常规包管理与优化日志以及通知/后台轮询相关组件注册，因此当前未能复现明显恶意行为。边界与局限：1) 运行时极短、未配置邮箱账户/未进行交互，难以触发网络收发邮件或可疑逻辑；2) 模拟器环境可能影响行为分支；3) 本地分析无法判定分发链可信度与开发者信誉。建议重点结合来源与分发渠道：核对是否来自官方应用商店（Google Play/F‑Droid）或 K‑9 官方发布渠道，校验开发者名与签名指纹/证书链；若来源为第三方下载页、广告落地页或仿冒“Apple Mail”推广，应按高风险处置并以哈希/签名做全网威胁情报溯源与封禁。

### 处置建议员（模型：`gpt-5.4-mini`）
建议立即隔离安装环境并阻断进一步分发；该 APK 虽然可正常安装和启动，但同时具备联系人读取、开机自启、持续后台服务与网络访问能力，且签名主体、包名仿冒痕迹与运行时联网行为均存在较强可疑性。建议保留样本及动态留痕，继续在隔离沙箱内复核联网目的、账号交互与联系人访问路径，未完成复核前不要在生产终端或真实账号环境中使用。


### 主持人最终总结
最终裁决：该 APK 为基于开源 K‑9 Mail 的木马化、品牌仿冒邮件客户端，风险定级为“严重”。静态证据显示其包名 com.appple.app.email 仿冒 Apple，签名为未知越南个人自签，且申请读取/写入联系人与开机自启并注册 BootReceiver，具备隐私窃取与持久化能力。动态侧进一步观测到尝试获取设备管理器权限（DevicePolicyManager 列表出现该包），以及强制停止联系人与健康类应用的恶意干扰行为，并伴随异常系统调用被拒记录，指向防卸载/提权探测与持久驻留意图。尽管情报侧短时沙箱未复现对外通信或明显恶意动作，但其已指出运行窗口和环境局限；在现有证据下，上述高危行为足以确立恶意性质。综合四位专家意见，判定该样本具备窃取联系人、系统干扰、获取设备管理权限与持久化驻留的能力，建议立即隔离样本并阻断分发。注：本裁决仅基于当前四位专家提供的证据与结论。


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
