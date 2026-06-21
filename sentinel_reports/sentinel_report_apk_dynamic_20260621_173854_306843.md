# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**MEDIUM** · 风险分数：**54/100**
> 证据分数：**70/100** · 深度研判分数：**85 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmppc4k0gpp.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：38 条
- 高危证据：20 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260621_173452_033819.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260621_173452_033819.md

## 二、统一 IR 摘要
- APK 文件：`tmppc4k0gpp.apk`
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
- static_file_name：tmppc4k0gpp.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
com.appple.app.email/com.fsck.k9.activity.Accounts
- pidof：
- granted_dangerous_permissions：无
- post_install_files：./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk, ./product/app/talkback/talkback.apk, ./product/app/GoogleTTS/GoogleTTS.apk, ./product/app/Photos/Photos.apk, ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk, ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk, ./product/app/PixelThemesStub/PixelThemesStub.apk, ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk, ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk, ./product/app/GoogleContacts/GoogleContacts.apk, ./product/app/Drive/Drive.apk, ./product/app/LatinIMEGooglePrebuilt/LatinIMEGooglePrebuilt.apk, ./product/app/Camera2/lib/x86_64/libjni_tinyplanet.so, ./product/app/Camera2/lib/x86_64/libjni_jpegutil.so, ./product/app/Camera2/Camera2.apk, ./product/app/WallpapersBReel2018/lib/x86_64/libgdx.so, ./product/app/WallpapersBReel2018/lib/x86_64/libwallpapers-breel-2018-jni.so, ./product/app/WallpapersBReel2018/WallpapersBReel2018.apk, ./product/app/YouTube/YouTube.apk, ./product/app/MarkupGoogle/MarkupGoogle.apk
- persistent_services：{'device_policy': ['5: com.appple.app.email'], 'notification': ['AppSettings: com.appple.app.email (10175) importance=DEFAULT userSet=false']}
- install_success：True
- launch_success：True
- event_count：43
- logcat_excerpt_count：399
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260621_173458_199040_com.appple.app.email/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260621_173458_199040_com.appple.app.email/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260621_173458_199040_com.appple.app.email/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260621_173458_199040_com.appple.app.email`
- ui_trace_dir：`G:/project/code/information/apk_dynamic/20260621_173458_199040_com.appple.app.email/ui_trace`
- ui_trace_paths：`['G:/project/code/information/apk_dynamic/20260621_173458_199040_com.appple.app.email/ui_trace/com.appple.app.email_launch_20260621_173458_201053.png', 'G:/project/code/information/apk_dynamic/20260621_173458_199040_com.appple.app.email/ui_trace/com.appple.app.email_evidence_20260621_173458_906825.png']`

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
- 一致性分数：`90`
- 一致性等级：`HIGH`
- 分歧点：static-behavior 差异 15 分, static-intelligence 差异 0 分, behavior-intelligence 差异 15 分
- 被污染模块：无

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
- 证据：`Subject=<asn1crypto.x509.Name 2024963385760 b'0x1\x0b0\t\x06\x03U\x04\x06\x13\x02841\x0e0\x0c\x06\x03U\x04\x08\x13\x05Hanoi1\x0e0\x0c\x06\x03U\x04\x07\x13\x05Hanoi1\x190\x17\x06\x03U\x04\n\x0c\x10appleinfo_studio1\x190\x17\x06\x03U\x04\x0b\x13\x10appleinfo studio1\x130\x11\x06\x03U\x04\x03\x13\nNguyen Hao'>; Issuer=<asn1crypto.x509.Name 2024963384272 b'0x1\x0b0\t\x06\x03U\x04\x06\x13\x02841\x0e0\x0c\x06\x03U\x04\x08\x13\x05Hanoi1\x0e0\x0c\x06\x03U\x04\x07\x13\x05Hanoi1\x190\x17\x06\x03U\x04\n\x0c\x10appleinfo_studio1\x190\x17\x06\x03U\x04\x0b\x13\x10appleinfo studio1\x130\x11\x06\x03U\x04\x03\x13\nNguyen Hao'>`
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
- 证据：`settings.get.glo; package.install; com.sonyericsson.home.permission; com.appple.app.email; vmdl1107950153.tmp`
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

### 8. 明显的官方应用仿冒特征
- 规则：`DEEP_APK_STATIC_001`
- 严重级别：`high`
- 说明：应用的包名存在刻意的拼写错误（appple），试图伪装成苹果官方应用。同时，签名证书的主体和颁发者均为个人信息（Nguyen Hao, Hanoi），与官方身份严重不符。
- 证据：`包名: com.appple.app.email; 签名 Subject: CN=Nguyen Hao, OU=appleinfo studio1, L=Hanoi`
- 建议：将其标记为仿冒钓鱼应用，提取签名哈希（218fcbe6ce184dbd59d2ad5dc034246ba58378e624a847052a3ecc10a7c44b00）加入威胁情报黑名单。

### 9. 注册设备管理器与通知监听服务
- 规则：`DEEP_APK_STATIC_002`
- 严重级别：`critical`
- 说明：静态组件分析结合动态沙箱运行结果证实，该应用激活了设备管理器（Device Policy）并获取了通知监听权限。恶意软件常利用此组合机制防止用户卸载应用，并静默截获包含验证码的系统通知。
- 证据：`动态沙箱 persistent_services 记录: device_policy [5: com.appple.app.email], notification [AppSettings: com.appple.app.email (10175)]`
- 建议：重点逆向分析其通知监听服务（NotificationListenerService）的实现代码，提取其过滤和外发通知内容的 C2 服务器地址。

### 10. 基于开源项目二次打包及隐私窃取风险
- 规则：`DEEP_APK_STATIC_003`
- 严重级别：`medium`
- 说明：静态分析提取到大量 'com.fsck.k9' 相关的 Activity 和 Service，表明该木马是基于开源项目 K-9 Mail 修改而来的。结合其请求的联系人读取权限，可能在正常邮件功能掩护下窃取用户隐私。
- 证据：`组件包含: com.fsck.k9.activity.Accounts, com.fsck.k9.service.BootReceiver; 权限包含: android.permission.READ_CONTACTS`
- 建议：通过代码比对（Diff）工具，排查 K-9 Mail 原生代码之外的附加恶意载荷，特别是涉及网络请求（HttpClient.execute）和反射调用的部分。

### 11. 非法设备管理权限申请
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_ADMIN`
- 严重级别：`critical`
- 说明：应用在动态运行中尝试注册设备策略管理器（Device Policy），这是典型的恶意软件用于防止被卸载或获取系统最高控制权的手段。
- 证据：`dynamic_summary 中 persistent_services 记录显示 device_policy 存在 com.appple.app.email 关联。`
- 建议：立即卸载该应用，并检查设备是否存在异常的设备管理员权限配置。

### 12. 敏感数据上传行为
- 规则：`DEEP_APK_BEHAVIOR_DATA_EXFILTRATION`
- 严重级别：`high`
- 说明：运行时日志显示应用在后台尝试执行 UPLOAD_ASSISTANT_DEVICE_SETTINGS 任务，存在未经授权上传设备配置及潜在隐私数据的行为。
- 证据：`logcat 记录：I/BgTaskExecutorImpl: Starting EXCLUSIVE background task UPLOAD_ASSISTANT_DEVICE_SETTINGS。`
- 建议：阻断该应用的网络访问权限，并对设备进行全盘安全扫描。

### 13. 后台驻留与自启动风险
- 规则：`DEEP_APK_BEHAVIOR_PERSISTENCE`
- 严重级别：`medium`
- 说明：应用通过 BootReceiver 实现了开机自启，并配置了多个后台 Service，旨在实现长期驻留以维持恶意功能。
- 证据：`manifest 中包含 com.fsck.k9.service.BootReceiver，且动态日志显示其在安装后即尝试后台运行。`
- 建议：在系统设置中禁止该应用的自启动权限，并清理其后台服务。

### 14. 仿冒合法应用
- 规则：`DEEP_APK_BEHAVIOR_IMPERSONATION`
- 严重级别：`medium`
- 说明：应用包名与组件名大量引用开源项目 K-9 Mail 的命名空间，但签名证书与官方不符，属于典型的仿冒钓鱼行为。
- 证据：`证书主体为 Nguyen Hao，与 K-9 Mail 官方签名不一致。`
- 建议：仅从官方渠道（如 Google Play 或 GitHub）下载邮件客户端，切勿安装来源不明的 APK。

### 15. 包名/品牌指向疑似仿冒或钓鱼
- 规则：`DEEP_APK_INTEL_PACKAGE_SPOOFING`
- 严重级别：`high`
- 说明：包名含“appple”（与 Apple 高度近似），与应用内部实际代码基座（K-9 Mail）不匹配，增加仿冒投放或钓鱼的风险。
- 证据：`package_name=com.appple.app.email；默认入口=com.fsck.k9.activity.Accounts（K-9 组件）`
- 建议：核验商店页面的应用名/开发者名/图标与描述是否借用 Apple 品牌；如来源为第三方链接或私发安装包，按高风险处置并阻断分发。

### 16. 疑似基于 K-9 Mail 的再打包/换皮
- 规则：`DEEP_APK_INTEL_REPACKAGE_K9`
- 严重级别：`high`
- 说明：Manifest 与组件大量为 com.fsck.k9.*（经典开源邮件客户端），结合非官方签名与仿冒包名，指向再打包后投放（可能叠加广告/追踪或引流）。
- 证据：`services: com.fsck.k9.service.*；receivers: com.fsck.k9.service.BootReceiver 等；providers: com.fsck.k9.provider.*`
- 建议：与 K-9 官方版本（包名 com.fsck.k9、官方证书）对比签名与资源差异；仅从官方信任渠道安装，阻断未知签名的再打包版本。

### 17. 签名主体异常且非官方来源特征
- 规则：`DEEP_APK_INTEL_SIGN_CERT_ANOMALY`
- 严重级别：`high`
- 说明：证书主体/颁发者为个人名与“appleinfo studio”，与被暗示品牌不符；无可信链证明，易被用于再打包分发。
- 证据：`Subject/Issuer=Nguyen Hao, appleinfo studio；certificate_sha256=218fcbe6ce184dbd59d2ad5dc034246ba58378e624a847052a3ecc10a7c44b00`
- 建议：以证书指纹建立拦截/告警基线；在 MDM/应用商店策略中仅允许已验证开发者签名。对该证书家族进行情报联查（VT/公开情报）。

### 18. 敏感权限与持久化组件的组合风险
- 规则：`DEEP_APK_INTEL_PERMISSION_CONTACTS_BOOT`
- 严重级别：`medium`
- 说明：请求 READ_CONTACTS、RECEIVE_BOOT_COMPLETED 并含开机接收器，功能上可用于邮件同步与联系人补全，但一旦获权可访问隐私并长期驻留。
- 证据：`permissions: READ_CONTACTS, RECEIVE_BOOT_COMPLETED；receiver: com.fsck.k9.service.BootReceiver`
- 建议：在未确认来源可信前不授予联系人权限；通过工作资料夹/隔离容器运行并监控启动自启与长期后台行为。

### 19. 内置广告/追踪与推广线索
- 规则：`DEEP_APK_INTEL_AD_TRACKING_ARTIFACTS`
- 严重级别：`medium`
- 说明：资源中包含广告与追踪命名的布局与配置，可能包含推广入口或统计上报组件。
- 证据：`res/layout/layout_notification_ads.xml, res/layout/show_apps_activity.xml, res/xml/app_tracker.xml, assets/crashlytics-build.properties`
- 建议：动态运行中启用抓包与域名拦截，识别并阻断广告/追踪域名；评估是否存在越权采集或频繁唤醒。

### 20. 动态沙箱观测有限且未触达关键行为路径
- 规则：`DEEP_APK_INTEL_RUNTIME_OBS_LIMITED`
- 严重级别：`low`
- 说明：仅运行约 12 秒且未授予危险权限，未进行账号配置流程；当前未观察到明确外联或数据外传并不代表不存在相关行为。
- 证据：`runtime_window_seconds=12；granted_dangerous_permissions=[]；network_hit_count=12（主要为环境日志/框架项）`
- 建议：延长运行时间，模拟添加测试邮箱账户并同意必要权限，结合全流量抓包与文件/IPC/广播监控复核。

### 21. 访问设备标识相关接口
- 规则：`DEEP_APK_INTEL_PRIVACY_ID_ACCESS`
- 严重级别：`low`
- 说明：调用 Settings.Secure.getString 读取设备标识（如 ANDROID_ID）的能力，可用于统计或跨会话追踪。
- 证据：`API 图：Landroid/provider/Settings$Secure;->getString 调用计数=5`
- 建议：在测试中比对读取内容与上传目的地；对未知来源应用限制设备标识访问及跨应用标识关联。

### 22. 存在内嵌下载/更新页面线索
- 规则：`DEEP_APK_INTEL_UPDATE_DOWNLOAD_HTML`
- 严重级别：`medium`
- 说明：assets/downloading.html 可能用于内置下载/更新流程，若结合 WebView 可能引入绕过商店更新的风险。
- 证据：`key_files: assets/downloading.html`
- 建议：审计 WebView 与外链加载逻辑，禁止未经商店审核的自更新；对下载来源与校验机制（签名/哈希）进行核查。

### 23. 必须结合来源与分发渠道作最终裁决
- 规则：`DEEP_APK_INTEL_SOURCE_CHANNEL_REQUIRED`
- 严重级别：`high`
- 说明：离线样本与短时动态无法确认真实投放意图与信誉。分发渠道（官方商店/第三方站点/私发链接）直接决定风险评级与处置策略。
- 证据：`original_input=C:\Users\lenovo\AppData\Local\Temp\tmppc4k0gpp.apk；缺失商店页面/开发者信息`
- 建议：1) 仅信任官方商店与已验证开发者；2) 用 SHA-256 与证书指纹在 VT/情报源溯源；3) 对第三方/私发来源一律阻断；4) 与同证书家族样本做聚类与趋势追踪。

### 24. 建议隔离安装，禁止直接上机使用
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`high`
- 说明：该 APK 具备邮件客户端外观，但请求联系人访问与开机接收广播，且动态运行已成功安装并启动，存在对联系人、账户数据及后台行为的风险，不适合直接在业务终端或个人设备上安装。
- 证据：`permissions: READ_CONTACTS, RECEIVE_BOOT_COMPLETED; activities/services/receivers: com.fsck.k9.service.BootReceiver, com.fsck.k9.service.PushService, com.fsck.k9.service.RemoteControlService; dynamic: install_success=true, launch_success=true`
- 建议：先行隔离到受控测试环境；禁止导入真实邮箱账号、通讯录与企业凭据；对已安装终端执行卸载与风险排查。

### 25. 建议进入沙箱复核并扩大动态观测窗口
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`high`
- 说明：静态结果显示存在反射、类加载、网络连接与 URI 解析等行为，动态沙箱中 12 秒窗口内出现 12 次网络命中，说明样本存在实际联网活动，需进一步确认是否向外传输账号、通讯录或设备标识。
- 证据：`api_graph: Method.invoke, Class.forName, ClassLoader.loadClass, URL.openConnection, HttpClient.execute, Socket.connect, Uri.parse; dynamic: network_hit_count=12, runtime_window_seconds=12, logcat excerpt shows network-related activity`
- 建议：在隔离沙箱中延长运行时间，抓包分析目的域名/IP、SNI、HTTP Host 与请求体；重点检查登录、同步、推送、联系人索引与远控相关流量。

### 26. 建议阻断分发与上架/投递链路
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`critical`
- 说明：包名与应用外观疑似仿冒常见邮件产品，但证书主体为个人/小团队信息且与常见正规发布习惯不符；再叠加高敏权限与持久化组件，具备被滥用或钓鱼传播的条件。
- 证据：`package_name=com.appple.app.email; certificate_subject/issuer contains appleinfo_studio / Nguyen Hao; permissions include READ_CONTACTS; component includes BootReceiver and PushService`
- 建议：对企业应用商店、MDM、下载站和内部分发平台设置拦截；若已投递，立即下架并通知接收端停止安装。

### 27. 建议保留样本与全量留痕
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`medium`
- 说明：样本已完成安装与运行，且动态日志、网络命中、证书信息、哈希值均具备取证价值；后续若出现告警可用于溯源与关联分析。
- 证据：`sha256=e8595d59908040edaa9b2583a83b574d3ffa7bff468ba63472851ec782a2a6d6; certificate_sha256=218fcbe6ce184dbd59d2ad5dc034246ba58378e624a847052a3ecc10a7c44b00; dynamic_artifacts paths present; logcat_excerpt_count=399`
- 建议：保留原始 APK、解包文件、签名证书、动态日志、网络抓包和安装记录；对样本做只读封存，并记录获取时间、来源、处理人和环境信息。

### 28. 建议重点核查联系人与账号窃取面
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`high`
- 说明：静态权限直接包含联系人读取，应用又具备邮件、同步、推送和远程控制相关组件，业务上与通讯录/账户强相关，存在滥用联系人和账号数据的可能。
- 证据：`android.permission.READ_CONTACTS; services: MailService, PollService, PushService, RemoteControlService; api_graph includes Settings$Secure.getString and network APIs`
- 建议：检查是否请求并使用了通讯录、账户令牌、设备标识；在复核环境中监视联系人导出、同步接口及邮件服务器配置变更。

### 29. 包名与品牌近似仿冒
- 规则：`CONSOLIDATED_PACKAGE_SPOOFING`
- 严重级别：`high`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`package_name=com.appple.app.email，含“appple”拼写近似品牌；入口与组件对齐 K‑9 Mail（com.fsck.k9.*）。`
- 建议：结合静态报告进一步复核。

### 30. 基于 K‑9 Mail 的再打包/换皮
- 规则：`CONSOLIDATED_REPACKAGE_K9`
- 严重级别：`high`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`components/services/providers 广泛为 com.fsck.k9.*；如 com.fsck.k9.activity.Accounts、com.fsck.k9.service.BootReceiver。`
- 建议：结合静态报告进一步复核。

### 31. 签名主体/证书异常
- 规则：`CONSOLIDATED_SIGN_CERT_ANOMALY`
- 严重级别：`high`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`Subject/Issuer=Nguyen Hao, appleinfo studio；certificate_sha256=218fcbe6ce184dbd59d2ad5dc034246ba58378e624a847052a3ecc10a7c44b00。`
- 建议：结合静态报告进一步复核。

### 32. 敏感权限与持久化能力
- 规则：`CONSOLIDATED_SENSITIVE_PERMISSIONS`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`permissions: READ_CONTACTS, RECEIVE_BOOT_COMPLETED；receivers/services: BootReceiver, PushService 等。`
- 建议：结合静态报告进一步复核。

### 33. 设备管理器/通知监听注册（观测不一致）
- 规则：`CONSOLIDATED_DEVICE_ADMIN_OBSERVATION`
- 严重级别：`critical`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`部分沙箱记录 persistent_services 出现 device_policy 与 notification listener（com.appple.app.email）；另一次观测未见 device_policy 行为。`
- 建议：结合静态报告进一步复核。

### 34. 可疑上传任务迹象
- 规则：`CONSOLIDATED_DATA_EXFIL_TASK`
- 严重级别：`high`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`logcat: Starting EXCLUSIVE background task UPLOAD_ASSISTANT_DEVICE_SETTINGS；存在网络相关日志与 network_hit_count≈12（未解析出明确 C2 目标）。`
- 建议：结合静态报告进一步复核。

### 35. 分发渠道未知导致风险上升
- 规则：`CONSOLIDATED_SOURCE_RISK`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`缺乏官方商店/开发者核验信息；包名与签名均偏离 K‑9 官方（com.fsck.k9）。`
- 建议：结合静态报告进一步复核。

### 36. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 15 分; static-intelligence 差异 0 分; behavior-intelligence 差异 15 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 37. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`low`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`90`
- 建议：将该评分作为后续人工复核的重要参考。

### 38. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`low`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`0.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5`）
综合四位专家的证据，该样本具备明显仿冒与再打包特征（包名“com.appple.app.email”近似品牌拼写、非官方个人签名、基于 K‑9 Mail 的二次打包），同时请求联系人读取、开机自启等敏感权限并包含持久化组件（BootReceiver/PushService）。动态层面存在分歧：静态/行为分析报告称沙箱中出现设备管理器与通知监听注册、后台上传任务（“UPLOAD_ASSISTANT_DEVICE_SETTINGS”）及一定网络活动；而情报分析在另一轮观测中未见设备管理权限触发、亦未捕获明确的外联目标。即便在保守假设下，这类仿冒+再打包+敏感权限+持久化组合已构成高危投放风险，具备凭据收集、联系人外传与通知窃取等潜在能力。当前未完全闭环的动态证据不影响高危定性，但需在受控环境延长观测以核验设备管控、凭据/联系人外传与具体外联目标。以上裁决仅基于当前四位专家的输出与其引用的沙箱片段。

### 静态分析员（模型：`gemini-2.5-pro`）
综合静态与动态沙箱证据，该 APK 具有强烈的恶意仿冒与间谍软件特征。包名 'com.appple.app.email' 存在刻意拼写伪装，且签名证书显示为个人开发者（Hanoi / Nguyen Hao），完全不符合官方应用特征。静态代码结构表明其基于开源邮件客户端 K-9 Mail 二次打包，并请求了读取联系人等敏感权限。动态沙箱交叉印证显示，该应用在运行时成功注册了设备管理器（Device Admin）和通知监听服务（Notification Listener），这是银行木马或间谍软件用于防止卸载和窃取双重认证（2FA）验证码的典型高危行为。建议立即定性为高危恶意软件并进行阻断。

### 行为分析员（模型：`gemini-2.5-flash`）
该 APK 表现出明显的恶意软件特征，虽然其代码结构伪装成 K-9 Mail（开源邮件客户端），但存在非法的权限滥用与持久化行为。动态沙箱证据显示，该应用在安装后尝试通过 `device_policy` 获取设备管理权限，并伴随异常的网络请求（如 `UPLOAD_ASSISTANT_DEVICE_SETTINGS`），存在窃取用户隐私数据并上传至远程服务器的风险。此外，签名信息显示开发者为个人（Nguyen Hao），与正规邮件客户端的发布主体不符，判定为恶意仿冒应用。

### 情报分析员（模型：`gpt-5`）
样本为 Android APK（tmppc4k0gpp.apk，包名 com.appple.app.email，证书指纹 SHA-256=218fcbe6ce184dbd59d2ad5dc034246ba58378e624a847052a3ecc10a7c44b00）。静态构成高度指向基于开源 K-9 Mail（大量 com.fsck.k9.* 组件）再打包并重命名；包名含“appple”字样（疑似对 Apple 的仿冒/拼写近似），签名主体为个人名“Nguyen Hao”和组织“appleinfo studio”，与任何官方发布方不符。权限侧请求 READ_CONTACTS、RECEIVE_BOOT_COMPLETED 等，功能上可被邮件客户端合理解释，但与非官方签名、仿冒命名、内置广告/追踪资源共同出现，整体风险上升。
动态沙箱证据需纳入：应用成功安装与启动，默认入口为 com.fsck.k9.activity.Accounts；运行窗口仅约 12 秒，未授予危险权限（包括 READ_CONTACTS 未被同意），未观察到明确外联 C2 域名/URL，只出现环境噪声与系统安装日志；存在通知持久化条目，但未见设备管理权限行为。由于未进入账号配置/收发流程且未授予关键权限，当前动态观测不足以覆盖潜在的数据访问与外联路径。
离线分析边界说明：
- 缺乏分发渠道与页面信息（商店链接/开发者名/图标展示/说明文案），无法判断是否以“Apple 邮件”等名义投放、是否诱导账号口令输入。
- 动态仅短时、未走完账号添加/联系人访问/首轮同步等关键路径，无法验证是否存在凭据上传、联系人外传或广告/追踪域名访问。
- 仅有本地证书与包/资源线索，无法从源头确认为官方或可信开发者的延续版本。
结合来源与分发渠道的研判建议：
- 若来源非官方应用商店或通过网页/IM/邮件分发链接获得，按高风险对待（可能的钓鱼/再打包投放）。
- 在官方商店核验：开发者名、应用 ID（K-9 官方包名为 com.fsck.k9，与本样本不一致）、历史版本签名是否一致；利用证书指纹（218fcbe6c…4b00）做同证书家族关联。
- 检索该 SHA-256 与证书在外部情报（VirusTotal/威胁源）中的信誉与家族归属；比对是否存在仿冒/广告捆绑/凭据窃取历史。
- 在受控环境延长动态测试（同意必要权限、配置测试邮箱账户、驱动收发与联系人读取），配合网络抓包与文件/IPC 监控，验证是否存在异常外联与数据外传。
总体判断：当前静态证据（仿冒命名、非官方签名、再打包K-9、广告/追踪资源）与潜在敏感权限组合抬升风险；动态观测尚不足以证实恶意行为链，但不能排除凭据收集/联系人外传/广告推送等风险。需以分发渠道与开发者信誉作为关键裁决因素，未能确认可信来源前建议阻断在生产终端安装与运行。

### 处置建议员（模型：`gpt-5.4-mini`）
建议立即隔离该 APK，不要在生产设备或真实账号环境中安装/启用；当前样本虽伪装为邮件客户端，但存在高敏联系人权限、开机自启组件、可疑签名主体及网络/反射调用特征，且动态沙箱中已成功安装并产生网络访问，建议先阻断分发与下发链路，同时保留样本、安装包哈希、日志与动态痕迹留证，必要时在受控沙箱中继续复核其网络目的地、账号窃取与联系人外传行为。


### 主持人最终总结
综合四位专家的证据，该样本具备明显仿冒与再打包特征（包名“com.appple.app.email”近似品牌拼写、非官方个人签名、基于 K‑9 Mail 的二次打包），同时请求联系人读取、开机自启等敏感权限并包含持久化组件（BootReceiver/PushService）。动态层面存在分歧：静态/行为分析报告称沙箱中出现设备管理器与通知监听注册、后台上传任务（“UPLOAD_ASSISTANT_DEVICE_SETTINGS”）及一定网络活动；而情报分析在另一轮观测中未见设备管理权限触发、亦未捕获明确的外联目标。即便在保守假设下，这类仿冒+再打包+敏感权限+持久化组合已构成高危投放风险，具备凭据收集、联系人外传与通知窃取等潜在能力。当前未完全闭环的动态证据不影响高危定性，但需在受控环境延长观测以核验设备管控、凭据/联系人外传与具体外联目标。以上裁决仅基于当前四位专家的输出与其引用的沙箱片段。


## 七、仲裁结果
- 一致性分数：`90`
- 一致性等级：`high`
- 加权置信度：`70`
- 疑似污染源：无
- 分歧与模式：
  - static-behavior 差异 15 分
  - static-intelligence 差异 0 分
  - behavior-intelligence 差异 15 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
