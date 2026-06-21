# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**MEDIUM** · 风险分数：**53/100**
> 证据分数：**70/100** · 深度研判分数：**82 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpq749pfjs.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：26 条
- 高危证据：12 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260621_153909_208096.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260621_153909_208096.md

## 二、统一 IR 摘要
- APK 文件：`tmpq749pfjs.apk`
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
- static_file_name：tmpq749pfjs.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
com.appple.app.email/com.fsck.k9.activity.Accounts
- pidof：
- granted_dangerous_permissions：无
- post_install_files：无
- persistent_services：{'device_policy': ['5: com.appple.app.email'], 'notification': ['AppSettings: com.appple.app.email (10175) importance=DEFAULT userSet=false']}
- install_success：True
- launch_success：True
- event_count：34
- logcat_excerpt_count：230
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260621_153911_213837_com.appple.app.email/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260621_153911_213837_com.appple.app.email/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260621_153911_213837_com.appple.app.email/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260621_153911_213837_com.appple.app.email`
- ui_trace_dir：`G:/project/code/information/apk_dynamic/20260621_153911_213837_com.appple.app.email/ui_trace`
- ui_trace_paths：`['G:/project/code/information/apk_dynamic/20260621_153911_213837_com.appple.app.email/ui_trace/com.appple.app.email_launch_20260621_153911_214834.png', 'G:/project/code/information/apk_dynamic/20260621_153911_213837_com.appple.app.email/ui_trace/com.appple.app.email_evidence_20260621_153911_852855.png']`

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
- 一致性分数：`83`
- 一致性等级：`HIGH`
- 分歧点：static-behavior 差异 25 分, static-intelligence 差异 25 分, behavior-intelligence 差异 0 分
- 被污染模块：无

## 四点四、鲁棒性分析
- 对抗技术：无
- 鲁棒性分数：`0.0`
- 抗干扰能力评估：**弱**

## 五、风险证据
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
- 证据：`Subject=<asn1crypto.x509.Name 2206329577536 b'0x1\x0b0\t\x06\x03U\x04\x06\x13\x02841\x0e0\x0c\x06\x03U\x04\x08\x13\x05Hanoi1\x0e0\x0c\x06\x03U\x04\x07\x13\x05Hanoi1\x190\x17\x06\x03U\x04\n\x0c\x10appleinfo_studio1\x190\x17\x06\x03U\x04\x0b\x13\x10appleinfo studio1\x130\x11\x06\x03U\x04\x03\x13\nNguyen Hao'>; Issuer=<asn1crypto.x509.Name 2206329601664 b'0x1\x0b0\t\x06\x03U\x04\x06\x13\x02841\x0e0\x0c\x06\x03U\x04\x08\x13\x05Hanoi1\x0e0\x0c\x06\x03U\x04\x07\x13\x05Hanoi1\x190\x17\x06\x03U\x04\n\x0c\x10appleinfo_studio1\x190\x17\x06\x03U\x04\x0b\x13\x10appleinfo studio1\x130\x11\x06\x03U\x04\x03\x13\nNguyen Hao'>`
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
- 证据：`settings.get.glo; package.install; HardwareBuffer.close; com.sonyericsson.home.permission; com.appple.app.email`
- 建议：后续可结合抓包或代理进行复核。

### 6. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`5: com.appple.app.email; AppSettings: com.appple.app.email (10175) importance=DEFAULT userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 7. 后台驻留与自启动行为
- 规则：`DEEP_APK_BEHAVIOR_PERSISTENCE`
- 严重级别：`high`
- 说明：应用通过 BootReceiver 注册了开机自启，并存在多个常驻 Service（如 PollService, PushService），在后台持续运行以维持连接或执行任务。
- 证据：`动态日志显示 com.fsck.k9.service.BootReceiver 注册，且系统服务列表包含多个常驻 Service，存在后台驻留风险。`
- 建议：建议监控该应用在后台的网络流量消耗及对联系人数据的访问频率。

### 8. 敏感权限组合与数据访问
- 规则：`DEEP_APK_BEHAVIOR_PRIVACY_RISK`
- 严重级别：`high`
- 说明：应用同时申请了 READ_CONTACTS 和 WRITE_CONTACTS，结合其邮件客户端的伪装身份，存在窃取用户通讯录或注入恶意联系人信息的风险。
- 证据：`静态权限列表包含 READ_CONTACTS/WRITE_CONTACTS，且代码中存在大量反射调用（Method.invoke, Field.get），可能用于隐藏敏感 API 调用。`
- 建议：限制该应用的联系人读取权限，并检查其是否存在向外部服务器上传通讯录数据的行为。

### 9. 系统级访问受限与异常行为
- 规则：`DEEP_APK_BEHAVIOR_SYSTEM_ANOMALY`
- 严重级别：`medium`
- 说明：动态日志中出现多次 avc: denied { getopt } 错误，表明应用试图越权访问系统底层 Socket 或进行非法的系统配置查询。
- 证据：`logcat 记录：avc: denied { getopt } for scontext=u:r:system_server:s0 tcontext=u:r:shell:s0。`
- 建议：该行为属于明显的恶意探测，建议在沙箱中进一步追踪其网络连接目标。

### 10. 疑似基于 K-9 Mail 的重打包/改造版
- 规则：`DEEP_APK_INTEL_REPACKAGE_K9`
- 严重级别：`high`
- 说明：应用内部核心组件集中于 com.fsck.k9.* 命名空间（典型 K-9 Mail），但包名与签名均非官方，且资源包含广告相关布局，符合第三方重打包特征。
- 证据：`classes 与组件：com.fsck.k9.activity.*, com.fsck.k9.service.*（MailService/PollService/PushService）；自定义/广告线索：com.banana.lib.RateDialogActivity、res/layout/layout_notification_ads.xml、show_apps_activity.xml；包名：com.appple.app.email 非 K-9 官方；签名 SHA-256：bc70057d3841d9ce…`
- 建议：对比官方 K-9 Mail 包名与签名（Play/F-Droid/官方发布），若不匹配，视为非官方重打包；在受控网络中进一步审计其广告/统计代码分发与外联域名。

### 11. 包名“com.appple.app.email”存在疑似品牌蹭名/仿冒
- 规则：`DEEP_APK_INTEL_TYPOSQUAT`
- 严重级别：`high`
- 说明：包名中的“appple”（多重 p）与知名品牌“apple”近似，结合邮件场景与非官方签名，存在引导误装或品牌仿冒风险。
- 证据：`package_name: com.appple.app.email（拼写近似 apple）；活动入口：com.fsck.k9.activity.Accounts`
- 建议：核验应用市场展示名、图标与开发者信息；若在企业环境出现侧载，建议按高风险仿冒处理并阻断分发。

### 12. 签名主体与官方发布习惯不符
- 规则：`DEEP_APK_INTEL_SIGNATURE_MISMATCH`
- 严重级别：`high`
- 说明：证书主体/颁发者显示“appleinfo studio/Nguyen Hao（Hanoi）”，不符合 K-9 Mail 官方签名；重打包与非官方分发概率高。
- 证据：`certificate_subject/issuer 含 appleinfo studio, Nguyen Hao, Hanoi；certificate_sha256=bc70057d3841d9ce…`
- 建议：与官方指纹比对（Play/F-Droid/官网），若不一致则判为非官方；结合来源日志确认是否来自第三方站点或聚合分发。

### 13. 联系人读取权限与邮件场景相关但需最小化验证
- 规则：`DEEP_APK_INTEL_PRIVACY_CONTACTS`
- 严重级别：`medium`
- 说明：静态声明 READ_CONTACTS、READ_SYNC_SETTINGS 可用于收件人自动补全/同步；当前短时动态未触发危险权限授予，隐私访问行为未被证实。
- 证据：`manifest 权限：READ_CONTACTS, READ_SYNC_SETTINGS, RECEIVE_BOOT_COMPLETED；动态摘要：granted_dangerous_permissions=[]，runtime ≈12s`
- 建议：在交互式沙箱配置邮箱账户，触发联系人访问点（撰写邮件、自动补全）并抓取网络流量；若与业务无关或越权访问，按隐私合规问题处置。

### 14. 开机自启与后台驻留能力
- 规则：`DEEP_APK_INTEL_PERSISTENCE_BOOT`
- 严重级别：`medium`
- 说明：存在 BootReceiver 和邮件轮询/推送服务，符合邮件客户端常见的持久化逻辑，但也提供长期驻留能力。
- 证据：`receiver: com.fsck.k9.service.BootReceiver；services: MailService/PollService/PushService；权限：RECEIVE_BOOT_COMPLETED；动态摘要中存在通知渠道初始化`
- 建议：在移动管理策略中限制自启与后台运行策略；若为非官方重打包版本，建议阻断以减少驻留与潜在外联风险。

### 15. 静态与动态证据存在差异，需人工复核
- 规则：`DEEP_APK_INTEL_STATIC_DYNAMIC_GAP`
- 严重级别：`medium`
- 说明：规则提示存在 WRITE_CONTACTS，但权限清单解析未见该项；短时沙箱也未观测到危险权限弹窗或网络目的地，可能因版本差异、解析适配或执行路径未覆盖。
- 证据：`静态规则证据：READ_CONTACTS, WRITE_CONTACTS；已解析权限：未列出 WRITE_CONTACTS；动态运行 12s 未触发权限与有效外联域名。`
- 建议：手动解包核对 AndroidManifest.xml 与 targetSdk；延长沙箱并进行 UI 操作覆盖收发邮件、设置同步等路径；捕获并解析实际外联域名/IP。

### 16. 存在 Crashlytics/反射与旧版网络栈使用迹象
- 规则：`DEEP_APK_INTEL_CRASHLYTICS_REFLECTION_HTTP`
- 严重级别：`medium`
- 说明：资源包含 crashlytics-build.properties；API 图显示 Settings.Secure.getString（可能读取 ANDROID_ID）、大量反射调用与 Apache HttpClient/HttpURLConnection 使用，存在设备标识收集与潜在隐私传输可能。
- 证据：`assets/crashlytics-build.properties；API 调用计数：Settings.Secure.getString x5、Method.invoke x67、Field.get x44、HttpClient.execute x9、URL.openConnection x14`
- 建议：在代理/抓包环境中复核实际上报目标与数据内容；若来源不明，限制网络访问直至完成隐私合规评估。

### 17. 建议隔离安装验证
- 规则：`DEEP_APK_ADVICE_ISOLATE_INSTALL`
- 严重级别：`high`
- 说明：该样本已在沙箱中安装成功并启动，且包含后台服务、开机广播接收器与联网能力，适合在隔离环境继续验证，不应在办公终端或真实用户设备直接安装。
- 证据：`install_success=true; launch_success=true; services=com.fsck.k9.service.PollService, com.fsck.k9.service.PushService, com.fsck.k9.service.RemoteControlService; receiver=com.fsck.k9.service.BootReceiver; permissions=INTERNET, RECEIVE_BOOT_COMPLETED, READ_CONTACTS`
- 建议：仅允许在受控沙箱/测试机中复核，禁止在生产终端安装；安装后立即恢复快照并清理残留。

### 18. 建议进行二次沙箱复核
- 规则：`DEEP_APK_ADVICE_SANDBOX_RECHECK`
- 严重级别：`high`
- 说明：动态窗口仅12秒，已出现12次网络命中，但当前日志未覆盖完整行为链，无法排除延迟触发、账号收集、同步外传或远程指令执行等行为。
- 证据：`runtime_window_seconds=12; network_hit_count=12; logcat_excerpt_count=230; post_install_files=[]; pidof为空`
- 建议：扩大沙箱观察窗口，模拟用户登录、同步、收发邮件、通知交互、重启后行为与断网重连场景，重点捕获请求域名、POST参数、证书校验与持久化痕迹。

### 19. 建议阻断分发与上线
- 规则：`DEEP_APK_ADVICE_BLOCK_DISTRIBUTION`
- 严重级别：`critical`
- 说明：包名为 com.appple.app.email，明显具备仿冒知名邮件应用的命名特征；同时请求联系人权限并含 BootReceiver、RemoteControlService 等组件，若进入分发链路存在较高误装与数据采集风险。
- 证据：`package_name=com.appple.app.email; permissions include READ_CONTACTS, RECEIVE_BOOT_COMPLETED; components include BootReceiver, RemoteControlService, PushService; certificate_subject=Nguyen Hao / appleinfo_studio`
- 建议：在来源未核实前阻断上线、灰度和外部分发；若已进入渠道，立即下架并通知安全运营与应用商店审核团队复核。

### 20. 建议保留样本与证据留痕
- 规则：`DEEP_APK_ADVICE_KEEP_SAMPLE_TRACE`
- 严重级别：`medium`
- 说明：样本签名、SHA256、动态日志和网络命中均已具备追溯价值，后续若发现关联样本或域名，可用于横向溯源和规则编写。
- 证据：`sha256=e8595d59908040edaa9b2583a83b574d3ffa7bff468ba63472851ec782a2a6d6; certificate_sha256=bc70057d3841d9ced9b6c24e4683d1239baf0ea95f39fa4828f67fe2c546aeb5; dynamic_logcat_path=G:/project/code/information/apk_dynamic/20260621_153911_213837_com.appple.app.email/logcat_excerpt.txt; dynamic_json_path=G:/project/code/information/apk_dynamic/20260621_153911_213837_com.appple.app.email/dynamic_artifacts.json`
- 建议：保留原始 APK、证书指纹、动态日志、网络域名列表与安装痕迹；生成 IOC 供检测平台和网关侧联动封禁。

### 21. 建议复核签名与来源可信度
- 规则：`DEEP_APK_ADVICE_REVIEW_SIGNATURE_SOURCE`
- 严重级别：`medium`
- 说明：签名主体显示为 Nguyen Hao / appleinfo_studio，和常见官方邮件客户端发布链路不匹配，需核实是否为第三方重打包或仿冒分发。
- 证据：`certificate_subject contains appleinfo_studio and Nguyen Hao; certificate_issuer similar; APK package_name mimics email app; key_files include crashlytics-build.properties and ad-like layouts`
- 建议：核对证书链、历史版本、发布者账号和市场来源；若无法证明同源可信，按非官方或重打包样本处理。

### 22. 联系人权限需重点约束
- 规则：`DEEP_APK_ADVICE_CONTACTS_PERMISSION_CAUTION`
- 严重级别：`high`
- 说明：样本请求 READ_CONTACTS，结合邮件客户端身份可读取联系人与同步信息，存在地址簿收集或外传风险。
- 证据：`android.permission.READ_CONTACTS; android.permission.READ_SYNC_SETTINGS; dynamic network_hit_count=12`
- 建议：禁止授予不必要的联系人访问；如业务必须使用，需对通讯录访问范围、同步接口与外联域名进行白名单控制。

### 23. 建议监控持久化与后台常驻行为
- 规则：`DEEP_APK_ADVICE_MONITOR_PERSISTENCE`
- 严重级别：`high`
- 说明：BootReceiver、PollService、PushService、RemoteControlService 等组件表明应用可在开机后和后台长期活动，具备持续通信和常驻能力。
- 证据：`receivers=com.fsck.k9.service.BootReceiver, com.fsck.k9.service.RemoteControlReceiver; services=com.fsck.k9.service.PollService, com.fsck.k9.service.PushService, com.fsck.k9.service.RemoteControlService`
- 建议：在沙箱和准生产环境中监控开机后自启、通知驻留、前台服务、Job/Alarm 触发与网络重连行为，确认无异常指令通道。

### 24. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 25 分; static-intelligence 差异 25 分; behavior-intelligence 差异 0 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 25. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`low`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`83`
- 建议：将该评分作为后续人工复核的重要参考。

### 26. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`low`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`0.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5`）
综合前四位专家意见，该样本虽以 K-9 Mail 代码框架为表象，但存在明显的非官方重打包与仿冒特征（包名“com.appple.app.email”易混淆品牌、签名主体与官方不符、资源中含广告/统计线索），叠加动态行为显示的开机自启与后台常驻（BootReceiver+RECEIVE_BOOT_COMPLETED、多个 Service 常驻）、异常系统访问日志（avc: denied）、以及超出最小化需求的敏感权限组合（如读取联系人并配合大量反射调用可能隐藏敏感 API），整体指向隐私采集与广告植入类高风险可疑样本。尽管当前沙箱时长较短（约 12 秒）且未观察到危险权限实际授予或明确的数据外传域名，部分静态指纹与解析权限清单亦存在不一致之处，但来源与签名可信度偏低、组件持久化能力明确、以及仿冒/侧载迹象，使其风险评估仍应按高风险处理，建议暂停分发并开展延长交互式动态验证与清单复核。注意：上述结论仅基于当前四位专家已提供的静态/动态与情报输出，尚未引入额外上下文与外部情报。

### 静态分析员（模型：`gemini-2.5-pro`）
APK 静态证据关注：存在敏感权限请求、存在持久化或高权限组件线索。

### 行为分析员（模型：`gemini-2.5-flash`）
经深度研判，该 APK（com.appple.app.email）表现出明显的“伪装合法应用”特征。虽然其代码结构（如 K-9 Mail 相关组件）试图模拟正常的邮件客户端，但动态沙箱日志显示其存在异常的系统权限调用与持久化尝试。特别是 `com.fsck.k9.service.BootReceiver` 的存在配合 `RECEIVE_BOOT_COMPLETED` 权限，证实了其具备开机自启与后台驻留能力。此外，日志中记录了 `avc: denied { getopt }` 等系统级访问受限行为，且存在重复的权限声明（如 `com.sonyericsson.home.permission.BROADCAST_BADGE`），这通常是恶意软件为了绕过安全检测或在不同 Android 版本中强行获取权限的常见手段。结合其签名信息（Nguyen Hao, Hanoi）与业务逻辑不符的敏感权限请求，判定该样本具有中高风险，可能用于后台数据窃取或恶意推广。

### 情报分析员（模型：`gpt-5`）
基于当前离线样本信息，tmpq749pfjs.apk（包名：com.appple.app.email）内部大量使用 com.fsck.k9.* 组件（K-9 Mail 开源邮件客户端命名空间），且资源中出现广告相关布局与 Crashlytics 线索，签名主体为“appleinfo studio/Nguyen Hao（Hanoi）”，与 K-9 官方发布不匹配，结合包名“appple”（疑似品牌蹭名/拼写误导）高度怀疑为在开源邮件客户端基础上的第三方二次打包/改造版。该类重打包样本常见于非官方分发渠道，风险在于植入广告、统计或潜在的隐私收集逻辑。静态权限包含 READ_CONTACTS、RECEIVE_BOOT_COMPLETED 等，对邮件类应用可解释，但仍需结合功能逻辑核查最小权限原则。
离线与沙箱边界：1）本次动态沙箱仅运行约 12 秒、无手动引导真实收发邮件流程，未触发危险权限授予（granted_dangerous_permissions 为空），网络命中未解析出有效域名，无法证明或否定敏感数据外传；2）静态规则指纹与权限清单存在不一致（规则提示 WRITE_CONTACTS，而已解析权限列表未见），需以 manifest 原文复核为准；3）证书信誉、历史版本对比、上下游来源未接入外部情报库，无法离线归因；4）本地路径来自临时目录 C:\Users\lenovo\AppData\Local\Temp\，更像侧载或二次分发来源，提升供应链与来源可信度风险。
处置与溯源建议：优先核验来源与分发渠道（Google Play/F-Droid 官方、K-9 官方 GitHub/官网或可信镜像），对比官方包名与签名指纹；若来源不明或证书不匹配官方发布，按高风险侧载处理。结合企业/终端侧网络日志复核是否存在非常规域名通信与联系人数据访问；在受控环境中进行延长、带交互的动态分析（配置邮箱账户、触发联系人自动补全与同步）以观察实际权限请求与网络行为。

### 处置建议员（模型：`gpt-5.4-mini`）
建议立即隔离安装环境，不向终端用户分发该 APK；在未完成更深层复核前应阻断继续投放，并保留样本、签名证书、动态日志与网络痕迹留痕。理由：静态与动态证据均显示其为邮件类应用但带有联系人读取、开机自启、后台服务、远程控制/推送/轮询等高风险特征，且动态沙箱中已成功安装并启动并产生网络访问，说明其具备真实联网与后台运行能力。当前未见明确恶意载荷落地证据，但来源证书、包名仿冒感和持久化组件使其风险不能按普通邮件客户端处理，建议按高风险可疑样本处置。


### 主持人最终总结
综合前四位专家意见，该样本虽以 K-9 Mail 代码框架为表象，但存在明显的非官方重打包与仿冒特征（包名“com.appple.app.email”易混淆品牌、签名主体与官方不符、资源中含广告/统计线索），叠加动态行为显示的开机自启与后台常驻（BootReceiver+RECEIVE_BOOT_COMPLETED、多个 Service 常驻）、异常系统访问日志（avc: denied）、以及超出最小化需求的敏感权限组合（如读取联系人并配合大量反射调用可能隐藏敏感 API），整体指向隐私采集与广告植入类高风险可疑样本。尽管当前沙箱时长较短（约 12 秒）且未观察到危险权限实际授予或明确的数据外传域名，部分静态指纹与解析权限清单亦存在不一致之处，但来源与签名可信度偏低、组件持久化能力明确、以及仿冒/侧载迹象，使其风险评估仍应按高风险处理，建议暂停分发并开展延长交互式动态验证与清单复核。注意：上述结论仅基于当前四位专家已提供的静态/动态与情报输出，尚未引入额外上下文与外部情报。


## 七、仲裁结果
- 一致性分数：`83`
- 一致性等级：`high`
- 加权置信度：`58`
- 疑似污染源：无
- 分歧与模式：
  - static-behavior 差异 25 分
  - static-intelligence 差异 25 分
  - behavior-intelligence 差异 0 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
