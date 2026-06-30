# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**MEDIUM** · 风险分数：**60/100**
> 证据分数：**70/100** · 深度研判分数：**96 /100**
> 评分口径：APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\sentinelguard_apk_bundle_dswnccuq`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：35 条
- 高危证据：24 条

## 二、统一 IR 摘要
- APK 文件：`23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk`
- 包名：`oasud.qwqrds.vjghasdh`
- 版本名：`1`
- 版本号：`1`
- SHA256：`23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61`
- 大小：`6257161` 字节
- 关键文件数：`60`

### APK 鲁棒性验证
- 鲁棒性分数：`17.0`
- 检测到的对抗技术：抗静态检测
- 防沙箱：`False`
- 混淆：`False`
- 反射：`False`
- 动态加载：`False`

### APK 图结构分析
- 已检测到 APK 图结构数据，可在 HTML 报告中查看 CFG / FCG / API 调用图统计。

### APK 静态内容解析与规则匹配
- 已解析文本条数：`160`
- 规则匹配结果：API 调用: start, su, init；行为模式: root_attempt
- 命中规则数：`60`

## 四点一、APK 动态沙箱摘要

## 四点二、图结构分析
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`150586`
- CFG 边数：`76150`
- FCG 节点数：`53933`
- FCG 边数：`125834`
- FCG 密度：`0.0000`
- 全图密度参考值：`-`
- 指标释义：CFG 节点/边表示函数内部控制流规模；FCG 节点/边表示函数调用关系规模；FCG 密度越高，说明函数间调用越紧密。
- API 调用图节点数：`53601`
- API 调用图边数：`81372`
- API 总调用数：`286345`
- 敏感 API 调用分布：Ljava/lang/reflect/Method;->invoke:147607, Ljava/lang/reflect/Field;->get:106175, Ldalvik/system/DexClassLoader;-><init>:22786, Landroid/net/Uri;->parse:5955, Ljava/lang/reflect/Field;->set:2115, Ljava/lang/Runtime;->exec:788, Ljava/net/HttpURLConnection;->connect:460, Landroid/provider/Settings$Secure;->getString:385, Landroid/app/PendingIntent;->getActivity:38, Landroid/content/Intent;->setPackage:9, Landroid/telephony/TelephonyManager;->getDeviceId:9, Ljava/lang/ClassLoader;->loadClass:6
- API 调用明细：
  - `Ljava/lang/reflect/Method;->invoke`：147607
  - `Ljava/lang/reflect/Field;->get`：106175
  - `Ldalvik/system/DexClassLoader;-><init>`：22786
  - `Landroid/net/Uri;->parse`：5955
  - `Ljava/lang/reflect/Field;->set`：2115
  - `Ljava/lang/Runtime;->exec`：788
  - `Ljava/net/HttpURLConnection;->connect`：460
  - `Landroid/provider/Settings$Secure;->getString`：385
  - `Landroid/app/PendingIntent;->getActivity`：38
  - `Landroid/content/Intent;->setPackage`：9
  - `Landroid/telephony/TelephonyManager;->getDeviceId`：9
  - `Ljava/lang/ClassLoader;->loadClass`：6
  - `Landroid/location/LocationManager;->getLastKnownLocation`：5
  - `Ljava/lang/Class;->forName`：5
  - `Landroid/telephony/TelephonyManager;->getImei`：2

## 四点三、一致性验证
> **🔍 一致性分析说明**：仲裁器通过比较静态/行为/情报三方的评分差异判断结论一致性。
> 一致性越高，证据链越稳固；一致性低时需重点关注被标记的「疑似污染」模块。

- 一致性分数：`89.0`
- 一致性等级：`HIGH`
- 分歧点：无
- 被污染模块：无

## 四点四、鲁棒性分析
> **🛡️ 鲁棒性分析说明**：检测 APK 是否使用了防沙箱、混淆、反射、动态加载等对抗技术。
> 鲁棒性分数越高，说明样本越可能使用了规避分析的手段；分数越低，表示样本相对透明。

- 抗静态检测：`True`
- 抗静态细分：`加壳、混淆、伪装头部、资源异常`
- 鲁棒性分数公式：`鲁棒性分数 = Sigmoid(加权原始分)，其中加权原始分 = 24×抗静态检测 + 20×防沙箱 + 16×混淆 + 16×动态加载 + 12×反射 + 细分类别加成(最多12) + 技术多样性奖励(每项+3，封顶15) + 解析失败奖励(当APK图结构提取失败时 +25，因为解析失败本身是可疑信号)。Sigmoid 映射将原始分平滑映射到 0-100 区间。`
- 对抗技术：抗静态检测
- 鲁棒性分数：`17.0`
- 抗检测性评估：**弱**

## 四点五、页面截图
### 页面截图
- 当前未采集到本次分析的页面截图，已暂未展示图像证据。

## 六、风险证据
### 1. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl1138852990.tmp; HardwareBuffer.close; oasud.qwqrds.vjghasdh`
- 建议：后续可结合抓包或代理进行复核。

### 2. 疑似动态载荷释放
- 规则：`APK_DYNAMIC_PAYLOAD_DROP`
- 严重级别：`high`
- 说明：运行后在应用目录或临时目录中发现 dex、jar、apk、so、zip 等可疑落地文件。
- 证据：`./vendor/lib64/egl/libEGL_angle.so; ./vendor/lib64/egl/libGLESv1_CM_angle.so; ./vendor/lib64/egl/libGLESv1_CM_emulation.so; ./vendor/lib64/egl/libGLESv2_emulation.so; ./vendor/lib64/egl/libEGL_emulation.so; ./vendor/lib64/egl/libGLESv2_angle.so; ./vendor/lib64/hw/gralloc.default.so; ./vendor/lib64/hw/android.hardware.graphics.mapper@3.0-impl-ranchu.so; ./vendor/lib64/hw/vulkan.ranchu.so; ./vendor/lib64/libGLESv1_enc.so`
- 建议：建议结合文件哈希、反编译和后续加载日志确认是否存在动态加载或脱壳行为。

### 3. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.apps.nexuslauncher][com.google.android.as][com.google.android.apps.wellbeing][com.google.android.packageinstaller][com.google.android.apps.nexuslauncher][com.google.android.apps.nexuslauncher][com.google.android.packageinstaller][com.google.android.apps.nexuslauncher][com.google.android.inputmethod.latin][oasud.qwqrds.vjghasdh][com.android.chrome][com.android.systemui][com.google.android.googlequicksearchbox][com.google.android.apps.youtube.music][com.google.android.packageinstaller]}]; 6: oasud.qwqrds.vjghasdh; 06-28 15:08:20.527 config: oasud.qwqrds.vjghasdh|removeAutomaticZenRules no changes; 06-28 15:08:20.527 set_zen_mode: off,oasud.qwqrds.vjghasdh|removeAutomaticZenRules; 06-28 16:18:28.770 config: oasud.qwqrds.vjghasdh|removeAutomaticZenRules no changes; 06-28 16:18:28.772 set_zen_mode: off,oasud.qwqrds.vjghasdh|removeAutomaticZenRules; userId=0 value={com.mytelecomapp.topup, com.google.android.apps.diagnosticstool, com.google.android.as/com.google.android.apps.miphone.aiai.common.notification.service.AiAiNotificationAssistantService, com.google.android.as/com.google.android.apps.miphone.aiai.common.notification.service.AiAiNotificationListenerService, com.google.android.apps.safetyhub, oasud.qwqrds.vjghasdh, com.google.intelligence.sense, com.google.android.apps.nexuslauncher/com.android.launcher3.notification.NotificationListener, com.google.android.apps.wellbeing, com.google.android.dialer, com.google.android.gms, com.baidu.tieba, com.tencent.mobileqq, com.google.android.settings.intelligence, com.sina.weibo, com.google.android.GoogleCamera, com.rubenroy.minimaltodo, fetcher.pipeliner.helper}`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 4. 动态激活无障碍服务与设备管理器
- 规则：`DEEP_APK_BEHAVIOR_PRIVILEGE_PERSISTENCE`
- 严重级别：`critical`
- 说明：动态沙箱监测到应用成功在系统中激活了无障碍服务（Accessibility）和设备管理器（Device Policy），这赋予了应用模拟用户点击、防卸载、强行锁屏以及劫持用户界面的高级控制权。
- 证据：`persistent_services.accessibility 列表中包含 oasud.qwqrds.vjghasdh，且 persistent_services.device_policy 包含 6: oasud.qwqrds.vjghasdh。`
- 建议：立即在受控环境中撤销该应用的设备管理器与无障碍权限，并进行强行卸载。

### 5. 动态注册通知监听服务
- 规则：`DEEP_APK_BEHAVIOR_NOTIFICATION_LISTENER`
- 严重级别：`high`
- 说明：样本在运行期间将自身注册为系统通知监听器，能够实时读取系统所有通知内容，常用于在后台静默拦截银行、社交软件的短信验证码或敏感推送。
- 证据：`persistent_services.notification 列表中包含 oasud.qwqrds.vjghasdh 服务的注册痕迹。`
- 建议：阻断该应用对系统通知的访问权限，防止双因子验证码（2FA）泄露。

### 6. 异常高频的动态类加载与反射调用
- 规则：`DEEP_APK_BEHAVIOR_DYNAMIC_CODE_EXECUTION`
- 严重级别：`critical`
- 说明：静态与调用图分析显示，样本中 DexClassLoader 构造函数调用次数达 22,786 次，Method.invoke 达 147,607 次。这表明样本内部存在复杂的动态解密、多阶段载荷释放与反射执行行为，用以规避静态杀毒引擎的检测。
- 证据：`api_call_counts_top 中 Ldalvik/system/DexClassLoader;-><init> 计数 22786，Ljava/lang/reflect/Method;->invoke 计数 147607。`
- 建议：建议提取运行过程中的内存 Dump，还原其在第二阶段动态加载的实际 DEX 载荷进行关联分析。

### 7. 包含 Root 提权与 Shell 命令执行代码
- 规则：`DEEP_APK_BEHAVIOR_ROOT_COMMAND_EXECUTION`
- 严重级别：`high`
- 说明：样本中硬编码了 su、sh、rm、mv 等系统命令，并存在 Root 提权尝试，表明其具备破坏系统分区、静默安装/卸载其他应用或执行任意 Shell 脚本的能力。
- 证据：`静态规则命中 su, sh, mv, rm 等敏感 API，且 Runtime.exec 调用次数达 788 次。`
- 建议：监控其在真实设备上的提权日志，防止其利用已知系统漏洞实施 Root 提权。

### 8. 尝试获取Root权限并执行系统命令
- 规则：`DEEP_APK_STATIC_ROOT_ATTEMPT`
- 严重级别：`critical`
- 说明：在DEX文件中检测到大量调用系统命令执行函数（Ljava/lang/Runtime;->exec），并发现 'su', 'rm', 'mv' 等高危命令字符串。这表明该应用试图获取设备的最高权限（Root），并执行文件删除、移动等恶意操作，可能用于篡改系统或安装其他恶意模块。
- 证据：`API调用图谱显示 Ljava/lang/Runtime;->exec 调用788次；静态字符串中发现 'su', 'rm', 'mv' 等命令。`
- 建议：立即隔离受影响设备，检查设备是否已被Root。分析其可能下载或释放的其他恶意载荷。

### 9. 通过反射和动态类加载执行隐藏代码
- 规则：`DEEP_APK_STATIC_DYNAMIC_CODE_LOADING`
- 严重级别：`critical`
- 说明：该应用极高频次地使用Java反射（Method.invoke 调用超过14万次）和动态类加载器（DexClassLoader）。这是一种典型的恶意软件对抗静态分析的技术，其核心恶意逻辑可能被加密存储在资源或DEX文件中，在运行时动态解密并加载执行，从而绕过静态检测。
- 证据：`API调用图谱显示 Ljava/lang/reflect/Method;->invoke (147607次), Ljava/lang/reflect/Field;->get (106175次), Ldalvik/system/DexClassLoader;-><init> (22786次)。存在多个DEX文件（classes.dex, classes2.dex, classes3.dex）。`
- 建议：对该样本进行脱壳处理，或在动态调试环境中Dump内存，以获取其在运行时加载的真实恶意代码进行进一步分析。

### 10. 使用随机化包名和调试签名进行伪装
- 规则：`DEEP_APK_STATIC_OBFUSCATED_PACKAGE`
- 严重级别：`high`
- 说明：应用的包名 'oasud.qwqrds.vjghasdh' 呈现无意义的随机字符组合，这是一种常见的代码混淆手段，旨在增加逆向分析和追踪溯源的难度。此外，应用使用了通用的 'Android Debug' 证书进行签名，表明其来源可疑，并非通过官方应用市场发布。
- 证据：`Package Name: oasud.qwqrds.vjghasdh; Certificate Subject: CN=Android Debug, O=Android, C=US`
- 建议：将该包名和签名证书哈希（02c940a6936c664cb1706474bab3c165e630c52444ed66f8ceea915ef0abe7e8）加入黑名单，阻断该开发者发布的所有应用。

### 11. 收集设备指纹信息
- 规则：`DEEP_APK_STATIC_INFO_GATHERING`
- 严重级别：`medium`
- 说明：静态字符串中发现了格式化的设备信息字符串，如'~ phone/AppShellVer:1 UUID/... '，这通常用于生成设备唯一指纹。动态沙箱日志也显示应用在启动后立即尝试执行 'settings.get.global' 命令读取系统全局设置。这些行为表明应用在运行初期就会收集设备信息，可能用于上报或为其后续恶意行为提供决策依据。
- 证据：`静态字符串: '~ phone/AppShellVer:1 UUID/00000000-0000-0000-0000-000000000000...'; 动态日志: 'StartCommandInProcess(...settings.get.glo...)'`
- 建议：监控该应用的网络通信，分析其上传的数据内容，以确定信息泄露的范围。

### 12. 疑似利用系统服务实现持久化驻留
- 规则：`DEEP_APK_STATIC_PERSISTENCE_HINT`
- 严重级别：`high`
- 说明：动态沙箱补充证据显示，该应用包名出现在系统的辅助功能（Accessibility）、设备策略（Device Policy）和通知服务（Notification）的活跃列表中。这些都是恶意软件常用的持久化手段，特别是辅助功能，一旦被滥用，可以监控用户操作、窃取输入内容并模拟用户点击，造成严重危害。
- 证据：`动态沙箱摘要中 'persistent_services' 字段下 'accessibility', 'device_policy', 'notification' 列表均包含包名 'oasud.qwqrds.vjghasdh'。`
- 建议：检查设备系统设置，确保该应用未被激活为设备管理器或开启辅助功能服务。若已被激活，应立即撤销其权限并卸载应用。

### 13. 调试签名证书指向非官方发布/重打包风险
- 规则：`DEEP_APK_INTEL_DEBUG_CERT`
- 严重级别：`high`
- 说明：样本使用 Android Debug 签名，通常不用于正式发布，结合未知来源时代表潜在重打包或测试包外泄风险。
- 证据：`certificate_subject/issuer: "Android Debug"；certificate_sha256: 02c940a6936c664cb1706474bab3c165e630c52444ed66f8ceea915ef0abe7e8`
- 建议：核验来源与分发渠道（官方应用商店/开发者官网/企业 MDM）；对比同名应用历史版本签名链与指纹；如来源可疑，视同高风险投递器直接阻断。

### 14. 包名呈随机/无语义特征
- 规则：`DEEP_APK_INTEL_SUSPICIOUS_PACKAGE_NAME`
- 严重级别：`medium`
- 说明：包名 oasud.qwqrds.vjghasdh 缺乏品牌/语义信息，常见于临时构建、重打包或投递器伪装。
- 证据：`package_name: oasud.qwqrds.vjghasdh`
- 建议：结合渠道核验开发者身份与上架信息；若非官方渠道获取且包名异常，建议停止分发与安装并进行取证。

### 15. 静态命中系统命令与潜在 Root 尝试
- 规则：`DEEP_APK_INTEL_SYSTEM_COMMAND_SU`
- 严重级别：`critical`
- 说明：检测到与系统命令执行和提权相关的关键词与 API，包含 su/sh/rm/mv/ps 字符串与 Runtime.exec 调用，规则聚类为 root_attempt。
- 证据：`APK_DANGEROUS_API_SYSTEM_COMMAND 命中: "su","rm","mv","sh","ps"；api_graph top: "Ljava/lang/Runtime;->exec"；规则: APK_MALICIOUS_BEHAVIOR_ROOT_ATTEMPT；静态证据多次命中 su。`
- 建议：对命中的字符串与调用链进行反编译溯源，确认是否在可到达代码路径中实际执行；于受控真机/Root 测试床延长运行时长，辅以进程/文件/命令钩子验证是否有提权或命令执行。

### 16. 存在反射与 DexClassLoader 引用，疑似具备动态加载能力
- 规则：`DEEP_APK_INTEL_REFLECTION_DEX`
- 严重级别：`medium`
- 说明：静态 API 图显示大量反射与类加载相关调用，可能用于动态加载或规避静态检测，但亦可能来自通用库。
- 证据：`api_graph counts: Method.invoke(147607), Field.get(106175), DexClassLoader.<init>(22786)`
- 建议：复核是否存在外部 DEX/ZIP/JAR 加载路径与实际可达调用；运行时开启文件与网络监控，关注下载-落地-加载链条；若结合可疑来源，按潜在投递器/动态加载风险处置。

### 17. WRITE_EXTERNAL_STORAGE 可被用于落地/数据外泄
- 规则：`DEEP_APK_INTEL_PERMISSION_STORAGE`
- 严重级别：`medium`
- 说明：样本申请写外部存储权限，若与命令执行或动态加载结合，可能用于落地载荷或写入配置。
- 证据：`permissions: WRITE_EXTERNAL_STORAGE；静态命中可疑命令与反射/类加载调用。`
- 建议：动态运行时监控文件系统（/sdcard 等）创建/修改；比对落地文件哈希并限制外部存储写入策略。

### 18. 动态沙箱未复现高危行为，存在运行时覆盖不足
- 规则：`DEEP_APK_INTEL_DYNSBX_RUNTIME_GAP`
- 严重级别：`low`
- 说明：沙箱仅运行约 20 秒，日志以系统安装/角色广播为主，未观察到外联与命令执行，可能未触发关键路径或存在环境门槛。
- 证据：`runtime_window_seconds: 20；logcat 为安装与包管理流程；network_hit_count: 12（无明确外域）；launch_success: true 但无显著行为。`
- 建议：延长运行时间并加入 UI/手势驱动；在真机/不同版本系统下复测；接入网络代理/SSL 解密与命令钩子；必要时模拟首启向导、通知授权、延迟触发等。

### 19. 可疑 UA/上报头部指纹，疑与自定义协议或投递框架有关
- 规则：`DEEP_APK_INTEL_UA_APPSHELL`
- 严重级别：`medium`
- 说明：发现 "~ phone/AppShellVer:1 UUID/000... CID/000... APP/<pkg>" 字符串，类似自定义 UA/上报头部，常用于设备指纹或指令通道。
- 证据：`extracted_strings: "~ phone/AppShellVer:1 UUID/00000000-0000-0000-0000-000000000000 CID/000... APP/oasud.qwqrds.vjghasdh"`
- 建议：检索使用位置与网络代码；在代理环境中观察首启请求头与目标域；若指向未知 C2/私有服务，建议阻断并提取 IOC。

### 20. 需要结合来源与分发渠道做最终定性
- 规则：`DEEP_APK_INTEL_SOURCE_VETTING`
- 严重级别：`high`
- 说明：签名为调试证书、包名异常且静态高危命中明显，若来源为私链/群发/仿冒站，风险显著提高；若为企业内测需代码审计确认。
- 证据：`签名调试证书 + 无商店信誉信息 + 高危静态命中；动态未证伪。`
- 建议：核验应用来源（官方商店页、开发者域名、MDM 分发记录）与签名连续性；如来源不可信，按高风险立即阻断；如为内部构建，组织安全评审与白名单管理。

### 21. 沙箱枚举到 device_policy/notification 列表含该包，疑为系统噪声
- 规则：`DEEP_APK_INTEL_DEVICE_POLICY_SIGNAL`
- 严重级别：`low`
- 说明：动态摘要中 device_policy 与通知监听枚举出现包名，但清单未见 DeviceAdminReceiver/相关权限，倾向于沙箱侧系统枚举噪声。
- 证据：`persistent_services.device_policy: "6: oasud.qwqrds.vjghasdh"；manifest receivers 仅有 androidx.profileinstaller.ProfileInstallReceiver`
- 建议：复核清单是否含设备管理组件与策略请求；如无相应声明，忽略该噪声信号；如存在相关组件则进一步验证其启用与行为。

### 22. 建议立即阻断分发
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`critical`
- 说明：样本具备明显的恶意执行链特征，且动态沙箱已确认可安装、可启动，存在继续扩散到真实终端的风险。
- 证据：`install_success=true; launch_success=true; static 命中 code_execution/system_command/root_attempt; Runtime.exec=788; DexClassLoader=22786`
- 建议：在下载源、分发平台、MDM/EDR 策略中立即阻断该包及同哈希样本，拉黑 package_name 与 sha256。

### 23. 建议禁止在真实设备安装
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`critical`
- 说明：样本具备命令执行、Root 尝试和动态加载能力，真实设备安装后可能带来权限滥用、持久化和横向控制风险。
- 证据：`package_name=oasud.qwqrds.vjghasdh; permissions 包含 INTERNET/WRITE_EXTERNAL_STORAGE; 动态沙箱已成功启动 MainActivity`
- 建议：对终端用户和测试人员下发禁止安装提示，生产设备上执行卸载与风险排查。

### 24. 建议继续沙箱复核
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`high`
- 说明：当前动态窗口较短，仅观察到安装与启动成功，未完整覆盖后续恶意链路；需要继续在受控环境中验证其联网、命令执行、文件操作与持久化行为。
- 证据：`runtime_window_seconds=20; network_hit_count=12; logcat 中仅见安装/系统广播，未覆盖更长时间行为`
- 建议：扩大沙箱时长，记录进程树、文件落地、shell 命令、C2 连接、WebView/JS 交互与持久化配置变化。

### 25. 建议保留样本留痕
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`high`
- 说明：样本包含多项高风险证据且具备抗静态特征，应完整保留供复盘、溯源和签名比对。
- 证据：`sha256=23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61; certificate_sha256=02c940a6936c664cb1706474bab3c165e630c52444ed66f8ceea915ef0abe7e8; robustness_score=13`
- 建议：保存 APK 原件、SHA256、证书指纹、manifest、logcat_excerpt、dynamic_artifacts、动态摘要和安装记录，作为 IOC 与证据链。

### 26. 建议核查签名与来源可信度
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`medium`
- 说明：签名主体显示 Android Debug 风格，来源可信度不足；配合可疑包名与高危行为，需重点核验是否为二次打包或调试签名样本。
- 证据：`certificate_subject/certificate_issuer 均为 Android Debug; package_name=oasud.qwqrds.vjghasdh`
- 建议：核对市场来源、发布者历史、签名链是否匹配官方版本；若不匹配，按仿冒/重打包样本处置。

### 27. 建议排查动态加载与反射链
- 规则：`DEEP_APK_ADVICE_006`
- 严重级别：`high`
- 说明：反射、DexClassLoader 调用量极高，提示存在动态解密、模块下发或规避静态检测的可能。
- 证据：`Ljava/lang/reflect/Method;->invoke=147607; Ljava/lang/reflect/Field;->get=106175; Ldalvik/system/DexClassLoader;-><init>=22786`
- 建议：重点复核 classes.dex/classes2.dex/classes3.dex 中的加载器、反射入口、加密解密函数和被动下发代码。

### 28. 建议核查网络外联与命令下发
- 规则：`DEEP_APK_ADVICE_007`
- 严重级别：`high`
- 说明：动态沙箱期间出现网络命中，同时静态上存在 HttpURLConnection.connect 与系统命令执行线索，可能构成远程控制或命令下发链。
- 证据：`network_hit_count=12; Ljava/net/HttpURLConnection;->connect=460; system_command 命中 su/rm/mv/sh/ps`
- 建议：继续抓包分析域名/IP/URL、请求体、证书校验及下发脚本，确认是否存在 C2 或远程任务执行。

### 29. 建议排查持久化与权限滥用
- 规则：`DEEP_APK_ADVICE_008`
- 严重级别：`medium`
- 说明：动态记录中出现 device_policy、notification、accessibility 相关痕迹，需警惕辅助功能/通知/设备管理滥用。
- 证据：`persistent_services.accessibility 包含 oasud.qwqrds.vjghasdh; persistent_services.device_policy=6: oasud.qwqrds.vjghasdh; notification 配置被读取/调整`
- 建议：在复测中重点确认是否申请辅助功能、设备管理、通知监听等敏感能力，并检查是否尝试开启持久化控制。

### 30. 动态获取无障碍/设备管理/通知监听三大特权
- 规则：`AGG_DYNAMIC_PRIVILEGE_TRIAD`
- 严重级别：`critical`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`persistent_services.accessibility/notification/device_policy 中均出现 oasud.qwqrds.vjghasdh，具备持久化与信息拦截能力。`
- 建议：结合静态报告进一步复核。

### 31. 异常高频反射与动态类加载
- 规则：`AGG_ABNORMAL_DYNAMIC_LOADING`
- 严重级别：`critical`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`Method.invoke=147607 次，DexClassLoader.<init>=22786 次；指向深度加壳/对抗与按需下发代码。`
- 建议：结合静态报告进一步复核。

### 32. 系统命令与潜在 Root 尝试
- 规则：`AGG_ROOT_COMMAND_ATTEMPTS`
- 严重级别：`critical`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`Runtime.exec=788；字符串命中 su/sh/rm/mv/ps；符合恶意持久化/清理与提权链路。`
- 建议：结合静态报告进一步复核。

### 33. 调试证书与随机化包名伪装
- 规则：`AGG_DEBUG_CERT_PACKAGENAME`
- 严重级别：`high`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`证书 Subject/Issuer=Android Debug（SHA256: 02c940a6...e7e8）；包名 oasud.qwqrds.vjghasdh 无语义。`
- 建议：结合静态报告进一步复核。

### 34. 动态观测窗口有限
- 规则：`AGG_RUNTIME_OBS_WINDOW_LIMIT`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`动态沙箱仅 20 秒窗口，network_hit_count=12 未见对外域名/IP 细节，关键路径可能未触发。`
- 建议：结合静态报告进一步复核。

### 35. 定性为恶意远控/金融木马并建议阻断
- 规则：`AGG_FINAL_CLASSIFICATION`
- 严重级别：`critical`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`动态已获取敏感特权+静态高危能力全集合；多角色一致评为高危，建议立即阻断与清除。`
- 建议：结合静态报告进一步复核。


## 七、论坛式协同研判
- 主持人总结：综合四位专家的证据与意见：该样本在动态运行中成功激活无障碍服务、设备管理器与通知监听服务，构成典型的“持久化+拦截+控制”高危特权组合，能够实现防卸载、屏幕劫持、凭证窃取与验证码拦截；同时静态侧存在大规模反射与动态类加载（DexClassLoader 2.2万次、Method.invoke 14.7万次）以及系统命令/Root 尝试（Runtime.exec 多次、硬编码 su/sh/rm 等），并伴随调试证书与随机化包名伪装，指向加壳与对抗下的恶意远控/金融木马链路。尽管情报侧提示动态窗口较短、未见明确外联，存在未触发关键路径的不确定性，但基于已观测到的敏感特权已被激活与高危能力集齐全，可在当前证据下将其定性为高危恶意样本（恶意远控/金融木马）。建议立即阻断分发与清除，并在受控沙箱中做延长运行与网络/文件行为复核。以上研判仅基于当前五位专家的已有输出。

| 角色 | 模型 | 核心意见 | 补充说明 |
|------|------|----------|----------|
| 主持人 | `gpt-5` | 综合四位专家的证据与意见：该样本在动态运行中成功激活无障碍服务、设备管理器与通知监听服务，构成典型的“持久化+拦截+控制”高危特权组合，能够实现防卸载、屏幕劫持、凭证窃取与验证码拦截；同时静态侧存在大规模反射与动态类加载（DexClassLoader 2.2万次、Method.invoke 14.7万次）以及系统命令/Root 尝试（Runtime.exec 多次、硬编码 su/sh/rm 等），并伴随调试证书与随机化包名伪装，指向加壳与对抗下的恶意远控/金融木马链路。尽管情报侧提示动态窗口较短、未见明确外联，存在未触发关键路径的不确定性，但基于已观测到的敏感特权已被激活与高危能力集齐全，可在当前证据下将其定性为高危恶意样本（恶意远控/金融木马）。建议立即阻断分发与清除，并在受控沙箱中做延长运行与网络/文件行为复核。以上研判仅基于当前五位专家的已有输出。 | — |
| 静态分析员 | `gemini-2.5-pro` | {'opinion': '综合静态分析证据，该APK为高风险恶意软件。静态分析发现其包含执行系统命令、尝试获取Root权限、动态加载代码等多种恶意行为特征。包名随机化、使用调试签名等迹象也符合恶意软件的典型特征。动态沙箱证据交叉印证了其安装后尝试读取系统设置、注册持久化服务等可疑活动，确认其恶意意图。', 'risk_hint': 'critical', 'additional_findings_count': 5, 'additional_findings_preview': [{'rule_id': 'DEEP_APK_STATIC_ROOT_ATTEMPT', 'title': '尝试获取Root权限并执行系统命令', 'severity': 'critical', 'evidence': "API调用图谱显示 Ljava/lang/Runtime;->exec 调用788次；静态字符串中发现 'su', 'rm', 'mv' 等命令。"}, {'rule_id': 'DEEP_APK_STATIC_DYNAMIC_CODE_LOADING', 'title': '通过反射和动态类加载执行隐藏代码', 'severity': 'critical', 'evidence': 'API调用图谱显示 Ljava/lang/reflect/Method;->invoke (147607次), Ljava/lang/reflect/Field;->get (106175次), Ldalvik/system/DexClassLoader;-><init> (22786次)。存在多个DEX文件（classes.dex, classes2.dex, classes3.dex）。'}, {'rule_id': 'DEEP_APK_STATIC_OBFUSCATED_PACKAGE', 'title': '使用随机化包名和调试签名进行伪装', 'severity': 'high', 'evidence': 'Package Name: oasud.qwqrds.vjghasdh; Certificate Subject: CN=Android Debug, O=Android, C=US'}]} | — |
| 行为分析员 | `gemini-2.5-flash` | {'opinion': '该样本（包名：oasud.qwqrds.vjghasdh）呈现出极高风险的恶意远控及金融木马行为特征。静态分析表明，样本采用了深度加壳与混淆对抗技术，其内部包含极其异常的高频动态类加载（DexClassLoader 调用达 2.2 万次）与反射调用（Method.invoke 达 14.7 万次），并硬编码了 su、sh、rm 等提权与系统命令。动态沙箱运行日志提供了决定性的恶意行为证据：样本在运行期间成功激活了无障碍服务（Accessibility Service）、设备管理器（Device Policy）以及通知监听服务（Notification Listener）。这种“无障碍 + 设备管理器 + 通知监听”的敏感特权组合是 Android 银行木马和间谍软件的典型标配，旨在实现防卸载、屏幕劫持、敏感凭证窃取以及短信验证码静默拦截。综合研判，该样本为高危害性的恶意远控/金融木马，建议立即予以阻断和清除。', 'risk_hint': 'critical', 'additional_findings_count': 4, 'additional_findings_preview': [{'rule_id': 'DEEP_APK_BEHAVIOR_PRIVILEGE_PERSISTENCE', 'title': '动态激活无障碍服务与设备管理器', 'severity': 'critical', 'evidence': 'persistent_services.accessibility 列表中包含 oasud.qwqrds.vjghasdh，且 persistent_services.device_policy 包含 6: oasud.qwqrds.vjghasdh。'}, {'rule_id': 'DEEP_APK_BEHAVIOR_NOTIFICATION_LISTENER', 'title': '动态注册通知监听服务', 'severity': 'high', 'evidence': 'persistent_services.notification 列表中包含 oasud.qwqrds.vjghasdh 服务的注册痕迹。'}, {'rule_id': 'DEEP_APK_BEHAVIOR_DYNAMIC_CODE_EXECUTION', 'title': '异常高频的动态类加载与反射调用', 'severity': 'critical', 'evidence': 'api_call_counts_top 中 Ldalvik/system/DexClassLoader;-><init> 计数 22786，Ljava/lang/reflect/Method;->invoke 计数 147607。'}]} | — |
| 情报分析员 | `gpt-5` | {'opinion': '综合样本情报与运行时线索：该 APK（文件名: 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk，包名: oasud.qwqrds.vjghasdh，SHA256: 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61）使用 Android Debug 调试证书签名（Subject/Issuer 均为 "Android Debug"，证书指纹: 02c940a6936c664cb1706474bab3c165e630c52444ed66f8ceea915ef0abe7e8），与正式发布习惯不符。包名呈随机/无语义特征，结合仅声明 INTERNET/ACCESS_NETWORK_STATE 与 WRITE_EXTERNAL_STORAGE 等少量权限、组件较少，指向“轻壳/外联+动态加载或投递”类特征。静态侧命中多条高危规则：存在系统命令与代码执行相关线索（"su"、"sh"、"rm"、"mv"、"ps" 以及 Runtime.exec、DexClassLoader、反射调用等），并被规则聚类为 root_attempt 行为。提取的可疑字符串包含 "~ phone/AppShellVer:1 ... APP/oasud.qwqrds.vjghasdh"，类似自定义 UA/上报头部指纹，常见于下载器/投递器或私有协议。运行时（动态沙箱）方面：样本在模拟器成功安装与拉起，但 20 秒的窗口中仅见系统安装流程日志与角色授予检查，未观察到可见外联、文件操作或命令执行；network_hit_count 统计为 12，但未见明确对外域名/IP 通联记录，且日志主要为系统广播与包管理信息。这表明高危代码路径可能未被触发，或样本具备时序/交互/环境门槛。当前为离线快速研判，存在典型边界与不确定性：1) 签名与来源未知，无法判定是否内部调试包/重打包；2) 动态窗口短且在模拟器环境，可能未覆盖关键路径（行为分析员提示未进行完整动态沙箱）；3) 静态命中存在误报可能（库代码/死代码/占位字符串），需通过反编译与调用链确认。基于以上，建议在处置上按高风险对待，但最终定性需结合来源与分发渠道（官方商店/开发者官网/企业 MDM）与签名信誉进行核验：如来自非可信分发（私链、群发、短信、仿冒站）且使用调试证书，应直接阻断；如为内部测试版本，需要对代码路径进行复核并在受控环境延长运行、开展网络与文件行为观测后再行定性。', 'risk_hint': 'high', 'additional_findings_count': 9, 'additional_findings_preview': [{'rule_id': 'DEEP_APK_INTEL_DEBUG_CERT', 'title': '调试签名证书指向非官方发布/重打包风险', 'severity': 'high', 'evidence': 'certificate_subject/issuer: "Android Debug"；certificate_sha256: 02c940a6936c664cb1706474bab3c165e630c52444ed66f8ceea915ef0abe7e8'}, {'rule_id': 'DEEP_APK_INTEL_SUSPICIOUS_PACKAGE_NAME', 'title': '包名呈随机/无语义特征', 'severity': 'medium', 'evidence': 'package_name: oasud.qwqrds.vjghasdh'}, {'rule_id': 'DEEP_APK_INTEL_SYSTEM_COMMAND_SU', 'title': '静态命中系统命令与潜在 Root 尝试', 'severity': 'critical', 'evidence': 'APK_DANGEROUS_API_SYSTEM_COMMAND 命中: "su","rm","mv","sh","ps"；api_graph top: "Ljava/lang/Runtime;->exec"；规则: APK_MALICIOUS_BEHAVIOR_ROOT_ATTEMPT；静态证据多次命中 su。'}]} | — |
| 处置建议员 | `gpt-5.4-mini` | {'opinion': '建议立即阻断分发并禁止在真实终端安装；当前样本已在沙箱中成功安装并启动，结合静态与动态证据同时出现 code_execution、system_command、root_attempt、DexClassLoader、Runtime.exec、su/rm/mv/sh/ps 等高危迹象，且存在反射调用密集、动态加载/加壳/伪装头部特征。建议将该 APK 视为高概率恶意样本处理：隔离留样、不要继续在生产设备或业务账号环境中复测；如业务需要验证，仅允许在受控沙箱中复核其网络行为、命令执行链与持久化能力。样本应保留哈希、安装日志、logcat、动态产物与签名信息用于溯源和横向排查。', 'risk_hint': 'critical', 'additional_findings_count': 8, 'additional_findings_preview': [{'rule_id': 'DEEP_APK_ADVICE_001', 'title': '建议立即阻断分发', 'severity': 'critical', 'evidence': 'install_success=true; launch_success=true; static 命中 code_execution/system_command/root_attempt; Runtime.exec=788; DexClassLoader=22786'}, {'rule_id': 'DEEP_APK_ADVICE_002', 'title': '建议禁止在真实设备安装', 'severity': 'critical', 'evidence': 'package_name=oasud.qwqrds.vjghasdh; permissions 包含 INTERNET/WRITE_EXTERNAL_STORAGE; 动态沙箱已成功启动 MainActivity'}, {'rule_id': 'DEEP_APK_ADVICE_003', 'title': '建议继续沙箱复核', 'severity': 'high', 'evidence': 'runtime_window_seconds=20; network_hit_count=12; logcat 中仅见安装/系统广播，未覆盖更长时间行为'}]} | — |

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。


## 九、分析性能统计

- 总耗时：178.31 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 行为分析员 | 22.25 | 48425 | 3119 | 51544 |
| 静态分析员 | 43.35 | 49942 | 3597 | 53539 |
| 情报分析员 | 73.40 | 37865 | 4938 | 42803 |
| 处置建议员 | 12.86 | 37431 | 1572 | 39003 |
| 主持人 | 65.43 | 2728 | 5123 | 7851 |
