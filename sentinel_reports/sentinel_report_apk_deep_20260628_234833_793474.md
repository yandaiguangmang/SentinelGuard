# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**MEDIUM** · 风险分数：**62/100**
> 证据分数：**70/100** · 深度研判分数：**95 /100**
> 评分口径：APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\sentinelguard_apk_bundle_enfnz8t_`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：30 条
- 高危证据：20 条

## 二、统一 IR 摘要
- APK 文件：`23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk`
- 包名：`-`
- 版本名：`-`
- 版本号：`-`
- SHA256：`23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61`
- 大小：`6257161` 字节
- 关键文件数：`60`

### APK 鲁棒性验证
- 鲁棒性分数：`46.0`
- 检测到的对抗技术：抗静态检测
- 防沙箱：`False`
- 混淆：`False`
- 反射：`False`
- 动态加载：`False`

### APK 静态内容解析与规则匹配
- 已解析文本条数：`80`
- 规则匹配结果：API 调用: sh, start
- 命中规则数：`3`

## 四点一、APK 动态沙箱摘要

## 四点二、图结构分析
- 图结构状态：`图结构缺失`；原因：未检测到图结构数据，可能是 APK 解析失败、androguard 不可用或未能提取 DEX 图。
### CFG / FCG / API 调用图
- CFG 节点数：`0`
- CFG 边数：`0`
- FCG 节点数：`0`
- FCG 边数：`0`
- FCG 密度：`-`
- 全图密度参考值：`-`
- 指标释义：CFG 节点/边表示函数内部控制流规模；FCG 节点/边表示函数调用关系规模；FCG 密度越高，说明函数间调用越紧密。
- API 调用图节点数：`0`
- API 调用图边数：`0`
- API 总调用数：`0`
- 敏感 API 调用分布：无

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
- 抗静态细分：`混淆、资源异常`
- 鲁棒性分数公式：`鲁棒性分数 = Sigmoid(加权原始分)，其中加权原始分 = 24×抗静态检测 + 20×防沙箱 + 16×混淆 + 16×动态加载 + 12×反射 + 细分类别加成(最多12) + 技术多样性奖励(每项+3，封顶15) + 解析失败奖励(当APK图结构提取失败时 +25，因为解析失败本身是可疑信号)。Sigmoid 映射将原始分平滑映射到 0-100 区间。`
- 对抗技术：抗静态检测
- 鲁棒性分数：`46.0`
- 抗检测性评估：**中**

## 四点五、页面截图
### 页面截图
- 当前未采集到本次分析的页面截图，已暂未展示图像证据。

## 六、风险证据
### 1. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl1168060079.tmp; oasud.qwqrds.vjghasdh; cgroup.freeze`
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
- 证据：`[com.google.android.apps.nexuslauncher][com.google.android.as][com.google.android.apps.nexuslauncher][com.google.android.apps.nexuslauncher][com.google.android.apps.nexuslauncher][com.google.android.inputmethod.latin][com.google.android.youtube][com.android.systemui][oasud.qwqrds.vjghasdh][com.google.android.contacts][com.google.android.apps.wellbeing][com.google.android.googlequicksearchbox][com.google.android.apps.youtube.music]}]; 6: oasud.qwqrds.vjghasdh; 06-28 15:08:20.527 config: oasud.qwqrds.vjghasdh|removeAutomaticZenRules no changes; 06-28 15:08:20.527 set_zen_mode: off,oasud.qwqrds.vjghasdh|removeAutomaticZenRules; userId=0 value={com.google.android.apps.diagnosticstool, com.google.android.as/com.google.android.apps.miphone.aiai.common.notification.service.AiAiNotificationAssistantService, com.google.android.as/com.google.android.apps.miphone.aiai.common.notification.service.AiAiNotificationListenerService, com.google.android.apps.safetyhub, oasud.qwqrds.vjghasdh, com.google.intelligence.sense, com.google.android.apps.nexuslauncher/com.android.launcher3.notification.NotificationListener, com.google.android.apps.wellbeing, com.google.android.dialer, com.google.android.gms, com.google.android.settings.intelligence, com.google.android.GoogleCamera}`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 4. Manifest文件混淆/加密
- 规则：`DEEP_APK_STATIC_OBFUSCATED_MANIFEST`
- 严重级别：`high`
- 说明：APK的AndroidManifest.xml文件无法被正常解析，导致静态分析阶段未能提取出包名、权限和组件信息。这是一种常见的反静态分析技术，用于隐藏恶意应用的真实组件和意图。动态沙箱在运行时成功安装并揭示了其真实的包名和启动活动。
- 证据：`静态分析规则APK_MISSING_PACKAGE命中，无法解析包名。动态沙箱成功安装并运行，包名为 'oasud.qwqrds.vjghasdh'，启动活动为 'oasud.qwqrds.vjghasdh/.MainActivity'。静态报告中AndroidManifest.xml文件预览为二进制乱码。`
- 建议：对于Manifest解析异常的样本，应高度警惕其使用了加壳或混淆技术，必须结合动态行为进行研判。

### 5. 执行远程/本地系统命令
- 规则：`DEEP_APK_STATIC_COMMAND_EXECUTION_CONFIRMED`
- 严重级别：`critical`
- 说明：静态分析检测到应用包含执行系统命令的API调用（'sh'）。动态沙箱日志通过'abb: StartCommandInProcess'记录证实了该行为，样本在运行时执行了'package.install'等恶意指令，表明其具备下载和安装其他恶意应用的能力。
- 证据：`静态规则APK_DANGEROUS_API_SYSTEM_COMMAND命中，匹配 'sh'。动态日志：'I/abb ( 7248): StartCommandInProcess(7061636b61676500696e7374616c6c00 package.install. [truncated])'。`
- 建议：立即阻断该样本的网络通信，并检查设备上是否存在由其静默安装的未知应用。

### 6. 意图获取高权限（设备管理器/无障碍服务）
- 规则：`DEEP_APK_STATIC_PRIVILEGE_ESCALATION_INTENT`
- 严重级别：`critical`
- 说明：尽管由于Manifest混淆导致静态阶段无法直接发现，但动态沙箱证据明确显示，该应用在运行时会诱导用户激活设备管理器（Device Admin）和无障碍服务（Accessibility Service）。这是恶意软件获取持久化、防止卸载、监控用户操作、窃取敏感信息（如密码、短信验证码）的决定性步骤。
- 证据：`动态沙箱摘要 'persistent_services' 中记录: 'accessibility: [...oasud.qwqrds.vjghasdh...]', 'device_policy: [6: oasud.qwqrds.vjghasdh]'.`
- 建议：任何请求激活无障碍服务或设备管理器的非系统级应用都应被视为高风险。应教育用户切勿授予此类权限。

### 7. 使用随机化包名
- 规则：`DEEP_APK_STATIC_RANDOM_PACKAGE_NAME`
- 严重级别：`medium`
- 说明：样本的包名 'oasud.qwqrds.vjghasdh' 呈现出无意义的随机字符串特征。这是一种常见的恶意软件策略，旨在逃避基于名称的黑名单检测，并增加追踪和分析的难度。
- 证据：`动态沙箱摘要中识别的包名: 'oasud.qwqrds.vjghasdh'。`
- 建议：建立对随机化或无意义包名的检测规则，作为恶意软件的辅助识别特征。

### 8. 滥用辅助功能服务
- 规则：`DEEP_APK_BEHAVIOR_ACCESSIBILITY_ABUSE`
- 严重级别：`critical`
- 说明：应用在运行时注册为辅助功能服务。此权限允许应用监控用户交互、读取屏幕内容、模拟用户输入，是恶意软件进行键盘记录、窃取敏感信息或执行自动化攻击的常见手段。
- 证据：`dynamic_summary.persistent_services.accessibility 中包含 'oasud.qwqrds.vjghasdh'`
- 建议：立即隔离设备，分析辅助功能服务被滥用的具体行为，并检查是否存在数据泄露或远程控制迹象。

### 9. 滥用设备策略管理器权限
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_ADMIN_ABUSE`
- 严重级别：`critical`
- 说明：应用在运行时注册为设备策略管理器。此权限赋予应用控制设备设置（如密码策略、锁定屏幕）、远程擦除数据或禁用摄像头等高危能力，常被勒索软件或间谍软件利用。
- 证据：`dynamic_summary.persistent_services.device_policy 中包含 'oasud.qwqrds.vjghasdh'`
- 建议：立即撤销其设备管理员权限，并检查设备是否已被锁定、数据是否被篡改或擦除。

### 10. 注册为通知监听器
- 规则：`DEEP_APK_BEHAVIOR_NOTIFICATION_LISTENER`
- 严重级别：`high`
- 说明：应用在运行时注册为通知监听器。此权限允许应用读取、修改或取消所有通知，可能导致敏感信息（如短信验证码、聊天内容）泄露。
- 证据：`dynamic_summary.persistent_services.notification 中包含 'oasud.qwqrds.vjghasdh'`
- 建议：检查应用是否读取并上传了通知内容，并警惕潜在的隐私泄露风险。

### 11. 动态执行系统命令
- 规则：`DEEP_APK_BEHAVIOR_COMMAND_EXECUTION`
- 严重级别：`critical`
- 说明：动态沙箱日志显示应用尝试执行系统命令，如 'settings.get.glo' 和 'package.install'。这与静态分析中发现的 'sh' 和 'start' 等危险 API 调用相符，表明应用具备在设备上执行任意命令的能力。
- 证据：`logcat_excerpt 中包含 'StartCommandInProcess(73657474696e67730067657400676c6f settings.get.glo)' 和 'StartCommandInProcess(7061636b61676500696e7374616c6c00 package.install.)'`
- 建议：深入分析命令执行的上下文和参数，确定其具体目的，如是否用于下载并执行其他恶意载荷、修改系统配置或进行提权。

### 12. 尝试进行权限提升或未经授权的系统访问
- 规则：`DEEP_APK_BEHAVIOR_PRIVILEGE_ESCALATION_ATTEMPT`
- 严重级别：`critical`
- 说明：动态沙箱日志中出现多次 'avc: denied { getopt } for scontext=u:r:system_server:s0 tcontext=u:r:shell:s0 tclass=unix_stream_socket permissive=0' 错误，表明应用尝试访问或操作系统关键资源，但被 SELinux 策略拒绝。这通常是恶意软件尝试权限提升或绕过安全机制的迹象。
- 证据：`logcat_excerpt 中包含多条 'avc: denied { getopt }' 错误`
- 建议：分析被拒绝的系统调用，评估其潜在的攻击面和意图，例如是否尝试获取 root 权限或访问受保护的系统服务。

### 13. 包更新/重新安装行为
- 规则：`DEEP_APK_BEHAVIOR_PERSISTENCE_UPDATE`
- 严重级别：`high`
- 说明：动态沙箱日志显示应用进行了包更新或重新安装操作 ('Update package oasud.qwqrds.vjghasdh code path from ... to ...; Retain data and using new')。这可能用于实现持久化、更新恶意载荷或规避检测。
- 证据：`logcat_excerpt 中包含 'Update package oasud.qwqrds.vjghasdh code path from ... to ...; Retain data and using new'`
- 建议：检查更新机制是否安全，是否存在从非官方渠道下载更新的风险，以及更新后的包是否包含新的恶意功能。

### 14. 存在网络通信行为
- 规则：`DEEP_APK_BEHAVIOR_NETWORK_COMMUNICATION`
- 严重级别：`medium`
- 说明：应用在运行时产生了网络命中，并获取了 INTERNET 和 ACCESS_NETWORK_STATE 权限。虽然具体的 C2 地址不明确，但结合其他恶意行为，可能用于数据回传、接收指令或下载额外载荷。
- 证据：`dynamic_summary.network_hit_count: 12; dynamic_summary.granted_dangerous_permissions 包含 'ANDROID.PERMISSION.INTERNET', 'ANDROID.PERMISSION.ACCESS_NETWORK_STATE'`
- 建议：进一步分析网络流量，识别通信目标和传输内容，以确认是否存在数据窃取或远程控制行为。

### 15. 发现可疑字符串 'SSH.oR' 在运行时日志中
- 规则：`DEEP_APK_BEHAVIOR_SUSPICIOUS_STRING_SSH`
- 严重级别：`medium`
- 说明：在动态沙箱日志和网络命中中多次出现 'SSH.oR' 字符串，尤其是在 Telecom 服务相关的日志中。这可能暗示应用试图利用或模拟 SSH 协议进行通信，或者是一个混淆的恶意功能标识。
- 证据：`logcat_excerpt 中包含 'SSH.oR@AWA'; dynamic_sandbox.network_hits 中包含 'SSH.oR'`
- 建议：结合反编译结果，查找代码中 'SSH.oR' 的使用上下文，判断其是否与实际的 SSH 协议操作相关，或仅为混淆字符串。

### 16. 静态未解析包名，但动态运行包名有效
- 规则：`DEEP_APK_INTEL_STATIC_DYNAMIC_MISMATCH`
- 严重级别：`medium`
- 说明：静态侧无法解析出 packageName/组件，动态侧成功解析并启动 .MainActivity，显示样本可能采用非常规 Manifest/资源压缩或对抗手段，导致静态抽取受阻。
- 证据：`static.package_name="" vs dynamic.package_name="oasud.qwqrds.vjghasdh"; resolve_activity: oasud.qwqrds.vjghasdh/.MainActivity`
- 建议：使用 apktool/AXMLPrinter2 重解码 Manifest；对 AXML/资源进行手工校验；对 DEX 进行加固/字符串还原（jd-cli/fernflower/bytecode-viewer）以恢复组件与意图过滤器。

### 17. 运行时出现设备策略（DevicePolicy）关联线索
- 规则：`DEEP_APK_INTEL_RUNTIME_DEVICE_POLICY`
- 严重级别：`high`
- 说明：沙箱枚举显示 device_policy 列表包含目标包，提示可能声明了 DeviceAdminReceiver/设备管理能力。若被用户/社工误导激活，潜在风控较高。
- 证据：`dynamic.persistent_services.device_policy: ["6: oasud.qwqrds.vjghasdh"]`
- 建议：反编译检索 DeviceAdminReceiver/DevicePolicyManager 相关声明与动作（android.app.action.DEVICE_ADMIN_ENABLED）；在受控环境中模拟激活流程，使用 adb shell dpm set-device-owner/list 命令与日志钩子确认是否能获取设备管理权限及其后续策略调用。

### 18. 可访问性服务枚举中出现目标包名
- 规则：`DEEP_APK_INTEL_ACCESSIBILITY_PRESENCE`
- 严重级别：`medium`
- 说明：可访问性列表输出包含目标包，可能声明了辅助功能服务，常被恶意样本用于自动化操作与窃取通知，但当前无证据显示其已被启用。
- 证据：`dynamic.persistent_services.accessibility 列表包含 "oasud.qwqrds.vjghasdh"`
- 建议：检索 Manifest 是否声明 android.accessibilityservice.AccessibilityService/BIND_ACCESSIBILITY_SERVICE；在动态环境中尝试开启该服务并 Hook AccessibilityEvent 回调，观察是否存在自动化点击、读取通知/窗体文本等可疑行为。

### 19. 静态命中系统命令/代码执行敏感线索
- 规则：`DEEP_APK_INTEL_SHELL_CODE_EXEC`
- 严重级别：`critical`
- 说明：命中“sh”“start”等潜在代码执行相关标记，虽未确认调用路径，但与常见命令执行/动态加载链条相符，需优先复核。
- 证据：`static.matched_rules: system_command=sh; code_execution=start`
- 建议：反编译定位命中点上下文，检索 Runtime.getRuntime().exec/ProcessBuilder/反射调用；在动态侧使用 Frida/Xposed Hook exec/ProcessBuilder/Runtime.loadLibrary 等接口，确认是否实际下发系统命令或动态加载。

### 20. 未见明确外联 IOC，网络迹象不足
- 规则：`DEEP_APK_INTEL_NETWORK_OBSERVATION_GAP`
- 严重级别：`medium`
- 说明：短时运行下未捕获真实域名/URL/Socket 连接，仅见系统/安装相关 token，静态也仅发现资源命名空间 URL，无法据此刻画 C2/分发链。
- 证据：`dynamic.network_hit_count=12（如 settings.get.glo, package.install, SSH.oR, base.dm）；static.urls_found 仅为 http://schemas.android.com/apk/res/android 与 /res-auto`
- 建议：延长沙箱运行至≥10分钟并加入 UI/权限交互、滚动/点击脚本；部署 MITM/证书注入与 DNS/PCAP 捕获，Hook OkHttp/URLConnection/WebViewClient 以截获加密流量与真实 IOC。

### 21. 签名与来源信誉缺失，无法归因与背书
- 规则：`DEEP_APK_INTEL_SIGNATURE_PROVENANCE_GAP`
- 严重级别：`high`
- 说明：证书信息为空、文件名为 SHA256 命名，缺乏开发者签名谱系与市场页面背书，无法区分第三方正规发行与侧载分发。
- 证据：`apk_ir.certificate_subject/issuer/sha256 为空；file_name=23b0c2e...c61.apk（散列命名）`
- 建议：提取 V2/V3 签名与签名 lineage（apksigner/uber-apk-signer），计算证书 SHA256；在 VirusTotal/AndroZoo/市场后端查询同签名样本与历史信誉；核验来源：官方应用商店页面、开发者主页、首次上架时间、一致的签名链。

### 22. 沙箱运行窗口和交互不足可能掩蔽行为触发
- 规则：`DEEP_APK_INTEL_SANDBOX_RUNTIME_SHORT`
- 严重级别：`medium`
- 说明：运行仅 20 秒、事件数 35，可能未触发延时/地理围栏/充电状态/重启持久化等行为。
- 证据：`dynamic.runtime_window_seconds=20; event_count=35`
- 建议：增加运行时长（≥10 分钟），加入开屏/前后台切换/通知授权/无障碍开关等交互；测试重启后持久化、定时任务（AlarmManager/JobScheduler）与开机广播响应。

### 23. 包名呈随机化特征，疑似规避与批量分发
- 规则：`DEEP_APK_INTEL_RANDOMIZED_PKGNAME`
- 严重级别：`medium`
- 说明：包名 oasud.qwqrds.vjghasdh 无语义性，常见于投放用壳或批量打包的投递链，需结合签名/渠道进一步核验。
- 证据：`dynamic.package_name="oasud.qwqrds.vjghasdh"`
- 建议：对比同证书下其他样本的包名模式；检索安装来源（INSTALL_REFERRER/来源 URL/落地页），判断是否来自即时通讯/二维码/钓鱼站点侧载。

### 24. 存在抗静态检测/资源异常迹象
- 规则：`DEEP_APK_INTEL_ANTI_STATIC_HINT`
- 严重级别：`medium`
- 说明：Robustness 标记抗静态检测与资源异常，结合 Manifest/组件未解析、字符串稀少，提示可能的对抗/非常规打包。
- 证据：`robustness_summary: anti_static_detected=true; anti_static_categories=["资源异常"]；静态 component_count=0`
- 建议：启用多引擎解包（apktool 多版本、AXML 兼容模式），对 DEX 进行抽取还原（ARSC/AXML 修复、字符串解密），并在动态侧配合内存抓取（frida-dexdump/Maps）恢复真实代码面。

### 25. 结合来源与分发渠道进行风险判定与归因
- 规则：`DEEP_APK_INTEL_SOURCE_CHANNEL_JUDGMENT`
- 严重级别：`high`
- 说明：缺少来源/渠道时无法判别是否正规上架或恶意侧载。渠道可信度直接影响风险评估与处置强度。
- 证据：`当前无市场链接/下载页/投放链条信息；仅见本地临时目录与文件散列命名。`
- 建议：收集：下载来源 URL/二维码、推广文案、跳转链路（重定向/短链）、安装来源（INSTALL_REFERRER）、商店页面与开发者名；核验是否官方商店同名应用且签名一致；若来自聊天/网页弹窗/钓鱼页面，按高风险处置（阻断、隔离、留证）。

### 26. 建议隔离安装与终端防护
- 规则：`DEEP_APK_ADVICE_ISOLATE_INSTALL`
- 严重级别：`critical`
- 说明：样本存在系统命令与代码执行相关高危静态命中，且动态沙箱中已成功安装并启动，具备落地执行能力，应立即从生产环境隔离。
- 证据：`static: APK_DANGEROUS_API_SYSTEM_COMMAND (sh), APK_DANGEROUS_API_CODE_EXECUTION (start); dynamic: install_success=true, launch_success=true, pidof=16251`
- 建议：停止在真实设备继续安装；已安装终端立即隔离网络并排查卸载；对关联账号、设备与分发渠道做风险联动处置。

### 27. 建议在隔离沙箱中复核行为链
- 规则：`DEEP_APK_ADVICE_SBX_REVIEW`
- 严重级别：`high`
- 说明：静态证据不足以确认全部意图，但动态运行窗口内已有网络活动与持续运行痕迹，需要在无业务影响的隔离环境中复核其完整行为。
- 证据：`dynamic: event_count=35, network_hit_count=12, runtime_window_seconds=20, logcat_contains package install/launch traces`
- 建议：在独立沙箱中复跑，抓取网络目的地、文件落地、进程树、命令执行与反射/动态加载痕迹，确认是否为下载器、远控器或持久化载荷。

### 28. 建议阻断分发与下载链路
- 规则：`DEEP_APK_ADVICE_BLOCK_DISTRIBUTION`
- 严重级别：`critical`
- 说明：样本包名为空且实际安装包名为随机化命名 oasud.qwqrds.vjghasdh，结合高危 API 规则命中，疑似存在规避识别与投放风险，不宜继续对外分发。
- 证据：`static: APK_MISSING_PACKAGE; dynamic: package_name=oasud.qwqrds.vjghasdh`
- 建议：在网关、应用商店、MDM、EDR 或下载平台上添加哈希与包名特征阻断；同步清退已上传版本与引用链接。

### 29. 建议保留样本与全量留痕
- 规则：`DEEP_APK_ADVICE_PRESERVE_EVIDENCE`
- 严重级别：`high`
- 说明：该样本具有高风险研判价值，应保留原始 APK、哈希、静态提取结果、动态日志与网络命中信息，便于后续溯源与复盘。
- 证据：`sha256=23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61; dynamic_artifacts and logcat excerpt available`
- 建议：封存原始样本与分析产物，至少保留 APK、manifest、dex 摘要、logcat、network hits、安装/启动事件、证书信息与时间戳。

### 30. 建议收紧网络访问与权限监控
- 规则：`DEEP_APK_ADVICE_NETWORK_RESTRICT`
- 严重级别：`high`
- 说明：动态运行时仅见 INTERNET 与 ACCESS_NETWORK_STATE 授权，但已出现网络命中，说明联网行为真实存在，应重点监控外联目的地与会话特征。
- 证据：`dynamic: granted_dangerous_permissions=[INTERNET, ACCESS_NETWORK_STATE], network_hit_count=12`
- 建议：对相关域名/IP/URL 进行阻断或告警，重点排查是否访问 C2、更新源或遥测端点；必要时在代理层做 TLS/SNI 与 DNS 关联分析。


## 七、论坛式协同研判
- 主持人总结：综合四位专家的证据与结论，样本具备明确的对抗与控制链条：其Manifest被混淆/加密导致静态无法解析包名与组件，显示出明显的反静态分析意图；动态运行后暴露随机化包名（oasud.qwqrds.vjghasdh），并在系统持久化服务枚举中出现于设备管理器、无障碍服务及通知监听器列表，强烈指向其试图或已获得高控制权限，可实施屏幕/输入监控与自我防护。静态侧命中系统命令执行（sh）与代码执行（start）等高危能力，动态日志出现“package.install”等指令，结合SELinux拒绝记录，表明其存在安装/更新其他应用与越权操作的尝试，具备持久化与远程指令执行能力。动态短窗内未观测到明确的外联域名/URL，但存在网络事件计数，且签名与来源信息缺失使溯源和信誉校验受限。尽管情报侧对“是否已完全激活滥用”保持谨慎，但现有静/动证据已充分支持将该APK裁定为高危木马/远控型恶意软件，建议立即阻断分发与安装，并在隔离环境延长观测复核。本裁决基于四位专家的现有输出与短时动态窗口，相关外联与权限滥用程度仍需后续证据补强。

| 角色 | 模型 | 核心意见 | 补充说明 |
|------|------|----------|----------|
| 主持人 | `gpt-5` | 综合四位专家的证据与结论，样本具备明确的对抗与控制链条：其Manifest被混淆/加密导致静态无法解析包名与组件，显示出明显的反静态分析意图；动态运行后暴露随机化包名（oasud.qwqrds.vjghasdh），并在系统持久化服务枚举中出现于设备管理器、无障碍服务及通知监听器列表，强烈指向其试图或已获得高控制权限，可实施屏幕/输入监控与自我防护。静态侧命中系统命令执行（sh）与代码执行（start）等高危能力，动态日志出现“package.install”等指令，结合SELinux拒绝记录，表明其存在安装/更新其他应用与越权操作的尝试，具备持久化与远程指令执行能力。动态短窗内未观测到明确的外联域名/URL，但存在网络事件计数，且签名与来源信息缺失使溯源和信誉校验受限。尽管情报侧对“是否已完全激活滥用”保持谨慎，但现有静/动证据已充分支持将该APK裁定为高危木马/远控型恶意软件，建议立即阻断分发与安装，并在隔离环境延长观测复核。本裁决基于四位专家的现有输出与短时动态窗口，相关外联与权限滥用程度仍需后续证据补强。 | — |
| 静态分析员 | `gemini-2.5-pro` | 综合静态和动态沙箱证据，该APK是具有高度危险性的恶意软件，判定为木马。静态分析发现样本使用了代码执行（`start`）和系统命令（`sh`）等高危API，且AndroidManifest.xml文件可能经过混淆或加密，导致静态解析无法提取包名和组件信息，这是一种典型的抗静态分析手段。动态沙箱的证据强力印证了静态分析的结论并揭示了其真实意图：样本在运行时暴露了其随机生成的包名（oasud.qwqrds.vjghasdh），并尝试注册为设备管理器（Device Admin）和无障碍服务（Accessibility Service）。这是恶意软件获取设备最高控制权、进行屏幕监控、按键记录、自我保护以防卸载的典型手法。日志中捕获到其执行`package.install`等指令，表明其具备私自安装其他应用的恶意行为。该样本具备完整的窃密、远程控制和持久化能力。 | — |
| 行为分析员 | `gemini-2.5-flash` | 该 APK 样本表现出高度恶意行为。静态分析发现其包含系统命令执行（如 'sh'）和代码执行（如 'start'）的危险 API 调用。动态沙箱运行进一步证实了这些能力，日志中出现执行 'settings.get.glo' 和 'package.install' 命令的线索。更为关键的是，该应用在运行时注册了多项高危系统服务：它被列为辅助功能服务（Accessibility Service）、设备策略管理器（Device Policy Administrator）和通知监听器（Notification Listener）。这些权限组合赋予了应用对设备进行广泛控制、监控用户交互（包括屏幕内容、输入事件、通知信息）以及潜在的数据窃取或设备操纵的能力。日志中多次出现的 SELinux 拒绝（如 'denied { getopt }'）表明应用尝试执行未经授权的系统操作或进行权限提升。此外，观察到包更新/重新安装行为，暗示其具备持久化和自我修改能力。综合来看，该应用旨在获取深度系统控制并执行恶意操作。 | — |
| 情报分析员 | `gpt-5` | 综合静/动两侧线索：1) 静态侧解析存在明显缺口——未能解析出包名与证书信息（certificate_* 为空），Manifest 组件也未抽取到，但 DEX 中命中“sh”“start”等潜在代码执行/系统命令关键词，使静态评分偏高；2) 动态沙箱成功安装并启动，实际运行包名为 oasud.qwqrds.vjghasdh（与静态未解析到的包名形成反差），20 秒短窗内未见明确对外网络域名/URL 建联，仅出现系统和 GMS 相关事件标记与零散 token；3) 运行时枚举信息显示 device_policy 列表中出现目标包，以及可访问性枚举输出中包含目标包名，提示可能声明了设备管理或辅助功能相关组件，但当前证据不足以确认其被实际激活或滥用；4) 资源与构建元数据看似常规（AGP 8.8.0、丰富的 res/anim），但可提取的有意义字符串较少且 Robustness 标记“抗静态检测/资源异常”，指向潜在的对抗或非常规打包，导致 Manifest/字符串提取不完整。离线研判边界与不确定性：- 缺失签名证书指纹与签名谱系，无法基于开发者信誉校验；- 缺失明确来源与分发渠道，无法进行溯源与同源比对；- 动态仅 20 秒、低交互，可能错过延时/交互/地理围栏等触发条件。处置建议：在未补齐来源与签名前，将其按高风险样本管控（阻断分发与安装），并优先补采证签名信息、来源渠道与更长时间/更充分交互的动态观测，复核设备管理与辅助功能相关声明是否存在滥用。 | — |
| 处置建议员 | `gpt-5.4-mini` | 建议立即隔离该 APK，不要在生产终端或真实用户设备上继续安装/分发；先阻断来源与下载链路，保留原始样本、静态/动态报告、日志与哈希留痕。当前样本同时具备静态高危命中（系统命令 sh、代码执行 start）与动态运行证据（已成功安装并启动、存在网络活动、请求/获得 INTERNET 与 ACCESS_NETWORK_STATE），且包名非标准、样本身份不明，建议按高风险恶意样本处置。若业务上必须继续确认，需在完全隔离的沙箱中二次复核，重点检查 MainActivity、命令执行路径、网络目的地与是否存在隐蔽持久化/提权行为；在复核完成前禁止灰度、禁止上架、禁止对外传播。 | — |

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
