# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**MEDIUM** · 风险分数：**62/100**
> 证据分数：**70/100** · 深度研判分数：**93 /100**
> 评分口径：APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\sentinelguard_apk_bundle_5hha8p_j`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：30 条
- 高危证据：17 条

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
- 规则匹配结果：API 调用: start, sh
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
- 证据：`settings.get.glo; package.install; vmdl1749675918.tmp; oasud.qwqrds.vjghasdh; cgroup.freeze`
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
- 证据：`[com.google.android.apps.nexuslauncher][com.google.android.as][oasud.qwqrds.vjghasdh][com.android.chrome][com.google.android.apps.nexuslauncher][com.google.android.apps.nexuslauncher][com.google.android.apps.nexuslauncher][com.google.android.inputmethod.latin][com.android.systemui][com.google.android.apps.wellbeing][com.google.android.googlequicksearchbox]}]; 6: oasud.qwqrds.vjghasdh; 06-28 15:08:20.527 config: oasud.qwqrds.vjghasdh|removeAutomaticZenRules no changes; 06-28 15:08:20.527 set_zen_mode: off,oasud.qwqrds.vjghasdh|removeAutomaticZenRules; userId=0 value={com.google.android.apps.diagnosticstool, com.google.android.as/com.google.android.apps.miphone.aiai.common.notification.service.AiAiNotificationAssistantService, com.google.android.as/com.google.android.apps.miphone.aiai.common.notification.service.AiAiNotificationListenerService, com.google.android.apps.safetyhub, oasud.qwqrds.vjghasdh, com.google.intelligence.sense, com.google.android.apps.nexuslauncher/com.android.launcher3.notification.NotificationListener, com.google.android.apps.wellbeing, com.google.android.dialer, com.google.android.gms, com.google.android.settings.intelligence, com.google.android.GoogleCamera}`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 4. 存在命令执行静态证据
- 规则：`DEEP_APK_STATIC_COMMAND_EXECUTION_EVIDENCE`
- 严重级别：`critical`
- 说明：静态分析在DEX文件中检测到对“sh”的调用，这是执行shell命令的明确标志，表明应用可能在后台执行任意系统级命令，用于提权、安装其他应用或破坏系统。
- 证据：`静态API检测命中: sh`
- 建议：阻断该应用，防止其执行任何潜在的恶意命令。对DEX文件进行深度反编译，定位调用'sh'的具体代码逻辑和上下文。

### 5. 权限提升向量得到动态印证
- 规则：`DEEP_APK_STATIC_PRIVILEGE_ESCALATION_VECTOR_CONFIRMED`
- 严重级别：`critical`
- 说明：尽管静态Manifest解析不完整，但动态沙箱证据显示，该应用成功注册了无障碍服务和设备管理器。这表明其代码中必然包含了请求这些高危权限的逻辑，旨在监控用户操作、窃取屏幕信息、绕过安全限制和防止被卸载。
- 证据：`动态沙箱证据: persistent_services.accessibility 包含 'oasud.qwqrds.vjghasdh'; persistent_services.device_policy 包含 'oasud.qwqrds.vjghasdh'`
- 建议：立即将此样本标记为恶意，此类权限组合对用户隐私和设备安全构成直接且严重的威胁。

### 6. 使用可疑的随机包名
- 规则：`DEEP_APK_STATIC_SUSPICIOUS_PACKAGE_NAME`
- 严重级别：`high`
- 说明：静态分析未能从损坏或混淆的Manifest中提取包名，而动态沙箱确认其包名为'oasud.qwqrds.vjghasdh'。这种类似随机生成的字符串是恶意软件常用的伪装手段，以逃避基于名称的检测和黑名单。
- 证据：`动态沙箱解析包名: oasud.qwqrds.vjghasdh`
- 建议：将此包名加入黑名单，并警惕具有类似命名模式的其他应用。

### 7. 存在自我更新行为迹象
- 规则：`DEEP_APK_STATIC_SELF_UPDATE_INDICATOR`
- 严重级别：`high`
- 说明：静态检测到的代码执行API（start）与动态日志中捕获的包安装命令（package.install）和从临时文件更新（vmdl*.tmp）的行为相吻合。这表明应用具备自我更新或下载安装其他恶意载荷的能力，以实现持久化控制和功能扩展。
- 证据：`静态API: start; 动态日志: I/abb(...): StartCommandInProcess(...package.install...), I/PackageManager(...): Integrity check passed for file:///data/app/vmdl1749675918.tmp`
- 建议：监控与此应用相关的网络流量，以识别其命令与控制（C2）服务器地址，并予以阻断。

### 8. 检测到应用自我更新/自我修改行为
- 规则：`DEEP_APK_BEHAVIOR_SELF_UPDATE`
- 严重级别：`critical`
- 说明：动态沙箱日志显示应用在运行时更新了自身的包代码路径，并保留了数据。此行为允许应用在不经用户明确同意的情况下更改其功能或加载新载荷，是恶意软件的典型特征。
- 证据：`logcat: 'Update package oasud.qwqrds.vjghasdh code path from /data/app/... to /data/app/...; Retain data and using new', 'Force stopping oasud.qwqrds.vjghasdh appid=10191 user=-1: installPackageLI', 'package.install' command execution.`
- 建议：立即隔离并深入分析更新后的载荷，确认其具体恶意功能。建议阻止此类应用运行。

### 9. 应用注册为设备管理员
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_ADMIN_REGISTRATION`
- 严重级别：`critical`
- 说明：动态分析显示应用成功注册为设备管理员。此权限赋予应用广泛的系统控制能力，包括但不限于强制密码策略、擦除设备数据、阻止卸载等，是恶意软件实现持久化和深度控制的关键手段。
- 证据：`dynamic_summary: 'persistent_services': {'device_policy': ['6: oasud.qwqrds.vjghasdh']}`
- 建议：此权限滥用风险极高，建议立即卸载并检查设备是否存在其他恶意活动。

### 10. 应用执行系统命令
- 规则：`DEEP_APK_BEHAVIOR_SYSTEM_COMMAND_EXECUTION`
- 严重级别：`high`
- 说明：动态日志中捕获到应用执行了 'StartCommandInProcess'，涉及 'settings.get.glo' 和 'package.install' 等系统级操作。这与静态分析中发现的系统命令（'sh'）和代码执行（'start'）API调用相吻合，表明应用试图在系统层面进行操作。
- 证据：`logcat: 'I/abb ( 7248): StartCommandInProcess(73657474696e67730067657400676c6f settings.get.glo [truncated])', 'I/abb ( 7248): StartCommandInProcess(7061636b61676500696e7374616c6c00 package.install. [truncated])'`
- 建议：进一步分析执行的具体命令及其参数，以确定其意图和潜在危害。此类行为可能用于信息窃取、权限提升或进一步的恶意载荷部署。

### 11. 应用被列入辅助功能服务
- 规则：`DEEP_APK_BEHAVIOR_ACCESSIBILITY_SERVICE_USAGE`
- 严重级别：`medium`
- 说明：动态沙箱报告显示该应用被列入辅助功能服务。虽然辅助功能服务本身是合法的，但恶意应用常滥用此权限来监控用户输入、劫持UI交互或执行点击操作，从而窃取敏感信息或进行欺诈。
- 证据：`dynamic_summary: 'persistent_services': {'accessibility': ['...oasud.qwqrds.vjghasdh...']}`
- 建议：结合其他高风险行为，此辅助功能服务的使用应被视为高度可疑。建议检查应用是否请求了辅助功能权限，并分析其在辅助功能服务中的具体实现。

### 12. 检测到与系统服务相关的网络命中
- 规则：`DEEP_APK_BEHAVIOR_NETWORK_ACTIVITY`
- 严重级别：`low`
- 说明：动态分析捕获到网络命中，包括 'settings.get.glo' 和 'package.install'。这些命中虽然看起来是系统内部通信或与包管理相关，但在应用自我更新和执行系统命令的背景下，可能与恶意载荷的下载或C2通信有关。
- 证据：`network_hits: ['settings.get.glo', 'package.install', 'vmdl1749675918.tmp', 'oasud.qwqrds.vjghasdh']`
- 建议：虽然这些网络命中本身不直接指示外部C2，但应结合其他行为链条进行综合判断，警惕其可能用于下载后续恶意组件。

### 13. 动态运行发现真实包名与入口组件
- 规则：`DEEP_APK_INTEL_DYNAMIC_PACKAGE_DISCOVERED`
- 严重级别：`medium`
- 说明：静态解析未得出包名/组件，但动态运行解析到包名与 MainActivity，说明静态清单/资源解析存在偏差或样本使用了 AAPT2 压缩格式。
- 证据：`resolve_activity: oasud.qwqrds.vjghasdh/.MainActivity；static: package_name=""、component_count=0`
- 建议：使用 aapt dump badging / apktool(最新版本) / androguard 重新解析 Manifest；对比动态包名与证书签名，修正静态画像后再判定。

### 14. 包名随机化特征
- 规则：`DEEP_APK_INTEL_SUSPICIOUS_PACKAGE_NAMING`
- 严重级别：`medium`
- 说明：运行包名 oasud.qwqrds.vjghasdh 随机感强，不符合常见品牌命名规范，常见于测试包或投递样本。
- 证据：`dynamic_sandbox.package_name=oasud.qwqrds.vjghasdh`
- 建议：结合签名证书 CN/O、证书指纹与历史版本比对；核验应用来源（商店/官网 vs. 非正规分发）。若签名为 debug/self-signed 且来源可疑，提升处置等级。

### 15. 静态敏感 API 命中存在误报可能
- 规则：`DEEP_APK_INTEL_STATIC_RULE_HITS_AMBIGUOUS`
- 严重级别：`medium`
- 说明：命中的 “sh”“start” 可能来自资源字符串（如 http://schemas…）或通用方法名，未见函数调用图与上下文支撑。
- 证据：`matched_rules: system_command=sh; code_execution=start; urls_found: http://schemas.android.com/apk/res/android`
- 建议：反编译 DEX（jadx/bytecode viewer）定位 Runtime.getRuntime().exec/ProcessBuilder("sh"/"su")、反射/动态加载路径；构建调用图验证是否实际执行系统命令。

### 16. 设备策略持久化可疑信号
- 规则：`DEEP_APK_INTEL_RUNTIME_POLICY_PERSISTENCE_SIGNAL`
- 严重级别：`high`
- 说明：动态摘要显示 device_policy 列表包含该包名，若确为设备管理器注册将显著提升控制能力与风险。
- 证据：`persistent_services.device_policy: ["6: oasud.qwqrds.vjghasdh"]`
- 建议：在设备上执行 dumpsys device_policy / dumpsys appops 确认是否注册 DeviceAdminReceiver；复查 Manifest 中是否存在 <device-admin> 或相关权限；必要时人工交互确认是否提示获取设备管理权限。

### 17. 无障碍服务存在性线索
- 规则：`DEEP_APK_INTEL_RUNTIME_ACCESSIBILITY_SIGNAL`
- 严重级别：`medium`
- 说明：accessibility 持久化列表中出现目标包名，若实际启用则具备大范围 UI 驱动与数据访问能力。
- 证据：`persistent_services.accessibility 列表含 "oasud.qwqrds.vjghasdh"`
- 建议：通过 dumpsys accessibility 检查是否注册/启用 AccessibilityService；核验 Manifest 中 BIND_ACCESSIBILITY_SERVICE；若属实并与应用宣称功能不匹配，按高危木马能力评估。

### 18. 外联证据不足
- 规则：`DEEP_APK_INTEL_NETWORK_EVIDENCE_WEAK`
- 严重级别：`low`
- 说明：动态运行未解析到有效域名/IP 的真实联机行为，network_hits 主要为系统事件片段，缺少 C2/接口指向。
- 证据：`network_hits 示例：settings.get.glo, package.install, SSH.oR, base.dm（非有效域名）`
- 建议：延长沙箱窗口并引入用户行为脚本；抓取 PCAP/HTTPS 代理日志；若后续出现外联，提取 IOC 与通信协议用于家族归属。

### 19. 签名证书缺失，信誉无法评估
- 规则：`DEEP_APK_INTEL_CERT_MISSING`
- 严重级别：`medium`
- 说明：当前样本未提取到证书主题/指纹，无法进行开发者信誉与版本谱系对比。
- 证据：`certificate_subject="", certificate_issuer="", certificate_sha256=""`
- 建议：使用 apksigner/uber-apk-signer 导出签名与 lineage；对照历史版本签名、公开商店条目与威胁情报（VT/MalwareBazaar）进行信誉核验。

### 20. Manifest 解析失败导致画像不完整
- 规则：`DEEP_APK_INTEL_MANIFEST_PARSE_FAILURE`
- 严重级别：`medium`
- 说明：静态报告显示未解析到包名和组件，影响权限与组件级别风险判断。
- 证据：`APK_MISSING_PACKAGE 命中；component_count=0`
- 建议：使用支持 AAPT2 的工具链重建 Manifest（apktool v2.9+/aapt2 dump），补全组件与权限画像后再评估。

### 21. 构建元数据显示新版本构建链
- 规则：`DEEP_APK_INTEL_BUILD_METADATA`
- 严重级别：`low`
- 说明：META-INF 标示 androidGradlePluginVersion=8.8.0，样本由较新构建工具打包，常见于近期编译或二次打包样本。
- 证据：`META-INF/com/android/build/gradle/app-metadata.properties: androidGradlePluginVersion=8.8.0`
- 建议：结合签名与时间线判断是否为官方近期版本或第三方重打包；如与官方签名/包名不匹配，提示可能为重打包风险。

### 22. 结合来源与分发渠道进行风险校准
- 规则：`DEEP_APK_INTEL_SOURCE_DISTRIBUTION_CONTEXT`
- 严重级别：`medium`
- 说明：来源渠道与签名信誉对风险分级影响显著，当前无来源信息应视为高风险待证实。
- 证据：`original_input: C:\Users\lenovo\AppData\Local\Temp\sentinelguard_apk_bundle_5hha8p_j（本地临时路径，缺失渠道信息）`
- 建议：核验是否来自官方商店/开发者官网；比对商店上架包名、签名、版本号；若为未知站点/社交分发/压缩包内置安装，按高风险处置并进行同证书/同家族溯源。

### 23. 静态高危命中需按恶意样本预处置
- 规则：`DEEP_APK_ADVICE_STATIC_CRITICAL`
- 严重级别：`critical`
- 说明：静态分析已命中系统命令与代码执行相关高危规则，且出现 start/sh 等敏感 API 线索，存在执行系统命令或动态加载/拉起外部逻辑的风险。
- 证据：`APK_STATIC_RULE_MATCH; APK_DANGEROUS_API_SYSTEM_COMMAND: sh; APK_DANGEROUS_API_CODE_EXECUTION: start; static severity=critical`
- 建议：立即隔离样本，阻断分发；保留 APK、反编译产物、字符串与规则命中记录，交由逆向人员复核命中上下文。

### 24. 动态沙箱已确认可安装可启动，需提升处置等级
- 规则：`DEEP_APK_ADVICE_DYNAMIC_EXECUTED`
- 严重级别：`critical`
- 说明：样本在模拟器中 install_success=true 且 launch_success=true，说明不是仅有静态噪声，已经进入真实执行阶段，应按可执行风险样本对待。
- 证据：`dynamic_summary.install_success=true; launch_success=true; pidof=14971; event_count=36; runtime_window_seconds=20`
- 建议：禁止在真实终端复测；保留沙箱镜像、进程信息与运行时事件序列，必要时重新在受控沙箱中分阶段复现。

### 25. 存在网络活动迹象，应阻断外联并追踪 IOC
- 规则：`DEEP_APK_ADVICE_NETWORK_ACTIVITY`
- 严重级别：`high`
- 说明：动态阶段记录到 network_hit_count=12，说明样本具备外联或访问系统服务/安装相关链路的能力；若继续运行，存在数据外传或拉取二阶段载荷风险。
- 证据：`network_hit_count=12; network_hits includes package.install, settings.get.glo, oasud.qwqrds.vjghasdh, base.dm, SSH.oR`
- 建议：立即在网关/代理/EDR 中阻断相关出站访问；提取并封禁可疑域名/URI 线索，保留网络命中日志用于 IOC 扩展排查。

### 26. 持久化控制相关迹象明显，建议重点核查无障碍/设备策略权限链
- 规则：`DEEP_APK_ADVICE_PERSISTENT_SERVICE_RISK`
- 严重级别：`critical`
- 说明：动态证据显示 accessibility、device_policy、notification 等持久服务条目中包含样本包名，暗示可能试图借助无障碍、设备管理或通知监听形成常驻控制能力。
- 证据：`persistent_services.accessibility contains oasud.qwqrds.vjghasdh; persistent_services.device_policy contains oasud.qwqrds.vjghasdh; persistent_services.notification includes oasud.qwqrds.vjghasdh`
- 建议：重点排查是否申请/诱导开启无障碍、设备管理员、通知访问等高风险能力；如在真实设备上出现，建议立即卸载并检查相关系统设置残留。

### 27. 安装后行为异常但具备系统交互痕迹，需沙箱复核
- 规则：`DEEP_APK_ADVICE_INSTALL_BEHAVIOR`
- 严重级别：`high`
- 说明：动态日志出现 PackageManager、ActivityManager、PermissionManager、PackageInstallerSession 等多类系统交互，结合样本运行结果，需要确认是否存在更新覆盖、保持数据、权限变更等可疑行为。
- 证据：`logcat shows Update package ... Retain data and using new; Permission ownership changed; Marking session as applied; PACKAGE_ADDED/PACKAGE_REMOVED events`
- 建议：在隔离沙箱中重新抓取完整安装链路与文件系统差异，确认是否存在二阶段安装、覆盖更新或持久化配置落地。

### 28. 包名缺失且样本身份不明，阻断传播更稳妥
- 规则：`DEEP_APK_ADVICE_MISSING_IDENTITY`
- 严重级别：`medium`
- 说明：静态侧未解析到原始包名，实际动态包名与静态文件名不一致，样本身份不透明，增加溯源与白名单判断难度。
- 证据：`APK_MISSING_PACKAGE; static package_name empty; dynamic package_name=oasud.qwqrds.vjghasdh`
- 建议：在确认签名证书、来源渠道与版本族谱前，不应放行或白名单化；建议保留哈希、样本来源与安装路径留痕。

### 29. 应完整保留样本与运行证据，便于复盘与联动处置
- 规则：`DEEP_APK_ADVICE_RETAIN_EVIDENCE`
- 严重级别：`high`
- 说明：样本同时具备静态高危、动态执行和网络活动证据，后续可能需要做 IOC 关联、签名比对、家族聚类与横向排查。
- 证据：`sha256=23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61; dynamic_artifacts paths; logcat_excerpt_count=222; network_hits present`
- 建议：保留 APK 原件、动态输出目录、logcat 截断与完整日志、网络命中清单、安装/启动事件时间线，并对样本做只读归档与留痕。

### 30. 动态确认持久化与高权限控制
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`critical`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`persistent_services 显示 device_policy 与 accessibility 列表均包含 oasud.qwqrds.vjghasdh；日志显示自我更新（更新 code path、Force stopping during install）。`
- 建议：结合静态报告进一步复核。


## 七、论坛式协同研判
- 主持人总结：综合前四位专家的证据与结论，最终判定该APK为高危恶意木马（critical）。动态行为在短时间窗口内即呈现出明确的持久化与权限提升链条：1) 通过PackageManager进行自我更新/替换代码路径并保留数据；2) 注册为设备管理员，并出现在无障碍持久服务列表；3) 执行系统级命令（如package.install、settings.get.*）；4) 使用随机化包名以规避追踪。这些行为足以在设备上建立高权限控制并显著提高卸载难度，且与静态侧的命令执行迹象相互印证。需注意证据边界：当前静态画像不完整（清单/签名解析失败），动态观察窗口较短且未捕获明确的对外联络，网络相关日志可能存在系统噪声；因此外联与家族归属尚待补充验证。尽管存在上述不确定性，已被动态印证的持久化与高权限控制能力足以支撑恶意裁决，应按恶意样本高等级处置。上述裁决仅基于现有四位专家输出与证据。

| 角色 | 模型 | 核心意见 | 补充说明 |
|------|------|----------|----------|
| 主持人 | `gpt-5` | 综合前四位专家的证据与结论，最终判定该APK为高危恶意木马（critical）。动态行为在短时间窗口内即呈现出明确的持久化与权限提升链条：1) 通过PackageManager进行自我更新/替换代码路径并保留数据；2) 注册为设备管理员，并出现在无障碍持久服务列表；3) 执行系统级命令（如package.install、settings.get.*）；4) 使用随机化包名以规避追踪。这些行为足以在设备上建立高权限控制并显著提高卸载难度，且与静态侧的命令执行迹象相互印证。需注意证据边界：当前静态画像不完整（清单/签名解析失败），动态观察窗口较短且未捕获明确的对外联络，网络相关日志可能存在系统噪声；因此外联与家族归属尚待补充验证。尽管存在上述不确定性，已被动态印证的持久化与高权限控制能力足以支撑恶意裁决，应按恶意样本高等级处置。上述裁决仅基于现有四位专家输出与证据。 | — |
| 静态分析员 | `gemini-2.5-pro` | 综合静态和动态证据，该样本为高风险恶意软件。静态分析发现可疑的系统命令调用（sh）和代码执行（start）API，动态沙箱证据证实了其恶意行为：样本安装后以随机包名（oasud.qwqrds.vjghasdh）运行，并试图注册为无障碍服务（Accessibility）和设备管理器（Device Policy），这是恶意软件获取设备完全控制权的典型手法。此外，日志显示其存在自我更新行为（package.install），进一步印证了其持久化驻留和下载后续恶意模块的企图。静态分析的风险点在动态行为中得到完全确认和放大，应判定为恶意木马。 | — |
| 行为分析员 | `gemini-2.5-flash` | 基于动态沙箱证据，该APK (oasud.qwqrds.vjghasdh) 表现出高度可疑和恶意行为。最关键的行为是其在运行时进行**自我更新/自我修改**，通过PackageManager更新自身代码路径，这通常是恶意软件用于规避检测、更新载荷或改变功能的常见手段。同时，该应用成功注册为**设备管理员**，赋予其对设备的高度控制权，包括可能阻止卸载、擦除数据或修改安全策略，这是典型的持久化和权限提升行为。此外，动态日志显示其执行了与系统设置和包安装相关的**系统命令**，与静态分析中检测到的危险API调用（如'sh'和'start'）相符，表明其有能力在系统层面进行操作。应用还被列入**辅助功能服务**，这可能使其能够监控用户交互、窃取敏感信息或执行未经授权的操作。综合来看，该应用的行为链指向一个具有强大控制能力和规避机制的恶意软件。 | — |
| 情报分析员 | `gpt-5` | 综合当前静态与动态线索：
- 静态面：样本 SHA256=23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61，包含多 DEX 与常见 Material/Design 动画资源；但解析未提取到包名与组件，签名信息亦为空，静态图谱为 0，属于明显的清单/资源解析不完整边界，无法仅凭离线静态结果确证威胁链条。规则命中的“sh”“start”存在来自资源字符串（如 schemas）或通用方法名的误报可能，需结合反编译上下文复核。
- 动态面：沙箱安装并拉起成功，运行时实际包名为 oasud.qwqrds.vjghasdh（随机感较强），授予的仅为网络类权限；20 秒窗口内未见明确对外网络主机/域名访问（network_hits 多为系统日志片段），暂缺有效外联证据。但“persistent_services”中显示 device_policy 与 accessibility 列表包含该包名，提示可能涉及设备策略/无障碍持久化能力，若真实启用将属于高风险行为；当前未见明确的 DeviceAdmin/Accessibility 注册 UI 或相关 Manifest 声明，需进一步以 dumpsys 与 UI 操作验证。
- 证据边界：离线样本缺失签名证书、发行方与来源渠道信息，Manifest 解析失败导致组件/权限画像不完整；动态窗口较短且为模拟器环境，行为可能被环境钳制或尚未触发。上述因素决定目前结论为“高风险征兆待证实”。
- 来源与分发渠道判断建议：若样本来自官方应用商店、签名可溯源且包名/证书指纹与历史版本一致，静态命中可降权并侧重功能性解释；若来自不明下载页/社交分发/钓鱼链接、签名为自签或 debug keystore、包名随机且与宣称品牌不符，应按高风险处置并进行联动封禁与威胁情报回溯（同证书指纹/同域分发/同家族样本）。 | — |
| 处置建议员 | `gpt-5.4-mini` | 建议立即隔离该 APK，阻断分发与继续安装；当前样本同时具备高危静态命中（系统命令/代码执行）与动态运行迹象（已成功安装、启动，且出现网络活动与设备策略/无障碍/通知相关持久服务线索），应按恶意样本处置。建议保留原始样本、安装/运行日志、logcat、网络命中与动态产物留痕，进入沙箱复核与人工深度逆向；在结论未完全澄清前，不允许在生产设备或正式账号环境中继续运行。 | — |

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
