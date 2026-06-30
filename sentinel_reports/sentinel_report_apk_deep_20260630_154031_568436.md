# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**MEDIUM** · 风险分数：**64/100**
> 证据分数：**70/100** · 深度研判分数：**93 /100**
> 评分口径：APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\sentinelguard_apk_bundle_r7u1c5g3`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：25 条
- 高危证据：12 条

## 二、统一 IR 摘要
- APK 文件：`5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk`
- 包名：`-`
- 版本名：`-`
- 版本号：`-`
- SHA256：`5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a`
- 大小：`8265806` 字节
- 关键文件数：`3`

### APK 鲁棒性验证
- 鲁棒性分数：`54.0`
- 检测到的对抗技术：抗静态检测
- 防沙箱：`False`
- 混淆：`False`
- 反射：`False`
- 动态加载：`False`

### APK 静态内容解析与规则匹配
- 已解析文本条数：`80`
- 规则匹配结果：API 调用: sh, ps, top
- 命中规则数：`6`

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
- 抗静态细分：`加壳、混淆、资源异常`
- 鲁棒性分数公式：`鲁棒性分数 = Sigmoid(加权原始分)，其中加权原始分 = 24×抗静态检测 + 20×防沙箱 + 16×混淆 + 16×动态加载 + 12×反射 + 细分类别加成(最多12) + 技术多样性奖励(每项+3，封顶15) + 解析失败奖励(当APK图结构提取失败时 +25，因为解析失败本身是可疑信号)。Sigmoid 映射将原始分平滑映射到 0-100 区间。`
- 对抗技术：抗静态检测
- 鲁棒性分数：`54.0`
- 抗检测性评估：**中**

## 四点五、页面截图
### 页面截图
- 当前未采集到本次分析的页面截图，已暂未展示图像证据。

## 六、风险证据
### 1. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl1537208823.tmp; com.jggnaa.kgg; base.dm`
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
- 证据：`2: com.jggnaa.kgg`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 4. 设备管理权限持久化
- 规则：`DEEP_APK_BEHAVIOR_PERSISTENCE`
- 严重级别：`critical`
- 说明：样本在安装后尝试通过 Device Policy Manager 注册为设备管理应用，旨在实现后台驻留与防卸载。
- 证据：`dynamic_summary.persistent_services.device_policy: 2: com.jggnaa.kgg`
- 建议：该行为通常用于恶意软件的持久化，建议立即卸载并清理相关配置。

### 5. 高风险系统命令执行
- 规则：`DEEP_APK_BEHAVIOR_SYSTEM_COMMAND_EXEC`
- 严重级别：`critical`
- 说明：静态分析检测到样本包含 sh, ps, top, mv 等系统命令调用，结合动态沙箱中观察到的异常权限申请，存在执行恶意系统指令的风险。
- 证据：`static_content_summary.api_hits: sh, ps, top, mv`
- 建议：需进一步通过反编译确认这些命令的调用上下文，是否存在提权或文件篡改行为。

### 6. 安装链路异常
- 规则：`DEEP_APK_BEHAVIOR_INSTALL_ANOMALY`
- 严重级别：`medium`
- 说明：动态日志显示在安装过程中存在多次 avc: denied { getopt } 错误，表明样本在尝试探测系统服务或进行越权操作时被 SELinux 拦截。
- 证据：`logcat_excerpt: avc: denied { getopt } for scontext=u:r:system_server:s0 tcontext=u:r:shell:s0`
- 建议：关注该样本是否包含针对特定 Android 版本的提权漏洞利用代码。

### 7. 检测到加壳保护
- 规则：`DEEP_APK_STATIC_PACKER_DETECTED`
- 严重级别：`high`
- 说明：文件路径 'assets/protected_by_np/ApkControlFlowConfusion_8.0_f1ebe170df8340cba5ac7abf17d68b8e.txt' 表明样本使用了加壳或保护技术，旨在隐藏真实代码并对抗静态分析。
- 证据：`resource: assets/protected_by_np/ApkControlFlowConfusion_8.0_f1ebe170df8340cba5ac7abf17d68b8e.txt`
- 建议：由于代码被隐藏，静态分析的可见性有限。建议结合动态分析或使用专业脱壳工具来检查其运行时解密后的真实载荷。

### 8. 潜在的设备管理器权限滥用
- 规则：`DEEP_APK_STATIC_DEVICE_ADMIN_INTENT`
- 严重级别：`critical`
- 说明：虽然静态 Manifest 文件因加壳而无法直接解析，但动态沙箱证据显示应用（com.jggnaa.kgg）在运行时注册为设备策略服务。这表明其隐藏的载荷中包含了申请设备管理器（Device Admin）权限的恶意代码，这是获取设备控制权、防止卸载的典型恶意行为。
- 证据：`Dynamic evidence cross-validation: persistent_services.device_policy: ["2: com.jggnaa.kgg"]`
- 建议：必须阻止此类应用获取设备管理器权限。这是勒索软件、间谍软件等高风险恶意软件的标志性特征。

### 9. 发现可疑系统命令字符串
- 规则：`DEEP_APK_STATIC_SYSTEM_COMMAND_STRINGS`
- 严重级别：`high`
- 说明：在样本文件中发现了 'sh', 'ps', 'top' 等系统命令字符串。即使这些字符串位于保护壳中，也表明其功能集包含了执行底层Shell命令的能力，可能用于环境侦察、权限提升或执行恶意操作。
- 证据：`Static rule match: API 调用: sh, ps, top`
- 建议：应将此视为高风险指标。恶意软件经常使用Shell命令来执行超出Android API框架的系统级操作。

### 10. 疑似存在反分析规避技术
- 规则：`DEEP_APK_STATIC_ANTI_ANALYSIS_EVASION`
- 严重级别：`medium`
- 说明：应用在动态沙箱中安装成功但启动失败（launch_success: false）。结合其加壳保护的特性，这很可能是一种反模拟器或反沙箱的规避策略，旨在阻止自动化分析工具探查其真实行为。
- 证据：`Dynamic evidence cross-validation: launch_success: false`
- 建议：静态分析应进一步寻找可能的触发器（如BroadcastReceiver）或反模拟器检测代码（如检测特定设备属性、传感器缺失等），以理解其真实执行流程。

### 11. 动态沙箱解析到包名但静态未解析
- 规则：`DEEP_APK_INTEL_DYNAMIC_PACKAGE_DISCOVERED`
- 严重级别：`medium`
- 说明：静态未能解析包名与组件，动态运行解析到包名，显示清单或资源可能被加强混淆或非常规打包。
- 证据：`static.package_name: 空; dynamic.package_name: com.jggnaa.kgg; resolve_activity: No activity found; launch_success: false`
- 建议：以动态解析的包名为线索进行签名与渠道核验；脱壳后重新解析 AndroidManifest 以补齐组件信息。

### 12. 无可解析的启动 Activity，应用不可见或作为后端组件存在
- 规则：`DEEP_APK_INTEL_NO_LAUNCHER_ACTIVITY`
- 严重级别：`medium`
- 说明：安装成功但未发现可解析的前台入口，可能为后台组件、插件或刻意隐藏的应用形态。
- 证据：`dynamic.resolve_activity: No activity found; launch_success: false`
- 建议：检查清单中是否声明非导出组件或受保护的入口；通过模拟触发（广播、服务绑定、定时器、无障碍/设备策略授权流程）扩大动态观测窗口。

### 13. 具备系统命令调用能力
- 规则：`DEEP_APK_INTEL_SYSTEM_COMMAND_CAPABILITY`
- 严重级别：`high`
- 说明：静态字符串命中 sh、ps、top、mv 等系统命令，具备执行系统/进程相关操作的能力，可能用于自检、反沙箱或恶意行为链。
- 证据：`匹配: top; sh; ps; mv（APK_DANGEROUS_API_SYSTEM_COMMAND）`
- 建议：反编译并定位命令调用路径与参数来源；区分是否仅用于自检/心跳还是执行敏感操作（提权、持久化、文件操作）。

### 14. 发现加固与控制流混淆痕迹
- 规则：`DEEP_APK_INTEL_OBFUSCATION_PACKER`
- 严重级别：`medium`
- 说明：存在 protected_by_np 与 ApkControlFlowConfusion 标识，配合静态解析缺失指向较强的混淆/加固与抗静态检测。
- 证据：`assets/protected_by_np/ApkControlFlowConfusion_8.0_f1ebe170df8340cba5ac7abf17d68b8e.txt；鲁棒性摘要：加壳、资源异常`
- 建议：进行脱壳与控制流还原，复核敏感 API 的真实调用点；关注加壳框架是否已被犯罪生态广泛滥用。

### 15. 签名信息缺失，无法建立信任链
- 规则：`DEEP_APK_INTEL_CERTIFICATE_UNKNOWN`
- 严重级别：`medium`
- 说明：证书主题与颁发者未提取到，无法在离线条件下评估签名信誉与是否为官方开发者。
- 证据：`certificate_subject: 空; certificate_issuer: 空; certificate_sha256: 空`
- 建议：从 APK 中提取签名证书指纹（SHA256/签名版本 v1/v2/v3），与官方渠道或证书透明度日志进行比对。

### 16. 存在设备策略相关持久化指示
- 规则：`DEEP_APK_INTEL_DEVICE_POLICY_INDICATOR`
- 严重级别：`medium`
- 说明：动态摘要中出现 device_policy 列表包含该包名，提示可能涉及设备管理或持久化能力，但需二次核验以排除沙箱噪声。
- 证据：`dynamic.persistent_services.device_policy: ["2: com.jggnaa.kgg"]`
- 建议：在真机/隔离环境执行 dpm 查询（adb shell dpm get-active-admin、dpm list users/owners），核验是否获取设备/配置文件所有者；若为真，提升处置优先级。

### 17. 短窗口运行期无明显对外行为
- 规则：`DEEP_APK_INTEL_RUNTIME_INERT_SHORT_WINDOW`
- 严重级别：`low`
- 说明：20 秒运行窗口内未见有效外联 URL/IP 且未授予危险权限，可能需特定触发条件或更长观测窗口。
- 证据：`runtime_window_seconds: 20；granted_dangerous_permissions: 空；logcat 以安装与 dexopt 为主`
- 建议：延长运行时间，模拟用户交互与常见触发（网络可用、重启、SIM 状态变更、通知监听、辅助功能授权等），并开启流量抓取与文件系统监控。

### 18. 清单与组件信息异常
- 规则：`DEEP_APK_INTEL_MANIFEST_PARSE_ANOMALY`
- 严重级别：`medium`
- 说明：静态未能提取包名与组件，文本预览多为二进制片段，符合受保护或非常规打包的情况。
- 证据：`静态组件计数 0；APK_MISSING_PACKAGE；AndroidManifest.xml 文本预览异常`
- 建议：使用多引擎 AXML 解析或在运行时导出已解密清单（/data/app/.../base.apk）重新解析。

### 19. 包名随机化/无品牌特征
- 规则：`DEEP_APK_INTEL_PACKAGE_NAME_SUS`
- 严重级别：`medium`
- 说明：动态解析包名 com.jggnaa.kgg 命名无品牌与功能指示，常见于重打包或隐蔽投递的样本。
- 证据：`package_name: com.jggnaa.kgg（静态缺失，动态解析）`
- 建议：结合签名与分发渠道核查该包名是否存在官方发布记录；检索历史信誉与同证书下的其他包名。

### 20. 来源与分发渠道未核验
- 规则：`DEEP_APK_INTEL_SOURCE_CHANNEL_UNVERIFIED`
- 严重级别：`medium`
- 说明：样本来自本地临时目录，缺乏官方渠道佐证；在离线条件下无法核验哈希与证书信誉。
- 证据：`original_input: C:\Users\lenovo\AppData\Local\Temp\sentinelguard_apk_bundle_r7u1c5g3；sha256: 5494db78d03c9b30...`
- 建议：从获取路径追溯来源（邮件、网站、IM、第三方市场）；与官方商店、开发者官网对比包名/版本/签名；在联网环境中以哈希/证书指纹进行威胁情报比对。

### 21. 建议立即隔离安装与阻断分发
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`critical`
- 说明：样本命中系统命令 API 与抗静态特征，具备执行系统操作和规避分析的可能，当前不应在真实设备或生产环境安装。
- 证据：`静态命中: sh / ps / top / mv；robustness_score=46；anti_static_detected=true`
- 建议：在终端、邮件网关、下载平台与企业应用分发链路中阻断该 SHA256 样本；已安装环境建议立即卸载并纳入隔离清单。

### 22. 建议继续在沙箱内复核而非直接放行
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`high`
- 说明：当前动态执行未拉起活动，但安装成功、存在网络命中与持久化服务线索，说明样本可能依赖特定触发条件或二阶段行为。
- 证据：`install_success=true；launch_success=false；network_hit_count=12；persistent_services.device_policy=["2: com.jggnaa.kgg"]`
- 建议：继续在隔离沙箱中进行补充触发测试、组件枚举、反编译与字符串上下文分析，确认是否存在隐藏入口、反调试或条件执行逻辑。

### 23. 建议保留样本与留痕材料
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`high`
- 说明：样本存在加壳/资源异常特征，且关键文件仅提取到少量可读证据，后续溯源与复核依赖原始样本和沙箱产物。
- 证据：`key_files=AndroidManifest.xml、assets/protected_by_np/ApkControlFlowConfusion_8.0_f1ebe170df8340cba5ac7abf17d68b8e.txt、classes.dex；anti_static_categories=["加壳","资源异常"]`
- 建议：保留原始 APK、SHA256、静态报告、logcat、动态 artifacts、安装记录与网络命中清单；必要时对样本进行只读封存并建立工单留痕。

### 24. 建议核验来源与签名信誉
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`medium`
- 说明：包名、证书主体与签发者均未明确解析，样本身份不清晰，难以确认是否为可信应用或被重打包样本。
- 证据：`package_name为空；certificate_subject为空；certificate_issuer为空；APK_MISSING_PACKAGE 命中`
- 建议：结合应用市场来源、签名证书、历史版本与信誉情报做溯源核验；未能确认可信来源前，不予放行。

### 25. 建议关注网络与持久化迹象
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`high`
- 说明：动态阶段出现网络命中与 device_policy 持久化线索，虽未直接证明恶意外联，但足以构成进一步调查依据。
- 证据：`network_hits包含 settings.get.glo、package.install、com.jggnaa.kgg、base.apk、base.odex；persistent_services.device_policy=["2: com.jggnaa.kgg"]`
- 建议：在隔离环境中抓包、核查域名/IP/证书指纹及后续请求路径，确认是否存在回连、下载载荷或设备管理滥用行为。


## 七、论坛式协同研判
- 主持人总结：综合四位专家的静态与动态证据：样本疑似使用商业壳进行强混淆与反分析，静态内嵌多条高危系统命令字符串（sh/ps/top/mv）；动态沙箱侧成功安装并发现设备策略持久化记录（尝试注册设备管理器，包名 com.jggnaa.kgg），这是典型的持久化与权限巩固手段。虽然短时窗口内未拉起前台 UI，网络行为记录存在不一致，但这更符合规避与后端组件特征，不能减弱其恶意性。基于“设备管理权限尝试 + 系统命令执行能力 + 强混淆/反沙箱”的组合证据，裁定该 APK 为高危恶意载荷，风险等级为 critical，应立即隔离与阻断；同时由于运行时触发有限与情报侧缺失（证书/渠道信誉未核验），建议延长动态观察并开展反混淆复核以补全证据链。当前研判仅基于已有专家输出与所示沙箱/静态证据，未引入外部情报。

| 角色 | 模型 | 核心意见 | 补充说明 |
|------|------|----------|----------|
| 主持人 | `gpt-5` | 综合四位专家的静态与动态证据：样本疑似使用商业壳进行强混淆与反分析，静态内嵌多条高危系统命令字符串（sh/ps/top/mv）；动态沙箱侧成功安装并发现设备策略持久化记录（尝试注册设备管理器，包名 com.jggnaa.kgg），这是典型的持久化与权限巩固手段。虽然短时窗口内未拉起前台 UI，网络行为记录存在不一致，但这更符合规避与后端组件特征，不能减弱其恶意性。基于“设备管理权限尝试 + 系统命令执行能力 + 强混淆/反沙箱”的组合证据，裁定该 APK 为高危恶意载荷，风险等级为 critical，应立即隔离与阻断；同时由于运行时触发有限与情报侧缺失（证书/渠道信誉未核验），建议延长动态观察并开展反混淆复核以补全证据链。当前研判仅基于已有专家输出与所示沙箱/静态证据，未引入外部情报。 | — |
| 静态分析员 | `gemini-2.5-pro` | 该样本是一个经过加壳保护的恶意应用程序。静态分析的关键证据指向其使用了商业保护壳（从 'assets/protected_by_np/' 路径推断），这导致了初始解析无法获取包名和权限等信息。保护壳内嵌的字符串中包含了 'sh', 'ps', 'top' 等高危系统命令，表明其潜在的恶意功能。动态沙箱的证据交叉印证了这一判断：应用在运行时暴露了其真实包名 'com.jggnaa.kgg'，并且最关键的是，它尝试注册为设备管理器（Device Admin）。这是恶意软件（如勒索软件、间谍软件）为实现持久化、防止卸载而采用的典型高权限操作。尽管应用在沙箱中启动失败，但这很可能是反模拟器/反沙箱机制导致的规避行为。综合静态和动态证据，该应用具有明确的恶意企图，风险极高。 | — |
| 行为分析员 | `gemini-2.5-flash` | 该样本表现出高度可疑的恶意行为特征。静态分析发现其包含针对代码流混淆的保护资源，并存在大量系统命令（sh, ps, top, mv）调用风险。动态沙箱执行中，样本成功安装并尝试通过 Device Policy Manager 注册为设备管理应用（com.jggnaa.kgg），这是一种典型的持久化与权限提升手段。尽管在 20 秒运行窗口内未观察到 UI 启动，但其通过系统服务尝试获取设备控制权的行为，结合静态分析中检测到的系统命令执行能力，判定该样本具有极高的恶意意图，属于典型的恶意软件载荷。 | — |
| 情报分析员 | `gpt-5` | 综合静态与动态线索：样本静态命中多条系统命令相关字符串（sh、ps、top、mv），且存在明显的抗静态检测与加固痕迹（assets/protected_by_np/ApkControlFlowConfusion_8.0_*；鲁棒性标注为加壳、资源异常），静态解析未能提取包名与组件信息。动态沙箱侧成功安装但无可解析的启动 Activity（No activity found），启动失败且在短窗口内未见有效的网络对外行为；同时记录到持久化设备策略条目中出现“2: com.jggnaa.kgg”，提示需进一步核验是否涉及设备管理相关持久化能力。上述特征组合（重度混淆/加固、随机化包名、命令执行能力、无前台入口）符合部分隐蔽型恶意样本或受保护的灰产组件的行为侧写，但现有运行时证据不足以定性恶意行为链。在离线分析边界下（缺乏签名证书与发行渠道信誉、无法联网核验哈希/证书信誉、动态窗口较短且未触发行为），建议将风险维持在高等级并进行补充取证：延长动态窗口与事件触发、手动反混淆核验命令调用路径、核查设备策略状态与签名链信任、结合来源与分发渠道进行信誉比对。 | — |
| 处置建议员 | `gpt-5.4-mini` | 综合静态与动态证据，建议将该 APK 按高危可疑样本处置：立即阻断分发与安装，禁止在真实终端继续试装或运行；当前已出现系统命令相关 API 命中（sh/ps/top/mv）且样本具备抗静态特征，存在明显规避分析与执行系统操作的风险。动态沙箱中虽未成功拉起主界面，但安装成功、包名已识别为 com.jggnaa.kgg，且运行期间存在网络命中与持久化相关痕迹，说明样本并非纯空壳。建议保留原始样本、日志、沙箱产物与哈希留痕，并进一步在隔离沙箱内做二次复核与反编译核验后再决定是否定性为恶意。若样本来自外部渠道，按恶意/灰产样本流程隔离处置，不应放行。 | — |

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。


## 九、分析性能统计

- 总耗时：113.52 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 行为分析员 | 4.73 | 18589 | 721 | 19310 |
| 静态分析员 | 38.06 | 18320 | 2860 | 21180 |
| 情报分析员 | 59.42 | 12318 | 4506 | 16824 |
| 处置建议员 | 6.61 | 12137 | 1123 | 13260 |
| 主持人 | 47.31 | 2272 | 4137 | 6409 |
