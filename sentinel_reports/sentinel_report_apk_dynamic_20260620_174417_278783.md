# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**LOW** · 风险分数：**26/100**
> 证据分数：**50/100** · 深度研判分数：**45 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpg4qbwzgh.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：26 条
- 高危证据：4 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260620_174142_626783.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260620_174142_626783.md

## 二、统一 IR 摘要
- APK 文件：`tmpg4qbwzgh.apk`
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
- static_file_name：tmpg4qbwzgh.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：9024
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：无
- persistent_services：{'accessibility': ['[com.google.android.googlequicksearchbox][com.google.android.as][com.google.android.inputmethod.latin][com.google.android.apps.wellbeing][com.malmstein.yahnac][com.google.android.apps.nexuslauncher][com.google.android.apps.photos]}]'], 'device_policy': ['6: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：47
- logcat_excerpt_count：267
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260620_174144_496681_com.malmstein.yahnac/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260620_174144_496681_com.malmstein.yahnac/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260620_174144_496681_com.malmstein.yahnac/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260620_174144_496681_com.malmstein.yahnac`

## 四点二、图结构分析
- 图结构状态：`回退生成`；原因：androguard_unavailable_or_parse_failed
### CFG / FCG / API 调用图
- CFG 节点数：`1`
- CFG 边数：`0`
- FCG 节点数：`2`
- FCG 边数：`1`
- FCG 密度：`0.1667`
- API 调用图节点数：`0`
- API 调用图边数：`0`
- API 总调用数：`0`
- 敏感 API 调用分布：network:0, payment:0, privacy:0, reflection:0, system:0
- API 调用明细：
  - `network`：0
  - `payment`：0
  - `privacy`：0
  - `reflection`：0
  - `system`：0

## 四点三、一致性验证
- 一致性分数：`71`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 43 分, static-intelligence 差异 38 分, behavior-intelligence 差异 5 分
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
- 证据：`Subject=<asn1crypto.x509.Name 1797955354928 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>; Issuer=<asn1crypto.x509.Name 1797955355456 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl1585856488.tmp; com.malmstein.yahnac; base.dm`
- 建议：后续可结合抓包或代理进行复核。

### 4. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.googlequicksearchbox][com.google.android.as][com.google.android.inputmethod.latin][com.google.android.apps.wellbeing][com.malmstein.yahnac][com.google.android.apps.nexuslauncher][com.google.android.apps.photos]}]; 6: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 5. 应用使用通用调试密钥签名
- 规则：`DEEP_APK_STATIC_DEBUG_SIGNATURE`
- 严重级别：`high`
- 说明：该APK使用了标准的Android调试密钥进行签名。任何拥有相同调试密钥的攻击者都可以创建并安装一个恶意的更新版本，从而完全接管该应用或窃取其数据。这表明该应用要么是一个不应公开发布的调试版本，要么其完整性已受损，容易被仿冒或注入恶意代码。
- 证据：`Signature Certificate Subject: CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US
Certificate SHA256: 713ee5352714d43b1642c57aed8ddc815589a3c190b01a0c6f49f0c7c5c8cf8c`
- 建议：绝对不要安装和信任使用通用调试密钥签名的应用，除非来源完全可信且用于受控的测试环境。开发者应始终使用唯一的私钥为公开发布的应用签名，以确保应用的完整性和来源可追溯性。

### 6. 应用运行轨迹正常
- 规则：`DEEP_APK_BEHAVIOR_NORMAL_EXECUTION`
- 严重级别：`low`
- 说明：沙箱运行期间，应用成功完成安装、dexopt 优化及主 Activity 启动，未发现异常的进程注入或恶意代码执行。
- 证据：`Logcat 记录显示应用启动了 NewsActivity，且 dex2oat 过程正常完成，无异常崩溃或权限拦截。`
- 建议：无需进一步干预，该应用表现为正常功能应用。

### 7. 系统服务注册行为合规
- 规则：`DEEP_APK_BEHAVIOR_SYSTEM_SERVICE_REGISTRATION`
- 严重级别：`low`
- 说明：应用在系统服务列表中出现，但未表现出恶意接管或持久化攻击行为。
- 证据：`dynamic_summary 中显示的 accessibility 和 device_policy 记录属于系统对已安装应用的常规状态跟踪，未发现恶意配置。`
- 建议：无需采取特殊处置措施。

### 8. 网络行为未见异常
- 规则：`DEEP_APK_BEHAVIOR_NETWORK_ACTIVITY`
- 严重级别：`low`
- 说明：沙箱网络命中记录主要为系统级包管理与框架交互，未发现向未知域名发送敏感数据的行为。
- 证据：`网络命中列表包含 base.apk、base.dm 等系统文件处理记录，未见外部恶意 C2 连接。`
- 建议：应用网络行为处于安全范围。

### 9. 短时运行未见对外网络联通
- 规则：`DEEP_APK_INTEL_RUNTIME_NO_EXT_EGRESS`
- 严重级别：`low`
- 说明：沙箱运行约 12 秒内未解析到外部域名/IP 的访问，network_hits 仅包含安装/系统相关关键词，未体现真实对外通信。
- 证据：`dynamic_summary.network_hit_count=12；network_hits=["settings.get.glo","package.install","vmdl1585856488.tmp","base.dm","base.apk",…]；logcat 未见外部主机/域名。`
- 建议：延长运行时长并模拟真实用户路径（浏览列表/查看评论/登录），同时抓取 DNS/HTTP(S) 流量与证书链，确认是否存在外联与数据回传。

### 10. dumpsys 显示被列入无障碍（accessibility）持久服务清单
- 规则：`DEEP_APK_INTEL_ACCESSIBILITY_LISTING`
- 严重级别：`medium`
- 说明：动态持久服务清单包含 com.malmstein.yahnac，需确认是否实际注册/启用无障碍服务，防止权限滥用或环境噪声误报。
- 证据：`dynamic_summary.persistent_services.accessibility 包含 "[...][com.malmstein.yahnac][...]"`
- 建议：在沙箱与真实设备中检查 设置->无障碍 是否存在并已启用该应用服务；同时抓取无障碍绑定相关日志（AccessibilityManager）核实是否真的建立监听。若非预期，应审计安装来源与应用完整性。

### 11. dumpsys 显示 device_policy 列表出现目标包
- 规则：`DEEP_APK_INTEL_DEVICE_POLICY_ENTRY`
- 严重级别：`medium`
- 说明：设备策略清单中出现 “6: com.malmstein.yahnac”，需排查是否被激活为设备管理相关实体（可能为环境枚举或误报）。
- 证据：`dynamic_summary.persistent_services.device_policy=["6: com.malmstein.yahnac"]`
- 建议：在设备上执行 adb shell dpm get-active-admins 或检查 设置->安全->设备管理员，确认是否处于激活状态；若发现异常激活，立即撤销并复核应用来源。

### 12. Play 服务日志显示未被跟踪，疑似侧载
- 规则：`DEEP_APK_INTEL_PLAY_UNTRACKED_SIDELOAD`
- 严重级别：`medium`
- 说明：Google Play (Finsky) 日志多次提示未缓存/未跟踪该包，结合安装路径与签名，表明为非商店安装，需加强来源甄别。
- 证据：`logcat: "Finsky: skipping onPackageRemoved(replacing=true) for untracked package=com.malmstein.yahnac"；"ItemStore: Not cached: com.malmstein.yahnac"`
- 建议：用 SHA-256 向官方渠道或开发者发布页核验；优先从官方商店或开发者签名一致的发布页安装。对侧载样本应隔离、校验签名指纹与来源可信度后再投入使用。

### 13. 运行时加载 org.apache.http.legacy，表明使用旧版网络栈
- 规则：`DEEP_APK_INTEL_LEGACY_HTTP_LIB`
- 严重级别：`low`
- 说明：类加载器在启动时装载 org.apache.http.legacy.jar，暗示 target/依赖较老，可能使用过时 HTTP 客户端组件，安全加固需关注。
- 证据：`logcat: "Configuring classloader-namespace ... /system/framework/org.apache.http.legacy.jar ... target_sdk_version=23"`
- 建议：在动态抓包中重点验证其 TLS 配置（SNI/证书校验/明文降级）；若发现明文或弱加密连接，应在网络侧做阻断并评估数据风险。

### 14. 运行期仅授予网络/唤醒类权限，未见高危敏感权限
- 规则：`DEEP_APK_INTEL_GRANTED_PERMS_MINIMAL`
- 严重级别：`low`
- 说明：沙箱记录显示授予 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK，未显示读取联系人/短信/传感器等敏感权限的授权。
- 证据：`dynamic_summary.granted_dangerous_permissions=["ANDROID.PERMISSION.INTERNET","ANDROID.PERMISSION.ACCESS_NETWORK_STATE","ANDROID.PERMISSION.ACCESS_WIFI_STATE","ANDROID.PERMISSION.WAKE_LOCK"]`
- 建议：在更完整的交互场景下复测权限请求弹窗与权限使用轨迹；结合流量与日志确认是否存在越权或未声明权限的可疑行为。

### 15. 沙盒已成功安装并启动，说明样本具备真实执行能力
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`medium`
- 说明：动态沙盒中安装与启动均成功，且能够进入主活动，表明该 APK 不是静态死样本，具备可运行、可触发行为链的能力。
- 证据：`install_success=true; launch_success=true; resolve_activity=com.malmstein.yahnac/.stories.NewsActivity; START u0 ... cmp=com.malmstein.yahnac/.stories.NewsActivity`
- 建议：保留样本与运行日志留痕；继续在隔离沙箱复核联网目的地、启动后行为和持久化行为，不要直接投放生产环境。

### 16. 运行期出现网络命中，存在外联或在线资源拉取行为
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`medium`
- 说明：沙盒日志显示 12 次 network hits，说明应用启动后存在实际网络交互，需进一步确认访问域名、请求内容与业务合理性。
- 证据：`network_hit_count=12; network_hits includes settings.get.glo, package.install, base.apk, com.android.art, s.nexuslauncher`
- 建议：建议阻断分发前先做网络侧复核；如需继续分析，使用代理抓包或 MITM 在隔离环境中确认是否存在可疑外联、配置下发或遥测上报。

### 17. 存在持久化/系统驻留迹象，需重点复核权限与驻留方式
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`medium`
- 说明：动态摘要中出现 accessibility、device_policy、notification 等 persistent_services 记录，说明样本在设备上留下了可持续影响的系统痕迹或被系统枚举为常驻相关对象。
- 证据：`persistent_services.accessibility includes com.malmstein.yahnac; persistent_services.device_policy includes '6: com.malmstein.yahnac'; persistent_services.notification includes 'AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false'`
- 建议：对该样本执行持久在线性复核，重点检查是否通过前台服务、通知、设备管理或辅助功能形成驻留；在未澄清前建议阻断分发。

### 18. 签名使用 TESTKEY，发布可信度不足
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`high`
- 说明：动态样本对应的证书链显示 TESTKEY 相关签名痕迹，这通常不符合正式商店发布或可信供应链的常规做法，存在被篡改、重打包或测试包外泄风险。
- 证据：`signature_files: META-INF/TESTKEY.SF, META-INF/TESTKEY.RSA, META-INF/MANIFEST.MF; certificate_sha256=713ee5352714d43b1642c57aed8ddc815589a3c190b01a0c6f49f0c7c5c8cf8c`
- 建议：建议立即阻断外部分发并保留证据；对来源渠道、历史版本指纹和签名链进行二次核验，必要时按可疑安装包处置。

### 19. 应用行为与普通内容客户端相符，但仍需来源验证
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`low`
- 说明：动态启动指向 NewsActivity，结合权限仅为网络、唤醒和消息接收，整体更像资讯/内容客户端而非典型高危木马；但这只能降低行为恶意概率，不能替代来源可信度确认。
- 证据：`resolve_activity=com.malmstein.yahnac/.stories.NewsActivity; permissions include INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK, C2DM RECEIVE; no dangerous permission granted in sandbox`
- 建议：可暂列为低到中风险业务样本，但在签名与来源未确认前不得直接放行生产分发；建议保留样本留痕并做版本溯源。

### 20. 使用 AOSP 通用调试密钥（TESTKEY）签名
- 规则：`DEEP_APK_STATIC_DEBUG_SIGNATURE`
- 严重级别：`high`
- 说明：APK 由通用调试密钥签名，不符合正式发布规范，存在被重打包/仿冒风险，无法证明来源与完整性。
- 证据：`signature_files: META-INF/TESTKEY.SF, META-INF/TESTKEY.RSA; certificate_subject/issuer=Android (android@android.com); certificate_sha256=713ee5352714d43b1642c57aed8ddc815589a3c190b01a0c6f49f0c7c5c8cf8c`
- 建议：勿在生产设备上安装。用 SHA-256=b34ee7bdbd6c9b034f38c7f3a27969445d5ebf351b92214356f4db16576275fd 与官方发布指纹比对，改用开发者正式签名版本。

### 21. 权限与资讯客户端功能匹配
- 规则：`APK_MANIFEST_PERMISSIONS_PROFILE`
- 严重级别：`low`
- 说明：申请 INTERNET/网络状态/WIFI 状态/WAKE_LOCK 及 C2DM 接收权限，未见读取短信/通讯录/定位等高危敏感权限。
- 证据：`permissions=[INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK, com.google.android.c2dm.permission.RECEIVE, com.malmstein.yahnac.permission.C2D_MESSAGE]`
- 建议：在真实交互场景下复核权限使用路径与网络流量，防止越权调用。

### 22. 组件与 Firebase 集成符合场景
- 规则：`APK_COMPONENTS_FIT_FUNCTION`
- 严重级别：`low`
- 说明：Activity/Service/Receiver/Provider 声明与资讯/推送/崩溃上报场景一致，包含 Firebase Init/Crash/InstanceId 等。
- 证据：`activities=[...NewsActivity, StoryActivity...]; services=[FirebaseCrashSenderService, FirebaseInstanceIdService...]; receivers=[FirebaseInstanceIdReceiver...]; providers=[FirebaseInitProvider, com.malmstein.yahnac.data.HNewsProvider]`
- 建议：确认 Provider/Receiver 是否对外导出及权限保护，避免被其他应用滥用。

### 23. 代码级静态解析失败，证据覆盖不全
- 规则：`STATIC_CODE_ANALYSIS_FALLBACK`
- 严重级别：`medium`
- 说明：Androguard 解析回退，未获得方法调用/API 图，无法验证潜在可疑逻辑。
- 证据：`graph_data.fallback=true; api_graph_node_count=0; classes.dex 存在但未反编译成功`
- 建议：采用替代反编译链路（jadx/fernflower + smali）复核核心代码路径（网络、存储、动态加载）。

### 24. 资源与 UI 资产正常，未见可疑 IoC
- 规则：`RESOURCE_ANALYSIS_NO_IOC`
- 严重级别：`low`
- 说明：大量 Material/Design 与 Google 按钮/过渡/布局资源，符合常规客户端形态；未发现硬编码的可疑域名或指令资源。
- 证据：`res/* 包含 abc_/design_/common_google_signin_*、layout/notification_*、xml/global_tracker.xml 等常见资源；extracted_strings 多为无意义片段，未见域名/URL`
- 建议：继续在代码与运行期流量中搜寻真实外联域名与证书链。

### 25. 短时动态旁证未见对外主机通信
- 规则：`DEEP_APK_INTEL_RUNTIME_NO_EXT_EGRESS`
- 严重级别：`low`
- 说明：沙箱约 12 秒运行仅见系统安装/优化相关命中，未观测外部域名/IP 访问。
- 证据：`runtime_window_seconds=12; network_hits=[settings.get.glo, package.install, base.apk, org.apache.http.legacy.jar, ...]`
- 建议：延长运行并模拟登录/浏览/评论等用户路径，抓取 DNS/HTTP(S) 流量以排除延时触发行为。

### 26. 系统清单枚举出现 accessibility/device_policy 条目（需复核）
- 规则：`ENV_ENUM_ACCESSIBILITY_DEVICE_POLICY_LISTING`
- 严重级别：`medium`
- 说明：持久化服务清单中出现目标包名，当前证据不足以证明已启用相关能力，更可能是系统枚举或环境噪声。
- 证据：`persistent_services.accessibility 含 com.malmstein.yahnac；device_policy=["6: com.malmstein.yahnac"]`
- 建议：在设备上核查是否被激活为无障碍/设备管理员；若异常启用，立即撤销并追溯安装来源。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5`）
综合静态证据链与短时动态旁证，本样本更像一款 Hacker News 客户端的开发/侧载构建：Manifest 中的权限（INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK 及 C2DM 广播接收）与其资讯读取、推送和崩溃分析场景相符；组件声明包含常见的 Activity（NewsActivity/StoryActivity 等）、Firebase 相关 Service/Receiver 以及自有 Provider（com.malmstein.yahnac.data.HNewsProvider），资源文件以 Material/Design 与 Google Sign-In 相关为主，未见典型恶意 IoC。关键异常在于签名：APK 携带 META-INF/TESTKEY.SF/RSA，证书主题为 Android(android@android.com)，SHA256=713ee535…，明确指向 AOSP 通用调试密钥（TESTKEY）。这不符合正式发布习惯，意味着来源与完整性不可验证，存在被重打包/仿冒的供应链风险。代码级静态解析失败（fallback），无法验证更深层逻辑；动态沙箱仅短时启动（约 12 秒）未见异常外联或越权行为，accessibility/device_policy 列表出现目标包更像系统枚举或环境噪声，不能据此定性。基于上述，当前未发现确证恶意负载，但由于签名与分发可信度问题，将整体定级为中等风险：建议仅在隔离环境验证并以官方签名版本替换，必要时以哈希与签名指纹对照官方渠道复核。说明：由于静态代码解析失败，结论主要基于离线静态证据（Manifest/签名/资源）并辅以短时动态旁证，仍需进一步取证与来源核验。

### 静态分析员（模型：`gemini-2.5-pro`）
从静态分析角度看，此应用（com.malmstein.yahnac）的权限和组件声明与其作为新闻阅读器（Hacker News 客户端）的功能基本相符，集成了常见的 Google 和 Firebase 服务用于消息推送和崩溃分析。然而，最关键的静态证据是该应用使用了通用的 Android 调试密钥进行签名，这是一个严重的安全漏洞，表明该应用可能是一个不应公开发布的调试版本，或其完整性无法保证，存在被恶意代码替换的风险。代码层面因解析失败未能深入，但现有静态证据中，除签名问题外，未发现其他明确的恶意特征。

### 行为分析员（模型：`gemini-2.5-flash`）
基于动态沙箱运行行为分析，该 APK (com.malmstein.yahnac) 表现为正常的应用启动行为。沙箱日志显示应用成功安装并启动了主 Activity (com.malmstein.yahnac.stories.NewsActivity)，未发现异常的后台驻留、敏感权限滥用或恶意网络连接。虽然在 `persistent_services` 中检测到应用出现在辅助功能列表和设备策略管理中，但结合上下文日志分析，这属于 Android 系统对已安装应用的常规记录，并未触发任何恶意行为逻辑。整体运行轨迹符合正常应用特征。

### 情报分析员（模型：`gpt-5`）
目标为临时文件名 tmpg4qbwzgh.apk，包名 com.malmstein.yahnac（看似个人域名命名的应用）。签名侧本地证据显示使用 AOSP TESTKEY（META-INF/TESTKEY.*；证书主题 android@android.com，指纹 713ee535…），更接近开发/侧载构建而非官方商店发布版。动态沙箱在短窗口（~12 秒）内安装和启动均成功，未观察到对外主机的实际联通与可疑行为。但需明确当前离线分析边界：仅一次快速启动、无用户深度交互、网络环境有限，未触发登录/推送/数据拉取等路径，无法代表完整行为。结合来源与分发渠道判断时，应：1）用 SHA-256（b34ee7bd…75fd）在可信情报源/官方发布页比对；2）核对签名是否与官方渠道一致（官方通常不会用 TESTKEY）；3）确认获取渠道（官方商店/开发者 GitHub Release/可信镜像）与分发指纹一致。若为第三方站点或即时通讯侧载包，供应链风险上升，应从设备上移除并改用可信来源重装后再评估。

### 处置建议员（模型：`gpt-5.4-mini`）
建议阻断对外分发并保留样本留痕；当前样本虽未见明确恶意载荷特征，但签名为 TESTKEY 且沙盒已确认安装/启动后产生持续网络访问与持久化相关痕迹，来源可信度不足。若必须在业务环境内继续验证，仅允许在隔离沙箱或受控测试机中复核，不建议直接隔离安装到生产终端。


### 主持人最终总结
综合静态证据链与短时动态旁证，本样本更像一款 Hacker News 客户端的开发/侧载构建：Manifest 中的权限（INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK 及 C2DM 广播接收）与其资讯读取、推送和崩溃分析场景相符；组件声明包含常见的 Activity（NewsActivity/StoryActivity 等）、Firebase 相关 Service/Receiver 以及自有 Provider（com.malmstein.yahnac.data.HNewsProvider），资源文件以 Material/Design 与 Google Sign-In 相关为主，未见典型恶意 IoC。关键异常在于签名：APK 携带 META-INF/TESTKEY.SF/RSA，证书主题为 Android(android@android.com)，SHA256=713ee535…，明确指向 AOSP 通用调试密钥（TESTKEY）。这不符合正式发布习惯，意味着来源与完整性不可验证，存在被重打包/仿冒的供应链风险。代码级静态解析失败（fallback），无法验证更深层逻辑；动态沙箱仅短时启动（约 12 秒）未见异常外联或越权行为，accessibility/device_policy 列表出现目标包更像系统枚举或环境噪声，不能据此定性。基于上述，当前未发现确证恶意负载，但由于签名与分发可信度问题，将整体定级为中等风险：建议仅在隔离环境验证并以官方签名版本替换，必要时以哈希与签名指纹对照官方渠道复核。说明：由于静态代码解析失败，结论主要基于离线静态证据（Manifest/签名/资源）并辅以短时动态旁证，仍需进一步取证与来源核验。


## 七、仲裁结果
- 一致性分数：`71`
- 一致性等级：`medium`
- 加权置信度：`26`
- 疑似污染源：static, behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 43 分
  - static-intelligence 差异 38 分
  - behavior-intelligence 差异 5 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
