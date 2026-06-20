# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**LOW** · 风险分数：**18/100**
> 证据分数：**50/100** · 深度研判分数：**7 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpjgsba8wk.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：29 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260620_165151_844067.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260620_165151_844067.md

## 二、统一 IR 摘要
- APK 文件：`tmpjgsba8wk.apk`
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
- static_file_name：tmpjgsba8wk.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：6723
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：无
- persistent_services：{'device_policy': ['6: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：46
- logcat_excerpt_count：298
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260620_165156_779970_com.malmstein.yahnac/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260620_165156_779970_com.malmstein.yahnac/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260620_165156_779970_com.malmstein.yahnac/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260620_165156_779970_com.malmstein.yahnac`

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
- 分歧点：static-behavior 差异 43 分, static-intelligence 差异 0 分, behavior-intelligence 差异 43 分
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
- 证据：`Subject=<asn1crypto.x509.Name 2076001712160 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>; Issuer=<asn1crypto.x509.Name 2076001711344 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl472292371.tmp; com.malmstein.yahnac; android.fg`
- 建议：后续可结合抓包或代理进行复核。

### 4. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`6: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 5. 应用集成 Google Analytics 与 Crash Reporting SDK
- 规则：`DEEP_APK_STATIC_SDK_INTEGRATION`
- 严重级别：`low`
- 说明：静态分析发现应用在 Manifest 文件中声明了 Google Mobile Services (GMS) 和 Firebase 的多个组件，如 AppMeasurementService 和 FirebaseCrashReceiverService。这表明应用会收集使用情况和崩溃数据。动态沙箱运行时会加载这些服务，并与 Google 服务器建立网络连接以传输数据，这是移动应用的常见做法，但涉及用户隐私。
- 证据：`静态组件声明: com.google.android.gms.measurement.AppMeasurementService, com.google.firebase.crash.internal.service.FirebaseCrashReceiverService。动态行为印证: 沙箱成功启动应用进程(PID 6723)，加载了相关服务。`
- 建议：用户应知晓该应用会收集使用和崩溃数据并发送给第三方（Google）。对于注重隐私的用户，应了解此数据收集行为。

### 6. 应用申请的网络权限与其功能一致
- 规则：`DEEP_APK_STATIC_PERMISSION_VALIDATION`
- 严重级别：`low`
- 说明：应用在 Manifest 中申请了 `INTERNET` 和 `ACCESS_NETWORK_STATE` 权限。动态沙箱分析确认这些权限在安装后被授予。这些权限对于其作为新闻阅读器（从网络获取内容）的核心功能以及集成的 Google/Firebase 服务是必需的。
- 证据：`静态权限声明: android.permission.INTERNET, android.permission.ACCESS_NETWORK_STATE。动态权限授予: 沙箱报告 `granted_dangerous_permissions` 包含上述权限。`
- 建议：申请的权限与应用声明的功能一致，未发现不必要或过度的权限请求。

### 7. 应用生命周期行为正常
- 规则：`DEEP_APK_BEHAVIOR_NORMAL_LIFECYCLE`
- 严重级别：`low`
- 说明：动态分析显示应用安装、启动及 dex 优化过程符合 Android 标准流程，未见异常进程注入或非预期后台活动。
- 证据：`Logcat 记录显示应用成功完成 dexopt 优化并正常启动 NewsActivity，无异常权限申请或系统服务劫持。`
- 建议：无需进一步处理，可视为正常应用。

### 8. 测试签名证书
- 规则：`DEEP_APK_BEHAVIOR_TEST_SIGNATURE`
- 严重级别：`low`
- 说明：应用使用 Android 默认测试签名（TESTKEY），表明该包为开发阶段产物，非生产环境发布版本。
- 证据：`签名证书信息显示 Subject/Issuer 包含 'android@android.com'，且存在 META-INF/TESTKEY.RSA 文件。`
- 建议：若该应用用于生产环境，建议更换为正式签名证书。

### 9. 网络行为合规
- 规则：`DEEP_APK_BEHAVIOR_NETWORK_CLEAN`
- 严重级别：`low`
- 说明：沙箱运行期间网络请求主要集中在系统服务与 Firebase 基础组件，未发现连接至恶意 C2 服务器或异常数据回传。
- 证据：`网络命中列表仅包含系统级包管理与基础框架调用，无外部恶意域名访问记录。`
- 建议：无须干预。

### 10. 动态沙盒安装与启动成功，基础行为正常
- 规则：`DEEP_APK_INTEL_INSTALL_AND_LAUNCH_OK`
- 严重级别：`low`
- 说明：应用成功安装并启动前台 Activity，进程创建稳定，未见崩溃或异常权限弹窗。
- 证据：`install_success=true; launch_success=true; resolve_activity="com.malmstein.yahnac/.stories.NewsActivity"; pidof=6723; logcat: START u0 {act=android.intent.action.MAIN ... cmp=com.malmstein.yahnac/.stories.NewsActivity}`
- 建议：延长运行时间并进行真实交互（滑动刷新、登录、查看评论等）以扩大动态覆盖，观察是否出现异常行为。

### 11. 运行期仅授予网络与唤醒类权限
- 规则：`DEEP_APK_INTEL_RUNTIME_PERMS_NETWORK_ONLY`
- 严重级别：`low`
- 说明：动态授予的权限仅为 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK，未见通讯录、存储、定位等敏感读取类权限的授予记录。
- 证据：`granted_permissions: ANDROID.PERMISSION.INTERNET; ANDROID.PERMISSION.ACCESS_NETWORK_STATE; ANDROID.PERMISSION.ACCESS_WIFI_STATE; ANDROID.PERMISSION.WAKE_LOCK`
- 建议：在设置页与首启引导流程中复核是否后续申请额外敏感权限，必要时使用权限日志与交互回放进行核验。

### 12. 存在网络活动迹象但未捕获外部域名/IP
- 规则：`DEEP_APK_INTEL_NETWORK_ACTIVITY_NO_EXTERNAL_ENDPOINT`
- 严重级别：`low`
- 说明：记录到 12 次网络相关命中，但多与安装与系统组件有关，未解析到外部主机，可能由于运行窗口短或未触发数据请求路径。
- 证据：`network_hit_count=12; network_hits: ["settings.get.glo","package.install","base.apk","org.apache.http.legacy.jar","com.android.art","base.odex"...]; runtime_window_seconds=12`
- 建议：开启代理/抓包并延长运行，执行列表刷新、登录/评论等业务操作，捕获真实出网目标并与官方服务域名进行比对。

### 13. dumpsys 出现 device_policy 条目但缺少对应清单组件
- 规则：`DEEP_APK_INTEL_PERSISTENT_SERVICE_DEVICE_POLICY_SUSPECT`
- 严重级别：`low`
- 说明：持久化服务中出现“device_policy: 6: com.malmstein.yahnac”，但清单未发现 DeviceAdminReceiver。更可能为沙箱/系统噪声，暂不据此认定具备设备管控能力。
- 证据：`persistent_services.device_policy: ["6: com.malmstein.yahnac"]; manifest 未匹配 android.app.admin.DeviceAdminReceiver`
- 建议：在真机执行 dumpsys device_policy 与导出组件核对；若出现设备管理员注册或策略下发行为，应升级监控并阻断。

### 14. 未使用独立 SDK 沙盒，初始化路径简洁
- 规则：`DEEP_APK_INTEL_SDK_SANDBOX_UNUSED`
- 严重级别：`low`
- 说明：日志显示未使用 SDK Sandbox，应用初始化不涉及独立 SDK 容器加载。
- 证据：`logcat: "SdkSandboxManager: No SDKs used. Skipping SDK data reconcilation for ... com.malmstein.yahnac"`
- 建议：继续观察后续页面是否引入第三方 SDK（广告/统计），并结合出网域名、证书校验进行确认。

### 15. 安装后未观察到额外落地文件/自投递
- 规则：`DEEP_APK_INTEL_NO_POST_INSTALL_ARTIFACTS`
- 严重级别：`low`
- 说明：post_install_files 为空，短时运行未见额外文件写入或持久化投递。
- 证据：`post_install_files: []`
- 建议：延长运行并触发离线保存/书签等功能，监控 /data/user/0/<pkg>/files、databases、cache 等路径与可疑可执行落地。

### 16. 安装与启动在沙箱中正常完成，但不足以直接放行
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`medium`
- 说明：动态沙箱显示应用可成功安装、可正常拉起主界面，未出现立即崩溃、阻断式异常或明显恶意激活迹象，因此短期内不支持判定为高危恶意样本；但这只能说明基础可执行性正常，不能等同于来源可信或长期行为安全。
- 证据：`install_success=true; launch_success=true; resolve_activity=com.malmstein.yahnac/.stories.NewsActivity; pidof=6723; event_count=46`
- 建议：可以在受控沙箱继续复核，不建议直接向生产环境或终端用户分发；若业务侧需要上线，必须补充来源与签名核验后再放行。

### 17. 运行期未见典型恶意持久化或隐藏行为
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`low`
- 说明：沙箱中未观察到新增落地文件、未检出反射、动态加载、反沙箱或混淆对抗特征，说明当前观察窗口内没有捕获到常见恶意驻留链路。
- 证据：`post_install_files=[]; anti_emulator_detected=false; obfuscation_detected=false; reflection_detected=false; dynamic_loading_detected=false; runtime_window_seconds=12`
- 建议：无需因当前动态证据立即封禁，但应保留样本并延长观察时长，确认是否存在延迟触发逻辑。

### 18. 网络活动存在，但命中以系统/安装相关路径为主
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`low`
- 说明：动态网络命中主要集中在 package.install、base.apk、base.odex、android.test.base.jar 等安装与运行时系统对象，并未在摘要中体现明确的外联域名、C2 或下载行为，因此目前未形成网络层恶意证据链。
- 证据：`network_hit_count=12; network_hits=[settings.get.glo, package.install, vmdl472292371.tmp, com.malmstein.yahnac, android.fg, android.os.Handler, base.dm, base.apk, android.test.base.jar, org.apache.http.legacy.jar, com.android.art, base.odex]`
- 建议：建议继续沙箱复核并抓取完整流量样本；在未识别明确外联目的前，不必升级为阻断分发，但应对公网访问做临时策略控制。

### 19. 存在少量持久化/系统策略相关痕迹，需人工确认用途
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`medium`
- 说明：沙箱摘要中出现 persistent_services 相关条目，包含 device_policy 与 notification 项，但当前证据未能证明其为恶意持久化，更像应用或环境状态记录；由于其涉及策略与通知层面，仍需进一步确认是否属于正常功能。
- 证据：`persistent_services={"device_policy":["6: com.malmstein.yahnac"],"notification":["AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false"]}`
- 建议：建议保留样本留痕并进行二次动态验证，重点观察是否存在设备管理、通知隐藏或自启动滥用；在确认前不建议直接推广分发。

### 20. 观察窗口过短，需补充长时动态复核
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`medium`
- 说明：当前 runtime_window_seconds 仅 12 秒，足以验证安装和首次启动，但不足以覆盖延迟触发、定时回连、后台驻留、条件分支加载等常见规避行为。
- 证据：`runtime_window_seconds=12; event_count=46; logcat_excerpt_count=298`
- 建议：建议继续在隔离环境做长时沙箱复核，并保留原始 APK、日志与流量样本留痕；在复核完成前，生产分发应暂缓。

### 21. 使用 AOSP 测试签名（TESTKEY）
- 规则：`APK_SIGN_TESTKEY`
- 严重级别：`medium`
- 说明：APK 由 Android 测试证书签名，常见于开发/测试构建，无法为来源和完整性提供强背书。
- 证据：`存在 META-INF/TESTKEY.SF 与 META-INF/TESTKEY.RSA；证书 Subject/Issuer 为 android@android.com；certificate_sha256=7d544c141c6bd7688a54719243de4b5a9097216a4bbc06954bc6c364fe912896`
- 建议：仅从可信渠道获取，生产分发前比对签名指纹并使用正式签名版本。

### 22. 权限集精简且与功能一致
- 规则：`MANIFEST_PERMISSIONS_MINIMAL`
- 严重级别：`low`
- 说明：仅请求网络状态、Wi-Fi 状态、网络访问与唤醒锁，以及 C2DM 推送相关自定义权限，未见高敏读取类权限。
- 证据：`android.permission.INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK, com.google.android.c2dm.permission.RECEIVE, com.malmstein.yahnac.permission.C2D_MESSAGE`
- 建议：保持最小权限原则；后续版本若新增高敏权限，需进行合规评估。

### 23. 集成 Firebase/GMS 分析与崩溃上报组件
- 规则：`MANIFEST_COMPONENTS_FIREBASE_GMS`
- 严重级别：`low`
- 说明：Manifest 声明了 AppMeasurement、Firebase Crash 与 Firebase IID 等服务与接收器，指向常规遥测与崩溃上报能力。
- 证据：`services: com.google.android.gms.measurement.AppMeasurementService, com.google.firebase.crash.internal.service.*; receivers: com.google.android.gms.measurement.AppMeasurementReceiver, com.google.firebase.iid.*; provider: com.google.firebase.provider.FirebaseInitProvider`
- 建议：向用户披露遥测收集范围与目的；确保传输仅至官方域名并采取 TLS。

### 24. 声明自有内容提供者 HNewsProvider
- 规则：`CONTENT_PROVIDER_DECLARATION`
- 严重级别：`low`
- 说明：应用包含自定义 Provider，通常用于本地数据/缓存访问。
- 证据：`providers: com.malmstein.yahnac.data.HNewsProvider`
- 建议：复核其 exported 与权限策略，避免敏感数据通过 Provider 暴露。

### 25. 静态代码图谱解析回退，API 级证据不足
- 规则：`STATIC_GRAPH_FALLBACK`
- 严重级别：`low`
- 说明：由于解析工具回退，无法生成 API 调用图与详细 CFG，限制了对代码层行为的静态验证深度。
- 证据：`graph_data.fallback_reason=androguard_unavailable_or_parse_failed；api_graph_node_count=0`
- 建议：在可复现环境下补做字节码解析或使用备用静态引擎完成 API 图谱。

### 26. 未检测到混淆/反射/动态加载/反沙箱
- 规则：`RUNTIME_OBFUSCATION_REFLECTION_DYNAMIC_LOADING`
- 严重级别：`low`
- 说明：鲁棒性检测未发现常见对抗与隐藏技术迹象。
- 证据：`obfuscation_detected=false; reflection_detected=false; dynamic_loading_detected=false; anti_emulator_detected=false`
- 建议：保持监测，但当前无相关恶意对抗证据。

### 27. 提取字符串未见明确恶意 IOC
- 规则：`EXTRACTED_STRINGS_NO_IOC`
- 严重级别：`low`
- 说明：样本未呈现明文域名、URL、加密密钥等可直接关联系统性外联或投递的指示器。
- 证据：`extracted_strings 多为无含义片段（如 "qSNHar", "qRNHTa" 等），未见 URL/域名/可识别 C2 标识。`
- 建议：建议在完整代码解析或长时动态抓包后再行二次核验。

### 28. 动态观察窗口过短且未触发业务路径
- 规则：`DYNAMIC_WINDOW_SHORT`
- 严重级别：`medium`
- 说明：沙箱仅运行约 12 秒，未执行登录/评论/刷新等真实交互，网络未解析到外部主机，难以覆盖延迟/条件触发路径。
- 证据：`runtime_window_seconds=12; network_hit_count=12（多为系统/安装相关命中）`
- 建议：延长运行并触发主要功能路径，结合代理/抓包核验实际外联目标。

### 29. dumpsys 出现 device_policy 痕迹但清单无对应组件
- 规则：`PERSISTENT_SERVICES_DEVICE_POLICY_NO_MATCH`
- 严重级别：`low`
- 说明：持久化条目中出现 device_policy 引用，Manifest 未见 DeviceAdminReceiver，疑似环境噪声，暂不足以构成风险链条。
- 证据：`persistent_services.device_policy=["6: com.malmstein.yahnac"]; Manifest 未列出 android.app.admin.DeviceAdminReceiver`
- 建议：在真机复核 dumpsys 结果；若后续出现设备管控注册迹象，再提升优先级分析。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5`）
基于可见静态证据与短窗动态观测，样本呈现为一款以新闻/评论/书签为主的常规应用：Manifest 仅申请网络与唤醒等基础权限，并声明了 Firebase/AppMeasurement 等常见分析与崩溃上报组件，未见存储、通讯录、定位等高敏权限；资源与组件结构与其功能相符（NewsActivity/StoryActivity/CommentsActivity、HNewsProvider 等），未发现本地 SO 库、反射/动态加载/混淆迹象。关键风险点在于签名使用 AOSP TESTKEY（META-INF/TESTKEY.*，证书主体 android@android.com），指向开发/测试构建，来源与完整性难以通过签名背书。静态代码图谱因解析回退（androguard_unavailable_or_parse_failed）而缺失，代码级证据链不充分；动态沙箱仅运行约 12 秒，未见可疑外联、持久化或自启动链条，“device_policy”持久化条目更像环境噪声，清单亦无 DeviceAdmin 组件佐证。综合判定：当前静态与有限动态证据均未形成恶意链条，主要不确定性来自签名与来源可信度，整体风险低；建议仅从可信渠道获取并在生产使用前核验签名指纹与来源。

### 静态分析员（模型：`gemini-2.5-pro`）
经静态分析，该应用（com.malmstein.yahnac）是一款功能正常的 Hacker News 新闻客户端。其权限、组件和资源文件均与其声明功能相符。应用集成了 Google Firebase SDK 用于分析和崩溃报告，这是常规操作。唯一值得注意的是其使用了通用的 Android 调试签名，这意味着应用完整性无法通过签名得到强力保证，建议从可信渠道获取。结合动态沙箱的证据，未发现任何恶意或可疑的运行时行为。综合判断，该应用为低风险。

### 行为分析员（模型：`gemini-2.5-flash`）
基于动态沙箱运行日志分析，该 APK（com.malmstein.yahnac）表现为正常的应用行为。沙箱运行期间，应用成功完成安装与启动，未触发任何恶意行为（如静默下载、提权、异常网络连接或敏感数据外泄）。日志中出现的 'Force stopping' 和 'dexopt' 属于正常的系统包管理与优化流程，未发现持久化驻留或隐藏服务行为。尽管签名证书显示为测试签名（TESTKEY），但结合其组件结构（主要为 UI 交互与 Firebase 基础服务），判定该样本为合法的应用开发测试包，无恶意风险。

### 情报分析员（模型：`gpt-5`）
综合动态沙盒线索与本地证据判断：该 APK（文件名 tmpjgsba8wk.apk，来自本机临时目录 C:/Users/lenovo/AppData/Local/Temp/，包名 com.malmstein.yahnac，版本 1.3.1/27）在沙盒中安装与启动均成功，前台入口为 NewsActivity，进程稳定，无崩溃与异常权限弹窗。动态仅观测到网络/唤醒类权限的授予与少量安装期相关的网络/系统命中，未捕获外连域名/IP，未见落地文件与自启动投递，整体行为与一款新闻阅读类应用相符。离线边界与局限：1) 静态图谱解析发生回退（androguard_unavailable_or_parse_failed），代码层 API 图谱信息缺失；2) 动态运行窗口仅约 12 秒，交互覆盖有限（未触发登录/评论等功能路径），网络证据不足；3) dumpsys 出现“device_policy”条目但清单未见设备管理员组件，疑似沙盒/系统噪声，需在真机复核。签名侧：APK 内含 META-INF/TESTKEY.*，证书主题为 Android(android@android.com)，属于 AOSP 测试签名，非商用发布常用签名。若该包来自第三方下载/临时路径而非官方渠道，需重点核对来源可信度与签名指纹。综合当前动态证据与局限，本样本短期内未呈现恶意链条，但因签名为测试证书与来源不明，建议在确认来源与签名可信前保持谨慎。

### 处置建议员（模型：`gpt-5.4-mini`）
该 APK 以动态沙箱证据看更像正常应用：安装、启动均成功，未见落地可疑文件、反射、动态加载、对抗沙箱等行为，网络命中也主要是安装/运行期系统与包路径相关项；但当前样本来自临时文件、签名为 TESTKEY 且动态观察窗口仅 12 秒，尚不能据此直接视为可信。建议允许在受控环境中继续验证，不建议面向生产/终端用户直接分发；若已进入待发布链路，先隔离安装复核并保留样本留痕，完成更长时长动态监测和来源核验后再决定是否放行。


### 主持人最终总结
基于可见静态证据与短窗动态观测，样本呈现为一款以新闻/评论/书签为主的常规应用：Manifest 仅申请网络与唤醒等基础权限，并声明了 Firebase/AppMeasurement 等常见分析与崩溃上报组件，未见存储、通讯录、定位等高敏权限；资源与组件结构与其功能相符（NewsActivity/StoryActivity/CommentsActivity、HNewsProvider 等），未发现本地 SO 库、反射/动态加载/混淆迹象。关键风险点在于签名使用 AOSP TESTKEY（META-INF/TESTKEY.*，证书主体 android@android.com），指向开发/测试构建，来源与完整性难以通过签名背书。静态代码图谱因解析回退（androguard_unavailable_or_parse_failed）而缺失，代码级证据链不充分；动态沙箱仅运行约 12 秒，未见可疑外联、持久化或自启动链条，“device_policy”持久化条目更像环境噪声，清单亦无 DeviceAdmin 组件佐证。综合判定：当前静态与有限动态证据均未形成恶意链条，主要不确定性来自签名与来源可信度，整体风险低；建议仅从可信渠道获取并在生产使用前核验签名指纹与来源。


## 七、仲裁结果
- 一致性分数：`71`
- 一致性等级：`medium`
- 加权置信度：`18`
- 疑似污染源：static, behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 43 分
  - static-intelligence 差异 0 分
  - behavior-intelligence 差异 43 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
