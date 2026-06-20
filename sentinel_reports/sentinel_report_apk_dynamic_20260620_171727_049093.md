# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**LOW** · 风险分数：**27/100**
> 证据分数：**50/100** · 深度研判分数：**30 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmp3iwx92fa.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：26 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260620_171515_062023.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260620_171515_062023.md

## 二、统一 IR 摘要
- APK 文件：`tmp3iwx92fa.apk`
- 包名：`-`
- 版本名：`-`
- 版本号：`-`
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

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要
- device_id：emulator-5554
- package_name：com.malmstein.yahnac
- static_file_name：tmp3iwx92fa.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：8026
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：无
- persistent_services：{'accessibility': ['[com.google.android.googlequicksearchbox][com.malmstein.yahnac][com.google.android.youtube][com.google.android.as][com.google.android.inputmethod.latin][com.google.android.apps.wellbeing][com.google.android.apps.nexuslauncher][com.google.android.calendar]}]'], 'device_policy': ['6: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：56
- logcat_excerpt_count：569
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260620_171518_366830_com.malmstein.yahnac/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260620_171518_366830_com.malmstein.yahnac/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260620_171518_366830_com.malmstein.yahnac/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260620_171518_366830_com.malmstein.yahnac`

## 四点二、图结构分析
- 图结构状态：`图结构缺失`；原因：未检测到图结构数据，可能是 APK 解析失败、androguard 不可用或未能提取 DEX 图。
### CFG / FCG / API 调用图
- CFG 节点数：`0`
- CFG 边数：`0`
- FCG 节点数：`0`
- FCG 边数：`0`
- FCG 密度：`-`
- API 调用图节点数：`0`
- API 调用图边数：`0`
- API 总调用数：`0`
- 敏感 API 调用分布：无

## 四点三、一致性验证
- 一致性分数：`80`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 30 分, static-intelligence 差异 10 分, behavior-intelligence 差异 20 分
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
- 证据：`manifest: AndroidManifest.xml; resource: res/anim-v21/design_bottom_sheet_slide_in.xml; resource: res/anim-v21/design_bottom_sheet_slide_out.xml; resource: res/anim/abc_fade_in.xml; resource: res/anim/abc_fade_out.xml; resource: res/anim/abc_grow_fade_in_from_bottom.xml; resource: res/anim/abc_popup_enter.xml; resource: res/anim/abc_popup_exit.xml; resource: res/anim/abc_shrink_fade_out_from_bottom.xml; resource: res/anim/abc_slide_in_bottom.xml; resource: res/anim/abc_slide_in_top.xml; resource: res/anim/abc_slide_out_bottom.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 未解析到包名
- 规则：`APK_MISSING_PACKAGE`
- 严重级别：`medium`
- 说明：APK 中未能提取出明确的包名，样本身份不够清晰。
- 证据：`tmp3iwx92fa.apk`
- 建议：补充样本来源与签名信息后再复核。

### 3. 存在可疑字符串线索
- 规则：`APK_SUSPICIOUS_STRINGS`
- 严重级别：`medium`
- 说明：样本中出现命令执行、远程地址或系统调用相关字符串。
- 证据：`http://schemas.android.com/apk/res/android; http://schemas.android.com/apk/res-auto; android.support.design.widget.AppBarLayout; android.support.v7.widget.Toolbar; --android.support.design.widget.TextInputLayout; android.support.v7.widget.AppCompatEditText; 55android.support.design.widget.Snackbar; android.support.v7.widget.ButtonBarLayout`
- 建议：结合反编译结果确认这些字符串是否参与实际行为。

### 4. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; vmdl1348303287.tmp; com.malmstein.yahnac; com.google.android.gms.measurement.START`
- 建议：后续可结合抓包或代理进行复核。

### 5. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.googlequicksearchbox][com.malmstein.yahnac][com.google.android.youtube][com.google.android.as][com.google.android.inputmethod.latin][com.google.android.apps.wellbeing][com.google.android.apps.nexuslauncher][com.google.android.calendar]}]; 6: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 6. 动态解析到应用身份与入口组件
- 规则：`DEEP_APK_INTEL_RUNTIME_IDENTITY`
- 严重级别：`low`
- 说明：沙盒期正确解析到包名和可启动 Activity，修正了静态层未解析到包名的问题，样本在前台正常拉起。
- 证据：`dynamic_summary.package_name = com.malmstein.yahnac; resolve_activity = com.malmstein.yahnac/.stories.NewsActivity; logcat: START u0 {act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] ... cmp=com.malmstein.yahnac/.stories.NewsActivity}`
- 建议：以 com.malmstein.yahnac 为索引在官方应用商店/可信仓库检索，核对开发者信息与应用描述；据此比对签名证书指纹与官方指纹，确认是否为原版而非二次打包。

### 7. ADB 侧载与非商店管控迹象
- 规则：`DEEP_APK_INTEL_INSTALL_SOURCE_OFFSTORE`
- 严重级别：`medium`
- 说明：安装过程与系统商店服务日志显示该包不受商店管控（未缓存、查询失败），结合 vmdl*.tmp 与 package.install 迹象，指向本地侧载来源而非官方分发渠道。
- 证据：`logcat: Integrity check passed for file:///data/app/vmdl1348303287.tmp; abb StartCommandInProcess ... package.install; Finsky: ItemStore: Not cached: com.malmstein.yahnac; Finsky: getItems RPC failed for item com.malmstein.yahnac`
- 建议：在生产/企业环境中将侧载来源视为中等风险：需验证样本 SHA256 与官方发布一致；比对签名证书指纹；限制仅允许来自官方商店/MDM 白名单的安装。若无法确认来源可靠，建议暂缓上线并加强网络与主机侧监控。

### 8. 运行期仅授予网络与唤醒相关权限
- 规则：`DEEP_APK_INTEL_RUNTIME_PERMS_NET`
- 严重级别：`low`
- 说明：沙盒内观测到授予 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK 等常见网络与保活类权限，未见高危敏感权限动态授权。
- 证据：`granted_permissions: ANDROID.PERMISSION.INTERNET; ANDROID.PERMISSION.ACCESS_NETWORK_STATE; ANDROID.PERMISSION.ACCESS_WIFI_STATE; ANDROID.PERMISSION.WAKE_LOCK`
- 建议：从权限面看风险较低，但仍应对网络访问进行出站监控与域名白名单控制；延长运行时间与交互脚本，观察是否出现新增敏感权限请求或动态行为变化。

### 9. 绑定 Google 测量/分析服务迹象
- 规则：`DEEP_APK_INTEL_GMS_MEASUREMENT_BIND`
- 严重级别：`low`
- 说明：运行日志显示与 com.google.android.gms.measurement.START 交互，属于常见统计/测量组件绑定，可能产生遥测数据上报。
- 证据：`logcat: onUnbind: Intent { act=com.google.android.gms.measurement.START pkg=com.google.android.gms }`
- 建议：评估隐私与合规影响；在企业环境可通过工作配置关闭统计或限制出站至相关测量域；对流量做目的域可视化与基线建模。

### 10. dumpsys 显示与无障碍/设备策略/通知相关条目
- 规则：`DEEP_APK_INTEL_PERSISTENT_SERVICE_ENUM_FLAGS`
- 严重级别：`medium`
- 说明：dumpsys 枚举中出现 accessibility 与 device_policy 字段包含该包名，但未见管理员激活或权限授予流程日志，可能为系统枚举或占位信息，尚不足以证明已启用对应能力。
- 证据：`persistent_services: {"accessibility": "[...][com.malmstein.yahnac][...]", "device_policy": ["6: com.malmstein.yahnac"], "notification": ["... importance=NONE ..."]}`
- 建议：手工复核 manifest 是否声明 AccessibilityService 或 DeviceAdminReceiver；执行 adb shell dumpsys device_policy 逐项核对 active admins；延长交互观察是否出现设备管理员激活对话框或策略下发。若确认存在且非预期，应提升处置优先级。

### 11. 安装更新过程中的可见性异常（可能与进程重启相关）
- 规则：`DEEP_APK_INTEL_ACTIVITY_LIFECYCLE_EXCEPTION`
- 严重级别：`low`
- 说明：WindowManager 报告 DeadObjectException，多见于安装/更新导致的进程被杀后可见性回调异常，未见与持久化恶意行为直接相关迹象。
- 证据：`logcat: WindowManager ... android.os.DeadObjectException at BinderProxy.transactNative ... Force removing ActivityRecord ... app died, no saved state`
- 建议：作为稳定性信号观察，无需单独作为恶意指征。建议在干净环境重复安装-启动流程，确认是否稳定复现并与安全行为脱钩。

### 12. 动态执行成功但存在持续性系统痕迹
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`medium`
- 说明：样本在沙箱中安装与启动均成功，说明具备可执行性；同时在系统侧留下了 accessibility、device_policy、notification 等持久化相关痕迹，虽然不等同于恶意，但提示需要关注其是否具备长期驻留或系统能力申请行为。
- 证据：`install_success=true; launch_success=true; persistent_services.accessibility 包含 com.malmstein.yahnac; persistent_services.device_policy 包含 com.malmstein.yahnac; persistent_services.notification 显示 com.malmstein.yahnac`
- 建议：建议保持隔离安装状态，进入二次沙箱复核，重点检查是否触发无障碍服务、设备管理器或通知常驻逻辑；在确认业务必要性前不要向生产终端分发。

### 13. 存在网络交互但缺少明确远端对象画像
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`medium`
- 说明：运行期间出现 12 次网络命中，且日志中出现 com.google.android.gms.measurement.START、package.install、settings.get.glo 等网络/服务相关线索，说明样本会与外部服务交互；但当前证据未能明确远端域名、IP、请求路径和敏感数据外发内容。
- 证据：`network_hit_count=12; network_hits 包含 com.google.android.gms.measurement.START、com.google.android.gms、settings.get.glo、package.install、vmdl1348303287.tmp`
- 建议：建议阻断对生产网络的直接放行，先在受控网络中补采流量并做 DNS/HTTP(S) 还原；若无法完成流量审计，按高关注样本处理并暂缓分发。

### 14. 应用可正常解析并启动指定主界面
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`low`
- 说明：沙箱中 resolve_activity 指向 com.malmstein.yahnac/.stories.NewsActivity，表明 APK 结构完整且主入口明确，偏向正常应用样本特征，而非明显畸形或空壳载荷。
- 证据：`resolve_activity=priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false\ncom.malmstein.yahnac/.stories.NewsActivity`
- 建议：可作为低风险正样本继续做来源核验和版本比对；若与已知官方发布包不一致，应暂停分发并保留原始样本。

### 15. 未见动态加载、反射或对抗行为，降低直接恶意指向
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`low`
- 说明：沙箱鲁棒性结果未检测到 anti-emulator、obfuscation、reflection、dynamic_loading 等典型对抗或隐藏行为，当前没有明显的恶意规避证据。
- 证据：`anti_emulator_detected=false; obfuscation_detected=false; reflection_detected=false; dynamic_loading_detected=false; robustness_score=0.0`
- 建议：不建议直接判定为恶意，但仍需结合来源、签名和流量复核；在证据未补齐前，不建议进入广泛分发。

### 16. 安装时触发包更新与进程强停，需留痕排查版本来源
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`medium`
- 说明：日志显示系统在安装阶段执行了包更新路径切换，并强制停止旧进程后再加载新包，这符合覆盖安装/版本替换特征。若样本来源不可控，这类更新行为需要保留留痕以便追溯。
- 证据：`PackageManager: Update package com.malmstein.yahnac code path ... Retain data and using new; ActivityManager: Force stopping com.malmstein.yahnac ... installPackageLI`
- 建议：建议保留原始 APK、安装日志、包名/签名摘要与动态流量样本；如来自第三方分发渠道，建议阻断继续传播并做版本来源一致性核验。

### 17. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已检查 Manifest、签名与资源等关键文件，用于后续静态研判。
- 证据：`AndroidManifest.xml; META-INF/TESTKEY.SF; META-INF/TESTKEY.RSA; classes.dex; 多个 res/anim 与 res/drawable 资源`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 18. 未解析到包名
- 规则：`APK_MISSING_PACKAGE`
- 严重级别：`medium`
- 说明：静态解析未提取包名与组件，样本身份在静态层不清晰。
- 证据：`package_name 空; activities/services/receivers/providers 列表为空`
- 建议：复核解析流程并以动态沙箱结果补齐身份信息。

### 19. 所谓可疑字符串实为常规 UI/命名空间
- 规则：`APK_SUSPICIOUS_STRINGS`
- 严重级别：`low`
- 说明：字符串多为 layout/schema/支持库组件（如 AppBarLayout、Toolbar、TextInputLayout、Snackbar 等），不构成恶意外联或执行指令证据。
- 证据：`http://schemas.android.com/apk/res/android; http://schemas.android.com/apk/res-auto; android.support.*; com.malmstein.yahnac.*`
- 建议：结合反编译确认是否存在真实网络端点或命令字串；当前未见。

### 20. 动态解析到应用身份与入口组件
- 规则：`DEEP_APK_INTEL_RUNTIME_IDENTITY`
- 严重级别：`low`
- 说明：沙箱期正确解析到包名和可启动 Activity，修正静态层未解析到包名的问题。
- 证据：`package_name=com.malmstein.yahnac; resolve_activity=com.malmstein.yahnac/.stories.NewsActivity`
- 建议：据此在官方渠道核验应用页面与开发者信息，并比对签名指纹与发行版。

### 21. ADB 侧载与非商店管控迹象
- 规则：`DEEP_APK_INTEL_INSTALL_SOURCE_OFFSTORE`
- 严重级别：`medium`
- 说明：安装与系统商店服务日志显示该包不受商店管控，指向侧载来源。
- 证据：`Integrity check passed for vmdl*.tmp; Finsky: Not cached/getItems RPC failed`
- 建议：视为供应链风险，需验证 SHA256 与官方一致并比对签名。

### 22. 运行期仅授予网络与保活相关权限
- 规则：`DEEP_APK_INTEL_RUNTIME_PERMS_NET`
- 严重级别：`low`
- 说明：观测到 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK，未见高危敏感权限。
- 证据：`granted_permissions: INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK`
- 建议：对出站流量做白名单与可视化监控。

### 23. 绑定 Google 测量/分析服务迹象
- 规则：`DEEP_APK_INTEL_GMS_MEASUREMENT_BIND`
- 严重级别：`low`
- 说明：与 com.google.android.gms.measurement.START 的交互属于常见统计组件绑定。
- 证据：`logcat onUnbind: com.google.android.gms.measurement.START`
- 建议：评估隐私与合规影响，对相关域名进行基线控制。

### 24. dumpsys 枚举出现无障碍/设备策略/通知条目
- 规则：`DEEP_APK_INTEL_PERSISTENT_SERVICE_ENUM_FLAGS`
- 严重级别：`medium`
- 说明：尚不足以证明已启用对应系统能力，需进一步核验。
- 证据：`accessibility/device_policy/notification 列表含包名`
- 建议：复核 manifest 是否声明对应组件，核查 active admins 并延长交互观察。

### 25. 未见动态加载、反射或对抗行为
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`low`
- 说明：鲁棒性检测未发现隐藏/规避类技术，降低直接恶意指向。
- 证据：`anti_emulator=false; obfuscation=false; reflection=false; dynamic_loading=false; robustness_score=0.0`
- 建议：在来源与签名核验前不宜直接判定恶意或完全放行。

### 26. 安装时触发包更新与进程强停
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`medium`
- 说明：符合覆盖安装/版本替换特征，需记录留痕以便追溯来源。
- 证据：`PackageManager: Update package code path; ActivityManager: Force stopping … due to installPackageLI`
- 建议：保留安装日志与签名摘要，核验版本一致性。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5`）
基于现有离线静态证据与短时动态沙箱线索，样本整体更像“正常应用的非官方构建/侧载版本”，未见直接恶意行为指征，但在来源与签名可信度上存在明显不确定性，故综合判定为中等风险。静态层：Manifest 文件存在但解析未提取到包名/组件（权限计数为 0、组件为空更符合解析失败而非真实无权限的情形），签名目录出现 META-INF/TESTKEY.SF/RSA（常见于非官方构建或测试签名），证书指纹仅提供 SHA256（7a9f…），缺少权威渠道对照；资源与字符串大量为 Android 支持库/UI 构件与 com.malmstein.yahnac 命名空间（如 LoginView、YahnacTextView、NewsActivity、design/snackbar 等），未发现典型恶意 C2/命令执行字串，所谓“可疑字符串”多为布局/主题/命名空间的常规字段。动态沙箱补充：成功解析并启动 com.malmstein.yahnac/.stories.NewsActivity，仅授予 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK 等常见权限，出现与 com.google.android.gms.measurement.START 的绑定（统计/测量常见），网络命中为通用服务项，未捕获明确恶意外联域名；安装/运行日志显示 ADB 侧载与非商店管控（Finsky 缓存未命中、RPC 失败），存在可指向覆盖安装/版本替换的路径更新；dumpsys 枚举出现 accessibility/device_policy/notification 条目，但未见管理员激活或无障碍服务启用流程，当前不足以认定滥用系统能力。鲁棒性：未检测到混淆、反射、动态加载或反模拟，对抗迹象为零（robustness_score=0.0）。仲裁结果：一致性评分 80（中等），但静态-情报与行为-情报存在 30 分差异，整体加权置信度偏低（22）。最终结论：当前证据链不支持“恶意软件”定性，更接近开源 Hacker News 客户端（com.malmstein.yahnac）的侧载/非官方签名构建；风险主要来自供应链与来源不明（TESTKEY 签名、侧载），建议在放行前完成来源与签名指纹比对、哈希一致性核验，并延长动态运行时间与交互覆盖以补采网络与权限行为。如无法确认与官方发行版一致，应继续隔离并阻断分发。注：静态层 manifest/权限/组件解析不足，部分判断基于短时动态沙箱补充，仍属有限证据。

### 静态分析员（模型：`gemini-2.5-pro`）
APK 静态证据关注：未解析到包名、存在可疑字符串线索。

### 行为分析员（模型：`gemini-2.5-flash`）
当前版本仅提供静态 APK 检测，未执行动态沙箱。

### 情报分析员（模型：`gpt-5`）
样本文件名为临时路径 tmp3iwx92fa.apk（C:/Users/lenovo/AppData/Local/Temp），动态沙盒运行期正确解析到包名为 com.malmstein.yahnac，入口为 .stories.NewsActivity。沙盒仅运行约 12 秒，网络命中计数为 12，但未捕获到清晰的远程域名/URL 明细，且未见动态加载、反射或抗模拟迹象。安装与运行日志显示为 ADB 侧载路径与非商店管控特征（Finsky 未命中缓存/Not cached、getItems RPC failed），说明当前样本来源与分发渠道不明。证书细节在本地仅掌握到指纹（certificate_sha256），缺少权威渠道指纹对照，无法据此确认是否为官方签名。结合以上，本地离线与短时沙盒分析的边界在于：1) 运行窗口短、场景触发不足，可能遗漏条件/地域/账号驱动的行为与网络流量；2) 模拟器环境可能屏蔽广告/统计等第三方 SDK 的完整交互；3) 未能核验发行渠道（Google Play/F-Droid/官方仓库）及签名信誉，无法排除二次打包。处置建议：务必结合来源与分发渠道进行核验——以动态解析到的包名 com.malmstein.yahnac 为索引，到官方商店或可信镜像核对应用页面与开发者信息；比对签名证书指纹与官方发布指纹；校验样本 SHA256 与官方发行版是否一致；若为企业场景，仅允许来自白名单商店/MDM 的安装，并延长动态运行时间与交互脚本以补充行为覆盖。

### 处置建议员（模型：`gpt-5.4-mini`）
建议先隔离留观，不建议直接放行到生产环境或向终端用户分发。当前样本动态执行已成功，启动了 com.malmstein.yahnac/.stories.NewsActivity，并产生网络活动与持续性系统痕迹，但未见明确恶意载荷、权限滥用或动态加载/反射/加固对抗迹象。综合判断更接近“低度可疑但需复核”的应用样本，建议进入沙箱复核与来源核验流程；若无法确认其来自可信渠道或签名一致性，建议阻断分发并保留样本留痕。


### 主持人最终总结
基于现有离线静态证据与短时动态沙箱线索，样本整体更像“正常应用的非官方构建/侧载版本”，未见直接恶意行为指征，但在来源与签名可信度上存在明显不确定性，故综合判定为中等风险。静态层：Manifest 文件存在但解析未提取到包名/组件（权限计数为 0、组件为空更符合解析失败而非真实无权限的情形），签名目录出现 META-INF/TESTKEY.SF/RSA（常见于非官方构建或测试签名），证书指纹仅提供 SHA256（7a9f…），缺少权威渠道对照；资源与字符串大量为 Android 支持库/UI 构件与 com.malmstein.yahnac 命名空间（如 LoginView、YahnacTextView、NewsActivity、design/snackbar 等），未发现典型恶意 C2/命令执行字串，所谓“可疑字符串”多为布局/主题/命名空间的常规字段。动态沙箱补充：成功解析并启动 com.malmstein.yahnac/.stories.NewsActivity，仅授予 INTERNET/ACCESS_NETWORK_STATE/ACCESS_WIFI_STATE/WAKE_LOCK 等常见权限，出现与 com.google.android.gms.measurement.START 的绑定（统计/测量常见），网络命中为通用服务项，未捕获明确恶意外联域名；安装/运行日志显示 ADB 侧载与非商店管控（Finsky 缓存未命中、RPC 失败），存在可指向覆盖安装/版本替换的路径更新；dumpsys 枚举出现 accessibility/device_policy/notification 条目，但未见管理员激活或无障碍服务启用流程，当前不足以认定滥用系统能力。鲁棒性：未检测到混淆、反射、动态加载或反模拟，对抗迹象为零（robustness_score=0.0）。仲裁结果：一致性评分 80（中等），但静态-情报与行为-情报存在 30 分差异，整体加权置信度偏低（22）。最终结论：当前证据链不支持“恶意软件”定性，更接近开源 Hacker News 客户端（com.malmstein.yahnac）的侧载/非官方签名构建；风险主要来自供应链与来源不明（TESTKEY 签名、侧载），建议在放行前完成来源与签名指纹比对、哈希一致性核验，并延长动态运行时间与交互覆盖以补采网络与权限行为。如无法确认与官方发行版一致，应继续隔离并阻断分发。注：静态层 manifest/权限/组件解析不足，部分判断基于短时动态沙箱补充，仍属有限证据。


## 六点一、角色结果说明
- **行为分析员**：该角色当前仅输出静态研判结果，原因是 APK 动态沙箱尚未执行或未接入。

## 七、仲裁结果
- 一致性分数：`80`
- 一致性等级：`medium`
- 加权置信度：`27`
- 疑似污染源：无
- 分歧与模式：
  - static-behavior 差异 30 分
  - static-intelligence 差异 10 分
  - behavior-intelligence 差异 20 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
