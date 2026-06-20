# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**MEDIUM** · 风险分数：**70/100**


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmp2c1p3ieo.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：24 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260619_104605_298243.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260619_104605_298243.md

## 二、统一 IR 摘要
该对象类型尚未实现。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要
- device_id：emulator-5554
- package_name：com.malmstein.yahnac
- static_file_name：tmp2c1p3ieo.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：9700
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：无
- persistent_services：{'device_policy': ['6: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：34
- logcat_excerpt_count：529
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`C:/Users/lenovo/AppData/Local/Temp/sentinelguard_dynamic/sentinel_apk_dynamic_com.malmstein.yahnac_20260619_104608_858337.json`
- dynamic_json_name：`sentinel_apk_dynamic_com.malmstein.yahnac_20260619_104608_858337.json`

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
- 证据：`tmp2c1p3ieo.apk`
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
- 证据：`settings.get.glo; package.install; vmdl1843509505.tmp; com.malmstein.yahnac; base.dm`
- 建议：后续可结合抓包或代理进行复核。

### 5. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`6: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 6. 动态分析成功解析包名
- 规则：`DEEP_APK_STATIC_PACKAGE_RESOLVED`
- 严重级别：`low`
- 说明：静态分析未能提取到包名，但动态沙箱运行后成功识别出 APK 的包名为 `com.malmstein.yahnac`，并确认了主启动活动为 `com.malmstein.yahnac/.stories.NewsActivity`。这澄清了静态分析中的主要疑点。
- 证据：`动态沙箱报告的包名: "com.malmstein.yahnac"，主活动: "com.malmstein.yahnac/.stories.NewsActivity"`
- 建议：更新静态分析工具以提高包名提取的准确性。

### 7. 动态分析澄清了权限列表
- 规则：`DEEP_APK_STATIC_PERMISSIONS_CLARIFIED`
- 严重级别：`low`
- 说明：静态分析未能识别任何权限，但动态沙箱报告了应用程序请求并被授予的权限，包括 `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `WAKE_LOCK`。这些权限对于大多数正常应用程序来说是常见的，不构成高风险。
- 证据：`动态沙箱报告的权限: "ANDROID.PERMISSION.INTERNET", "ANDROID.PERMISSION.ACCESS_NETWORK_STATE", "ANDROID.PERMISSION.ACCESS_WIFI_STATE", "ANDROID.PERMISSION.WAKE_LOCK"`
- 建议：结合代码分析确认这些权限的使用方式是否符合预期。

### 8. 发现测试签名证书
- 规则：`DEEP_APK_STATIC_SIGNATURE_TESTKEY`
- 严重级别：`medium`
- 说明：APK 使用了 `TESTKEY` 签名证书。这通常用于开发或测试阶段，但也可能被恶意行为者用于重新打包合法应用。
- 证据：`签名文件: "META-INF/TESTKEY.SF", "META-INF/TESTKEY.RSA"; 证书SHA256: "7a9fda6ae4d150f37993c2f8d499c726cfd831377e4b55e8bf1adf853f8d5c2f"`
- 建议：建议追溯 APK 来源，确认其是否为官方发布版本。如果不是，则存在被篡改的风险。

### 9. 可疑字符串经动态分析判断为良性
- 规则：`DEEP_APK_STATIC_BENIGN_STRINGS`
- 严重级别：`low`
- 说明：静态分析中标记为“可疑”的字符串（如 `android.support.design.widget.AppBarLayout`, `com.malmstein.yahnac.login.LoginView` 等）在动态分析确认了包名和应用类型后，被判断为正常的 Android UI 组件、库引用或应用内部类名，不具有直接的恶意行为指示。
- 证据：`提取字符串中包含: "com.malmstein.yahnac.login.LoginView", "android.support.design.widget.AppBarLayout", "android.support.v7.widget.Toolbar", "android.support.design.widget.Snackbar", "android.support.v7.widget.AppCompatEditText"`
- 建议：结合反编译代码进一步验证这些字符串的具体用途。

### 10. 动态网络活动主要为内部系统操作
- 规则：`DEEP_APK_STATIC_NETWORK_ACTIVITY_INTERNAL`
- 严重级别：`low`
- 说明：动态沙箱检测到的网络活动（`network_hits`）主要涉及 `settings.get.glo`, `package.install` 等系统级操作以及文件路径，未发现与外部恶意服务器进行通信的明确证据。
- 证据：`动态沙箱网络命中: "settings.get.glo", "package.install", "com.malmstein.yahnac", "base.apk", "base.odex"`
- 建议：尽管当前未发现恶意网络行为，但仍需对 DEX 代码进行更深入的分析，以排除隐藏的通信机制。

### 11. 应用在运行时被关联到异常的系统服务
- 规则：`DEEP_APK_BEHAVIOR_UNUSUAL_SERVICE_REGISTRATION`
- 严重级别：`medium`
- 说明：沙箱动态分析显示，应用包 'com.malmstein.yahnac' 在运行时被系统列入 'device_policy' 服务中。对于一个新闻阅读器应用，这是一个非典型的行为。虽然在测试期间未观察到应用请求设备管理器权限，但这种关联可能被用作一种持久化或权限提升的潜在手段。
- 证据：`dumpsys persistent_services: {"device_policy": ["6: com.malmstein.yahnac"]}`
- 建议：监控该应用是否会弹出设备管理器激活请求。检查代码中与 DevicePolicyManager 相关的API调用，以确定其意图。

### 12. 应用在不安全的签名上下文中运行
- 规则：`DEEP_APK_BEHAVIOR_INSECURE_SIGNATURE_CONTEXT`
- 严重级别：`medium`
- 说明：动态行为确认该应用包（com.malmstein.yahnac）成功安装并运行，但其身份验证依赖于一个通用的“TESTKEY”调试证书。这意味着任何恶意行为都发生在一个易于被仿冒和篡改的身份之下，增加了供应链攻击的风险。使用调试密钥签名的应用不应在生产环境中使用。
- 证据：`Dynamic analysis confirms successful installation and launch of package 'com.malmstein.yahnac', which static analysis shows is signed with 'TESTKEY.RSA'.`
- 建议：不要信任使用通用调试密钥签名的应用。仅从官方或可信的应用商店下载应用，并验证其开发者签名。

### 13. 动态分析成功识别包名
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`low`
- 说明：静态分析未能解析到APK包名，但动态沙箱运行后，成功识别出包名为 'com.malmstein.yahnac'。这有助于明确样本身份，降低了因包名缺失带来的不确定性。
- 证据：`动态沙箱报告中 'package_name': 'com.malmstein.yahnac'`
- 建议：更新样本信息，将包名 'com.malmstein.yahnac' 纳入记录。

### 14. 沙箱环境内行为正常，未发现外部恶意通信
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`low`
- 说明：样本在沙箱中成功安装和启动，其网络活动主要表现为系统内部组件（如包管理器、dex优化）的交互，未检测到与已知恶意C2服务器的通信或数据外泄行为。
- 证据：`动态沙箱报告显示 'install_success': true, 'launch_success': true, 'network_hits' 主要为系统内部或安装相关条目。`
- 建议：持续监控样本的长期行为，以防延迟触发的恶意活动。

### 15. 申请了常见权限，但未滥用
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`low`
- 说明：样本在运行时获取了 'INTERNET', 'ACCESS_NETWORK_STATE', 'ACCESS_WIFI_STATE', 'WAKE_LOCK' 等常见权限。在沙箱观察期间，这些权限未被用于恶意目的。
- 证据：`动态沙箱报告中 'granted_dangerous_permissions': ['ANDROID.PERMISSION.INTERNET', 'ANDROID.PERMISSION.ACCESS_NETWORK_STATE', 'ANDROID.PERMISSION.ACCESS_WIFI_STATE', 'ANDROID.PERMISSION.WAKE_LOCK']`
- 建议：这些权限本身不构成高风险，但仍需结合应用功能判断其合理性。

### 16. 存在设备策略管理服务提及
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`medium`
- 说明：动态沙箱报告的持久化服务中提及 'device_policy': ['6: com.malmstein.yahnac']。这表明该应用可能具备或尝试获取设备管理员权限，若被恶意利用，可能导致设备被远程控制或数据被擦除等严重后果。
- 证据：`动态沙箱报告中 'persistent_services': {'device_policy': ['6: com.malmstein.yahnac']}`
- 建议：对样本进行逆向工程，分析其代码中与设备策略管理相关的API调用，确认其是否实际请求或激活了设备管理员权限，以及其使用目的。在部署前，务必谨慎评估其必要性。

### 17. 静态分析发现可疑字符串，动态行为未完全验证
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`medium`
- 说明：静态分析报告指出样本中存在 '命令执行、远程地址或系统调用相关字符串'。尽管动态沙箱未直接观察到这些字符串被用于恶意行为，但其潜在风险依然存在，需要进一步的代码层面的确认。
- 证据：`静态分析报告中 'APK_SUSPICIOUS_STRINGS' 规则的 'evidence' 部分。`
- 建议：进行详细的代码逆向分析，追踪这些可疑字符串在代码中的引用和使用方式，以判断其是否构成实际威胁。

### 18. 当前结论仅基于离线静态证据与短时动态窗口
- 规则：`STATIC_EVIDENCE_SCOPE_LIMITATION`
- 严重级别：`medium`
- 说明：静态侧能确认关键文件、签名与资源线索，动态侧仅覆盖 12 秒运行窗口；未做完整逆向与长时行为观测，因此对延迟触发、条件触发或分阶段载荷无法定性。
- 证据：`dynamic_sandbox.runtime_window_seconds=12; classes.dex 存在但未提供完整反编译结果；AndroidManifest.xml 仅作为关键文件提取，未给出完整组件清单。`
- 建议：继续进行 dex 逆向、Manifest 深挖和更长时长动态监控。

### 19. 使用 TESTKEY 调试/测试签名
- 规则：`APK_SIGNATURE_TESTKEY`
- 严重级别：`medium`
- 说明：META-INF/TESTKEY.SF 与 META-INF/TESTKEY.RSA 表明样本并非标准官方签名链，存在测试构建外泄、二次打包或供应链风险。
- 证据：`certificate_sha256=7a9fda6ae4d150f37993c2f8d499c726cfd831377e4b55e8bf1adf853f8d5c2f; META-INF/TESTKEY.SF; META-INF/TESTKEY.RSA`
- 建议：核查来源渠道与历史签名，确认是否为官方构建。

### 20. 动态沙箱已解析出包名与主活动
- 规则：`DYNAMIC_PACKAGE_RESOLVED`
- 严重级别：`low`
- 说明：静态阶段未能提取包名，但动态安装与启动成功后确认包名为 com.malmstein.yahnac，主活动为 .stories.NewsActivity，说明样本具备完整可执行应用结构。
- 证据：`package_name=com.malmstein.yahnac; resolve_activity=com.malmstein.yahnac/.stories.NewsActivity; launch_success=true`
- 建议：将该包名纳入后续情报检索与样本归档。

### 21. 权限组合符合常规联网应用特征
- 规则：`COMMON_NETWORK_PERMISSIONS`
- 严重级别：`low`
- 说明：仅见 INTERNET、ACCESS_NETWORK_STATE、ACCESS_WIFI_STATE、WAKE_LOCK，未见高危敏感权限集合（如短信、通讯录、无障碍、设备管理等）作为静态已知权限。
- 证据：`granted_dangerous_permissions: ANDROID.PERMISSION.INTERNET; ANDROID.PERMISSION.ACCESS_NETWORK_STATE; ANDROID.PERMISSION.ACCESS_WIFI_STATE; ANDROID.PERMISSION.WAKE_LOCK`
- 建议：结合代码确认这些权限是否被用于正常联网与前台保持。

### 22. 字符串主要指向正常 UI/框架组件
- 规则：`UI_FRAMEWORK_STRINGS_BENIGN`
- 严重级别：`low`
- 说明：提取字符串以 AppBarLayout、Toolbar、TextInputLayout、Snackbar、AppCompatEditText、ButtonBarLayout、样式资源与自定义视图类名为主，更符合 Android 应用界面资源，而非典型恶意载荷特征。
- 证据：`android.support.design.widget.AppBarLayout; android.support.v7.widget.Toolbar; com.malmstein.yahnac.login.LoginView; android.support.design.widget.Snackbar; android.support.v7.widget.AppCompatEditText`
- 建议：在反编译中确认这些类名对应的 UI 逻辑是否仅限于界面展示。

### 23. device_policy 关联为非典型风险信号
- 规则：`UNUSUAL_DEVICE_POLICY_ASSOCIATION`
- 严重级别：`medium`
- 说明：动态沙箱 persistent_services 中出现 device_policy: ["6: com.malmstein.yahnac"]，对新闻类应用而言不常见，可能涉及设备管理员、持久化或系统级权限相关逻辑，但本次窗口内未观察到实际激活。
- 证据：`persistent_services.device_policy=["6: com.malmstein.yahnac"]`
- 建议：重点检查 DevicePolicyManager、设备管理员接收器及相关权限声明/请求逻辑。

### 24. 未观察到直接恶意行为
- 规则：`NO_DIRECT_MALICIOUS_BEHAVIOR_OBSERVED`
- 严重级别：`low`
- 说明：在安装、启动和短时运行窗口内，未检测到明确的 C2 通信、数据外传、静默安装、SMS/通话窃取或高危破坏行为。
- 证据：`install_success=true; launch_success=true; network_hit_count=12; network_hits mostly installation/system artifacts; no explicit malicious domain or payload observed.`
- 建议：保持监控，防止延迟触发或条件触发行为。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于当前离线静态证据与短时动态沙箱结果，这个 APK 更像是一个功能性新闻应用（包名已在沙箱中解析为 com.malmstein.yahnac，主活动为 .stories.NewsActivity），而非已证实的恶意样本。证据上，Manifest/组件信息在静态侧未完整解析，但动态侧确认了正常启动链路；权限仅见 INTERNET、ACCESS_NETWORK_STATE、ACCESS_WIFI_STATE、WAKE_LOCK，符合联网类应用常见配置；资源与字符串大量指向 Android UI 组件、Design Support Library 和应用内部类名，没有出现明确的 C2 域名、加密落地、短信/通话窃取、无障碍劫持或明显执行载荷线索。另一方面，样本使用 TESTKEY 签名，且证书 SHA256 已给出，这意味着它不是标准官方发布签名，存在被重打包或测试构建流入外部的供应链风险；动态日志还出现 device_policy 相关关联，这对新闻阅读器来说是非典型信号，虽未在本次 12 秒窗口内触发设备管理员激活或其他恶意动作，但不能忽略其潜在持久化/权限扩展可能。综上，当前裁决为“中等风险、偏可疑但未实证恶意”，结论仅能建立在本次离线静态证据与短时动态观测之上，若要定性仍需进一步逆向 classes.dex、核查 Manifest 组件与签名来源、并做更长时长动态验证。 综合静态证据、动态沙箱和四位专家意见，样本身份已从静态缺失澄清为 com.malmstein.yahnac，但 TESTKEY 签名与 device_policy 异常关联保留风险点，因此不判定为恶意已实证，但应保持中等风险。

### 静态分析员（模型：`gemini-2.5-flash`）
静态侧未解析到包名与权限，但动态沙箱已补全为 com.malmstein.yahnac / .stories.NewsActivity；网络与权限行为看起来像正常新闻应用；TESTKEY 签名提示可能是开发版或重打包版本，暂无直接恶意证据。

### 行为分析员（模型：`gemini-2.5-pro`）
沙箱中表现为功能性新闻阅读器，安装与启动成功，未见数据窃取、C2 或安装其他应用；但 TESTKEY 签名不安全，且 device_policy 服务关联对新闻应用不典型，需警惕潜在持久化或权限提升尝试。

### 情报分析员（模型：`gpt-5`）
建议继续结合市场来源、签名证书与历史信誉核验，当前证据不足以确认恶意，但签名与来源可信度仍是关键风险控制点。

### 处置建议员（模型：`gemini-2.5-flash`）
建议在隔离环境中继续复核，重点逆向代码中可疑字符串与设备策略管理相关逻辑；在未确认来源与意图前，不应在真实设备或生产环境中信任该 APK。


### 主持人最终总结
基于当前离线静态证据与短时动态沙箱结果，这个 APK 更像是一个功能性新闻应用（包名已在沙箱中解析为 com.malmstein.yahnac，主活动为 .stories.NewsActivity），而非已证实的恶意样本。证据上，Manifest/组件信息在静态侧未完整解析，但动态侧确认了正常启动链路；权限仅见 INTERNET、ACCESS_NETWORK_STATE、ACCESS_WIFI_STATE、WAKE_LOCK，符合联网类应用常见配置；资源与字符串大量指向 Android UI 组件、Design Support Library 和应用内部类名，没有出现明确的 C2 域名、加密落地、短信/通话窃取、无障碍劫持或明显执行载荷线索。另一方面，样本使用 TESTKEY 签名，且证书 SHA256 已给出，这意味着它不是标准官方发布签名，存在被重打包或测试构建流入外部的供应链风险；动态日志还出现 device_policy 相关关联，这对新闻阅读器来说是非典型信号，虽未在本次 12 秒窗口内触发设备管理员激活或其他恶意动作，但不能忽略其潜在持久化/权限扩展可能。综上，当前裁决为“中等风险、偏可疑但未实证恶意”，结论仅能建立在本次离线静态证据与短时动态观测之上，若要定性仍需进一步逆向 classes.dex、核查 Manifest 组件与签名来源、并做更长时长动态验证。


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
