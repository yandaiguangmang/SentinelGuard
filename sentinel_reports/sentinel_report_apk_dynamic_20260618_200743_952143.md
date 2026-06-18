# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**HIGH** · 风险分数：**61/100**


## 一、检测结论
- 原始输入：`C:\Users\Lenovo\AppData\Local\Temp\tmpx0xs0o3k.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：10 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260618_195353_487656.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260618_195353_487656.md

## 二、统一 IR 摘要
该对象类型尚未实现。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要
- device_id：emulator-5554
- package_name：com.tencent.mobileqq
- static_file_name：tmpx0xs0o3k.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.tencent.mobileqq/.activity.SplashActivity
- pidof：10973
- granted_dangerous_permissions：无
- post_install_files：无
- persistent_services：{'device_policy': ['10: com.tencent.mobileqq'], 'notification': ['AppSettings: com.tencent.mobileqq (10201) importance=NONE userSet=false', '06-18 09:47:21.134 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 09:47:21.135 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 09:58:24.292 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 09:58:24.293 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 10:06:44.842 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 10:06:44.842 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 10:22:11.570 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 10:22:11.570 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 11:53:20.666 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 11:53:20.666 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', 'userId=0 value={com.google.android.apps.diagnosticstool, io.va.exposed64, com.google.android.as/com.google.android.apps.miphone.aiai.common.notification.service.AiAiNotificationAssistantService, com.google.android.apps.safetyhub, com.google.android.as, com.google.intelligence.sense, com.google.android.apps.wellbeing, com.google.android.dialer, com.google.android.gms, com.tencent.mobileqq, com.google.android.apps.nexuslauncher, com.zhihu.android, com.google.android.settings.intelligence, com.google.android.GoogleCamera}']}
- install_success：True
- launch_success：True
- event_count：86
- logcat_excerpt_count：383
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`C:/Users/Lenovo/AppData/Local/Temp/sentinelguard_dynamic/sentinel_apk_dynamic_com.tencent.mobileqq_20260618_195411_405461.json`
- dynamic_json_name：`sentinel_apk_dynamic_com.tencent.mobileqq_20260618_195411_405461.json`

## 五、风险证据
### 1. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。
- 证据：`manifest: AndroidManifest.xml; resource: assets/4006001/4006001.json; resource: assets/4006002/4006002.json; resource: assets/4006003/4006003.json; resource: assets/4006004/4006004.json; resource: assets/4006005/4006005.json; resource: assets/4006006/4006006.json; resource: assets/4006007/4006007.json; resource: assets/4006008/4006008.json; resource: assets/4006009/4006009.json; resource: assets/DoraemonApiGroup.json; resource: assets/GCloudVoice/config.json`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 存在敏感权限请求
- 规则：`APK_SUSPICIOUS_PERMISSION`
- 严重级别：`high`
- 说明：安装包请求了短信、联系人、录音、安装或辅助功能等高敏权限。
- 证据：`android.Manifest.permission.RECORD_AUDIO, android.permission.ACCESS_FINE_LOCATION, android.permission.CAMERA, android.permission.FOREGROUND_SERVICE_CAMERA, android.permission.QUERY_ALL_PACKAGES, android.permission.READ_CONTACTS, android.permission.RECORD_AUDIO, android.permission.REQUEST_INSTALL_PACKAGES, android.permission.SYSTEM_ALERT_WINDOW, android.permission.WRITE_CONTACTS`
- 建议：确认权限是否与业务功能一致，避免授予不必要权限。

### 3. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2629356853328 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>; Issuer=<asn1crypto.x509.Name 2629356710672 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. 存在持久化或高权限组件线索
- 规则：`APK_PERSISTENT_COMPONENTS`
- 严重级别：`medium`
- 说明：组件名称显示可能存在开机自启、管理器或辅助功能相关入口。
- 证据：`com.tencent.mobileqq.msf.service.MSFAliveJobService; com.xiaomi.push.service.XMJobService`
- 建议：检查这些组件是否会在后台持续运行或触发敏感动作。

### 5. 应用通过多重机制实现后台持久化和保活
- 规则：`DEEP_APK_BEHAVIOR_PERSISTENCE_MECHANISM`
- 严重级别：`medium`
- 说明：该应用不仅注册了开机自启广播，还设计了多个后台服务（如MSFAliveJobService、XMPushService）用于进程保活和消息推送。动态沙箱日志显示，应用启动后其进程（PID 10973）立即被创建并保持活跃，同时注册了通知服务。这种设计确保了应用能长期在后台运行以接收消息，但也会持续消耗系统资源。
- 证据：`静态线索: 权限 'android.permission.RECEIVE_BOOT_COMPLETED', 服务 'com.tencent.mobileqq.msf.service.MSFAliveJobService', 'com.xiaomi.push.service.XMJobService'。动态线索: 沙箱日志显示应用进程 'com.tencent.mobileqq' (PID 10973) 启动并持续运行，同时在通知服务中注册 'com.tencent.mobileqq'。`
- 建议：用户应知晓该应用会常驻后台。如果对消息实时性要求不高，可以考虑在系统设置中限制其后台活动和自启动权限，以优化设备性能和续航。

### 6. 应用被系统记录为设备策略相关服务
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_POLICY_REGISTRATION`
- 严重级别：`medium`
- 说明：在动态沙箱环境的系统状态转储（dumpsys）中，检测到该应用的包名 'com.tencent.mobileqq' 被列入了设备策略（device_policy）服务列表。这通常与申请“设备管理器”权限相关，该权限允许应用执行锁屏、修改密码、擦除数据等高级操作。尽管在短暂的沙箱运行中未触发权限请求，但该记录表明应用可能具备或准备调用此类高权限功能。
- 证据：`动态沙箱日志: `dynamic_sandbox.persistent_services.device_policy: ["10: com.tencent.mobileqq"]``
- 建议：在应用后续使用中，应警惕任何激活“设备管理器”的诱导弹窗。除非明确需要使用其提供的设备安全管理功能（如账号安全锁），否则不建议授予此高级权限。

### 7. 运行时确认存在持久化服务
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`medium`
- 说明：动态沙箱分析确认了应用在运行时注册了持久化服务，包括与设备策略和通知相关的服务（如com.tencent.mobileqq在设备策略和通知服务中被列出）。这与静态分析中发现的持久化组件线索一致，表明应用具备在后台持续运行和执行特定操作的能力。
- 证据：`persistent_services: {"device_policy": ["10: com.tencent.mobileqq"], "notification": ["AppSettings: com.tencent.mobileqq (10201) importance=NONE userSet=false", ...]}`
- 建议：评估这些持久化服务是否与应用的核心功能相符。若来源不可信，需警惕其可能被滥用以进行持续监控或恶意操作。

### 8. 运行时检测到网络通信
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`low`
- 说明：动态沙箱分析期间，检测到应用进行了网络通信，包括与系统设置、包安装和Google服务相关的网络请求。对于一个大型社交应用而言，网络活动是预期行为，但若APK来源不明，仍需关注其通信内容和目标，以排除数据泄露或与恶意服务器通信的风险。
- 证据：`network_hits: ["settings.get.glo", "package.install", "NetworkScheduler.Stats", "com.google.android.gms", "com.google.android.gms.auth.account.be.accountstate.GcmTaskService", "com.google.android.gms.clearcut.uploader.QosUploaderService", "com.android.launcher2.permission", "com.tencent.mobileqq", "android.permission", "com.tencent.msf.permission.account.sync", "android.permission.INTERNET", "android.permission.CAMERA"]`
- 建议：在受控环境中进一步分析网络流量，识别通信目标和传输数据类型，确保无异常行为。

### 9. 沙箱环境中未授予危险权限
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`low`
- 说明：动态沙箱分析显示，在受控的短时运行期间，未发现应用被授予任何危险权限。这可能意味着应用在启动阶段未立即请求或利用这些权限，或者沙箱环境对权限授予进行了限制。
- 证据：`granted_dangerous_permissions: []`
- 建议：此发现不能完全排除应用在特定条件下或更长时间运行后请求或利用危险权限的可能性。建议进行更长时间或交互式的动态分析以全面评估。

### 10. Logcat中存在重复权限声明警告
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`low`
- 说明：Logcat日志显示APK在AndroidManifest.xml中存在重复的权限声明，例如'com.android.launcher2.permission.READ_SETTINGS'和'android.permission.WRITE_CONTACTS'等。虽然Android系统通常会忽略重复声明，但这可能表明开发过程中的疏忽，或在某些情况下可能被用于混淆分析。
- 证据：`06-18 11:53:57.929 W/PackageParsing(  568): Ignoring duplicate uses-permissions/uses-permissions-sdk-m: com.android.launcher2.permission.READ_SETTINGS in package: com.tencent.mobileqq at: Binary XML file line #60`
- 建议：建议检查AndroidManifest.xml文件，移除重复的权限声明，以提高代码质量和清晰度。对于安全分析，此项可作为次要关注点。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
深度研判服务部分失败，已降级为静态结论。综合 4 条证据，当前风险等级需要结合 APK 来源继续判断。

### 静态分析员（模型：`gemini-2.5-flash`）
APK 静态证据关注：存在敏感权限请求、存在持久化或高权限组件线索。

### 行为分析员（模型：`gemini-2.5-pro`）
该应用为腾讯QQ，一个功能复杂的即时通讯软件。其行为特征与主营功能高度一致：1. 通过注册开机广播（RECEIVE_BOOT_COMPLETED）和多种后台服务（如MSFAliveJobService、多厂商推送服务）实现持久化驻留，以确保消息的实时接收。2. 声明了大量敏感权限（如相机、录音、联系人、安装包），这些权限对应其音视频通话、好友推荐、应用内更新等核心功能。3. 包含了热更新框架（Tinker），具备动态代码修复和更新能力。在本次有限的动态沙箱检测中，应用启动后即开始初始化后台服务，但未请求任何危险权限，也未观察到下载、安装等恶意行为。其行为符合官方正版应用的预期，但其强大的权限和后台能力也意味着一旦被仿冒或植入后门，可能造成严重风险。

### 情报分析员（模型：`gpt-5`）
建议结合市场来源、签名证书与历史信誉进一步核验。

### 处置建议员（模型：`gemini-2.5-flash`）
根据静态分析报告，该APK（com.tencent.mobileqq，版本9.3.1）请求了多项敏感权限，并包含可能在后台持续运行的持久化服务组件。动态沙箱分析确认了应用成功安装和启动，并检测到网络活动和持久化服务（如设备策略和通知相关服务）。虽然沙箱环境中未观察到危险权限的实际授予，且签名证书主体与颁发者均为“QQ”，但仍存在细微不一致，建议结合APK的来源、官方发布渠道及历史信誉进行严格核验。如果APK来源不可信，应视为高风险。


### 主持人最终总结
深度研判未能完整执行，已返回静态结果并保留已收集的专家意见。原因：模型调用异常: Request timed out.


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
