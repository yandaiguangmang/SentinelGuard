# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**MEDIUM** · 风险分数：**30/100**
> 证据分数：**50/100** · 深度研判分数：**35 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\Lenovo\AppData\Local\Temp\tmpdj_r6rn2.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：18 条
- 高危证据：5 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260623_161351_547072.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260623_161351_547072.md

## 二、统一 IR 摘要
- APK 文件：`tmpdj_r6rn2.apk`
- 包名：`com.tencent.mobileqq`
- 版本名：`9.3.1`
- 版本号：`14378`
- SHA256：`a774efc81d5d5c197326a087aae1cadb7a1cb9d47893baa313cc1cc64e0316a6`
- 大小：`403996641` 字节
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
- package_name：com.tencent.mobileqq
- static_file_name：tmpdj_r6rn2.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.tencent.mobileqq/.activity.SplashActivity
- pidof：13279
- granted_dangerous_permissions：无
- post_install_files：./product/priv-app/ImsServiceEntitlement/ImsServiceEntitlement.apk, ./product/priv-app/SettingsIntelligenceGooglePrebuilt/SettingsIntelligenceGooglePrebuilt.apk, ./product/priv-app/WellbeingPrebuilt/WellbeingPrebuilt.apk, ./product/priv-app/PrebuiltGmsCore/PrebuiltGmsCore.apk, ./product/priv-app/GoogleRestorePrebuilt/GoogleRestorePrebuilt.apk, ./product/priv-app/Velvet/Velvet.apk, ./product/priv-app/DeviceIntelligenceNetworkPrebuilt/DeviceIntelligenceNetworkPrebuilt.apk, ./product/priv-app/OdadPrebuilt/OdadPrebuilt.apk, ./product/priv-app/DevicePersonalizationPrebuiltPixel2021/DevicePersonalizationPrebuiltPixel2021.apk, ./product/priv-app/AndroidAutoStubPrebuilt/AndroidAutoStubPrebuilt.apk, ./product/priv-app/PartnerSetupPrebuilt/PartnerSetupPrebuilt.apk, ./product/priv-app/GoogleOneTimeInitializer/GoogleOneTimeInitializer.apk, ./product/priv-app/KidsSupervisionStub/KidsSupervisionStub.apk, ./product/priv-app/PrebuiltBugle/PrebuiltBugle.apk, ./product/priv-app/GoogleDialer/GoogleDialer.apk, ./product/priv-app/ConfigUpdater/ConfigUpdater.apk, ./product/lib64/libjni_jpegutil.so, ./product/lib64/libjni_tinyplanet.so, ./product/lib64/libempty.so, ./product/framework/com.google.android.dialer.support.jar
- persistent_services：{'accessibility': ['[com.google.android.apps.nexuslauncher][com.google.android.apps.wellbeing][com.android.systemui][com.tencent.mobileqq][com.google.android.apps.nexuslauncher][com.google.android.as][com.google.android.youtube][com.google.android.apps.youtube.music][com.google.android.packageinstaller][com.google.android.apps.nexuslauncher][com.google.android.inputmethod.latin][com.google.android.googlequicksearchbox][com.android.chrome]}]'], 'device_policy': ['10: com.tencent.mobileqq'], 'notification': ['AppSettings: com.tencent.mobileqq (10202) importance=NONE userSet=false', '06-18 09:47:21.134 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 09:47:21.135 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 09:58:24.292 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 09:58:24.293 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 10:06:44.842 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 10:06:44.842 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 10:22:11.570 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 10:22:11.570 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 11:53:20.666 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 11:53:20.666 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-23 08:11:40.812 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-23 08:11:40.813 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', 'userId=0 value={com.google.android.apps.diagnosticstool, io.va.exposed64, com.google.android.as/com.google.android.apps.miphone.aiai.common.notification.service.AiAiNotificationAssistantService, com.google.android.apps.safetyhub, com.google.android.as, com.google.intelligence.sense, com.google.android.apps.wellbeing, com.google.android.dialer, com.google.android.gms, com.tencent.mobileqq, com.google.android.apps.nexuslauncher, com.zhihu.android, com.google.android.settings.intelligence, com.google.android.GoogleCamera}']}
- install_success：True
- launch_success：True
- event_count：87
- logcat_excerpt_count：434
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`E:/xinansai/workplace/SentinelGuard/information/apk_dynamic/20260623_161412_527008_com.tencent.mobileqq/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`E:/xinansai/workplace/SentinelGuard/information/apk_dynamic/20260623_161412_527008_com.tencent.mobileqq/dynamic_summary.json`
- dynamic_logcat_path：`E:/xinansai/workplace/SentinelGuard/information/apk_dynamic/20260623_161412_527008_com.tencent.mobileqq/logcat_excerpt.txt`
- dynamic_output_dir：`E:/xinansai/workplace/SentinelGuard/information/apk_dynamic/20260623_161412_527008_com.tencent.mobileqq`
- ui_trace_dir：`E:/xinansai/workplace/SentinelGuard/information/apk_dynamic/20260623_161412_527008_com.tencent.mobileqq/ui_trace`
- ui_trace_paths：`['E:/xinansai/workplace/SentinelGuard/information/apk_dynamic/20260623_161412_527008_com.tencent.mobileqq/ui_trace/com.tencent.mobileqq_launch_20260623_161412_529069.png', 'E:/xinansai/workplace/SentinelGuard/information/apk_dynamic/20260623_161412_527008_com.tencent.mobileqq/ui_trace/com.tencent.mobileqq_evidence_20260623_161413_199688.png']`

## 四点二、图结构分析
- 图结构状态：`API 图为空`；原因：已提取 CFG / FCG，但未识别到敏感 API 调用。
### CFG / FCG / API 调用图
- CFG 节点数：`0`
- CFG 边数：`0`
- FCG 节点数：`0`
- FCG 边数：`0`
- FCG 密度：`0.0000`
- API 调用图节点数：`0`
- API 调用图边数：`0`
- API 总调用数：`0`
- 敏感 API 调用分布：无

## 四点三、函数风险热力图
- 当前未生成可用的函数风险热力图数据。

## 四点四、一致性验证
> **🔍 一致性分析说明**：仲裁器通过比较静态/行为/情报三方的评分差异判断结论一致性。
> 一致性越高，证据链越稳固；一致性低时需重点关注被标记的「疑似污染」模块。

- 一致性分数：`100`
- 一致性等级：`HIGH`
- 分歧点：static-behavior 差异 0 分, static-intelligence 差异 0 分, behavior-intelligence 差异 0 分
- 被污染模块：无

## 四点五、鲁棒性分析
> **🛡️ 鲁棒性分析说明**：检测 APK 是否使用了防沙箱、混淆、反射、动态加载等对抗技术。
> 鲁棒性分数越高，说明样本越可能使用了规避分析的手段；分数越低，表示样本相对透明。

- 对抗技术：无
- 鲁棒性分数：`0.0`
- 抗干扰能力评估：**弱**

## 五、截图证据
- 当前未采集到页面截图。

## 六、风险证据
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
- 证据：`Subject=<asn1crypto.x509.Name 2653524318608 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>; Issuer=<asn1crypto.x509.Name 2653524313296 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; package.install; com.android.launcher2.permission; com.tencent.mobileqq; android.permission`
- 建议：后续可结合抓包或代理进行复核。

### 5. 疑似动态载荷释放
- 规则：`APK_DYNAMIC_PAYLOAD_DROP`
- 严重级别：`high`
- 说明：运行后在应用目录或临时目录中发现 dex、jar、apk、so、zip 等可疑落地文件。
- 证据：`./product/priv-app/ImsServiceEntitlement/ImsServiceEntitlement.apk; ./product/priv-app/SettingsIntelligenceGooglePrebuilt/SettingsIntelligenceGooglePrebuilt.apk; ./product/priv-app/WellbeingPrebuilt/WellbeingPrebuilt.apk; ./product/priv-app/PrebuiltGmsCore/PrebuiltGmsCore.apk; ./product/priv-app/GoogleRestorePrebuilt/GoogleRestorePrebuilt.apk; ./product/priv-app/Velvet/Velvet.apk; ./product/priv-app/DeviceIntelligenceNetworkPrebuilt/DeviceIntelligenceNetworkPrebuilt.apk; ./product/priv-app/OdadPrebuilt/OdadPrebuilt.apk; ./product/priv-app/DevicePersonalizationPrebuiltPixel2021/DevicePersonalizationPrebuiltPixel2021.apk; ./product/priv-app/AndroidAutoStubPrebuilt/AndroidAutoStubPrebuilt.apk`
- 建议：建议结合文件哈希、反编译和后续加载日志确认是否存在动态加载或脱壳行为。

### 6. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.apps.nexuslauncher][com.google.android.apps.wellbeing][com.android.systemui][com.tencent.mobileqq][com.google.android.apps.nexuslauncher][com.google.android.as][com.google.android.youtube][com.google.android.apps.youtube.music][com.google.android.packageinstaller][com.google.android.apps.nexuslauncher][com.google.android.inputmethod.latin][com.google.android.googlequicksearchbox][com.android.chrome]}]; 10: com.tencent.mobileqq; AppSettings: com.tencent.mobileqq (10202) importance=NONE userSet=false; 06-18 09:47:21.134 config: com.tencent.mobileqq|removeAutomaticZenRules no changes; 06-18 09:47:21.135 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules; 06-18 09:58:24.292 config: com.tencent.mobileqq|removeAutomaticZenRules no changes; 06-18 09:58:24.293 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules; 06-18 10:06:44.842 config: com.tencent.mobileqq|removeAutomaticZenRules no changes; 06-18 10:06:44.842 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules; 06-18 10:22:11.570 config: com.tencent.mobileqq|removeAutomaticZenRules no changes`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 7. 清单文件重复声明敏感权限
- 规则：`DEEP_APK_STATIC_DUPLICATE_PERMISSION`
- 严重级别：`high`
- 说明：动态沙箱日志显示AndroidManifest.xml存在重复权限声明（如android.permission.WRITE_CONTACTS），可能为注入痕迹。
- 证据：`logcat_excerpt: 'W/PackageParsing(  568): Ignoring duplicate uses-permissions/uses-permissions-sdk-m: android.permission.WRITE_CONTACTS in package: com.tencent.mobileqq at: Binary XML file line #84'`
- 建议：反编译确认AndroidManifest.xml完整性，排查非官方权限声明。

### 8. 证书主体与官方存疑
- 规则：`DEEP_APK_STATIC_CERTIFICATE_INTEGRITY`
- 严重级别：`medium`
- 说明：证书subject字段显示腾讯无线业务系统，但证书SHA256(1163ef54897fd8dfe3aa748d2a6c4d5f70e7e3b1e4633226baa0dbf7094dd237)需与官方发布版本比对。
- 证据：`certificate_sha256: 1163ef54897fd8dfe3aa748d2a6c4d5f70e7e3b1e4633226baa0dbf7094dd237`
- 建议：获取腾讯官方同版本APK进行证书摘要比对。

### 9. 应用注册设备策略服务 (Device Policy/Admin)
- 规则：`DEEP_APK_BEHAVIOR_PERSISTENCE_DEVICE_ADMIN`
- 严重级别：`high`
- 说明：动态沙箱监测到应用在运行时注册了设备策略服务，这通常与申请“设备管理器”权限相关。一旦激活，该权限允许应用执行锁屏、擦除数据、修改密码、禁止卸载等高权限操作，常被恶意软件用于持久化驻留和勒索。
- 证据：`动态沙箱系统服务日志显示该应用 (com.tencent.mobileqq) 出现在 device_policy 服务列表中: dynamic_summary.persistent_services.device_policy: ["10: com.tencent.mobileqq"]`
- 建议：严格审查应用申请设备管理器权限的必要性。除企业安全管理软件外，普通应用不应申请此权限，建议用户拒绝授权。

### 10. 签名主体看似官方但需对照信誉
- 规则：`DEEP_APK_INTEL_SIGNATURE_REPUTATION`
- 严重级别：`low`
- 说明：证书 Subject/Issuer 含“腾讯/无线业务系统/QQ”，形态符合厂商自签常见模式，但仅凭离线信息无法确认为官方发布证书。
- 证据：`certificate_subject/issuer 含 腾讯 与 QQ；certificate_sha256=1163ef54897fd8dfe3aa748d2a6c4d5f70e7e3b1e4633226baa0dbf7094dd237；APK sha256=a774efc81d5d5c197326a087aae1cadb7a1cb9d47893baa313cc1cc64e0316a6`
- 建议：与官方商店/官网公布的签名指纹与版本对照（证书指纹、包名、versionCode），仅信任来自官方渠道的安装包。

### 11. 包名正牌但文件名可疑需核验来源
- 规则：`DEEP_APK_INTEL_PACKAGE_IMPERSONATION_CHECK`
- 严重级别：`medium`
- 说明：包名 com.tencent.mobileqq 与官方一致，但文件名为临时名 tmpdj_r6rn2.apk，提升来源不明确的风险（侧载、转发或第三方站点下载）。
- 证据：`file_name=tmpdj_r6rn2.apk；package_name=com.tencent.mobileqq；version=9.3.1(14378)`
- 建议：核对下载来源（官方应用宝/官网/系统应用商店），比对版本与哈希；如来源不明，建议重新从官方渠道获取安装包。

### 12. 动态运行短时未见危险权限授予与明显恶意行为
- 规则：`DEEP_APK_INTEL_RUNTIME_OBSERVATIONS`
- 严重级别：`low`
- 说明：模拟器中安装/启动成功，未显示危险权限授予；logcat 出现完整性检查通过，网络命中未见明确可疑域名，存在解析器列出的 device_policy/accessibility 线索需二次确认。
- 证据：`dynamic: install_success=true, launch_success=true, runtime_window_seconds=12, granted_dangerous_permissions=[], logcat: "Integrity check passed"；persistent_services.device_policy=["10: com.tencent.mobileqq"], accessibility 列表包含 com.tencent.mobileqq`
- 建议：延长运行时长并在真机/登录后场景复测；核对应用是否真正声明设备管理或无障碍服务并要求用户开启，避免误报。

### 13. 本地库与动态网络栈较多，扩大行为面
- 规则：`DEEP_APK_INTEL_NATIVE_LIB_SURFACE`
- 严重级别：`medium`
- 说明：包含大量 native 库（音视频、网络、加密、Quic、定位等），潜在通过 JNI/动态加载实现复杂行为，静态图谱未构建导致细粒度路径未见。
- 证据：`示例: libQSec.so, libMSFKernel.so, librawquic_jni.so, libqimei.so, libtencentloc.so, libx5linker.so 等`
- 建议：在真机抓包与系统调用跟踪（Frida/ptrace/内核审计），并开启符号/脱壳后做 SAST 分析确认隐私与网络调用路径。

### 14. 当前离线与沙箱分析边界与盲区
- 规则：`DEEP_APK_INTEL_ANALYSIS_BOUNDARIES`
- 严重级别：`low`
- 说明：代码图谱未生成（CFG/FCG/API=0），动态运行仅 12 秒且在模拟器，未触发登录后行为/远端更新/反调试分支；无法对数据外传/广告 SDK 行为做定论。
- 证据：`graph_data 全为 0；dynamic runtime_window_seconds=12；未见明确网络 IOC`
- 建议：使用真机、延长运行、完成登录与典型场景（私聊/语音/视频/扫一扫/文件传输），抓取域名/IP/TLS 指纹；与官方版本差分比对代码与资源。

### 15. 结合来源与分发渠道做最终判定
- 规则：`DEEP_APK_INTEL_SOURCE_VALIDATION`
- 严重级别：`medium`
- 说明：当前证据更多指向官方构建，但来源未知和文件名可疑使重打包/投毒链仍需排除。
- 证据：`临时文件名 tmpdj_r6rn2.apk；static 分数 38（medium）；官方型签名但未与官方指纹交叉验证`
- 建议：仅从官方渠道（官网/应用宝/系统商店）下载；比对证书指纹与 APK 哈希；企业侧启用软件供应链校验（MAM/白名单）。

### 16. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 0 分; static-intelligence 差异 0 分; behavior-intelligence 差异 0 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 17. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`low`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`100`
- 建议：将该评分作为后续人工复核的重要参考。

### 18. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`low`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`0.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
主持人模型调用失败，已基于静态分析与已完成的四位专家意见完成本地归纳。综合风险等级为medium，风险分数为35分。主要专家意见：静态分析员：经静态分析发现，该样本为腾讯手机QQ官方应用（package_name为com.tencent.mobileqq），但动态沙箱检测到清单文件中存在重复权限声明（如RECORD_AUDIO、CAMERA等）及华为推送服务组件，需警惕第三方渠道篡改风险。关键证据：1) 签名证书显示主体为腾讯，但需核对官方证书摘要；2) 动态安装日志显示解析时重复权限警告（WRI；行为分析员：该样本为官方签名的腾讯QQ应用。静态分析显示其请求了大量敏感权限，并注册了多种系统服务与广播接收器，符合其作为大型即时通讯软件的功能定位。动态沙箱分析确认了应用可以成功安装和启动。关键行为证据在于，应用运行时注册了“辅助功能服务(Accessibility Service)”和“设备策略服务(Device Policy)”，这两种服务均授予了应用极高的系统控；情报分析员：目标为 APK（tmpdj_r6rn2.apk），包名 com.tencent.mobileqq，版本 9.3.1(14378)，体量约 404MB。签名证书 Subject/Issuer 显示“腾讯/无线业务系统/QQ”，整体更接近官方应用构建特征。静态侧请求的权限面较广（含录音、相机、定位、可能的安装/悬浮窗/查询所有包等高敏权限），从即时通讯/语音视频；处置建议员：模型返回原始内容（非标准JSON）: ```json
{
  "opinion": "根据现有静态和动态分析结果，该APK文件被识别为『com.tencent.mobileqq』，并带有腾讯公司签名。静态分析发现存在大量敏感权限请求，被标记为高风险，但这是主流通讯应用常见的功能需求。动态沙箱运行时，应用成功安装并启动，但运行时间较短（12秒），且在此期间未发。

### 静态分析员（模型：`deepseek-reasoner`）
经静态分析发现，该样本为腾讯手机QQ官方应用（package_name为com.tencent.mobileqq），但动态沙箱检测到清单文件中存在重复权限声明（如RECORD_AUDIO、CAMERA等）及华为推送服务组件，需警惕第三方渠道篡改风险。关键证据：1) 签名证书显示主体为腾讯，但需核对官方证书摘要；2) 动态安装日志显示解析时重复权限警告（WRITE_CONTACTS等）；3) 存在高敏权限如REQUEST_INSTALL_PACKAGES。建议结合证书SHA256与官方发布版本对比验证完整性。

### 行为分析员（模型：`gemini-2.5-pro`）
该样本为官方签名的腾讯QQ应用。静态分析显示其请求了大量敏感权限，并注册了多种系统服务与广播接收器，符合其作为大型即时通讯软件的功能定位。动态沙箱分析确认了应用可以成功安装和启动。关键行为证据在于，应用运行时注册了“辅助功能服务(Accessibility Service)”和“设备策略服务(Device Policy)”，这两种服务均授予了应用极高的系统控制与监控权限，例如读取屏幕内容、模拟用户操作、甚至设备管理（如锁屏、数据擦除）。此外，结合静态权限(REQUEST_INSTALL_PACKAGES)和动态日志(package.install)，应用具备应用内下载与安装更新的能力。尽管在本次短暂的沙箱运行中未观察到明确的恶意载荷下载或隐私窃取行为，但其获取的高权限服务和自我更新能力构成了潜在的风险敞口，若被利用或滥用，可能导致严重后果。综合判断，该应用行为符合其复杂功能所需，但高权限设计使其存在潜在风险。

### 情报分析员（模型：`gpt-5`）
目标为 APK（tmpdj_r6rn2.apk），包名 com.tencent.mobileqq，版本 9.3.1(14378)，体量约 404MB。签名证书 Subject/Issuer 显示“腾讯/无线业务系统/QQ”，整体更接近官方应用构建特征。静态侧请求的权限面较广（含录音、相机、定位、可能的安装/悬浮窗/查询所有包等高敏权限），从即时通讯/语音视频/扫码等业务角度存在一定合理性，但仍需与发行渠道和使用场景逐项核验。动态沙箱在模拟器中安装与启动成功，运行窗口仅约 12 秒，未见危险权限在运行时被授予，logcat 通过了完整性检查，未出现可归因的恶意网络 IOC；但沙箱记录中出现 device_policy 与 accessibility 列表包含 com.tencent.mobileqq 的线索，需要进一步人工复核其真实性和配置来源（可能为解析器枚举/系统状态噪声，而非确认为设备管理或无障碍滥用）。当前离线研判边界：1）代码图谱未能构建（CFG/FCG/API 图均为 0），对方法级行为、反射/动态加载和隐私调用路径无法给出确证；2）动态运行时间短且在模拟器环境，复杂功能（登陆后行为、运营域名、广告/更新插件、证书锁定/反调试分支）未被触发；3）证书/版本/哈希与官方对照尚未完成。综合判断：在未确认分发渠道与签名信誉前，维持中等风险提示，重点关注来源真伪与权限实际使用合规性。

### 处置建议员（模型：`gemini-2.5-flash`）
模型返回原始内容（非标准JSON）: ```json
{
  "opinion": "根据现有静态和动态分析结果，该APK文件被识别为『com.tencent.mobileqq』，并带有腾讯公司签名。静态分析发现存在大量敏感权限请求，被标记为高风险，但这是主流通讯应用常见的功能需求。动态沙箱运行时，应用成功安装并启动，但运行时间较短（12秒），且在此期间未发现有危险权限被授予，也未记录到明确的恶意网络通信行为。logcat中存在大量关于权限重复声明的警告，这是APK打包层面的问题，而非恶意行为指征。综合来看，如果此APK来自官方或可信来源，则其风险可控；若来源不明，仍需警惕其高危权限的潜在滥用风险。",
  "risk_hint": "medium",
  "additional_findings": [
    {
      "rule_id": "DEEP_APK_ADVICE_001",
      "title": "强烈建议核验APK分发来源",
      "severity": "high",
      "description": "该APK宣称是『com.tencent.mobileqq』，且签名信息显示为腾讯公司。但在未确定其具体分发渠道（如官方应用商店）的情况下，应将其视为潜在风险样本。恶意分子可能利用知名应用的包名和伪造签名进行混淆。",
      "evidence": "package_name: com.tencent.mobileqq; certificate_subject/issuer: Tencent; expert_opinions: 主持人、情报分析员均建议结合APK来源判断。",
      "recommendation": "在任何处置前，务必通过官方渠道（如腾讯应用宝、官方网站）获取该版本APK的SHA256哈希值，并与当前样本的SHA256（a774efc81d5d5c197326a087aae1cadb7a1cb9d47893baa313cc1cc64e0316a6）进行比对，以验证其真实性和完整性。"
    },
    {
      "rule_id": "DEEP_APK_ADVICE_002",
      "title": "敏感权限请求风险评估与必要性核实",
      "severity": "high",
      "d


### 主持人最终总结
主持人模型调用失败，已基于静态分析与已完成的四位专家意见完成本地归纳。综合风险等级为medium，风险分数为35分。主要专家意见：静态分析员：经静态分析发现，该样本为腾讯手机QQ官方应用（package_name为com.tencent.mobileqq），但动态沙箱检测到清单文件中存在重复权限声明（如RECORD_AUDIO、CAMERA等）及华为推送服务组件，需警惕第三方渠道篡改风险。关键证据：1) 签名证书显示主体为腾讯，但需核对官方证书摘要；2) 动态安装日志显示解析时重复权限警告（WRI；行为分析员：该样本为官方签名的腾讯QQ应用。静态分析显示其请求了大量敏感权限，并注册了多种系统服务与广播接收器，符合其作为大型即时通讯软件的功能定位。动态沙箱分析确认了应用可以成功安装和启动。关键行为证据在于，应用运行时注册了“辅助功能服务(Accessibility Service)”和“设备策略服务(Device Policy)”，这两种服务均授予了应用极高的系统控；情报分析员：目标为 APK（tmpdj_r6rn2.apk），包名 com.tencent.mobileqq，版本 9.3.1(14378)，体量约 404MB。签名证书 Subject/Issuer 显示“腾讯/无线业务系统/QQ”，整体更接近官方应用构建特征。静态侧请求的权限面较广（含录音、相机、定位、可能的安装/悬浮窗/查询所有包等高敏权限），从即时通讯/语音视频；处置建议员：模型返回原始内容（非标准JSON）: ```json
{
  "opinion": "根据现有静态和动态分析结果，该APK文件被识别为『com.tencent.mobileqq』，并带有腾讯公司签名。静态分析发现存在大量敏感权限请求，被标记为高风险，但这是主流通讯应用常见的功能需求。动态沙箱运行时，应用成功安装并启动，但运行时间较短（12秒），且在此期间未发。


## 六点一、角色结果说明
- **主持人**：已返回补齐后的研判结果。

## 七、仲裁结果
- 一致性分数：`100`
- 一致性等级：`high`
- 加权置信度：`45`
- 疑似污染源：无
- 分歧与模式：
  - static-behavior 差异 0 分
  - static-intelligence 差异 0 分
  - behavior-intelligence 差异 0 分

### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
