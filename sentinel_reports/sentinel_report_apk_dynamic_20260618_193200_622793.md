# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**HIGH** · 风险分数：**70/100**


## 一、检测结论
- 原始输入：`C:\Users\Lenovo\AppData\Local\Temp\tmp4lfdsq3y.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：6 条
- 高危证据：2 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260618_193137_251539.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260618_193137_251539.md

## 二、统一 IR 摘要
该对象类型尚未实现。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要
- device_id：emulator-5554
- package_name：com.tencent.mobileqq
- static_file_name：tmp4lfdsq3y.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.tencent.mobileqq/.activity.SplashActivity
- pidof：
- granted_dangerous_permissions：无
- post_install_files：无
- persistent_services：{'device_policy': ['10: com.tencent.mobileqq'], 'notification': ['AppSettings: com.tencent.mobileqq (10200) importance=NONE userSet=false', '06-18 09:47:21.134 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 09:47:21.135 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 09:58:24.292 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 09:58:24.293 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 10:06:44.842 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 10:06:44.842 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', '06-18 10:22:11.570 config: com.tencent.mobileqq|removeAutomaticZenRules no changes', '06-18 10:22:11.570 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules', 'userId=0 value={com.google.android.apps.diagnosticstool, io.va.exposed64, com.google.android.as/com.google.android.apps.miphone.aiai.common.notification.service.AiAiNotificationAssistantService, com.google.android.apps.safetyhub, com.google.android.as, com.google.intelligence.sense, com.google.android.apps.wellbeing, com.google.android.dialer, com.google.android.gms, com.tencent.mobileqq, com.google.android.apps.nexuslauncher, com.zhihu.android, com.google.android.settings.intelligence, com.google.android.GoogleCamera}']}
- install_success：True
- launch_success：True
- event_count：78
- logcat_excerpt_count：376
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`C:/Users/Lenovo/AppData/Local/Temp/sentinelguard_dynamic/sentinel_apk_dynamic_com.tencent.mobileqq_20260618_193200_612260.json`
- dynamic_json_name：`sentinel_apk_dynamic_com.tencent.mobileqq_20260618_193200_612260.json`

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
- 证据：`Subject=<asn1crypto.x509.Name 2286691536272 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>; Issuer=<asn1crypto.x509.Name 2286691393616 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. 存在持久化或高权限组件线索
- 规则：`APK_PERSISTENT_COMPONENTS`
- 严重级别：`medium`
- 说明：组件名称显示可能存在开机自启、管理器或辅助功能相关入口。
- 证据：`com.tencent.mobileqq.msf.service.MSFAliveJobService; com.xiaomi.push.service.XMJobService`
- 建议：检查这些组件是否会在后台持续运行或触发敏感动作。

### 5. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`settings.get.glo; com.android.launcher2.permission; com.tencent.mobileqq; android.permission; com.tencent.msf.permission.account.sync`
- 建议：后续可结合抓包或代理进行复核。

### 6. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`10: com.tencent.mobileqq; AppSettings: com.tencent.mobileqq (10200) importance=NONE userSet=false; 06-18 09:47:21.134 config: com.tencent.mobileqq|removeAutomaticZenRules no changes; 06-18 09:47:21.135 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules; 06-18 09:58:24.292 config: com.tencent.mobileqq|removeAutomaticZenRules no changes; 06-18 09:58:24.293 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules; 06-18 10:06:44.842 config: com.tencent.mobileqq|removeAutomaticZenRules no changes; 06-18 10:06:44.842 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules; 06-18 10:22:11.570 config: com.tencent.mobileqq|removeAutomaticZenRules no changes; 06-18 10:22:11.570 set_zen_mode: off,com.tencent.mobileqq|removeAutomaticZenRules`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。


## 六、论坛式协同研判
### 主持人（模型：`local-adb-sandbox`）
APK 动态沙箱已完成，包名 com.tencent.mobileqq 在运行窗口内的风险提示为 high。

### 静态分析员（模型：`local-adb-sandbox`）
动态证据与静态预检结果可交叉验证，重点关注崩溃、异常权限和可疑网络线索。

### 行为分析员（模型：`local-adb-sandbox`）
当前版本基于模拟器 logcat、权限、文件落地与系统服务状态做轻量动态采集。

### 情报分析员（模型：`local-adb-sandbox`）
运行时结果主要来自本地沙箱环境，仍建议结合样本来源与分发渠道做外部复核。

### 处置建议员（模型：`local-adb-sandbox`）
建议在隔离环境继续复测，并根据动态证据决定是否阻断分发或进一步逆向。


### 主持人最终总结
APK 动态沙箱完成，采集到 78 条运行时线索。


### 专家模型映射
- 主持人：`local-adb-sandbox`
- 静态分析员：`local-adb-sandbox`
- 行为分析员：`local-adb-sandbox`
- 情报分析员：`local-adb-sandbox`
- 处置建议员：`local-adb-sandbox`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
