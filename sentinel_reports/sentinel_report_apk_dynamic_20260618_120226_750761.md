# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**HIGH** · 风险分数：**62/100**


## 一、检测结论
- 原始输入：`C:\Users\Lenovo\AppData\Local\Temp\tmp37urshe6.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：5 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260618_120131_061032.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260618_120131_061032.md

## 二、统一 IR 摘要
该对象类型尚未实现。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要
- device_id：emulator-5554
- package_name：com.zhihu.android
- static_file_name：tmp37urshe6.apk
- install_success：True
- launch_success：True
- event_count：2
- logcat_excerpt_count：18
- runtime_window_seconds：12
- dynamic_json_path：`C:/Users/Lenovo/AppData/Local/Temp/sentinelguard_dynamic/sentinel_apk_dynamic_com.zhihu.android_20260618_120226_618373.json`
- dynamic_json_name：`sentinel_apk_dynamic_com.zhihu.android_20260618_120226_618373.json`

## 五、风险证据
### 1. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。
- 证据：`manifest: AndroidManifest.xml; resource: assets/Night_Tabbar_Feed.json; resource: assets/Night_Tabbar_More.json; resource: assets/Night_Tabbar_Notifications.json; resource: assets/Night_Tabbar_Shop.json; resource: assets/Night_Tabbar_Video.json; resource: assets/Night_Tabbar_explore2_Feed.json; resource: assets/Night_Tabbar_explore2_Friend.json; resource: assets/Night_Tabbar_explore2_More.json; resource: assets/Night_Tabbar_explore2_Notifications.json; resource: assets/Night_Tabbar_explore2_Shop.json; resource: assets/Ogv_UIConfig.json`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 存在敏感权限请求
- 规则：`APK_SUSPICIOUS_PERMISSION`
- 严重级别：`high`
- 说明：安装包请求了短信、联系人、录音、安装或辅助功能等高敏权限。
- 证据：`android.permission.ACCESS_FINE_LOCATION, android.permission.CAMERA, android.permission.QUERY_ALL_PACKAGES, android.permission.READ_CONTACTS, android.permission.RECORD_AUDIO, android.permission.REQUEST_INSTALL_PACKAGES, android.permission.SYSTEM_ALERT_WINDOW`
- 建议：确认权限是否与业务功能一致，避免授予不必要权限。

### 3. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 1418914686288 b'0g1\x0b0\t\x06\x03U\x04\x06\x13\x02CN1\x0f0\r\x06\x03U\x04\x08\x13\x06Peking1\x0f0\r\x06\x03U\x04\x07\x13\x06Peking1\x120\x10\x06\x03U\x04\n\x13\tzhihu.com1\x120\x10\x06\x03U\x04\x0b\x13\tzhihu.com1\x0e0\x0c\x06\x03U\x04\x03\x13\x05Zhihu'>; Issuer=<asn1crypto.x509.Name 1418723435088 b'0g1\x0b0\t\x06\x03U\x04\x06\x13\x02CN1\x0f0\r\x06\x03U\x04\x08\x13\x06Peking1\x0f0\r\x06\x03U\x04\x07\x13\x06Peking1\x120\x10\x06\x03U\x04\n\x13\tzhihu.com1\x120\x10\x06\x03U\x04\x0b\x13\tzhihu.com1\x0e0\x0c\x06\x03U\x04\x03\x13\x05Zhihu'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. 存在持久化或高权限组件线索
- 规则：`APK_PERSISTENT_COMPONENTS`
- 严重级别：`medium`
- 说明：组件名称显示可能存在开机自启、管理器或辅助功能相关入口。
- 证据：`com.taobao.accs.internal.AccsJobService; com.xiaomi.push.service.XMJobService; com.zhihu.android.app.jobservice.AdTracksPushService`
- 建议：检查这些组件是否会在后台持续运行或触发敏感动作。

### 5. 未发现明显运行时异常
- 规则：`APK_DYNAMIC_BASELINE`
- 严重级别：`low`
- 说明：模拟器沙箱窗口内未观察到明显崩溃、ANR 或可疑联网线索。
- 证据：`com.zhihu.android`
- 建议：建议结合更长窗口或加入抓包/权限交互复测。


## 六、论坛式协同研判
### 主持人（模型：`local-adb-sandbox`）
APK 动态沙箱已完成，包名 com.zhihu.android 在运行窗口内的风险提示为 low。

### 静态分析员（模型：`local-adb-sandbox`）
动态证据与静态预检结果可交叉验证，重点关注崩溃、异常权限和可疑网络线索。

### 行为分析员（模型：`local-adb-sandbox`）
当前版本基于模拟器 logcat 与安装启动线索做最小动态采集，后续可继续扩展抓包和文件监控。

### 情报分析员（模型：`local-adb-sandbox`）
运行时结果主要来自本地沙箱环境，仍建议结合样本来源与分发渠道做外部复核。

### 处置建议员（模型：`local-adb-sandbox`）
建议在隔离环境继续复测，并根据动态证据决定是否阻断分发或进一步逆向。


### 主持人最终总结
APK 动态沙箱完成，采集到 2 条运行时线索。


### 专家模型映射
- 主持人：`local-adb-sandbox`
- 静态分析员：`local-adb-sandbox`
- 行为分析员：`local-adb-sandbox`
- 情报分析员：`local-adb-sandbox`
- 处置建议员：`local-adb-sandbox`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
