# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**HIGH** · 风险分数：**61/100**


## 一、检测结论
- 原始输入：`C:\Users\Lenovo\AppData\Local\Temp\tmp2wvw2m2g.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：4 条
- 高危证据：1 条

## 二、统一 IR 摘要
该对象类型尚未实现。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要

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
- 证据：`Subject=<asn1crypto.x509.Name 1841811174928 b'0g1\x0b0\t\x06\x03U\x04\x06\x13\x02CN1\x0f0\r\x06\x03U\x04\x08\x13\x06Peking1\x0f0\r\x06\x03U\x04\x07\x13\x06Peking1\x120\x10\x06\x03U\x04\n\x13\tzhihu.com1\x120\x10\x06\x03U\x04\x0b\x13\tzhihu.com1\x0e0\x0c\x06\x03U\x04\x03\x13\x05Zhihu'>; Issuer=<asn1crypto.x509.Name 1841811175184 b'0g1\x0b0\t\x06\x03U\x04\x06\x13\x02CN1\x0f0\r\x06\x03U\x04\x08\x13\x06Peking1\x0f0\r\x06\x03U\x04\x07\x13\x06Peking1\x120\x10\x06\x03U\x04\n\x13\tzhihu.com1\x120\x10\x06\x03U\x04\x0b\x13\tzhihu.com1\x0e0\x0c\x06\x03U\x04\x03\x13\x05Zhihu'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. 存在持久化或高权限组件线索
- 规则：`APK_PERSISTENT_COMPONENTS`
- 严重级别：`medium`
- 说明：组件名称显示可能存在开机自启、管理器或辅助功能相关入口。
- 证据：`com.taobao.accs.internal.AccsJobService; com.xiaomi.push.service.XMJobService; com.zhihu.android.app.jobservice.AdTracksPushService`
- 建议：检查这些组件是否会在后台持续运行或触发敏感动作。


## 六、论坛式协同研判
### 主持人（模型：`unknown`）
综合 4 条证据，当前风险等级需要结合 APK 来源继续判断。

### 静态分析员（模型：`unknown`）
APK 静态证据关注：存在敏感权限请求、存在持久化或高权限组件线索。

### 行为分析员（模型：`unknown`）
当前版本仅提供静态 APK 检测，未执行动态沙箱。

### 情报分析员（模型：`unknown`）
建议结合市场来源、签名证书与历史信誉进一步核验。

### 处置建议员（模型：`unknown`）
建议阻断访问，不输入账号密码，不下载或运行页面提供的文件，并保留链接与报告用于复核。


## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
