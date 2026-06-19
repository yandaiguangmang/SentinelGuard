# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**MEDIUM** · 风险分数：**29/100**

## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpygsiwkgy.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：2 条
- 高危证据：0 条

## 二、统一 IR 摘要
该对象类型尚未实现。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、浏览器证据 / 截图

## 五、风险证据
### 1. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。
- 证据：`manifest: AndroidManifest.xml; resource: assets/Night_Tabbar_Feed.json; resource: assets/Night_Tabbar_More.json; resource: assets/Night_Tabbar_Notifications.json; resource: assets/Night_Tabbar_Shop.json; resource: assets/Night_Tabbar_Video.json; resource: assets/Night_Tabbar_explore2_Feed.json; resource: assets/Night_Tabbar_explore2_Friend.json; resource: assets/Night_Tabbar_explore2_More.json; resource: assets/Night_Tabbar_explore2_Notifications.json; resource: assets/Night_Tabbar_explore2_Shop.json; resource: assets/Ogv_UIConfig.json`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 未解析到包名
- 规则：`APK_MISSING_PACKAGE`
- 严重级别：`medium`
- 说明：APK 中未能提取出明确的包名，样本身份不够清晰。
- 证据：`tmpygsiwkgy.apk`
- 建议：补充样本来源与签名信息后再复核。


## 六、论坛式协同研判
### 主持人（模型：`unknown`）
综合 2 条证据，当前风险等级需要结合 APK 来源继续判断。

### 静态分析员（模型：`unknown`）
APK 静态证据关注：未解析到包名。

### 行为分析员（模型：`unknown`）
当前版本仅提供静态 APK 检测，未执行动态沙箱。

### 情报分析员（模型：`unknown`）
建议结合市场来源、签名证书与历史信誉进一步核验。

### 处置建议员（模型：`unknown`）
建议在隔离浏览器中复核最终域名，不在页面提交敏感信息。


## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
