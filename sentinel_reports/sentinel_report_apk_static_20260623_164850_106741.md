# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**MEDIUM** · 风险分数：**38/100**
> 证据分数：**38/100** · 深度研判分数：**- /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\Lenovo\AppData\Local\Temp\tmptkikyigd.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：3 条
- 高危证据：1 条

## 二、统一 IR 摘要
- APK 文件：`tmptkikyigd.apk`
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

- 一致性分析结果：未获取到仲裁/一致性结果，但本次报告已显式展示缺失原因。
- 一致性分数：`-`
- 一致性等级：`-`
- 分歧点：未获取
- 被污染模块：未获取

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
- 证据：`Subject=<asn1crypto.x509.Name 2653133785808 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>; Issuer=<asn1crypto.x509.Name 2653346137872 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>`
- 建议：核对签名证书是否符合官方发布习惯。


## 七、论坛式协同研判
### 主持人（模型：`unknown`）
综合 4 条证据，当前风险等级需要结合 APK 来源继续判断。

### 静态分析员（模型：`unknown`）
APK 静态证据关注：存在敏感权限请求、存在持久化或高权限组件线索。

### 行为分析员（模型：`unknown`）
当前版本仅提供静态 APK 检测，未执行动态沙箱。

### 情报分析员（模型：`unknown`）
建议结合市场来源、签名证书与历史信誉进一步核验。

### 处置建议员（模型：`unknown`）
建议在隔离浏览器中复核最终域名，不在页面提交敏感信息。


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
