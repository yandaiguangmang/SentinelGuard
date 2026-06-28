# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**MEDIUM** · 风险分数：**30/100**
> 证据分数：**50/100** · 深度研判分数：**35 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\Lenovo\AppData\Local\Temp\tmpbeut75uw.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：14 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260623_164110_695713.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260623_164110_695713.md

## 二、统一 IR 摘要
- APK 文件：`tmpbeut75uw.apk`
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

- 一致性分数：`83`
- 一致性等级：`HIGH`
- 分歧点：static-behavior 差异 25 分, static-intelligence 差异 0 分, behavior-intelligence 差异 25 分
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
- 证据：`Subject=<asn1crypto.x509.Name 2653531511248 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>; Issuer=<asn1crypto.x509.Name 2653525372944 b'0m1\x0e0\x0c\x06\x03U\x04\x06\x13\x05China1\x0f0\r\x06\x03U\x04\x08\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\x07\x0c\x06\xe5\x8c\x97\xe4\xba\xac1\x0f0\r\x06\x03U\x04\n\x0c\x06\xe8\x85\xbe\xe8\xae\xaf1\x1b0\x19\x06\x03U\x04\x0b\x0c\x12\xe6\x97\xa0\xe7\xba\xbf\xe4\xb8\x9a\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f1\x0b0\t\x06\x03U\x04\x03\x13\x02QQ'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. assets 下发配置文件
- 规则：`DEEP_APK_STATIC_002`
- 严重级别：`medium`
- 说明：assets 目录存在多个 JSON 文件（如4006001.json），可能与动态功能配置相关，攻击者可能滥用此类机制远程加载指令。
- 证据：`resource: assets/4006001/4006001.json, assets/4006002/4006002.json, ...`
- 建议：反编译 DEX 代码验证资源加载逻辑是否受控，检查 JSON 内容是否加密或校验。

### 5. 签名主题与腾讯 QQ 特征相符（需指纹校验）
- 规则：`DEEP_APK_INTEL_SIGNING_SUBJECT_MATCH_HINT`
- 严重级别：`medium`
- 说明：证书主题包含 C=China, ST=北京, L=北京, O=腾讯, OU=无线业务系统, CN=QQ 等字段，形式与腾讯 QQ 官方签名常见主体相符，但仅凭主题不可证明真伪，仍需比对证书指纹。
- 证据：`certificate_subject: <asn1crypto ... CN=QQ>; certificate_sha256: c6f9f8a4030d44a1252ff28ea5389c67800d48ac35e14b4c68ab03bd6a9977d8`
- 建议：使用 apksigner/Keytool 提取签名证书指纹（SHA-256），与官方渠道（官网/主流应用商店已安装版本）已知指纹比对；若不一致或无法验证来源，按高风险处理。

### 6. 包名为广泛知名应用（com.tencent.mobileqq）
- 规则：`DEEP_APK_INTEL_PACKAGE_WELL_KNOWN_APP`
- 严重级别：`low`
- 说明：包名对应腾讯 QQ，较高知名度降低伪造门槛但也常被仿冒/二次打包。
- 证据：`package_name: com.tencent.mobileqq; version_name: 9.3.1; version_code: 14378; sha256: a774efc81d5d5c197326a087aae1cadb7a1cb9d47893baa313cc1cc64e0316a6`
- 建议：优先从官方商店/官网获取安装包；对侧载文件校验 APK 与证书指纹；若需替换升级，验证与既有官方安装包签名一致。

### 7. 语音/音视频能力相关资产存在
- 规则：`DEEP_APK_INTEL_AUDIO_VIDEO_ASSETS`
- 严重级别：`low`
- 说明：资产包含 GCloudVoice 配置、DoraemonApiGroup 等，印证语音/多媒体能力需求，解释 RECORD_AUDIO 等权限。
- 证据：`assets: assets/GCloudVoice/config.json, assets/DoraemonApiGroup.json, assets/4006xxx.json`
- 建议：结合业务确认语音采集实现与最小权限原则，确保麦克风、相机访问有明确的用户触发与前台指示。

### 8. 代码/API 图为空，静态语义分析受限
- 规则：`DEEP_APK_INTEL_ANALYSIS_GAP_NO_CODE_GRAPH`
- 严重级别：`high`
- 说明：CFG/FCG/API 图节点为 0，无法展开方法级调用链与敏感 API 证据，当前结论主要基于 Manifest/资源与签名元数据。
- 证据：`graph_data.stats: cfg_node_count=0, fcg_node_count=0, api_graph_node_count=0`
- 建议：复核解包/反编译流程（可能因包体大、multidex或保护导致）；启用备选反编译器并开展动态沙箱测试，获取实际联网、权限调用与组件交互行为。

### 9. 分发来源不明（本地临时目录）
- 规则：`DEEP_APK_INTEL_PROVENANCE_UNKNOWN`
- 严重级别：`high`
- 说明：样本来自本机临时路径，无法据此确认下载渠道与供应链可信度，供应链/二次打包风险不可忽视。
- 证据：`original_input: C:\Users\Lenovo\AppData\Local\Temp\tmpbeut75uw.apk`
- 建议：仅从官方商店/官网获取；核验 APK SHA-256 与签名指纹；保留获取链条（下载页、证书、时间戳）以供合规追溯。

### 10. APK 体积较大，疑似通用包（包含多架构/资源）
- 规则：`DEEP_APK_INTEL_APK_SIZE_PROFILE`
- 严重级别：`low`
- 说明：约 404 MB，符合大型 IM 应用整合多架构/语音视频/推送 SDK 的体量特征，非独立恶意指标。
- 证据：`size_bytes: 403,996,641; 多厂商服务与多媒体资产存在`
- 建议：若使用官方分发渠道可接受；企业侧优先选择官方分包/应用商店分发的按需包以降低攻击面与更新成本。

### 11. 基于来源与签名一致性进行风险分级
- 规则：`DEEP_APK_INTEL_SOURCE_BASED_RISK_ESCALATION`
- 严重级别：`medium`
- 说明：若证书指纹与官方已知值一致且来源可信，权限虽多但属功能需要，整体风险趋低；若来源可疑或签名不匹配，二打/投毒风险显著升高。
- 证据：`certificate_sha256: c6f9f8a4...；包名与版本：com.tencent.mobileqq 9.3.1；未知分发渠道`
- 建议：比对证书指纹/版本号与官方发布；必要时在已安装官方 QQ 的设备上进行签名一致性校验（不同签名无法覆盖安装）；不可信来源样本置隔离区动态分析。

### 12. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 25 分; static-intelligence 差异 0 分; behavior-intelligence 差异 25 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 13. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`low`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`83`
- 建议：将该评分作为后续人工复核的重要参考。

### 14. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`low`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`0.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
主持人模型调用失败，已基于静态分析与已完成的四位专家意见完成本地归纳。综合风险等级为medium，风险分数为35分。主要专家意见：静态分析员：APK 为 com.tencent.mobileqq (QQ 手机版) 的官方应用，签名证书 Subject 显示为 Tencent（腾讯），与中国区证书一致。然而静态分析发现高敏感权限请求：RECORD_AUDIO、ACCESS_FINE_LOCATION、CAMERA 等，且提取的字符串包含随机化字符序列（如."n< ;），需关注是否用于命令拼接或动态混；行为分析员：该应用（包名com.tencent.mobileqq）静态分析显示其具备复杂的后台行为能力和强大的隐私数据访问权限。应用通过集成多种推送SDK（如华为、OPPO），能够被远程唤醒并在后台驻留。其申请了包括“请求安装应用包”(REQUEST_INSTALL_PACKAGES)、“录音”(RECORD_AUDIO)、“相机”(CAMERA)、“读取联系人”(RE；情报分析员：该 APK 声称为 com.tencent.mobileqq (QQ) v9.3.1，包体较大且包含语音/推送等典型组件；签名主题字段与腾讯 QQ 常见信息相符（C=China, ST=北京, L=北京, O=腾讯, OU=无线业务系统, CN=QQ）。静态证据显示申请了音视频、定位、联系人、安装包管理、悬浮窗、查询已装应用等敏感权限。此类权限与即时通信/音；处置建议员：模型返回原始内容（非标准JSON）: ```json
{
  "opinion": "该APK声称是腾讯QQ（com.tencent.mobileqq），且签名证书显示为腾讯。然而，它请求了包括SYSTEM_ALERT_WINDOW、RECORD_AUDIO、ACCESS_FINE_LOCATION、QUERY_ALL_PACKAGES在内的多项高危敏感权限。

### 静态分析员（模型：`deepseek-reasoner`）
APK 为 com.tencent.mobileqq (QQ 手机版) 的官方应用，签名证书 Subject 显示为 Tencent（腾讯），与中国区证书一致。然而静态分析发现高敏感权限请求：RECORD_AUDIO、ACCESS_FINE_LOCATION、CAMERA 等，且提取的字符串包含随机化字符序列（如."n< ;），需关注是否用于命令拼接或动态混淆。assets 下的 JSON 配置文件名序列化（4006001.json 等）需复核是否嵌入指令配置文件。

### 行为分析员（模型：`gemini-2.5-pro`）
该应用（包名com.tencent.mobileqq）静态分析显示其具备复杂的后台行为能力和强大的隐私数据访问权限。应用通过集成多种推送SDK（如华为、OPPO），能够被远程唤醒并在后台驻留。其申请了包括“请求安装应用包”(REQUEST_INSTALL_PACKAGES)、“录音”(RECORD_AUDIO)、“相机”(CAMERA)、“读取联系人”(READ_CONTACTS)和“精确定位”(ACCESS_FINE_LOCATION)在内的一组高危权限。此权限组合构成了潜在的恶意行为链：可通过推送指令被唤醒 -> 利用权限进行录音、拍照、定位等监视行为 -> 窃取联系人等隐私数据 -> 联网下载新的APK并诱导用户安装，实现恶意代码的持久化和进一步传播。尽管这些功能可能服务于大型即时通讯应用的正常业务，但从恶意软件分析角度看，其潜在滥用风险极高。

### 情报分析员（模型：`gpt-5`）
该 APK 声称为 com.tencent.mobileqq (QQ) v9.3.1，包体较大且包含语音/推送等典型组件；签名主题字段与腾讯 QQ 常见信息相符（C=China, ST=北京, L=北京, O=腾讯, OU=无线业务系统, CN=QQ）。静态证据显示申请了音视频、定位、联系人、安装包管理、悬浮窗、查询已装应用等敏感权限。此类权限与即时通信/音视频通话/文件分享/设备兼容适配等业务存在合理性，但同样提升攻击面。当前离线分析存在显著边界：代码/API 图为 0，未能展开方法级静态语义，未做动态沙箱与联网行为验证；证书指纹与官方指纹未在此离线环境中完成权威比对；样本来源路径为本地临时目录（Temp），分发渠道未知。因此仅凭现有静态迹象无法给出确定的恶意结论，风险主要取决于来源与签名指纹是否匹配官方。建议以来源与分发渠道为主线：仅从官方商店/官网获取，核对 APK 与签名证书指纹与已知官方值一致；若签名/来源不一致，需按高风险处置。

### 处置建议员（模型：`gemini-2.5-flash`）
模型返回原始内容（非标准JSON）: ```json
{
  "opinion": "该APK声称是腾讯QQ（com.tencent.mobileqq），且签名证书显示为腾讯。然而，它请求了包括SYSTEM_ALERT_WINDOW、RECORD_AUDIO、ACCESS_FINE_LOCATION、QUERY_ALL_PACKAGES在内的多项高危敏感权限。静态分析无法确认其行为是否与声称功能一致或存在恶意活动。由于缺失动态沙箱分析，其真实意图和潜在风险未能完全暴露。强烈建议对该样本进行隔离安装与沙箱复核，并在确认其安全或官方真实性之前，暂停其分发。",
  "risk_hint": "medium",
  "additional_findings": [
    {
      "rule_id": "DEEP_APK_ADVICE_SENSITIVE_PERMISSIONS",
      "title": "存在高危敏感权限请求，需沙箱复核",
      "severity": "high",
      "description": "该APK请求了大量高危敏感权限，包括录音、精确定位、摄像头、查询所有应用、读写联系人、请求安装应用、以及系统浮窗权限（`SYSTEM_ALERT_WINDOW`）。这些权限常被恶意软件滥用进行监听、数据窃取、应用伪造或实施覆盖攻击。",
      "evidence": "权限列表：android.Manifest.permission.RECORD_AUDIO, android.permission.ACCESS_FINE_LOCATION, android.permission.CAMERA, android.permission.FOREGROUND_SERVICE_CAMERA, android.permission.QUERY_ALL_PACKAGES, android.permission.READ_CONTACTS, android.permission.REQUEST_INSTALL_PACKAGES, android.permission.SYSTEM_ALERT_WINDOW, android.permission.WRITE_CONTACTS。",
      "recommendation": "强烈建议隔离安装，并在安全沙箱环境中进


### 主持人最终总结
主持人模型调用失败，已基于静态分析与已完成的四位专家意见完成本地归纳。综合风险等级为medium，风险分数为35分。主要专家意见：静态分析员：APK 为 com.tencent.mobileqq (QQ 手机版) 的官方应用，签名证书 Subject 显示为 Tencent（腾讯），与中国区证书一致。然而静态分析发现高敏感权限请求：RECORD_AUDIO、ACCESS_FINE_LOCATION、CAMERA 等，且提取的字符串包含随机化字符序列（如."n< ;），需关注是否用于命令拼接或动态混；行为分析员：该应用（包名com.tencent.mobileqq）静态分析显示其具备复杂的后台行为能力和强大的隐私数据访问权限。应用通过集成多种推送SDK（如华为、OPPO），能够被远程唤醒并在后台驻留。其申请了包括“请求安装应用包”(REQUEST_INSTALL_PACKAGES)、“录音”(RECORD_AUDIO)、“相机”(CAMERA)、“读取联系人”(RE；情报分析员：该 APK 声称为 com.tencent.mobileqq (QQ) v9.3.1，包体较大且包含语音/推送等典型组件；签名主题字段与腾讯 QQ 常见信息相符（C=China, ST=北京, L=北京, O=腾讯, OU=无线业务系统, CN=QQ）。静态证据显示申请了音视频、定位、联系人、安装包管理、悬浮窗、查询已装应用等敏感权限。此类权限与即时通信/音；处置建议员：模型返回原始内容（非标准JSON）: ```json
{
  "opinion": "该APK声称是腾讯QQ（com.tencent.mobileqq），且签名证书显示为腾讯。然而，它请求了包括SYSTEM_ALERT_WINDOW、RECORD_AUDIO、ACCESS_FINE_LOCATION、QUERY_ALL_PACKAGES在内的多项高危敏感权限。


## 六点一、角色结果说明
- **主持人**：已返回补齐后的研判结果。

## 七、仲裁结果
- 一致性分数：`83`
- 一致性等级：`high`
- 加权置信度：`52`
- 疑似污染源：无
- 分歧与模式：
  - static-behavior 差异 25 分
  - static-intelligence 差异 0 分
  - behavior-intelligence 差异 25 分

### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
