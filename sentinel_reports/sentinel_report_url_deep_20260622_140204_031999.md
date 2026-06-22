# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**95/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：15 条
- 高危证据：7 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_140117_784005.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_140117_784005.md

## 二、统一 IR 摘要
- 规范化 URL：`https://baksmany.net/zh/`
- 协议：`https`
- 主机：`baksmany.net`
- 路径：`/zh/`
- 查询参数数量：`0`

## 三、跳转链
- https://baksmany.net/zh/

## 四、页面线索
- status_code：200
- content_type：text/html; charset=UTF-8
- final_url：https://baksmany.net/zh/
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://127.0.0.1:7897', 'https': 'http://127.0.0.1:7897', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- title：数字货币兑换，买卖比特币
- visible_text_excerpt：数字货币兑换，买卖比特币 (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem('slow_connection_detected')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem('slow_connection_detected', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( 'load', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码 → 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全书 常见问题 AML 我的申请单 设置 平衡 推
- password_forms：4
- hidden_inputs：1
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<!DOCTYPE html> <html lang="zh"> <head> <meta charset="UTF-8"/> <meta content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0" name="viewport"/> <meta content="ie=edge" http-equiv="X-UA-Compatible"/> <title>数字货币兑换，买卖比特币</title> <meta name="description" content="买卖比特币以及进行比特币兑换，提供了Baksmany.net兑换服务。 该交换器具有大量的储备，并提供了高速度的应用程序执行。" /> <meta name="keywords" content="交换器，比特币交换，比特币到qiwi，数字货币交换器，电子货币交换器，购买比特币，出售比特币" /> <meta name="format-detection" content="telephone=no"> <link rel="icon" href="/favicon-logo2.png"> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/chosen.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/style.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/exchangebox/select2/css/select2.min.css?v=15" /> <script> (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', () => clearInterval(', 'text_excerpt': '数字货币兑换，买卖比特币 (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码 → 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全书 常见问题 AML 我的申请单 设置 平衡 推'}
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': None, 'whois_creation_date': '2024-10-21T15:02:27Z', 'whois_age_days': 608}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 域名注册时间：`2024-10-21T15:02:27Z`
- 域名注册天数：`608` 天

## 五、截图证据
- 截图数量：`1` 张，完整图像请查看 HTML 报告。
- 截图 1：
  - URL：`https://baksmany.net/zh/`
  - 最终地址：`https://baksmany.net/zh/`
  - 大小：`562901` 字节
  - 视口：`{'width': 1440, 'height': 1600}`

## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 20 天前。
- 证据：`Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`medium`
- 说明：密码表单提交与当前域名一致或为相对路径，可能为正常登录功能。
- 证据：`密码框数量: 4`
- 建议：确认域名归属和证书可信后再输入账号密码。

### 3. 可疑的页面加载诱导行为
- 规则：`DEEP_STATIC_SUSPICIOUS_JS_BEHAVIOR`
- 严重级别：`high`
- 说明：页面通过 setTimeout 强制弹出 confirm 对话框，诱导用户跳转至所谓的“轻版网站”，这种行为常用于规避安全扫描或引导用户进入更易于实施钓鱼攻击的页面。
- 证据：`代码片段: setTimeout(() => { ... confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); ... }, 20000);`
- 建议：严禁在该网站输入任何敏感信息，建议将其列入高风险名单。

### 4. 异常的密码输入框密度
- 规则：`DEEP_STATIC_MULTIPLE_PASSWORD_FORMS`
- 严重级别：`high`
- 说明：页面中存在 4 个密码输入框，对于一个简单的兑换平台而言，这种布局极不寻常，极有可能是为了在不同场景下诱导用户输入密码以进行凭据窃取。
- 证据：`密码框数量: 4`
- 建议：此类布局高度可疑，建议进行深度流量分析以确认表单提交的目标地址。

### 5. 域名注册信息分析
- 规则：`INTEL_INFRA_DOMAIN`
- 严重级别：`medium`
- 说明：该域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，注册时间为 608 天，显示出相对年轻的特征。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 域名存在天数: 608`
- 建议：建议进一步调查该注册商的声誉及其与恶意活动的关联性。

### 6. TLS 证书分析
- 规则：`INTEL_INFRA_CERTIFICATE`
- 严重级别：`medium`
- 说明：该网页的 TLS 证书签发时间较短，可能影响其可信度。
- 证据：`证书签发于 20 天前。`
- 建议：建议结合其他证据综合判断该网站的安全性。

### 7. 涉嫌加密货币诈骗与非法汇兑诱导
- 规则：`DEEP_BEHAVIOR_CRYPTO_SCAM_LURE`
- 严重级别：`high`
- 说明：页面包含“零手续费支付卢布账单”、“直接从USDT余额中扣除”、“上传卢布QR码”等极具诱惑性的异常金融交易话术，属于典型的加密货币诈骗或非法资金盘特征。
- 证据：`可见文本：“朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码 → 选择私人支付服务！”`
- 建议：极高风险，切勿在此类网站上传任何付款二维码、连接加密货币钱包、进行转账或输入账号密码。

### 8. 页面构建粗糙（暴露JS代码）
- 规则：`DEEP_BEHAVIOR_POOR_CONSTRUCTION`
- 严重级别：`low`
- 说明：页面可见文本中直接暴露了未正确解析或转义的JavaScript代码，表明网站开发质量低下，这种粗制滥造的现象常见于生命周期短的诈骗或钓鱼网站。
- 证据：`可见文本包含原始代码：“(function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem('slow_connection_detected'));...”`
- 建议：结合其提供的敏感金融服务，此类低质量页面进一步降低了网站的可信度，建议直接拦截。

### 9. 建议立即拦截访问
- 规则：`DEEP_ADVICE_BLOCK_CRITICAL`
- 严重级别：`critical`
- 说明：该网站具备典型的钓鱼与加密货币诈骗特征，包括诱导性金融话术、异常的密码输入框密度以及粗糙的页面构建，存在极高的用户资产与凭据泄露风险。
- 证据：`多项证据指向：4个密码输入框、强制JS跳转诱导、涉嫌非法汇兑的诈骗话术。`
- 建议：将该域名加入黑名单，禁止用户访问，并对相关网络流量进行阻断。

### 10. 用户安全警示
- 规则：`DEEP_ADVICE_USER_WARNING`
- 严重级别：`high`
- 说明：该网站可能通过诱导用户上传支付二维码或输入敏感凭据进行诈骗。
- 证据：`页面可见文本中包含“上传卢布QR码”、“零手续费”等诱导性内容。`
- 建议：若用户必须访问，应在隔离浏览器环境中进行，严禁输入任何账号密码或上传任何支付凭证。

### 11. TLS 证书较新，可信度有限
- 规则：`STATIC_CERT_RECENT_REEVALUATED`
- 严重级别：`low`
- 说明：证书签发时间较短本身并不能直接证明恶意，但结合页面诱导性金融话术与高风险表单结构，会削弱站点可信度；在本案中应视为辅助风险信号，而非单独定性证据。
- 证据：`证书签发于 20 天前。`
- 建议：在未完成域名归属与站点合规性核验前，不要输入账号密码或进行任何资金操作。

### 12. 页面存在异常数量的密码输入框
- 规则：`STATIC_PAGE_PASSWORD_FORM_REEVALUATED`
- 严重级别：`high`
- 说明：页面包含 4 个密码输入框，这对普通兑换站点而言异常偏多；结合专家对钓鱼与凭据窃取风险的判断，应将其视为显著高危信号，而不仅是普通登录功能提示。
- 证据：`密码框数量: 4`
- 建议：建议立即停止交互，尤其不要在页面中输入任何密码、验证码或钱包相关信息。

### 13. 页面含高诱导性加密货币交易话术
- 规则：`BEHAVIOR_SUSPICIOUS_LURE_REEVALUATED`
- 严重级别：`critical`
- 说明：页面可见文本包含“零手续费”“直接从USDT余额中扣除”“上传卢布QR码”等强诱导话术，与常见诈骗、非法汇兑或资金盘宣传高度一致；结合行为分析员与处置建议员意见，应提升为极高风险。
- 证据：`可见文本包含相关金融诱导语句与支付二维码上传提示。`
- 建议：建议直接拦截访问，并将该域名纳入重点监控名单。

### 14. 页面暴露未正确解析的脚本代码
- 规则：`BEHAVIOR_JAVASCRIPT_RENDERING_ISSUE_REEVALUATED`
- 严重级别：`medium`
- 说明：可见文本直接出现 JavaScript 代码，说明页面渲染或转义处理较差。单独看属于质量问题，但在高风险金融诱导语境下，会进一步强化站点粗糙、短期部署或规避检测的嫌疑。
- 证据：`可见文本中直接出现 setTimeout / confirm / localStorage 相关脚本片段。`
- 建议：建议在隔离环境中进一步核查；若业务上必须访问，应先进行完整安全评估。

### 15. 域名注册信息仅提供有限支持
- 规则：`INTEL_DOMAIN_REGISTRATION_REEVALUATED`
- 严重级别：`low`
- 说明：域名注册商信息可见，但未提供足够的信誉或黑名单结论；注册时长 608 天说明并非极新域名，但也不能排除被用于恶意业务。该情报只能作为辅助背景，不能降低页面本身的高危判断。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED；域名存在天数: 608`
- 建议：如需进一步验证，应补充 WHOIS 历史、证书透明度与威胁情报查询。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包以及四位专家意见，当前页面应判定为高风险，偏向 malicious_lean。证据链显示该站点表面上是“数字货币兑换，买卖比特币”平台，但页面可见文本包含明显的高诱导金融话术，如“零手续费支付卢布账单”“直接从USDT余额中扣除”“上传卢布QR码 → 选择私人支付服务”，同时页面暴露出未正确解析的脚本代码，且存在 4 个密码输入框和 1 个隐藏字段。此类组合特征更符合加密货币诈骗、非法汇兑诱导或钓鱼式凭据收集场景，而非普通合规交易站点。外部情报仅能确认域名注册商与注册时长，未能提供更强信誉背书，因此当前结论主要依赖离线证据与页面内容本身。专家意见整体偏向恶意，其中两位给出 critical/高危判断，另一位给出 high，情报分析员保持 uncertain，但未形成方向性反对。综合考虑，我采纳高危结论，而不采用中等风险或简单平均。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
认为该站点是典型数字货币兑换平台，但存在 4 个密码输入框、TLS 证书签发时间较短、页面混杂多语言与可疑加载诱导脚本，倾向 malicious_lean，置信度较高。

### 行为分析员（模型：`gemini-2.5-pro`）
认为页面存在明显加密货币诈骗诱导话术、暴露原始 JavaScript 代码、密码输入框异常，倾向 malicious_lean，置信度较高。

### 情报分析员（模型：`gpt-4o-mini`）
认为当前网页未明确模仿特定品牌，主要是数字货币兑换服务，风险判断为 uncertain/medium；并明确说明当前版本采用离线规则研判，若用于实战需补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`gemini-2.5-flash`）
认为该站点应判定为高风险钓鱼及加密货币诈骗站点，建议 block；同时提示不要提交敏感信息，必要时仅在隔离浏览器中复核。


### 主持人最终总结
基于静态检测结果、浏览器证据包以及四位专家意见，当前页面应判定为高风险，偏向 malicious_lean。证据链显示该站点表面上是“数字货币兑换，买卖比特币”平台，但页面可见文本包含明显的高诱导金融话术，如“零手续费支付卢布账单”“直接从USDT余额中扣除”“上传卢布QR码 → 选择私人支付服务”，同时页面暴露出未正确解析的脚本代码，且存在 4 个密码输入框和 1 个隐藏字段。此类组合特征更符合加密货币诈骗、非法汇兑诱导或钓鱼式凭据收集场景，而非普通合规交易站点。外部情报仅能确认域名注册商与注册时长，未能提供更强信誉背书，因此当前结论主要依赖离线证据与页面内容本身。专家意见整体偏向恶意，其中两位给出 critical/高危判断，另一位给出 high，情报分析员保持 uncertain，但未形成方向性反对。综合考虑，我采纳高危结论，而不采用中等风险或简单平均。


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。


## 九、分析性能统计

- 总耗时：40.89 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 5.95 | 4254 | 450 | 4704 |
| 情报分析员 | 6.29 | 4071 | 283 | 4354 |
| 行为分析员 | 21.22 | 3961 | 1949 | 5910 |
| 处置建议员 | 4.82 | 5266 | 440 | 5706 |
| 主持人 | 14.84 | 5671 | 1634 | 7305 |
