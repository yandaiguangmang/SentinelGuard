# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**95/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：5 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_150337_246070.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_150337_246070.md

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
  - 大小：`596561` 字节
  - 视口：`{'width': 1440, 'height': 1600}`

## 六、风险证据
### 1. TLS 证书近期签发
- 规则：`CERT_RECENT`
- 严重级别：`high`
- 说明：证书签发时间较新，结合专家意见应视为提高可疑度的辅助信号，而非单独定性依据。
- 证据：`证书签发于 20 天前；域名注册已 608 天。`
- 建议：继续核查证书透明度、证书绑定历史与站点历史变更记录。

### 2. 高风险金融交互界面
- 规则：`DEEP_STATIC_FINANCIAL_PHISHING_RISK`
- 严重级别：`critical`
- 说明：页面作为数字货币兑换平台，在未明确安全凭证的情况下部署了4个密码输入框，极易导致用户凭证泄露。
- 证据：`HTML中检测到4个密码输入框，且页面内容涉及USDT、卢布等敏感金融交易。`
- 建议：该页面属于高风险金融钓鱼范畴，建议立即阻断访问。

### 3. 可疑的页面加载诱导脚本
- 规则：`DEEP_STATIC_SUSPICIOUS_JS_BEHAVIOR`
- 严重级别：`high`
- 说明：页面包含一段通过localStorage检测连接速度并强制弹出confirm对话框跳转至轻量版页面的脚本，此类逻辑常用于规避安全扫描或在特定环境下隐藏恶意内容。
- 证据：`脚本中包含: setTimeout(() => { ... confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); ... }, 20000);`
- 建议：严禁在未受信任的环境下与该页面的交互逻辑进行交互，建议重点审查跳转后的轻量版页面内容。

### 4. 域名注册信息分析
- 规则：`INTEL_INFRA_DOMAIN`
- 严重级别：`medium`
- 说明：该域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，注册时间为 608 天，显示出一定的存在时间，但仍然相对年轻。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 域名存在天数: 608`
- 建议：建议进一步调查该注册商的信誉及其与恶意活动的关联性。

### 5. 证书信息分析
- 规则：`INTEL_INFRA_CERTIFICATE`
- 严重级别：`medium`
- 说明：当前证书的有效期较短，可能影响用户对网站的信任度。
- 证据：`证书签发于 20 天前。`
- 建议：建议监控该网站的证书更新情况，并结合其他证据进行综合判断。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包以及四位专家意见，当前页面更接近“高风险可疑金融站点/潜在钓鱼站点”，但证据链仍主要来自离线与页面静态证据，缺少外部信誉、黑名单或证书透明度等在线情报支撑，因此不能直接上升为已确认恶意。页面标题与正文明确指向“数字货币兑换、买卖比特币”，并出现4个密码输入框、1个隐藏字段，以及一段在20秒后检测网络状况并弹出确认框、可跳转到轻量版页面的脚本。此类金融登录/交易界面叠加诱导性前端逻辑，会显著抬高凭证窃取、虚假交易或规避检测的风险。静态报告中的两项中等风险发现（短期证书、密码表单）在专家复核后被整体上调为更高关注级别，其中“诱导性脚本”和“高风险金融交互界面”构成主要风险支撑。专家意见存在明显分歧：静态分析员与处置建议员偏向 malicious_lean/阻断，行为分析员偏向 benign_lean，而情报分析员保持 uncertain；由于方向冲突且 risk_hint 跨度超过两级，本结论不采用简单折中，而是基于页面结构、密码表单密度、可疑脚本、金融业务属性及证书较新等组合证据，最终采纳高风险判定。当前结论主要依赖离线证据，外部情报不足，需后续补充域名信誉、证书透明度和威胁情报进一步验证。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
{'claim': 'malicious_lean', 'confidence': 0.85, 'risk_hint': 'critical', 'opinion': '页面呈现典型数字货币兑换平台特征，但存在多项高风险信号：4个密码输入框、页面加载时的诱导性 JavaScript、短期 TLS 证书，以及涉及金融兑换和账户登录等敏感场景，整体更偏向恶意或钓鱼用途。'}

### 行为分析员（模型：`gemini-2.5-pro`）
{'claim': 'benign_lean', 'confidence': 0.7, 'risk_hint': 'medium', 'opinion': '从页面行为看未发现自动跳转或恶意下载，多个密码输入框与登录/注册功能可能一致；仅凭行为证据不足以直接认定恶意，但该类加密货币平台本身存在较高诈骗风险。'}

### 情报分析员（模型：`gpt-4o-mini`）
{'claim': 'uncertain', 'confidence': 0.7, 'risk_hint': 'medium', 'opinion': '网页未明显模仿特定品牌或组织，外部情报不足；当前更适合按离线规则研判，建议补充域名信誉、证书透明度和黑名单情报。'}

### 处置建议员（模型：`gemini-2.5-flash`）
{'claim': 'uncertain', 'confidence': 0.0, 'risk_hint': 'critical', 'recommended_action': 'block', 'opinion': '该站点伪装成数字货币兑换平台，结合短期证书、诱导性脚本和多个密码输入框，具有显著钓鱼风险，建议阻断访问并避免输入敏感信息。'}


### 主持人最终总结
基于静态检测结果、浏览器证据包以及四位专家意见，当前页面更接近“高风险可疑金融站点/潜在钓鱼站点”，但证据链仍主要来自离线与页面静态证据，缺少外部信誉、黑名单或证书透明度等在线情报支撑，因此不能直接上升为已确认恶意。页面标题与正文明确指向“数字货币兑换、买卖比特币”，并出现4个密码输入框、1个隐藏字段，以及一段在20秒后检测网络状况并弹出确认框、可跳转到轻量版页面的脚本。此类金融登录/交易界面叠加诱导性前端逻辑，会显著抬高凭证窃取、虚假交易或规避检测的风险。静态报告中的两项中等风险发现（短期证书、密码表单）在专家复核后被整体上调为更高关注级别，其中“诱导性脚本”和“高风险金融交互界面”构成主要风险支撑。专家意见存在明显分歧：静态分析员与处置建议员偏向 malicious_lean/阻断，行为分析员偏向 benign_lean，而情报分析员保持 uncertain；由于方向冲突且 risk_hint 跨度超过两级，本结论不采用简单折中，而是基于页面结构、密码表单密度、可疑脚本、金融业务属性及证书较新等组合证据，最终采纳高风险判定。当前结论主要依赖离线证据，外部情报不足，需后续补充域名信誉、证书透明度和威胁情报进一步验证。


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

- 总耗时：54.96 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 3.57 | 4254 | 482 | 4736 |
| 情报分析员 | 7.58 | 4071 | 290 | 4361 |
| 行为分析员 | 37.79 | 3960 | 1951 | 5911 |
| 处置建议员 | 3.36 | 5300 | 148 | 5448 |
| 主持人 | 13.80 | 5267 | 1855 | 7122 |
