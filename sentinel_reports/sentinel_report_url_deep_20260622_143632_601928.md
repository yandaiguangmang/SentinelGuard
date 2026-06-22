# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：8 条
- 高危证据：2 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_143545_866450.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_143545_866450.md

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
  - 大小：`596070` 字节
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

### 3. 可疑的 JS 诱导跳转逻辑
- 规则：`DEEP_STATIC_SUSPICIOUS_JS_REDIRECT`
- 严重级别：`medium`
- 说明：页面包含一段定时器脚本，通过 localStorage 检测连接速度并诱导用户跳转至 /zh/lite/ 路径，此类逻辑常被用于规避安全检测或在特定网络环境下切换至更易于实施钓鱼的页面。
- 证据：`setTimeout(() => { ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：需进一步分析 /zh/lite/ 路径下的页面内容，检查是否存在与主站不同的表单逻辑。

### 4. 页面存在多个密码输入框
- 规则：`DEEP_STATIC_HIGH_PASSWORD_DENSITY`
- 严重级别：`medium`
- 说明：页面内存在 4 个密码输入框，对于一个简单的兑换页面而言，密码输入框数量异常，可能存在窃取用户凭据的风险。
- 证据：`password_forms: 4`
- 建议：检查这些表单的提交目标地址（action），确认是否指向可信的后端接口。

### 5. 域名注册信息分析
- 规则：`INTEL_INFRA_1`
- 严重级别：`medium`
- 说明：该域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，域名创建于 2024 年 10 月 21 日，至今已有 608 天，显示出一定的存在时间，但仍相对年轻。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 域名存在天数: 608`
- 建议：建议进一步调查该注册商的信誉及其与恶意活动的关联性。

### 6. TLS 证书分析
- 规则：`INTEL_INFRA_2`
- 严重级别：`medium`
- 说明：该网站的 TLS 证书签发时间较短，可能影响其可信度。
- 证据：`证书签发于 20 天前。`
- 建议：建议结合其他证据综合判断该网站的安全性。

### 7. 页面脚本代码泄漏
- 规则：`DEEP_BEHAVIOR_SCRIPT_LEAKAGE`
- 严重级别：`high`
- 说明：页面可见文本中直接暴露了 JavaScript 源代码，反映出明显的实现缺陷与低质量开发特征。在金融交易场景下，这类异常通常会显著削弱可信度，并放大钓鱼或欺诈嫌疑。
- 证据：`可见文本包含：(function(){ let TimerID = setTimeout(() => { ...`
- 建议：将其视为高优先级风险信号，避免在该站点提交任何敏感信息。

### 8. 高风险金融诱导行为
- 规则：`DEEP_BEHAVIOR_FINANCIAL_LURE`
- 严重级别：`high`
- 说明：网站以“数字货币兑换”、“买卖比特币”以及“零手续费支付卢布账单”为诱饵，吸引用户进行资金操作。结合其粗糙的页面质量和多个密码输入框，这极有可能是用于窃取加密货币资产或收集用户凭据的诈骗平台。
- 证据：`页面标题为“数字货币兑换，买卖比特币”，且包含诱导性文本：“现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除”。`
- 建议：切勿在该平台进行任何充值、转账或授权操作，防范加密货币诈骗。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包与四位专家意见，目标站点 baksmany.net/zh/ 被评估为高风险。页面自称“数字货币兑换，买卖比特币”，并出现“零手续费支付卢布账单”“USDT余额”等资金诱导话术，同时可见文本中直接暴露了 JavaScript 代码，说明页面质量和实现规范性明显异常。静态证据还显示页面包含 4 个密码输入框，且存在一个定时器脚本，会根据 localStorage 的网络检测结果提示用户切换到 /zh/lite/ 轻版页面；这类逻辑本身未必等同恶意，但在当前页面的整体语境下，结合多个密码框和金融诱导文案，显著增加了钓鱼或欺诈平台的可疑度。外部情报方面，仅能确认域名注册信息与证书年龄：域名已存在 608 天，TLS 证书签发时间约 20 天前，均不足以单独定性，但也未能提供足够的可信背书。需要强调的是，本次结论主要依赖离线静态与浏览器证据，外部威胁情报不足，无法补充更强的信誉或黑名单证据。

四位专家意见整体偏向恶意：静态分析员给出 malicious_lean（0.65），行为分析员给出 malicious_lean（0.8），情报分析员为 uncertain（0.7），处置建议员虽标注 uncertain（0.0）但明确建议 block。不存在 benign_lean 方向的对立意见，因此没有方向性冲突；但风险提示跨度从 medium 到 critical，分歧明显，表明专家对严重程度判断并不完全一致。综合证据强度与一致性，我最终采纳高风险而非临界风险：原因是页面同时具备金融场景、多个密码输入框、可见脚本泄漏、诱导性资金话术和可疑跳转逻辑，形成了多重弱到中强信号叠加，足以支持“高风险、偏恶意”的结论，但尚不足以仅凭现有离线证据直接升级为 confirmed malicious。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
认为该站点是数字货币兑换平台，但存在多个密码输入框和一段定时器诱导切换轻量版页面的脚本；域名注册时间较长但证书较新，静态证据不足以直接判恶意，但存在一定钓鱼或欺诈风险，倾向 malicious_lean，置信度 0.65。

### 行为分析员（模型：`gemini-2.5-pro`）
认为页面可见文本直接暴露 JavaScript 源码，开发质量极低；结合多个密码输入框和“零手续费”等资金诱导话术，极有可能是粗制滥造的诈骗或钓鱼网站，倾向 malicious_lean，置信度 0.8。

### 情报分析员（模型：`gpt-4o-mini`）
认为页面未明显模仿特定品牌或组织，主要是数字货币兑换服务；域名注册商与注册时间提供有限背景，TLS 证书较新但不足以定性，整体保持 uncertain，置信度 0.7，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`gemini-2.5-flash`）
认为该站点伪装成数字货币兑换平台，但存在严重异常：脚本泄漏、多个密码输入框、资金诱导话术、证书较新与可疑跳转逻辑并存，极大概率为钓鱼或加密货币诈骗平台；虽然给出 uncertain，但明确建议 block。


### 主持人最终总结
基于静态检测结果、浏览器证据包与四位专家意见，目标站点 baksmany.net/zh/ 被评估为高风险。页面自称“数字货币兑换，买卖比特币”，并出现“零手续费支付卢布账单”“USDT余额”等资金诱导话术，同时可见文本中直接暴露了 JavaScript 代码，说明页面质量和实现规范性明显异常。静态证据还显示页面包含 4 个密码输入框，且存在一个定时器脚本，会根据 localStorage 的网络检测结果提示用户切换到 /zh/lite/ 轻版页面；这类逻辑本身未必等同恶意，但在当前页面的整体语境下，结合多个密码框和金融诱导文案，显著增加了钓鱼或欺诈平台的可疑度。外部情报方面，仅能确认域名注册信息与证书年龄：域名已存在 608 天，TLS 证书签发时间约 20 天前，均不足以单独定性，但也未能提供足够的可信背书。需要强调的是，本次结论主要依赖离线静态与浏览器证据，外部威胁情报不足，无法补充更强的信誉或黑名单证据。

四位专家意见整体偏向恶意：静态分析员给出 malicious_lean（0.65），行为分析员给出 malicious_lean（0.8），情报分析员为 uncertain（0.7），处置建议员虽标注 uncertain（0.0）但明确建议 block。不存在 benign_lean 方向的对立意见，因此没有方向性冲突；但风险提示跨度从 medium 到 critical，分歧明显，表明专家对严重程度判断并不完全一致。综合证据强度与一致性，我最终采纳高风险而非临界风险：原因是页面同时具备金融场景、多个密码输入框、可见脚本泄漏、诱导性资金话术和可疑跳转逻辑，形成了多重弱到中强信号叠加，足以支持“高风险、偏恶意”的结论，但尚不足以仅凭现有离线证据直接升级为 confirmed malicious。


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

- 总耗时：32.62 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 5.12 | 4254 | 426 | 4680 |
| 情报分析员 | 6.72 | 4071 | 301 | 4372 |
| 行为分析员 | 19.31 | 3961 | 1662 | 5623 |
| 处置建议员 | 1.88 | 5451 | 130 | 5581 |
| 主持人 | 11.43 | 5361 | 2030 | 7391 |
