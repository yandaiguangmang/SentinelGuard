# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：7 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_144549_069584.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_144549_069584.md

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
- 未采集到截图证据。

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

### 3. 可疑的页面加载诱导脚本
- 规则：`DEEP_STATIC_SUSPICIOUS_JS_BEHAVIOR`
- 严重级别：`medium`
- 说明：页面包含一段通过setTimeout强制触发confirm弹窗的脚本，诱导用户切换至所谓的“轻版网站”，此类行为常用于绕过安全检测或引导用户进入更易于实施钓鱼的页面。
- 证据：`let TimerID = setTimeout(() => { ... confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); ... }, 20000);`
- 建议：严禁在页面中输入任何敏感信息，警惕此类强制跳转行为。

### 4. 异常的密码输入框密度
- 规则：`DEEP_STATIC_EXCESSIVE_PASSWORD_FIELDS`
- 严重级别：`high`
- 说明：页面中存在4个密码输入框，对于一个普通的兑换平台首页而言，该数量异常，极大概率用于窃取用户凭证。
- 证据：`密码框数量: 4`
- 建议：该页面存在极高的凭证窃取风险，建议立即停止访问。

### 5. 域名注册信息分析
- 规则：`INTEL_INFRA_1`
- 严重级别：`medium`
- 说明：该域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，注册时间为 608 天，表明该域名并不新，但也不算非常成熟。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 域名存在天数: 608`
- 建议：建议进一步调查该注册商的声誉及其与恶意活动的关联性。

### 6. 加密货币交易与利益诱导
- 规则：`DEEP_BEHAVIOR_CRYPTO_INDUCEMENT`
- 严重级别：`medium`
- 说明：页面提供加密货币（比特币、USDT）与法币（卢布）的兑换服务，并使用“抓住这个不容错过的机会”、“零手续费”等强烈诱导性话术。结合页面中存在的多个密码输入框，若该站点为虚假平台，则存在极高的资金诈骗和凭据窃取风险。
- 证据：`可见文本包含：“数字货币兑换，买卖比特币”、“朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。”；密码框数量: 4。`
- 建议：在未通过可靠的第三方渠道核实该交易平台（Baksmany）的真实性和信誉之前，切勿注册账号、输入密码或进行任何资金转账。

### 7. 基于超时的延迟跳转提示
- 规则：`DEEP_BEHAVIOR_TIMEOUT_REDIRECT_PROMPT`
- 严重级别：`low`
- 说明：页面包含一段 JavaScript 代码，在页面加载 20 秒后会弹窗提示用户网络连接慢，并询问是否跳转到“轻量版”网站（/zh/lite/?confirm=1）。虽然这可能是正常的弱网体验优化，但由于其具有较长的延迟属性，且需要用户交互（confirm弹窗），也常被恶意网站用于规避自动化分析沙箱的检测（沙箱通常运行时间较短且无法处理复杂的弹窗交互）。
- 证据：`脚本内容：setTimeout(() => { ... cnf = confirm('我们注意到你的网站加载速度很低。 使用轻版网站？'); ... if (cnf) { location.href = '/zh/lite/?confirm=1'; } }, 20000);`
- 建议：建议在隔离环境中手动触发该弹窗并允许跳转，以观察“轻量版”页面是否隐藏了真正的恶意行为或钓鱼表单。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包以及专家意见综合判断，该站点当前更符合“高风险加密货币兑换/金融服务页面”的特征，但现有离线证据不足以直接证明其为明确恶意钓鱼站点。支持风险升高的核心证据包括：页面存在4个密码输入框、含20秒后触发的延迟确认弹窗脚本、强烈的利益诱导话术（如“零手续费”“不容错过”）、以及较新的TLS证书签发时间。另一方面，页面未见外链脚本、未观察到重定向链异常、未发现明确冒充知名品牌的证据，且域名注册已存在608天，说明其并非典型“新注册即投放”的短生命周期站点。专家意见整体偏向风险较高，但在最终定性上存在分歧：静态分析员给出 malicious_lean，行为分析员与情报分析员维持 uncertain/medium，处置建议员给出更激进的 critical 但其置信度为0且未提供可验证的新证据。综合证据链，本结论采用“medium偏高风险”的保守判定，建议仅在隔离环境中继续核验，当前结论主要依赖离线证据。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
认为该站点具备较高风险，重点关注 TLS 证书较新、页面含4个密码输入框以及可疑的延迟确认弹窗脚本，倾向 malicious_lean，置信度 0.85。

### 行为分析员（模型：`gemini-2.5-pro`）
认为页面呈现数字货币兑换与强营销诱导特征，存在多个密码输入框和20秒延迟提示脚本，但仅凭当前行为证据不足以断定为恶意，倾向 uncertain，置信度 0.6。

### 情报分析员（模型：`gpt-4o-mini`）
认为当前主要是离线规则研判，域名注册已608天且未明确冒充知名品牌，整体维持 uncertain，置信度 0.7，并建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`gemini-2.5-flash`）
认为页面存在异常密码输入框、延迟弹窗诱导和强利益诱导话术，倾向 critical 风险并建议 block，但其 confidence 为 0.0，缺乏额外可验证证据支撑。


### 主持人最终总结
基于静态检测结果、浏览器证据包以及专家意见综合判断，该站点当前更符合“高风险加密货币兑换/金融服务页面”的特征，但现有离线证据不足以直接证明其为明确恶意钓鱼站点。支持风险升高的核心证据包括：页面存在4个密码输入框、含20秒后触发的延迟确认弹窗脚本、强烈的利益诱导话术（如“零手续费”“不容错过”）、以及较新的TLS证书签发时间。另一方面，页面未见外链脚本、未观察到重定向链异常、未发现明确冒充知名品牌的证据，且域名注册已存在608天，说明其并非典型“新注册即投放”的短生命周期站点。专家意见整体偏向风险较高，但在最终定性上存在分歧：静态分析员给出 malicious_lean，行为分析员与情报分析员维持 uncertain/medium，处置建议员给出更激进的 critical 但其置信度为0且未提供可验证的新证据。综合证据链，本结论采用“medium偏高风险”的保守判定，建议仅在隔离环境中继续核验，当前结论主要依赖离线证据。


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

- 总耗时：47.88 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 5.15 | 4254 | 439 | 4693 |
| 情报分析员 | 7.72 | 4071 | 289 | 4360 |
| 行为分析员 | 32.53 | 3961 | 3181 | 7142 |
| 处置建议员 | 2.01 | 5635 | 149 | 5784 |
| 主持人 | 13.34 | 5590 | 1661 | 7251 |
