# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**MEDIUM** · 风险分数：**53/100**
> 评分口径：URL 深度研判分数已综合证据分数，最终风险分数直接采用深度研判分数。
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：5 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260625_200105_692086.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260625_200105_692086.md

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
- proxy_config：{'http': 'http://127.0.0.1:7897', 'https': 'http://127.0.0.1:7897', 'ftp': 'http://127.0.0.1:7897'}
- title：加密货币交换 | 购买和出售比特币，USDT，ETH - Baksmany
- visible_text_excerpt：加密货币交换 | 购买和出售比特币，USDT，ETH - Baksmany (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem('slow_connection_detected')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem('slow_connection_detected', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( 'load', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在您可以用 USDT 余额直接支付卢布账单，无需任何手续费。 只需上传卢布二维码→ 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全
- password_forms：4
- hidden_inputs：1
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<!DOCTYPE html> <html lang="zh"> <head> <meta charset="UTF-8"/> <meta content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0" name="viewport"/> <meta content="ie=edge" http-equiv="X-UA-Compatible"/> <title>加密货币交换 | 购买和出售比特币，USDT，ETH - Baksmany</title> <meta name="description" content="快速且匿名的加密货币交换，无需强制注册。对BTC，USDT，ETH有优惠的汇率。私人支付，现金返还和24/7支持。" /> <meta name="keywords" content="兑换机，比特币兑换，比特币到奇异果，数字货币兑换机，电子货币兑换机，购买比特币，出售比特币" /> <meta name="format-detection" content="telephone=no"> <link rel="icon" href="/favicon-logo2.png"> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/chosen.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/style.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/exchangebox/select2/css/select2.min.css?v=15" /> <script> (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', ()', 'text_excerpt': '加密货币交换 | 购买和出售比特币，USDT，ETH - Baksmany (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在您可以用 USDT 余额直接支付卢布账单，无需任何手续费。 只需上传卢布二维码→ 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全'}
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': None, 'whois_creation_date': '2024-10-21T15:02:27Z', 'whois_age_days': 611}

## 四点一、页面线索
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 域名注册时间：`2024-10-21T15:02:27Z`
- 域名注册天数：`611` 天

## 五、截图证据
### 截图 1
- 标题：`加密货币交换 | 购买和出售比特币，USDT，ETH - Baksmany`
- 落点：`https://baksmany.net/zh/`
- 时间：`2026-06-25T12:01:02.788384+00:00`
- 大小：`597649` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 23 天前。
- 证据：`Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`medium`
- 说明：密码表单提交与当前域名一致或为相对路径，可能为正常登录功能。
- 证据：`密码框数量: 4`
- 建议：确认域名归属和证书可信后再输入账号密码。

### 3. 域名注册商信息
- 规则：`INTEL_INFRA_1`
- 严重级别：`medium`
- 说明：该域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，其注册时间为 611 天，具有一定的历史，但仍然相对较年轻。此信息意味着该域名可能是为了短期的目的而创建。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED；域名存在天数: 611。`
- 建议：建议进一步调查该注册商的声誉和以往的注册情况，以便评估此域名的潜在风险。

### 4. 域名创建时间
- 规则：`INTEL_INFRA_2`
- 严重级别：`low`
- 说明：该域名于 2024 年 10 月 21 日创建，注册时间较短，可能不具备足够的信誉。
- 证据：`域名创建时间: 2024-10-21T15:02:27Z。`
- 建议：在考虑使用该网站时应保持谨慎，确保不会泄露任何敏感信息。

### 5. 页面呈现加密货币交易功能并包含多个密码输入框
- 规则：`DEEP_BEHAVIOR_CRYPTO_PHISHING_INDICATOR`
- 严重级别：`high`
- 说明：该页面是一个加密货币交易平台，包含用于登录和注册的密码输入框。虽然页面本身没有执行恶意跳转或下载，但其业务性质（金融服务）与静态分析发现的新证书（签发于23天前）相结合，增加了钓鱼或诈骗的风险。表单提交可能由JavaScript处理，其最终目的无法在不进行交互的情况下确定。
- 证据：`最终页面URL: https://baksmany.net/zh/, 页面标题: '加密货币交换 | 购买和出售比特币，USDT，ETH - Baksmany', 浏览器证据显示页面上存在4个密码输入框。静态分析发现证书签发时间较短。`
- 建议：在未确认该网站是合法、受信任的加密货币交易所之前，绝对不要输入任何账户名、密码或个人财务信息。对新的、声誉不明的金融平台应保持高度警惕。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
深度研判服务部分失败，已基于已收集的证据重新评估。综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`deepseek-reasoner`）
URL 结构层面关注：TLS 证书签发时间较短、页面包含密码输入框。

### 行为分析员（模型：`gemini-2.5-pro`）
行为分析显示，该页面加载后未执行明显的恶意操作，如强制重定向或自动下载。页面呈现为一个加密货币交易平台，并包含多个密码输入框，这与其声称的功能一致。然而，由于无法在自动分析中验证表单提交的目标，且结合静态分析发现的证书签发时间较短，该页面存在钓鱼或诈骗的高度潜在风险。仅从观测到的行为链来看，证据不足以判定其为明确的恶意软件，但其特征与金融钓鱼网站高度相似。

### 情报分析员（模型：`gpt-4o-mini`）
该域名未直接模仿任何特定的品牌或组织，尽管其宣传加密货币交换的功能，但并未表明任何明确的目标品牌。

### 处置建议员（模型：`gemini-2.5-flash`）
建议在隔离浏览器中复核最终域名，不在页面提交敏感信息。


### 主持人最终总结
深度研判主持人阶段失败，已根据静态检测与四名专家的发现重新计算风险。原因：模型调用异常: Connection error.


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
