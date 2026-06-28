# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**HIGH** · 风险分数：**75/100**
> 评分口径：URL 深度研判分数已综合证据分数，最终风险分数直接采用深度研判分数。
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：4 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260625_220602_721833.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260625_220602_721833.md

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
- 时间：`2026-06-25T14:06:00.217566+00:00`
- 大小：`597091` 字节


## 六、风险证据
### 1. 域名注册信息
- 规则：`INTEL_INFRA_*`
- 严重级别：`medium`
- 说明：域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，创建时间为 2024 年 10 月 21 日，目前存在约 611 天。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 创建时间: 2024-10-21; 存在天数: 611天。`
- 建议：建议进一步调查该注册商的声誉以及此域名在安全方面的可信度。

### 2. 加密货币交易平台存在诈骗风险
- 规则：`DEEP_BEHAVIOR_CRYPTO_SCAM_RISK`
- 严重级别：`high`
- 说明：该网站自称为加密货币交易平台，并提供注册和登录功能以进行交易。虽然未观察到传统意义上的恶意行为（如恶意软件分发），但这类网站本身存在很高的金融诈骗风险。用户提交的凭证和存入的资金可能被平台非法侵占。结合静态分析发现的证书签发时间较短的特点，其作为诈骗网站的可能性增加。
- 证据：`页面内容和功能表明其为一个加密货币交换平台，包含4个密码输入框用于登录/注册。最终URL: https://baksmany.net/zh/`
- 建议：强烈建议不要在该网站上注册、登录或进行任何金融交易，除非能通过可靠的第三方渠道确认其合法性和信誉。与未知或信誉不佳的加密货币平台交互存在极高的资金损失风险。

### 3. 网页加载劫持行为
- 规则：`DEEP_STATIC_LOADING_HIJACK`
- 严重级别：`high`
- 说明：页面的JavaScript代码在文档加载后延迟20秒执行弹窗提示，询问用户是否跳转到轻量版本（/zh/lite/?confirm=1）。此行为可能导致用户被非自愿地重定向至其他版本网站。
- 证据：`JavaScript代码片段：`setTimeout(() => { ... cnf = confirm("我们注意到你的网站加载速度很低。使用轻版网站？"); ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);``
- 建议：在浏览器安全审查环境中验证跳转后的页面行为，此重定向可能用于加载更具攻击性的登录钓鱼页面。

### 4. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`high`
- 说明：证书签发于 23 天前，对于金融交易类网站而言，新证书配合旧域名可能暗示基础设施被接管或用于短期诈骗活动。
- 证据：`Jun  2 05:52:23 2026 GMT`
- 建议：高度警惕，不建议在此类证书配置的网站输入敏感金融信息。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合静态分析、行为分析及情报信息，该网站（baksmany.net）自称加密货币交易平台，但存在显著的可疑特征。主要风险点包括：TLS 证书签发时间极短（23 天），与域名注册时长（约 611 天）不匹配，可能暗示基础设施近期被重置或用于特定活动；页面包含 4 个密码输入框，存在凭证窃取风险；JavaScript 代码包含基于连接速度的重定向逻辑，可能用于规避分析或向特定用户展示不同内容。虽然情报分析员和主持人初步判定为中等风险，但静态与行为分析员指出其符合诈骗网站特征（高风险）。鉴于加密货币交易场景的高敏感性及上述技术疑点，最终判定为高风险，建议阻断访问。 综合静态分析、行为分析及情报信息，该网站（baksmany.net）自称加密货币交易平台，但存在显著的可疑特征。主要风险点包括：TLS 证书签发时间极短（23 天），与域名注册时长（约 611 天）不匹配，可能暗示基础设施近期被重置或用于特定活动；页面包含 4 个密码输入框，存在凭证窃取风险；JavaScript 代码包含基于连接速度的重定向逻辑，可能用于规避分析或向特定用户展示不同内容。虽然情报分析员和主持人初步判定为中等风险，但静态与行为分析员指出其符合诈骗网站特征（高风险）。鉴于加密货币交易场景的高敏感性及上述技术疑点，最终判定为高风险，建议阻断访问。

### 静态分析员（模型：`deepseek-reasoner`）
基于静态分析，该网页存在多个可疑特征。页面中包含4个密码输入框，结合跳转到轻量版网站的脚本（可能诱导非预期操作），证书较新（签发仅23天），以及域名注册信息（与加密货币高度相关，但脱离地域框架），这些综合因素难以支撑其为良性服务的判断。但需注意，页面本身无明确恶意重定向或外部恶意脚本。

### 行为分析员（模型：`gemini-2.5-pro`）
行为分析显示，该网站是一个加密货币交易平台。页面上存在登录和注册功能，包含多个密码输入框，这与该类网站的功能相符。未观察到自动恶意重定向、文件下载或欺骗性弹出窗口等典型的恶意行为。主要风险在于该平台本身的合法性存疑，可能是一个旨在窃取用户资金或凭证的诈骗网站。仅从行为链无法断定其是否为合法经营的服务。

### 情报分析员（模型：`gpt-4o-mini`）
该恶意网页目标为用户进行加密货币交易，但没有明显的品牌或组织冒充行为。

### 处置建议员（模型：`gemini-2.5-flash`）
综合静态分析、行为分析和情报信息，该网站自称加密货币交易平台，但存在多个可疑特征。TLS 证书签发时间极短（23天），且页面包含一段 JavaScript 代码，会在20秒后弹出提示，以“网站加载速度慢”为由诱导用户跳转至“轻量版”网站。这种行为模式高度可疑，可能旨在规避安全检测或将用户引向更具攻击性的页面。尽管未直接观察到恶意软件或钓鱼行为，但鉴于加密货币交易平台固有的高风险特性以及上述欺骗性行为，该网站存在极高的金融诈骗和凭证窃取风险。


### 主持人最终总结
综合静态分析、行为分析及情报信息，该网站（baksmany.net）自称加密货币交易平台，但存在显著的可疑特征。主要风险点包括：TLS 证书签发时间极短（23 天），与域名注册时长（约 611 天）不匹配，可能暗示基础设施近期被重置或用于特定活动；页面包含 4 个密码输入框，存在凭证窃取风险；JavaScript 代码包含基于连接速度的重定向逻辑，可能用于规避分析或向特定用户展示不同内容。虽然情报分析员和主持人初步判定为中等风险，但静态与行为分析员指出其符合诈骗网站特征（高风险）。鉴于加密货币交易场景的高敏感性及上述技术疑点，最终判定为高风险，建议阻断访问。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
