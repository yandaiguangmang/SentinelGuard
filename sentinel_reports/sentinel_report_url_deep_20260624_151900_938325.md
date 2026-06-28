# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**MEDIUM** · 风险分数：**38/100**
> 证据分数：**41/100** · 深度研判分数：**35 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：7 条
- 高危证据：0 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260624_151535_680498.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260624_151535_680498.md

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
- title：数字货币兑换，买卖比特币
- visible_text_excerpt：数字货币兑换，买卖比特币 (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem('slow_connection_detected')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem('slow_connection_detected', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( 'load', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在您可以用 USDT 余额直接支付卢布账单，无需任何手续费。 只需上传卢布二维码→ 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全书 常见问题 AML 我的申请单 设置 平衡 推荐
- password_forms：4
- hidden_inputs：1
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<!DOCTYPE html> <html lang="zh"> <head> <meta charset="UTF-8"/> <meta content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0" name="viewport"/> <meta content="ie=edge" http-equiv="X-UA-Compatible"/> <title>数字货币兑换，买卖比特币</title> <meta name="description" content="买卖比特币以及进行比特币兑换，提供了Baksmany.net兑换服务。 该交换器具有大量的储备，并提供了高速度的应用程序执行。" /> <meta name="keywords" content="交换器，比特币交换，比特币到qiwi，数字货币交换器，电子货币交换器，购买比特币，出售比特币" /> <meta name="format-detection" content="telephone=no"> <link rel="icon" href="/favicon-logo2.png"> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/chosen.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/style.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/exchangebox/select2/css/select2.min.css?v=15" /> <script> (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', () => clearInterval(', 'text_excerpt': '数字货币兑换，买卖比特币 (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在您可以用 USDT 余额直接支付卢布账单，无需任何手续费。 只需上传卢布二维码→ 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全书 常见问题 AML 我的申请单 设置 平衡 推荐'}
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': None, 'whois_creation_date': '2024-10-21T15:02:27Z', 'whois_age_days': 610}

## 四点一、页面线索
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 域名注册时间：`2024-10-21T15:02:27Z`
- 域名注册天数：`610` 天

## 五、截图证据
### 截图 1
- 标题：`数字货币兑换，买卖比特币`
- 落点：`https://baksmany.net/zh/`
- 时间：`2026-06-24T07:15:30.116819+00:00`
- 大小：`595931` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 22 天前。
- 证据：`Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`medium`
- 说明：密码表单提交与当前域名一致或为相对路径，可能为正常登录功能。
- 证据：`密码框数量: 4`
- 建议：确认域名归属和证书可信后再输入账号密码。

### 3. 域名注册信息分析
- 规则：`INTEL_INFRA_1`
- 严重级别：`medium`
- 说明：域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，存在时间610天，表明非极新的注册，可能具备一定的可追溯性。
- 证据：`注册商：NICENIC INTERNATIONAL GROUP CO., LIMITED，域名存在天数：610。`
- 建议：建议进一步调查注册商信誉和域名的整体可信度，以评估其潜在风险。

### 4. 证书时间值分析
- 规则：`INTEL_INFRA_2`
- 严重级别：`medium`
- 说明：该页面的TLS证书签发时间较短，包含密码输入框，可能引发用户提交信息的风险。
- 证据：`证书签发于22天前，页面包含密码表单。`
- 建议：建议用户在确认域名的所有权和证书可信性之前，不要在此页面输入任何敏感信息。

### 5. 密码表单符合网站声称的功能
- 规则：`DEEP_BEHAVIOR_FUNCTIONAL_FORMS`
- 严重级别：`medium`
- 说明：页面包含多个密码输入框，用于用户注册和登录。这与网站声称的“数字货币兑换，买卖比特币”平台功能一致。未观察到表单数据被提交到可疑的第三方域，该行为符合正常业务逻辑，不应被视为独立的风险点。
- 证据：`页面截图和HTML内容显示这是一个需要用户账户系统的加密货币兑换网站。表单是该系统的一部分。行为链中未发现数据提交到第三方恶意域名。`
- 建议：用户在与任何金融平台（尤其是加密货币交易所）交互前，应独立验证其信誉和合法性，然后再注册或存入资金。

### 6. 可疑的落地页重定向机制
- 规则：`DEEP_STATIC_UNPOSTED_REDIRECT`
- 严重级别：`medium`
- 说明：内置JavaScript检测用户网络延迟并诱导跳转至轻量版页面（/zh/lite/），该行为存在未明示重定向意图且操作本地存储计数器的特征。
- 证据：`let tr = parseInt(localStorage.getItem('slow_connection_detected')); ...location.href = "/zh/lite/?confirm=1";`
- 建议：审查轻版页面的功能差异，确认该跳转是否合理及是否存在规避检测目的。

### 7. 高频密码框聚集
- 规则：`DEEP_STATIC_PASSWORD_FORM_FOCUS`
- 严重级别：`medium`
- 说明：单一页面出现4个密码输入框，超出常规登录页面1-2个的典型数量，或存在多账号切换等特殊业务场景，但需防止钓鱼页面模仿。
- 证据：`password_forms:4`
- 建议：核查表单归属模块，确认是否存在权限分级等合理业务需求。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
该目标网址指向一个数字货币兑换平台。综合静态特征与专家意见，主要风险在于 TLS 证书签发时间（22 天）与域名注册时长（610 天）存在显著差异，且单页内密集出现 4 个密码输入框，符合钓鱼网站收集凭证的特征。虽然行为分析未检测到主动攻击脚本或恶意重定向（判定为良性），但情报分析员基于金融属性及凭证收集风险判定为恶意倾向。鉴于金融类网站的高敏感性，最终采纳较为谨慎的中等风险评级，建议用户在隔离环境中复核，避免直接提交敏感信息。 该目标网址指向一个数字货币兑换平台。综合静态特征与专家意见，主要风险在于 TLS 证书签发时间（22 天）与域名注册时长（610 天）存在显著差异，且单页内密集出现 4 个密码输入框，符合钓鱼网站收集凭证的特征。虽然行为分析未检测到主动攻击脚本或恶意重定向（判定为良性），但情报分析员基于金融属性及凭证收集风险判定为恶意倾向。鉴于金融类网站的高敏感性，最终采纳较为谨慎的中等风险评级，建议用户在隔离环境中复核，避免直接提交敏感信息。

### 静态分析员（模型：`deepseek-reasoner`）
基于URL结构和页面静态特征分析：域名baksmany.net注册于知名注册商，注册时间超过610天，但SSL证书签发时间仅22天，存在安全证书短期更新的风险信号。页面包含大量密码输入框（4个），但均在主域名内登录，可能属于加密货币交易平台正常身份验证流程。JS代码中存在未经验证的本地存储操作，并可能引导用户跳转至"轻版网站"，但未检测到明显恶意脚本或隐蔽重定向行为。整体静态特征符合加密货币交易平台功能需求，未发现强恶意性证据，风险级别中等。

### 行为分析员（模型：`gemini-2.5-pro`）
经过行为分析，该页面表现出数字货币兑换平台的典型特征。页面包含用户注册和登录的表单，这是此类服务所必需的。未发现自动恶意重定向、恶意脚本加载或强制下载等有害行为。页面中的一个延时脚本会提示网速慢的用户切换到“轻版”网站，这是一种基于用户交互的功能优化，而非恶意诱导。因此，从纯粹的网页行为角度来看，该页面不具有明显的恶意特征。

### 情报分析员（模型：`gpt-4o-mini`）
该域名并未模仿任何特定的品牌或组织，但提供了有关数字货币兑换的信息。其页面内容可能倾向于引发用户提交敏感信息的信任。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站是一个数字货币兑换平台，声称提供比特币买卖服务。尽管行为分析未发现明显的恶意重定向、恶意脚本或强制下载行为，但仍存在几个值得关注的风险点。首先，网站的TLS证书签发时间非常短（仅22天前），这对于一个处理金融交易的平台来说是不寻常的，可能暗示域名被近期接管、重新启用或用于潜在的可疑目的。其次，页面上存在多达4个密码输入框，虽然可能与平台提供的复杂账户管理功能相关，但也增加了被钓鱼网站模仿的风险。此外，页面中的JavaScript代码会在检测到用户网络速度较慢时提示用户切换到“轻量版”网站，并使用了本地存储，这种跳转机制需要通过沙箱环境进行深入的动态分析，以确保其合法性和安全性，防止可能的检测规避或恶意引导。鉴于数字货币交易平台本身固有的高风险属性，以及上述可疑迹象，建议进行进一步的动态行为分析以全面评估其潜在威胁。


### 主持人最终总结
该目标网址指向一个数字货币兑换平台。综合静态特征与专家意见，主要风险在于 TLS 证书签发时间（22 天）与域名注册时长（610 天）存在显著差异，且单页内密集出现 4 个密码输入框，符合钓鱼网站收集凭证的特征。虽然行为分析未检测到主动攻击脚本或恶意重定向（判定为良性），但情报分析员基于金融属性及凭证收集风险判定为恶意倾向。鉴于金融类网站的高敏感性，最终采纳较为谨慎的中等风险评级，建议用户在隔离环境中复核，避免直接提交敏感信息。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
