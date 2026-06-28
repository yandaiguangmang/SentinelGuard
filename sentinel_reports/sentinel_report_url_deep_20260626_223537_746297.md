# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**HIGH** · 风险分数：**75/100**
> 评分口径：URL 深度研判分数已综合证据分数，最终风险分数直接采用深度研判分数。
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：5 条
- 高危证据：2 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260626_223234_197591.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260626_223234_197591.md

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
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': None, 'whois_creation_date': '2024-10-21T15:02:27Z', 'whois_age_days': 612}

## 四点一、页面线索
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 域名注册时间：`2024-10-21T15:02:27Z`
- 域名注册天数：`612` 天

## 五、截图证据
### 截图 1
- 标题：`加密货币交换 | 购买和出售比特币，USDT，ETH - Baksmany`
- 落点：`https://baksmany.net/zh/`
- 时间：`2026-06-26T14:32:21.918276+00:00`
- 大小：`349052` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 24 天前。
- 证据：`Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 异常密码输入框数量
- 规则：`DEEP_STATIC_PASSWORD_FIELD_ABNORMALITY`
- 严重级别：`high`
- 说明：单页面出现4处密码输入框，远超常规登录页面需求。可能用于收集不同服务的凭证或重复用户输入。
- 证据：`密码表单数量:4`
- 建议：审查表单提交目标是否指向同一域名，确认是否存在凭证嗅探风险。

### 3. 域名注册信息分析
- 规则：`INTEL_INFRA_1`
- 严重级别：`medium`
- 说明：该域名于612天前创建，较为年轻，可能表明新近建立的服务，但并不一定恶意。
- 证据：`注册商为 NICENIC INTERNATIONAL GROUP CO., LIMITED，域名创建时间为 2024-10-21，域名存在天数为 612。`
- 建议：应监测该域名的未来活动及信誉，特别是在涉及密码或敏感信息时。

### 4. 证书信息缺失
- 规则：`INTEL_INFRA_2`
- 严重级别：`high`
- 说明：域名的TLS证书信息未提供，增加了潜在的风险。
- 证据：`TLS证书信息缺失。`
- 建议：强烈建议确保使用有效和可信的证书，特别是在涉及加密货币交易时。

### 5. 页面使用延迟弹窗诱导用户跳转
- 规则：`DEEP_BEHAVIOR_DECEPTIVE_PROMPT`
- 严重级别：`medium`
- 说明：页面加载20秒后，会弹出一个确认框，询问用户是否因为“网站加载速度很低”而切换到“轻版网站”。如果用户同意，页面将跳转到 /zh/lite/。这是一种利用看似合理的借口诱导用户进行导航操作的欺骗性行为，可能将用户引导至一个功能不同或更具风险的页面。
- 证据：`(function(){ let TimerID = setTimeout(() => { ... cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); ...})();`
- 建议：警惕网站以技术问题为由提出的跳转或操作建议，这可能是将用户引导至恶意页面的前奏。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合静态检测、浏览器证据及四位专家意见，该网页存在显著的高风险特征。虽然情报分析员与主持人初步判定风险为 medium 且定性为 uncertain，但静态分析员与行为分析员均指出关键恶意指标：单页面包含 4 个密码输入框（远超正常登录需求），且存在利用延迟弹窗诱导用户跳转至“轻版网站”的欺骗性行为（社会工程学手段）。处置建议员基于上述特征及证书签发时间短（24 天）判定风险为 critical 并建议拦截。鉴于密码表单异常与诱导跳转是典型的钓鱼或诈骗网站特征，最终结论采纳静态与行为分析员的高风险判定，认为该站点极可能为针对加密货币用户的钓鱼或诈骗平台。 综合静态检测、浏览器证据及四位专家意见，该网页存在显著的高风险特征。虽然情报分析员与主持人初步判定风险为 medium 且定性为 uncertain，但静态分析员与行为分析员均指出关键恶意指标：单页面包含 4 个密码输入框（远超正常登录需求），且存在利用延迟弹窗诱导用户跳转至“轻版网站”的欺骗性行为（社会工程学手段）。处置建议员基于上述特征及证书签发时间短（24 天）判定风险为 critical 并建议拦截。鉴于密码表单异常与诱导跳转是典型的钓鱼或诈骗网站特征，最终结论采纳静态与行为分析员的高风险判定，认为该站点极可能为针对加密货币用户的钓鱼或诈骗平台。

### 静态分析员（模型：`deepseek-reasoner`）
静态分析发现网页主体为加密货币交易平台界面，页面包含大量密码输入框（4处），结合高风险金融属性需重点警惕敏感信息采集风险。证据显示页面内嵌JavaScript存在主动降级引导行为：当检测到页面加载缓慢时，通过localStorage标记并弹窗建议用户跳转至简化版页面（/zh/lite/?confirm=1），此类行为虽可能出于性能优化目的，但结合TLS证书签发时间较短（24天）等特征，仍需谨慎评估其可信度。域名注册历史较久（612天），但注册商为香港商业机构，中立性存疑。综合分析关键风险：密码框数量异常+主动跳转机制+金融敏感业务场景，静态结构倾向可疑。

### 行为分析员（模型：`gemini-2.5-pro`）
页面呈现为一个加密货币交易平台，包含登录和注册功能。行为分析发现，页面在加载20秒后会弹出一个确认框，以“网站加载速度很低”为由，诱导用户跳转到“轻版网站”。这种利用延迟和看似合理的借口来触发导航的行为具有欺骗性，是社会工程学的一种手段。虽然页面没有执行其他明显的恶意行为（如自动下载或重定向到不相关的恶意网站），但其业务性质（加密货币交易）、存在多个密码输入框以及诱导性弹窗，共同构成了一个典型的金融诈骗或钓鱼网站的特征。结合静态分析发现的“证书签发时间短”这一高风险信号，该网站是恶意诈骗网站的可能性很高。

### 情报分析员（模型：`gpt-4o-mini`）
该页面并未明显模拟任何特定品牌或组织，指向加密货币交易的普通页面，且内容看似正常。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站声称提供加密货币交换服务，但存在多项可疑特征。首先，页面包含异常数量的密码输入框（4个），这极大地增加了用户凭证被盗用的风险。其次，网站在加载20秒后会弹出一个具有欺骗性的提示框，声称网站加载缓慢并诱导用户跳转到“轻版网站”，这是一种典型的社会工程学手段，可能用于规避检测或引导用户至恶意页面。此外，该网站的TLS证书签发时间较短（24天），且情报分析指出可能存在证书信息缺失问题，这进一步降低了其可信度。考虑到加密货币交易本身的高风险性质，以及上述多项高风险行为和指标，该网站极有可能是一个钓鱼或诈骗平台，旨在窃取用户敏感信息或资金。为了保护用户，建议采取拦截措施。


### 主持人最终总结
综合静态检测、浏览器证据及四位专家意见，该网页存在显著的高风险特征。虽然情报分析员与主持人初步判定风险为 medium 且定性为 uncertain，但静态分析员与行为分析员均指出关键恶意指标：单页面包含 4 个密码输入框（远超正常登录需求），且存在利用延迟弹窗诱导用户跳转至“轻版网站”的欺骗性行为（社会工程学手段）。处置建议员基于上述特征及证书签发时间短（24 天）判定风险为 critical 并建议拦截。鉴于密码表单异常与诱导跳转是典型的钓鱼或诈骗网站特征，最终结论采纳静态与行为分析员的高风险判定，认为该站点极可能为针对加密货币用户的钓鱼或诈骗平台。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
