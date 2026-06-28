# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**HIGH** · 风险分数：**75/100**
> 评分口径：URL 深度研判分数已综合证据分数，最终风险分数直接采用深度研判分数。
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：8 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260625_210401_261683.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260625_210401_261683.md

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
- 时间：`2026-06-25T13:03:51.324402+00:00`
- 大小：`596946` 字节


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

### 3. 域名信息分析
- 规则：`INTEL_INFRA_DOMAIN_AGE`
- 严重级别：`medium`
- 说明：该域名已经存在611天，虽然不是极新的域名，但也不能完全排除可能性。它的注册商是NICENIC INTERNATIONAL GROUP CO., LIMITED，但没有提供国家/地区信息，这限制了对其声誉的全面评估。
- 证据：`注册商：NICENIC INTERNATIONAL GROUP CO., LIMITED；域名存在天数：611`
- 建议：建议继续监控该域名的活动和声誉，特别是在与加密货币相关的交易中。

### 4. TLS证书分析
- 规则：`INTEL_INFRA_CERTIFICATE`
- 严重级别：`medium`
- 说明：域名的TLS证书较新，签发于23天前，这可能指示该站点是新启动的或只是在寻找时机来运营。进一步调查其使用的具体证书类型和来源显得尤为重要。
- 证据：`证书签发时间：23天前`
- 建议：建议审查此证书的透明度和信任度，以确保交易安全。

### 5. 疑似加密货币钓鱼网站
- 规则：`DEEP_BEHAVIOR_CRYPTO_PHISHING_PATTERN`
- 严重级别：`high`
- 说明：页面伪装成加密货币交易平台，包含多个密码输入框，意图诱导用户输入登录凭证。结合静态分析发现的近期签发的TLS证书，这种“金融主题 + 索取密码 + 新证书”的组合是钓鱼和金融诈骗网站的典型特征。尽管自动化浏览过程中未发现强制跳转或恶意下载等行为，但其核心功能是收集敏感金融凭证，存在极高的凭证失窃和财产损失风险。
- 证据：`页面功能：加密货币交换；
用户交互：页面包含4个密码输入框，用于登录和注册；
关联风险：静态分析发现TLS证书签发时间较短（23天前）。`
- 建议：强烈建议不要在此网站输入任何个人信息、账户凭证或进行任何交易。对此类未知来源的金融平台需保持高度警惕。

### 6. 可疑JavaScript行为诱导
- 规则：`DEEP_STATIC_JS_OBFUSCATION`
- 严重级别：`high`
- 说明：检测到脚本通过localStorage跟踪用户访问次数，伪造低网速警报诱导用户跳转至'/zh/lite/'页面，该行为具有典型钓鱼页面特征（如伪造轻量版以规避检测）。
- 证据：`代码片段：let tr = parseInt(localStorage.getItem('slow_connection_detected')); ... cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); ... location.href = "/zh/lite/?confirm=1";`
- 建议：此类强制跳转脚本需结合沙箱动态分析验证实际意图。

### 7. 品牌模仿文字内容
- 规则：`DEEP_STATIC_BRAND_IMITATION`
- 严重级别：`medium`
- 说明：可见文本包含'朋友们，抓住这个不容错过的机会！'等煽动性用语，并出现'币安所有用户的迁移服务'字样，涉嫌利用知名交易所名称进行欺诈引流。
- 证据：`可见文本片段：'现在您可以用 USDT 余额直接支付卢布账单...选择私人支付服务！' 及 '币安所有用户的迁移服务'`
- 建议：需通过威胁情报确认该域名是否在加密货币社群黑名单中。

### 8. 异常密码字段密度
- 规则：`DEEP_STATIC_PASSWORD_FIELD_ABUSE`
- 严重级别：`critical`
- 说明：同一页面存在4个密码输入框，远超正常登录页面需求（通常为1-2个）。结合'无需强制注册'宣传语，极可能用于收集多组用户凭证。
- 证据：`PAGE_PASSWORD_FORM证据：密码框数量: 4`
- 建议：即便表单提交路径为相对路径，仍需警惕凭证收集风险。建议将原PAGE_PASSWORD_FORM规则严重度提升至critical。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合静态检测、浏览器证据及四位专家意见，该网页被判定为高风险的加密货币钓鱼网站。尽管静态报告初始评级为 medium，但行为分析员和静态分析员均指出其具有典型的钓鱼特征：页面包含 4 个密码输入框（远超正常需求）、TLS 证书签发时间极短（23 天）、以及存在诱导用户跳转的伪造 JavaScript 逻辑。处置建议员进一步将其风险提升至 critical 并建议拦截。主要争议点在于情报分析员未发现明确的品牌模仿，而静态分析员指出页面文本涉及“币安用户迁移”等欺诈性引流内容。鉴于凭证窃取的高危害性及多项高风险指标吻合，最终结论采纳行为与静态分析员的恶意倾向判断，风险等级上调至 high，建议用户切勿输入任何敏感信息。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`deepseek-reasoner`）
静态证据分析结论：网页结构与内容存在多个可疑特征。尽管页面声称是加密货币交易平台，但存在伪造浏览器交互行为的 JavaScript 代码（伪加载速度检测及强制跳转）、刻意模仿知名品牌（如‘币安’的用户群体迁移通知）、界面冗余密码表单设计（包含 4 个密码输入框）等高风险信号。域名注册已存在 611 天但证书签发仅 23 天，此类证书短期签发行为常与钓鱼站点运营模式吻合。静态层面无法消除恶意倾向嫌疑。

### 行为分析员（模型：`gemini-2.5-pro`）
该页面是一个加密货币交易平台，行为上没有自动执行恶意操作（如恶意跳转、下载）。然而，其核心功能是引导用户进行登录或注册，包含多个密码输入框。结合静态分析中提到的

### 情报分析员（模型：`gpt-4o-mini`）
该网页似乎没有清晰的品牌或组织模仿目标，其内容围绕加密货币交换展开，但没有证据表明其剽窃知名品牌。

### 处置建议员（模型：`gemini-2.5-flash`）
综合分析静态和行为证据，该网页声称是加密货币交换平台，但存在多项高度可疑行为和特征。TLS 证书签发时间极短（23天前），同时页面包含异常数量的密码输入框（4个），结合“无需强制注册”的宣传语，强烈暗示其旨在进行凭证窃取。此外，页面存在伪造慢速连接并诱导用户跳转至“轻量版”的可疑 JavaScript 行为，以及通过提及“币安所有用户的迁移服务”来模仿知名品牌并提供异常金融服务（如 USDT 直接支付卢布）。所有证据均指向这是一个高风险的加密货币钓鱼或金融诈骗网站，旨在窃取用户的敏感信息和资产。尽管自动化浏览过程中未发现强制跳转或恶意下载等行为，但其诱导用户提交敏感信息的意图非常明确，构成极高的安全威胁。


### 主持人最终总结
综合静态检测、浏览器证据及四位专家意见，该网页被判定为高风险的加密货币钓鱼网站。尽管静态报告初始评级为 medium，但行为分析员和静态分析员均指出其具有典型的钓鱼特征：页面包含 4 个密码输入框（远超正常需求）、TLS 证书签发时间极短（23 天）、以及存在诱导用户跳转的伪造 JavaScript 逻辑。处置建议员进一步将其风险提升至 critical 并建议拦截。主要争议点在于情报分析员未发现明确的品牌模仿，而静态分析员指出页面文本涉及“币安用户迁移”等欺诈性引流内容。鉴于凭证窃取的高危害性及多项高风险指标吻合，最终结论采纳行为与静态分析员的恶意倾向判断，风险等级上调至 high，建议用户切勿输入任何敏感信息。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
