# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
> 证据分数：**80/100** · 深度研判分数：**80 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：8 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260624_213629_469201.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260624_213629_469201.md

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
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': None, 'whois_creation_date': '2024-10-21T15:02:27Z', 'whois_age_days': 610}

## 四点一、页面线索
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 域名注册时间：`2024-10-21T15:02:27Z`
- 域名注册天数：`610` 天

## 五、截图证据
- 当前未采集到页面截图。

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
- 说明：域名由NICENIC INTERNATIONAL GROUP CO., LIMITED注册，注册时间为610天，暗示该域名相对年轻但已经存在一段时间。
- 证据：`注册商：NICENIC INTERNATIONAL GROUP CO., LIMITED；域名存在天数：610。`
- 建议：建议监控该域名的信誉和活动，以防潜在的风险。

### 4. TLS证书信息分析
- 规则：`INTEL_COVERAGE_1`
- 严重级别：`medium`
- 说明：该域名的TLS证书较短时间内签发，可能表明该网站的安全性未得到充分验证。
- 证据：`证书签发于22天前。`
- 建议：建议结合其他证据综合判断域名的安全性和可信度。

### 5. 疑似虚假加密货币交易平台
- 规则：`DEEP_BEHAVIOR_CRYPTO_SCAM_SUSPICION`
- 严重级别：`high`
- 说明：网站提供加密货币与法币（如卢布）的兑换服务，并包含登录/注册表单（4个密码框）。但页面存在明显的代码渲染错误，且域名为近期注册。正规金融平台通常有严格的质量控制，此特征高度符合粗制滥造的诈骗（如杀猪盘）或钓鱼网站。
- 证据：`页面标题为“加密货币交换 | 购买和出售比特币，USDT，ETH - Baksmany”；包含4个密码框；Whois显示域名创建于 2024-10-21。`
- 建议：强烈建议不要在该平台进行任何注册、登录或资金转账操作。切勿输入真实的账号密码或连接加密货币钱包。

### 6. 前端代码明文泄露
- 规则：`DEEP_BEHAVIOR_JS_LEAKAGE`
- 严重级别：`high`
- 说明：页面可见文本中直接包含未执行的 JavaScript 代码片段（如 setTimeout 逻辑），表明网站前端配置严重错误。正规金融网站绝不会出现此类低级错误，这是判断其为欺诈网站的关键证据。
- 证据：`visible_text_excerpt 中包含 '(function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt...'`
- 建议：视为高风险钓鱼信号，禁止在该页面输入任何信息。

### 7. 可疑JS重定向逻辑
- 规则：`DEEP_STATIC_SUSPICIOUS_JS`
- 严重级别：`medium`
- 说明：页面加载JavaScript包含强制弹窗：检测用户网速缓慢后，诱导用户跳转至轻量版网站（/zh/lite），可能用于规避检测或实施针对性攻击。
- 证据：`JavaScript代码片段：setTimeout(()=>{confirm("我们注意到你的网站加载速度很低。 使用轻版网站？");...location.href="/zh/lite/?confirm=1";},20000)`
- 建议：审查该重定向逻辑的真实意图，避免在隔离环境外触发此行为。

### 8. 异常数量密码输入框
- 规则：`DEEP_STATIC_MULTIPLE_PASSWORD_FIELDS`
- 严重级别：`high`
- 说明：页面包含 4 个密码输入框，远超常规登录页需求（通常 1-2 个）。结合代码泄露和加密货币主题，极有可能是为了收集用户多个账户的凭证或进行复杂的钓鱼诱导。
- 证据：`密码框数量：4（来自静态报告及浏览器证据）`
- 建议：切勿在该页面输入任何敏感信息，尤其避免重复使用同一密码。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
目标 URL (https://baksmany.net/zh/) 被判定为高风险钓鱼或欺诈网站。核心证据在于页面存在严重的开发缺陷：JavaScript 代码未正确执行而直接以明文形式暴露在页面可见文本中，这对于声称提供金融/加密货币交易服务的网站而言是极不正常的，强烈暗示其为粗制滥造的诈骗站点。此外，页面包含 4 个密码输入框，远超常规登录需求，结合加密货币交易主题，存在极高的凭证窃取风险。尽管域名注册已约 610 天（非极新域名），但 TLS 证书签发仅 22 天，且网站质量低劣，不足以抵消上述恶意特征。专家意见存在分歧：情报与静态分析倾向于中等风险，而行为分析与处置建议基于代码泄露和表单异常判定为高风险/严重风险。最终结论采纳行为分析观点，因代码泄露是判断网站真实性和安全性的决定性负面指标。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`deepseek-reasoner`）
URL 结构层面关注：TLS 证书签发时间较短、页面包含密码输入框。基于静态分析，重点关注页面结构和代码特征：存在大量密码输入框（4 个），以及可疑的 JavaScript 弹窗重定向逻辑。总体静态证据指向可疑金融操作，但尚未发现直接恶意代码。

### 行为分析员（模型：`gemini-2.5-pro`）
页面声称为加密货币交易所，包含多个密码输入框用于收集用户凭据。然而，页面存在明显的开发缺陷（JavaScript 代码直接暴露在可见文本中），且结合外部情报显示域名注册时间极短。这种粗糙的制作质量与新注册域名结合，极不符合正规金融交易平台的特征，高度疑似虚假投资理财或加密货币钓鱼诈骗网站。

### 情报分析员（模型：`gpt-4o-mini`）
该网页并未明确模仿特定品牌或组织，可能是未知或新成立的加密货币相关服务网站。域名由 NICENIC 注册，存在 610 天，TLS 证书较短时间内签发。建议监控该域名的信誉和活动，以防潜在的风险。

### 处置建议员（模型：`gemini-2.5-flash`）
该网页高度疑似为虚假加密货币交易平台的钓鱼网站。核心风险证据包括：页面内包含多达 4 个异常的密码输入框，且网页前端开发质量极差，JavaScript 逻辑代码直接以文本形式暴露在页面正文中。尽管域名注册已有一定时间，但该网站表现出的欺诈特征非常明显。建议阻断。


### 主持人最终总结
目标 URL (https://baksmany.net/zh/) 被判定为高风险钓鱼或欺诈网站。核心证据在于页面存在严重的开发缺陷：JavaScript 代码未正确执行而直接以明文形式暴露在页面可见文本中，这对于声称提供金融/加密货币交易服务的网站而言是极不正常的，强烈暗示其为粗制滥造的诈骗站点。此外，页面包含 4 个密码输入框，远超常规登录需求，结合加密货币交易主题，存在极高的凭证窃取风险。尽管域名注册已约 610 天（非极新域名），但 TLS 证书签发仅 22 天，且网站质量低劣，不足以抵消上述恶意特征。专家意见存在分歧：情报与静态分析倾向于中等风险，而行为分析与处置建议基于代码泄露和表单异常判定为高风险/严重风险。最终结论采纳行为分析观点，因代码泄露是判断网站真实性和安全性的决定性负面指标。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
