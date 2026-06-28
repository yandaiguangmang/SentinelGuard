# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**MEDIUM** · 风险分数：**34/100**
> 证据分数：**38/100** · 深度研判分数：**29 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：7 条
- 高危证据：0 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260623_213332_698053.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260623_213332_698053.md

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
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': None, 'whois_creation_date': '2024-10-21T15:02:27Z', 'whois_age_days': 609, 'crt_earliest_cert_date': '2025-02-14T00:00:00', 'crt_age_days': 494, 'crt_total_certs': 46}

## 四点一、页面线索
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 域名注册时间：`2024-10-21T15:02:27Z`
- 域名注册天数：`609` 天
- 最早证书签发时间：`2025-02-14T00:00:00`
- 证书历史天数：`494` 天
- 证书总数：`46` 张

## 五、截图证据
### 截图 1
- 标题：`数字货币兑换，买卖比特币`
- 落点：`https://baksmany.net/zh/`
- 时间：`2026-06-23T13:33:32.580420+00:00`
- 大小：`596583` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 21 天前。
- 证据：`Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`medium`
- 说明：密码表单提交与当前域名一致或为相对路径，可能为正常登录功能。
- 证据：`密码框数量: 4`
- 建议：确认域名归属和证书可信后再输入账号密码。

### 3. 域名注册信息分析
- 规则：`INTEL_INFRA_DOMAIN`
- 严重级别：`medium`
- 说明：域名于2024年10月21日注册，至今存在609天，证明该域名相对历史较长，但创建时间较新，有可能用于潜在的恶意活动。
- 证据：`域名注册商：NICENIC INTERNATIONAL GROUP CO., LIMITED；域名存在天数：609天。`
- 建议：建议对该域名进行进一步监控，并分析其与已知恶意活动的关联性。

### 4. TLS证书分析
- 规则：`INTEL_INFRA_CERTIFICATE`
- 严重级别：`medium`
- 说明：该域名拥有46个证书，该证书最早签发时间为2025年2月14日，显示证书活动频繁，但首次证书签发日期距离今有较大时间差，可能隐含风险。
- 证据：`证书历史天数：494天；证书总数：46。`
- 建议：建议审查这些证书的来源和透明度，并比对历史恶意活动。

### 5. 密码表单功能与网站声称的服务一致
- 规则：`DEEP_BEHAVIOR_LEGITIMATE_LOGIN_FORM`
- 严重级别：`medium`
- 说明：行为分析显示，页面包含的密码输入框是数字货币交易平台正常的登录或注册功能的一部分。没有观察到表单数据被提交到非预期的第三方恶意域名的行为。因此，在没有恶意提交行为证据的情况下，单纯存在密码框不应被视为中等风险。
- 证据：`页面功能为数字货币兑换，需要用户认证。浏览器行为分析未检测到表单数据被提交到外部可疑域名。`
- 建议：建议将静态分析发现的“页面包含密码输入框”风险等级从“中等”调整为“信息性”，因为其功能与网站声称的服务类型相符。

### 6. 异常网络检测与轻量版切换逻辑
- 规则：`DEEP_STATIC_SUSPICIOUS_FUNCTION`
- 严重级别：`low`
- 说明：页面嵌入了检测弱网环境的脚本，20秒后提示切换到轻量版网站。该逻辑虽不常见但属于功能性设计，未发现恶意重定向或用户欺骗行为。
- 证据：`setTimeout(() => { ... confirm("我们注意到你的网站加载速度很低。使用轻版网站？") ... location.href = "/zh/lite/?confirm=1"; }, 20000);`
- 建议：弱网切换功能需警惕被利用为钓鱼入口，建议动态监测实际跳转行为。

### 7. TLS 证书活动频繁
- 规则：`CERT_RECENT_ACTIVITY`
- 严重级别：`medium`
- 说明：情报显示该域名拥有 46 个证书，且近期有证书更新（静态报告指出签发于 21 天前）。虽然域名注册已 609 天，但频繁的证书活动可能暗示基础设施的不稳定性或潜在的风险操作。
- 证据：`证书总数：46；最近证书签发：2026-06-02（约 21 天前）。`
- 建议：建议持续监控该域名的证书透明度日志，关注是否有异常的新增证书。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合静态检测、浏览器行为证据及四位专家意见，目标网址 https://baksmany.net/zh/ 被判定为低风险。该网站为数字货币兑换平台，页面功能（如密码输入框）与业务场景相符，浏览器行为分析未检测到恶意重定向、可疑脚本执行或数据外泄行为。静态分析发现 TLS 证书近期有更新且页面包含多个密码表单，情报分析指出域名注册于 2024 年 10 月且证书活动频繁，这些基础设施指标引发了一定程度的关注（中等风险提示），但结合运行时行为证据，未发现直接恶意利用迹象。处置建议允许访问，但建议用户确认链接来源可信并注意个人信息保护。 综合静态检测、浏览器行为证据及四位专家意见，目标网址 https://baksmany.net/zh/ 被判定为低风险。该网站为数字货币兑换平台，页面功能（如密码输入框）与业务场景相符，浏览器行为分析未检测到恶意重定向、可疑脚本执行或数据外泄行为。静态分析发现 TLS 证书近期有更新且页面包含多个密码表单，情报分析指出域名注册于 2024 年 10 月且证书活动频繁，这些基础设施指标引发了一定程度的关注（中等风险提示），但结合运行时行为证据，未发现直接恶意利用迹象。处置建议允许访问，但建议用户确认链接来源可信并注意个人信息保护。

### 静态分析员（模型：`deepseek-reasoner`）
静态证据分析表明，域名结构正常且路径稳定，页面内容明确与数字货币交易相关。HTML结构和脚本中虽有异常逻辑处理（弱网切换轻量版），但属于功能实现范畴。存在多个密码输入框，结合明确业务描述，符合交易所登录页面的特征。证书签发时间较早（2025年），与情报显示注册年龄609天能形成佐证，未发现直接恶意线索。

### 行为分析员（模型：`gemini-2.5-pro`）
从行为分析的角度看，该网页没有表现出任何恶意行为。页面直接加载，没有可疑的重定向。页面中包含一个JavaScript脚本，该脚本在20秒后检测到加载缓慢时，会弹窗询问用户是否愿意跳转到同一个域名下的轻量版页面。这是一个正常的用户体验优化功能，需要用户交互才会触发跳转，并非恶意的自动重定向。页面上存在的密码输入框与该网站作为数字货币兑换平台的功能相符，是预期的登录/注册功能，没有发现将数据提交到可疑第三方域名的行为。没有自动下载或加载可疑的外部脚本。综合来看，其行为链是清晰和良性的。

### 情报分析员（模型：`gpt-4o-mini`）
该页面未明确模仿任何特定品牌或组织，不存在明显的品牌冒充行为。

### 处置建议员（模型：`gemini-2.5-flash`）
该页面被识别为数字货币兑换服务网站，其内容和功能（包括多个密码输入框）与所声称的业务相符。行为分析显示，页面加载直接，没有观察到可疑的重定向、恶意脚本执行或向第三方可疑域名提交数据的行为。页面中检测到的慢速网络优化脚本属于正常的用户体验功能，需要用户主动确认才会触发轻量版切换。尽管静态分析和情报分析指出了一些潜在的关注点，例如 TLS 证书签发时间较短（约21天前）以及域名注册时间相对较新（2024年10月注册），但这些因素本身并未构成直接的恶意行为证据。情报分析员对域名和证书活动的判断为“不确定”，行为分析员和静态分析员均倾向于“良性”。综合所有证据，未发现明确的恶意活动或直接的安全威胁。


### 主持人最终总结
综合静态检测、浏览器行为证据及四位专家意见，目标网址 https://baksmany.net/zh/ 被判定为低风险。该网站为数字货币兑换平台，页面功能（如密码输入框）与业务场景相符，浏览器行为分析未检测到恶意重定向、可疑脚本执行或数据外泄行为。静态分析发现 TLS 证书近期有更新且页面包含多个密码表单，情报分析指出域名注册于 2024 年 10 月且证书活动频繁，这些基础设施指标引发了一定程度的关注（中等风险提示），但结合运行时行为证据，未发现直接恶意利用迹象。处置建议允许访问，但建议用户确认链接来源可信并注意个人信息保护。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
