# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：14 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260621_211845_497753.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260621_211845_497753.md

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
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': None, 'whois_creation_date': '2024-10-21T15:02:27Z', 'whois_age_days': 607}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 域名注册时间：`2024-10-21T15:02:27Z`
- 域名注册天数：`607` 天

## 五、截图证据
- 截图数量：`1` 张，完整图像请查看 HTML 报告。
- 截图 1：
  - URL：`https://baksmany.net/zh/`
  - 最终地址：`https://baksmany.net/zh/`
  - 大小：`596246` 字节
  - 视口：`{'width': 1440, 'height': 1600}`

## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 19 天前。
- 证据：`Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`medium`
- 说明：密码表单提交与当前域名一致或为相对路径，可能为正常登录功能。
- 证据：`密码框数量: 4`
- 建议：确认域名归属和证书可信后再输入账号密码。

### 3. 未发现品牌模仿
- 规则：`INTEL_BRAND_IMPERSONATION`
- 严重级别：`low`
- 说明：该网页没有明显模仿特定品牌或组织，内容主要围绕数字货币兑换展开。
- 证据：`网页标题为'数字货币兑换，买卖比特币'，未涉及任何知名品牌。`
- 建议：继续监控该域名的活动，确保没有后续的品牌模仿行为。

### 4. 域名注册信息分析
- 规则：`INTEL_INFRA_REPUTATION`
- 严重级别：`medium`
- 说明：该域名由NICENIC INTERNATIONAL GROUP CO., LIMITED注册，注册时间为607天，显示出一定的持续性，但缺乏其他信誉信息。
- 证据：`注册商为NICENIC INTERNATIONAL GROUP CO., LIMITED，注册时间为2024-10-21。`
- 建议：建议进一步调查该注册商的声誉及其与其他恶意活动的关联。

### 5. 地理位置影响
- 规则：`INTEL_COVERAGE_GEOGRAPHIC`
- 严重级别：`medium`
- 说明：当前未提供域名的注册国家信息，可能影响对该域名的全面评估。
- 证据：`whois_country字段为空。`
- 建议：建议获取更多关于该域名的地理位置和运营背景的信息，以便进行更准确的风险评估。

### 6. 可疑的页面跳转逻辑
- 规则：`DEEP_STATIC_JS_REDIRECT_OBSF`
- 严重级别：`medium`
- 说明：页面包含一段通过 localStorage 监测加载速度并使用 confirm 弹窗诱导用户跳转至 /lite/ 路径的脚本，此类逻辑常被用于规避安全扫描或引导用户进入更易于实施钓鱼的精简版页面。
- 证据：`setTimeout(() => { ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：需进一步分析 /lite/ 路径下的内容是否包含恶意表单或重定向。

### 7. 高风险金融交互特征
- 规则：`DEEP_STATIC_FINANCIAL_PHISHING_RISK`
- 严重级别：`medium`
- 说明：页面包含 4 个密码输入框，且涉及数字货币兑换业务。此类站点若缺乏合规资质，极易成为获取用户敏感凭据的钓鱼平台。
- 证据：`password_forms: 4`
- 建议：严禁在未确认平台合法性的情况下输入任何账号、密码或私钥。

### 8. 页面在加密货币交易场景下收集凭证
- 规则：`DEEP_BEHAVIOR_CREDENTIAL_HARVESTING_CONTEXT`
- 严重级别：`high`
- 说明：该网站作为一个加密货币交易平台，包含多个密码输入框用于用户登录和注册。虽然这是此类网站的正常功能，但加密货币领域是网络钓鱼和金融诈骗的高发区。用户在此类页面输入凭证将面临直接的财务损失风险，尤其是在该网站信誉未知且静态分析显示其TLS证书较新的情况下。
- 证据：`页面标题为“数字货币兑换，买卖比特币”，并包含4个密码输入框，引导用户进行“登记”和“进来”（登录）。`
- 建议：强烈建议不要在该网站输入任何个人信息或财务凭证，除非能通过可靠的第三方来源证实其为合法、信誉良好的交易平台。

### 9. 高风险金融凭据收集
- 规则：`DEEP_ADVICE_PHISHING_RISK`
- 严重级别：`high`
- 说明：页面包含 4 个密码输入框，且业务涉及数字货币兑换。在缺乏可信度验证的情况下，此类页面极易被用于钓鱼攻击，导致用户敏感凭据泄露及直接经济损失。
- 证据：`页面存在 4 个密码输入框，且包含“登记”、“进来”等引导登录的交互元素。`
- 建议：建议将该域名列入黑名单，禁止用户访问，防止凭据泄露。

### 10. 可疑的轻量版跳转逻辑
- 规则：`DEEP_ADVICE_SUSPICIOUS_REDIRECT`
- 严重级别：`medium`
- 说明：页面内置脚本通过监测加载速度诱导用户跳转至 /lite/ 路径。此类逻辑常见于钓鱼站点，旨在通过精简版页面绕过安全检测或针对特定用户进行欺诈。
- 证据：`JavaScript 代码中包含 setTimeout 逻辑，在 20 秒后通过 confirm 弹窗诱导用户跳转。`
- 建议：对 /lite/ 路径进行深度沙箱分析，并对该域名的所有子路径实施访问限制。

### 11. TLS 证书与信誉风险
- 规则：`DEEP_ADVICE_CERT_VIGILANCE`
- 严重级别：`medium`
- 说明：虽然域名注册时间较长，但 TLS 证书签发时间较短，且缺乏明确的行业合规背书，无法排除其作为短期钓鱼站点的可能性。
- 证据：`证书签发于 19 天前。`
- 建议：在未获得明确第三方可信认证前，保持封禁状态，并记录所有访问该域名的日志以备后续审计。

### 12. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：结合专家意见，该信号更适合作为“辅助性风险放大因素”，而非单独定性依据；它与页面凭证收集特征叠加后，提升了整体钓鱼嫌疑。
- 证据：`证书签发于 19 天前。`
- 建议：在未能确认站点合法性前，避免输入账号、密码或其他敏感信息，并继续核查证书透明度与站点归属。

### 13. 加密货币交易场景下的凭证收集风险
- 规则：`DEEP_BEHAVIOR_CREDENTIAL_HARVESTING_CONTEXT`
- 严重级别：`high`
- 说明：页面的核心交互是登录/注册和密码输入，且业务属于高风险金融领域。虽然这不等同于恶意，但在缺乏可信背书时应按高风险凭据收集场景处理。
- 证据：`页面标题为“数字货币兑换，买卖比特币”，并包含 4 个密码输入框。`
- 建议：建议将该站点视为高风险访问目标，禁止在未验证真实性前输入任何账户信息。

### 14. 域名注册信息缺乏充分信誉支撑
- 规则：`INTEL_INFRA_REPUTATION`
- 严重级别：`medium`
- 说明：WHOIS 显示域名注册时长约 607 天，说明并非极短生命周期域名；但注册商与注册国家信息不足以支撑其合法性，信誉证据仍然偏弱。
- 证据：`注册商为 NICENIC INTERNATIONAL GROUP CO., LIMITED，whois_country 为空，注册时间为 2024-10-21。`
- 建议：应补充域名信誉、历史解析、证书透明度和黑名单命中情况后再做放行判断。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于离线静态检测结果、浏览器证据包及四位专家意见，当前页面更符合“高风险金融凭据收集/钓鱼风险较高”的特征，而不仅仅是普通的数字货币兑换站点。证据链显示：页面标题与可见文本明确指向“数字货币兑换，买卖比特币”，并包含 4 个密码输入框；页面还嵌入了通过 localStorage 和 20 秒定时器触发的轻量版跳转逻辑，可能用于引导用户进入 /zh/lite/ 路径。虽然未观察到强制下载、外连脚本或明显的自动恶意重定向，但高风险金融场景叠加凭证输入框、可疑跳转逻辑、证书签发时间较短，以及缺乏权威背书，使其具备较强的钓鱼或金融诈骗嫌疑。域名 WHOIS 显示注册已约 607 天，说明并非极新域名，因此“域名很新所以危险”的理由不成立；但短期 TLS 证书与高风险业务特征仍然支持偏高风险判断。当前结论完全依赖离线证据，外部情报不足以进一步佐证其合法性或恶意归属。 {'claim': 'medium', 'confidence': None, 'opinion': '综合 2 条证据，当前风险等级为 medium。'}

### 静态分析员（模型：`gemini-2.5-flash`）
{'claim': 'malicious_lean', 'confidence': 0.75, 'opinion': '页面呈现为数字货币兑换平台，但包含 4 个密码输入框，并存在通过 localStorage 与延时弹窗诱导跳转到轻量版页面的脚本。结合较新的 TLS 证书和高风险金融交易属性，存在被用于钓鱼或欺诈的潜在风险。'}

### 行为分析员（模型：`gemini-2.5-pro`）
{'claim': 'uncertain', 'confidence': 0.5, 'opinion': '未发现自动重定向、恶意脚本加载或强制下载等直接恶意行为，但页面核心功能是收集凭证，且处于高风险加密货币场景，因此存在钓鱼或金融诈骗高度风险的可能。'}

### 情报分析员（模型：`gpt-4o-mini`）
{'claim': 'uncertain', 'confidence': 0.7, 'opinion': '该网页未见明显模仿特定品牌或组织，内容主要集中在数字货币兑换服务上；当前版本采用离线规则研判，若用于实战还需补充域名信誉、证书透明度和黑名单情报。'}

### 处置建议员（模型：`gemini-2.5-flash`）
{'claim': 'uncertain', 'confidence': 0.0, 'opinion': '页面表现为典型数字货币兑换平台，但包含多个密码输入框及可疑的轻量版跳转逻辑，结合高风险金融场景、缺乏权威背书和较新的证书，存在较高的金融诈骗或凭据窃取风险，建议封禁。'}


### 主持人最终总结
基于离线静态检测结果、浏览器证据包及四位专家意见，当前页面更符合“高风险金融凭据收集/钓鱼风险较高”的特征，而不仅仅是普通的数字货币兑换站点。证据链显示：页面标题与可见文本明确指向“数字货币兑换，买卖比特币”，并包含 4 个密码输入框；页面还嵌入了通过 localStorage 和 20 秒定时器触发的轻量版跳转逻辑，可能用于引导用户进入 /zh/lite/ 路径。虽然未观察到强制下载、外连脚本或明显的自动恶意重定向，但高风险金融场景叠加凭证输入框、可疑跳转逻辑、证书签发时间较短，以及缺乏权威背书，使其具备较强的钓鱼或金融诈骗嫌疑。域名 WHOIS 显示注册已约 607 天，说明并非极新域名，因此“域名很新所以危险”的理由不成立；但短期 TLS 证书与高风险业务特征仍然支持偏高风险判断。当前结论完全依赖离线证据，外部情报不足以进一步佐证其合法性或恶意归属。


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

- 总耗时：46.56 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 情报分析员 | 8.10 | 3932 | 426 | 4358 |
| 静态分析员 | 10.91 | 4244 | 463 | 4707 |
| 行为分析员 | 31.91 | 4360 | 421 | 4781 |
| 处置建议员 | 4.35 | 5214 | 601 | 5815 |
| 主持人 | 10.29 | 5849 | 1889 | 7738 |
