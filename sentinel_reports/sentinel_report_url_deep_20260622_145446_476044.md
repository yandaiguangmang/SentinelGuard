# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：12 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_145402_346756.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_145402_346756.md

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
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': None, 'whois_creation_date': '2024-10-21T15:02:27Z', 'whois_age_days': 608, 'crt_earliest_cert_date': '2025-02-14T00:00:00', 'crt_age_days': 493, 'crt_total_certs': 46}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 域名注册时间：`2024-10-21T15:02:27Z`
- 域名注册天数：`608` 天
- 最早证书签发时间：`2025-02-14T00:00:00`
- 证书历史天数：`493` 天
- 证书总数：`46` 张

## 五、截图证据
- 截图数量：`1` 张，完整图像请查看 HTML 报告。
- 截图 1：
  - URL：`https://baksmany.net/zh/`
  - 最终地址：`https://baksmany.net/zh/`
  - 大小：`596192` 字节
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

### 3. 可疑的轻量版跳转逻辑
- 规则：`DEEP_STATIC_SUSPICIOUS_REDIRECT_LOGIC`
- 严重级别：`medium`
- 说明：页面包含一段基于 localStorage 记录的定时器逻辑，若检测到加载缓慢则诱导用户跳转至 /zh/lite/ 路径。此类逻辑常被用于规避安全扫描或在特定环境下展示不同内容。
- 证据：`let TimerID = setTimeout(() => { ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：需进一步分析 /zh/lite/ 路径下的页面内容，检查是否存在更明显的钓鱼特征。

### 4. 页面存在多个密码输入框
- 规则：`MULTIPLE_PASSWORD_INPUTS`
- 严重级别：`high`
- 说明：页面检测到 4 个密码输入框。对于一个以数字货币兑换为主的页面，这一数量偏异常，可能意味着登录、提取或信息采集流程复杂化，增加了敏感信息泄露风险。
- 证据：`password_forms: 4`
- 建议：在未确认平台合法性和真实业务前，不要提交任何凭据。

### 5. 证书信息分析
- 规则：`INTEL_INFRA_CERT`
- 严重级别：`medium`
- 说明：该域名的证书历史较长，总共有46个证书，最早的证书签发于2025年2月，显示出一定的稳定性。
- 证据：`证书总数：46，最早证书签发时间：2025-02-14。`
- 建议：建议进一步调查该域名的信誉和历史，以评估其安全性。

### 6. 域名注册信息分析
- 规则：`INTEL_INFRA_WHOIS`
- 严重级别：`medium`
- 说明：该域名的注册商为NICENIC INTERNATIONAL GROUP CO., LIMITED，域名存在608天，显示出相对年轻的状态。
- 证据：`注册商：NICENIC INTERNATIONAL GROUP CO., LIMITED，域名存在天数：608。`
- 建议：建议检查该注册商的信誉及其与恶意活动的关联性。

### 7. 页面渲染异常暴露脚本代码
- 规则：`DEEP_BEHAVIOR_BROKEN_RENDERING`
- 严重级别：`medium`
- 说明：网页的可见文本中直接显示了未被正确解析的 JavaScript 代码。这种低级的前端错误通常表明网站制作粗糙，是许多批量生成的钓鱼或诈骗网站的常见特征。
- 证据：`可见文本中包含原始代码：`(function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem('slow_connection_detected'));...``
- 建议：对于制作如此粗糙且涉及金融交易的网站应保持高度警惕，切勿在此类站点注册或提交敏感信息。

### 8. 高风险加密货币交易诱导
- 规则：`DEEP_BEHAVIOR_CRYPTO_SCAM_LURE`
- 严重级别：`high`
- 说明：网站以“数字货币兑换”、“买卖比特币”为名，并以“零手续费支付卢布账单”等利益诱导用户进行交易。结合其粗劣的页面质量和较新的基础设施，极有可能是用于窃取用户加密资产或个人信息的诈骗平台。
- 证据：`页面标题为“数字货币兑换，买卖比特币”，正文包含“现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除”等诱导性话术。`
- 建议：强烈建议拦截该网站，警告用户不要进行任何充值、转账或授权钱包等操作，以防资产被盗。

### 9. 页面渲染异常暴露脚本代码
- 规则：`PAGE_RENDERING_ERROR_EXPOSES_SCRIPT`
- 严重级别：`high`
- 说明：浏览器可见文本中直接出现了原始 JavaScript 代码，说明页面前端渲染异常或模板处理失败。这类问题在正常金融服务站点中并不常见，会显著降低可信度，并常与粗制滥造的钓鱼或诈骗站点相伴出现。
- 证据：`可见文本包含 `(function(){ let TimerID = setTimeout(() => { ...` 等原始脚本片段。`
- 建议：建议将其视为高风险信号，不要在页面输入任何账号、密码或支付信息。

### 10. 存在可疑的轻版页面跳转逻辑
- 规则：`SUSPICIOUS_LIGHT_VERSION_REDIRECT`
- 严重级别：`medium`
- 说明：页面包含基于 localStorage 与定时器的“轻版网站”跳转逻辑。该逻辑本身不能直接证明恶意，但结合渲染异常与金融业务场景，会增加规避检测或内容分流的可疑度。
- 证据：`setTimeout 触发后提示使用轻版网站，并在确认后跳转到 `/zh/lite/?confirm=1`。`
- 建议：建议进一步检查轻版页面是否存在更强的诱导、收集或隐藏行为。

### 11. 金融场景下的近期证书信号
- 规则：`RECENT_CERT_IN_FINANCE_CONTEXT`
- 严重级别：`medium`
- 说明：证书签发时间较近，在金融业务页面中会进一步削弱信任，但单独不足以证明恶意；结合页面异常和高风险业务属性，可作为辅助风险因子。
- 证据：`证书最早可见时间为 2025-02-14，静态规则提示证书签发时间较短。`
- 建议：应结合域名信誉、站点历史与用户反馈继续核查。

### 12. 外部情报仅能提供有限稳定性线索
- 规则：`LOW_CONTINUITY_INTEL`
- 严重级别：`low`
- 说明：域名注册已存在约 608 天，且证书历史共有 46 条，说明基础设施并非完全新建，但这并不能抵消页面侧的高风险异常。
- 证据：`whois_age_days: 608, crt_total_certs: 46`
- 建议：当前结论主要依赖离线静态与浏览器证据，建议补充实时信誉与黑名单数据。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
综合静态检测结果、browser_evidence 与各专家意见判断，目标站点 baksmany.net/zh/ 属于高风险站点，最终结论偏向 malicious_lean。核心依据是：页面自称为“数字货币兑换，买卖比特币”，属于高敏感金融场景；可见文本中直接暴露了未正确解析的 JavaScript 代码，说明前端渲染存在明显异常，网页制作质量较差；页面同时出现 4 个密码输入框，这对普通兑换页面而言不常见，存在采集敏感信息的风险；此外还存在基于 localStorage 的“轻版网站”定时跳转逻辑，虽然不能单独证明恶意，但在高风险金融站点中会提升可疑度。外部情报方面，域名注册时间约 608 天，证书历史较长，说明基础设施并非全新搭建，但证书近期签发这一静态信号仍可视为风险加分项。由于当前没有更强的外部信誉情报、黑名单或已知品牌仿冒证据，本次结论主要仍然依赖离线静态证据与浏览器证据链，而不是外部威胁情报。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
该网站表现为典型的数字货币兑换平台。静态分析发现页面包含多个密码输入框，且存在一段基于 localStorage 的“轻量版”跳转逻辑，这种设计在某些钓鱼或低质量站点中用于绕过检测或引导用户进入更易于窃取信息的页面。虽然域名注册时间已超过一年，但证书签发时间较短，且此类金融类站点若缺乏权威背书，存在较高的资产风险。鉴于其涉及敏感的货币兑换业务，且存在诱导跳转行为，判定为具有一定风险的站点。风险提示为 medium，claim 为 malicious_lean，confidence 为 0.75。

### 行为分析员（模型：`gemini-2.5-pro`）
该网站自称为加密货币兑换平台，提供比特币买卖及USDT支付等服务。然而，页面可见文本中直接暴露了原始的 JavaScript 代码，表明网站前端存在明显的渲染错误或模板缺陷，这种粗制滥造的特征在快速部署的钓鱼或诈骗网站中非常典型。结合其涉及的高风险金融业务（加密货币交易）以及静态分析中提到的近期签发的证书，该网站具有较高的诈骗或钓鱼嫌疑。由于缺乏明确的已知品牌伪造证据，判定为倾向恶意。风险提示为 high，claim 为 malicious_lean，confidence 为 0.75。

### 情报分析员（模型：`gpt-4o-mini`）
该网页未明确模仿特定品牌或组织，内容主要集中在数字货币兑换服务上。当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。风险提示为 medium，claim 为 uncertain，confidence 为 0.7。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站伪装成数字货币兑换平台，但存在多项显著的恶意特征：页面前端渲染严重错误，导致 JavaScript 源代码直接暴露在可见文本中；页面包含多个异常的密码输入框，且存在诱导用户跳转至“轻量版”页面的可疑逻辑；同时以“零手续费”等利益诱导用户进行加密货币交易，极易导致用户资产损失。综合考虑其金融业务属性及上述高风险行为，判定该站点具有极高的诈骗风险。风险提示为 critical，claim 为 uncertain，confidence 为 0.0，recommended_action 为 block。


### 主持人最终总结
综合静态检测结果、browser_evidence 与各专家意见判断，目标站点 baksmany.net/zh/ 属于高风险站点，最终结论偏向 malicious_lean。核心依据是：页面自称为“数字货币兑换，买卖比特币”，属于高敏感金融场景；可见文本中直接暴露了未正确解析的 JavaScript 代码，说明前端渲染存在明显异常，网页制作质量较差；页面同时出现 4 个密码输入框，这对普通兑换页面而言不常见，存在采集敏感信息的风险；此外还存在基于 localStorage 的“轻版网站”定时跳转逻辑，虽然不能单独证明恶意，但在高风险金融站点中会提升可疑度。外部情报方面，域名注册时间约 608 天，证书历史较长，说明基础设施并非全新搭建，但证书近期签发这一静态信号仍可视为风险加分项。由于当前没有更强的外部信誉情报、黑名单或已知品牌仿冒证据，本次结论主要仍然依赖离线静态证据与浏览器证据链，而不是外部威胁情报。


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

- 总耗时：39.28 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 4.61 | 4434 | 444 | 4878 |
| 情报分析员 | 7.76 | 4238 | 315 | 4553 |
| 行为分析员 | 22.38 | 4141 | 1871 | 6012 |
| 处置建议员 | 2.10 | 5659 | 170 | 5829 |
| 主持人 | 14.79 | 5604 | 1984 | 7588 |
