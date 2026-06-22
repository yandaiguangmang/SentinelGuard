# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：12 条
- 高危证据：2 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_131331_117931.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_131331_117931.md

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
- 截图数量：`1` 张，完整图像请查看 HTML 报告。
- 截图 1：
  - URL：`https://baksmany.net/zh/`
  - 最终地址：`https://baksmany.net/zh/`
  - 大小：`596504` 字节
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

### 3. 域名注册信息分析
- 规则：`INTEL_INFRA_DOMAIN`
- 严重级别：`medium`
- 说明：域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，注册时间为 608 天，显示出该域名并不新颖，但也未达到成熟阶段。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 域名存在天数: 608`
- 建议：建议进一步调查该注册商的声誉以及与其他恶意活动的关联。

### 4. TLS 证书信息分析
- 规则：`INTEL_INFRA_CERTIFICATE`
- 严重级别：`medium`
- 说明：证书签发时间较短，可能影响信任度。建议结合其他证据进行综合判断。
- 证据：`证书签发于 19 天前。`
- 建议：在使用该网站时，务必谨慎处理敏感信息。

### 5. 包含常规用户体验优化脚本
- 规则：`DEEP_BEHAVIOR_UX_SCRIPT`
- 严重级别：`medium`
- 说明：页面包含一段用于检测加载速度并在加载缓慢时提示用户切换到“轻量版”网站的JavaScript代码，属于正常的网站功能逻辑，未见恶意意图。
- 证据：`setTimeout(() => { ... cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：属于正常功能代码，无需特殊处置。

### 6. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：网站的TLS证书签发于19天前。尽管域名注册时间较长（608天），但对于一个提供数字货币兑换服务的金融类网站而言，如此短的证书签发时间可能意味着近期有变动，增加了潜在的不确定性。
- 证据：`证书签发于 19 天前。WHOIS域名创建日期: 2024-10-21T15:02:27Z (608天前)。`
- 建议：建议结合域名信誉、证书颁发机构信息以及网站实际运营情况进行综合判断。在确认网站可信前，谨慎进行敏感操作。

### 7. 证书与域名生命周期不匹配
- 规则：`DEEP_ADVICE_CERT_ANOMALY`
- 严重级别：`medium`
- 说明：域名注册已超过600天，但TLS证书仅在19天前签发。对于金融类网站，这种频繁的证书变动或长期未维护后的突然更新是值得警惕的异常信号。
- 证据：`证书签发于19天前，域名创建于608天前。`
- 建议：在确认网站运营方背景及证书链可信度之前，不建议用户在页面输入任何敏感凭据。

### 8. 金融类网站高风险特征
- 规则：`DEEP_ADVICE_FINANCIAL_RISK`
- 严重级别：`medium`
- 说明：页面包含4个密码输入框，且涉及数字货币兑换业务。此类网站若被黑客篡改或为钓鱼站点，将直接导致用户资产损失。
- 证据：`页面包含4个密码输入框。`
- 建议：建议将该URL列入沙箱环境进行深度行为监控，重点观察表单提交的目标地址及后续的交互行为。

### 9. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`high`
- 说明：证书仅在近期签发，结合该站点自称提供数字货币兑换服务的场景，这种证书生命周期异常更像是需要重点核验的风险信号，而不是普通的低危现象。
- 证据：`证书签发于 19 天前；域名 WHOIS 创建日期为 2024-10-21T15:02:27Z，域名年龄 608 天。`
- 建议：在确认站点运营方、证书链与站点历史可信前，不要输入账号、密码或支付信息。

### 10. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`high`
- 说明：页面存在 4 个密码输入框，虽然对数字货币兑换平台可能是预期功能，但在金融场景中这类表单会显著放大凭据泄露和账户接管风险，应按高敏感度对待。
- 证据：`密码框数量: 4；表单未见外域提交证据，当前仅能从页面内容判断。`
- 建议：仅在隔离环境中复核表单提交目标与跳转逻辑，确认域名和证书可信后再考虑交互。

### 11. 包含常规用户体验优化脚本
- 规则：`DEEP_BEHAVIOR_UX_SCRIPT`
- 严重级别：`low`
- 说明：页面包含检测加载速度并提示切换轻量版的脚本，行为上更像常规网站优化逻辑，未见直接恶意意图。
- 证据：`setTimeout 后弹出轻量版提示并可跳转到 /zh/lite/?confirm=1。`
- 建议：该脚本本身不构成恶意证据，但不能抵消金融站点本身的高风险属性。

### 12. 域名注册信息分析
- 规则：`INTEL_INFRA_DOMAIN`
- 严重级别：`medium`
- 说明：域名注册时间超过一年半，说明并非新注册域名；但注册信息本身不足以证明站点可信，也无法消除金融类站点的风险。
- 证据：`注册商为 NICENIC INTERNATIONAL GROUP CO., LIMITED；域名存在天数 608。`
- 建议：建议结合站点历史、品牌背书与外部信誉记录进一步核验。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包与四位专家意见，当前目标页面更适合判定为高风险而非单纯的中风险。页面标题和正文明确指向“数字货币兑换、买卖比特币”，且可见内容包含登录/密码相关表单（密码框数量为4），这类金融/资产类站点天然具有较高的凭据与资金风险。虽然未发现外部恶意脚本、可疑重定向链或直接指向外域的表单提交行为，页面也与自述业务表面一致，但TLS证书签发时间仅19天、与WHOIS显示的域名注册已608天形成明显时间差；在金融服务场景下，这一生命周期不匹配属于需要重点警惕的异常信号。当前外部情报仅限于离线WHOIS与证书信息，缺乏更强的信誉或黑名单证据，因此结论主要依赖离线证据链。专家意见存在方向性分歧：静态分析员倾向 malicious_lean，情报分析员和处置建议员维持 uncertain/审慎判断，行为分析员认为未见明显恶意但保留不确定；我最终采用 high 风险结论，是因为金融类登录/交易页面叠加短期证书与多密码表单，在没有可信外部情报佐证前，应按高风险敏感站点处置，而不是下调为中风险或 benign。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
认为网站业务表面一致，但 TLS 证书较新、页面有多个密码输入框，倾向 malicious_lean，给出较高风险提示。

### 行为分析员（模型：`gemini-2.5-pro`）
认为页面主要是同源资源与常规轻量版提示脚本，未见明显恶意重定向或注入，倾向不确定但保留中风险。

### 情报分析员（模型：`gpt-4o-mini`）
指出当前仅能依赖离线规则研判，未明确冒充特定品牌，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`gemini-2.5-flash`）
建议在隔离浏览器中复核最终域名，不要在页面提交敏感信息，倾向审慎处置。


### 主持人最终总结
基于静态检测结果、浏览器证据包与四位专家意见，当前目标页面更适合判定为高风险而非单纯的中风险。页面标题和正文明确指向“数字货币兑换、买卖比特币”，且可见内容包含登录/密码相关表单（密码框数量为4），这类金融/资产类站点天然具有较高的凭据与资金风险。虽然未发现外部恶意脚本、可疑重定向链或直接指向外域的表单提交行为，页面也与自述业务表面一致，但TLS证书签发时间仅19天、与WHOIS显示的域名注册已608天形成明显时间差；在金融服务场景下，这一生命周期不匹配属于需要重点警惕的异常信号。当前外部情报仅限于离线WHOIS与证书信息，缺乏更强的信誉或黑名单证据，因此结论主要依赖离线证据链。专家意见存在方向性分歧：静态分析员倾向 malicious_lean，情报分析员和处置建议员维持 uncertain/审慎判断，行为分析员认为未见明显恶意但保留不确定；我最终采用 high 风险结论，是因为金融类登录/交易页面叠加短期证书与多密码表单，在没有可信外部情报佐证前，应按高风险敏感站点处置，而不是下调为中风险或 benign。


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

- 总耗时：45.50 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 情报分析员 | 7.03 | 4071 | 294 | 4365 |
| 行为分析员 | 31.77 | 3961 | 2931 | 6892 |
| 静态分析员 | 34.20 | 4000 | 3047 | 7047 |
| 处置建议员 | 3.21 | 5374 | 399 | 5773 |
| 主持人 | 8.09 | 5532 | 1449 | 6981 |
