# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：13 条
- 高危证据：4 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260621_213039_201464.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260621_213039_201464.md

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
  - 大小：`596925` 字节
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

### 3. 页面在加密货币交易场景下收集凭证
- 规则：`DEEP_BEHAVIOR_CREDENTIAL_HARVESTING_CONTEXT`
- 严重级别：`high`
- 说明：该网站作为一个加密货币交易平台，包含多个密码输入框用于用户登录和注册。虽然这是此类网站的正常功能，但加密货币领域是网络钓鱼和金融诈骗的高发区。用户在此类页面输入凭证将面临直接的财务损失风险，尤其是在该网站信誉未知且静态分析显示其TLS证书较新的情况下。
- 证据：`页面标题为“数字货币兑换，买卖比特币”，并包含4个密码输入框，引导用户进行“登记”和“进来”（登录）。`
- 建议：强烈建议不要在该网站输入任何个人信息或财务凭证，除非能通过可靠的第三方来源证实其为合法、信誉良好的交易平台。

### 4. 可疑的页面跳转逻辑
- 规则：`DEEP_STATIC_SUSPICIOUS_SCRIPT`
- 严重级别：`medium`
- 说明：页面包含一段基于 localStorage 的定时器脚本，用于检测网络速度并诱导用户跳转至特定路径（/zh/lite/），此类逻辑常见于规避分析或针对性钓鱼。
- 证据：`setTimeout(() => { ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：需进一步分析 /zh/lite/ 路径下的内容，确认是否存在恶意重定向或钓鱼表单。

### 5. 高风险金融交互特征
- 规则：`DEEP_STATIC_FINANCIAL_RISK`
- 严重级别：`high`
- 说明：页面包含 4 个密码输入框，且涉及数字货币兑换及卢布支付等敏感金融业务，极易成为钓鱼攻击的目标。
- 证据：`密码框数量: 4`
- 建议：严禁在该页面输入任何账户密码或进行资金操作，建议将其列入高风险观察名单。

### 6. 域名注册信息分析
- 规则：`INTEL_INFRA_1`
- 严重级别：`medium`
- 说明：该域名由NICENIC INTERNATIONAL GROUP CO., LIMITED注册，注册时间为607天，表明该域名并不新鲜，但也不算非常成熟。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 域名存在天数: 607`
- 建议：建议进一步调查该注册商的信誉及相关域名的历史记录。

### 7. TLS证书分析
- 规则：`INTEL_INFRA_2`
- 严重级别：`medium`
- 说明：当前网页的TLS证书签发时间较短，可能存在安全隐患。
- 证据：`证书签发于19天前。`
- 建议：建议结合其他证据综合判断该网站的安全性。

### 8. 高风险金融交互特征
- 规则：`DEEP_ADVICE_FINANCIAL_PHISHING`
- 严重级别：`high`
- 说明：页面包含 4 个密码输入框，且涉及数字货币兑换及卢布支付等敏感金融业务，极易成为钓鱼攻击的目标。
- 证据：`密码框数量: 4`
- 建议：严禁在该页面输入任何账户密码或进行资金操作，建议将其列入高风险观察名单。

### 9. 可疑的页面跳转逻辑
- 规则：`DEEP_ADVICE_SUSPICIOUS_REDIRECT`
- 严重级别：`medium`
- 说明：页面包含一段基于 localStorage 的定时器脚本，用于检测网络速度并诱导用户跳转至特定路径（/zh/lite/），此类逻辑常见于规避安全分析或针对性钓鱼。
- 证据：`setTimeout(() => { ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：需进一步分析 /zh/lite/ 路径下的内容，确认是否存在恶意重定向或钓鱼表单。

### 10. TLS证书签发时间较短
- 规则：`DEEP_ADVICE_CERT_RISK`
- 严重级别：`medium`
- 说明：当前网页的TLS证书签发时间仅为19天前，对于金融类网站而言，证书频繁更新或签发时间过短可能存在安全隐患。
- 证据：`证书签发于 19 天前。`
- 建议：建议结合其他证据综合判断该网站的安全性，不建议在未验证信誉的情况下进行交互。

### 11. 高风险金融交互特征
- 规则：`DEEP_STATIC_FINANCIAL_RISK`
- 严重级别：`high`
- 说明：页面以数字货币兑换和卢布支付为核心业务，并包含4个密码输入框，符合高频钓鱼和金融欺诈页面常见特征。在专家意见整体偏高风险的情况下，应将其视为高风险交互点。
- 证据：`页面标题为“数字货币兑换，买卖比特币”，密码框数量: 4`
- 建议：不要在该页面输入任何账号密码、验证码或支付信息；如需验证业务真实性，应通过独立渠道核验域名归属与平台资质。

### 12. 域名注册信息提示中等可信度
- 规则：`INTEL_INFRA_1`
- 严重级别：`low`
- 说明：域名注册商信息可见，且域名年龄约607天，说明并非刚注册不久；但仅凭注册时长不足以证明信誉或安全性。结合专家意见，这一情报仅能作为辅助背景，不能显著降低风险。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED；域名存在天数: 607`
- 建议：应继续核查历史解析、站点内容变更记录及关联域名是否存在滥用迹象。

### 13. TLS证书较新但不能单独定性
- 规则：`INTEL_INFRA_2`
- 严重级别：`medium`
- 说明：TLS证书签发于19天前。对于金融类页面，这一特征在高风险站点中常见，但也可能出现在正常新站或证书轮换场景，因此只能作为辅助风险信号。
- 证据：`证书签发于 19 天前`
- 建议：结合域名信誉、证书透明度记录和页面交互行为综合判断，不建议直接基于证书新鲜度下结论。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包以及四位专家意见，当前更倾向将该站点判定为高风险可疑金融/钓鱼页面，而不是普通良性交易站点。页面标题与可见内容均指向“数字货币兑换、买卖比特币”，表面上像加密货币交易平台；但页面同时存在4个密码输入框、仅19天前签发的TLS证书，以及一段使用 localStorage 和定时器、引导用户切换到“轻量版”路径 /zh/lite/ 的脚本。综合来看，这些特征并非单独即可定性为恶意，但在金融敏感场景下叠加后，风险显著升高。

四位专家中，静态分析员与处置建议员明确给出 high / malicious_lean 倾向，行为分析员则认为行为层面未见自动重定向、恶意脚本加载或强制下载，因此不宜仅凭当前观察直接定性为恶意，风险为 medium；情报分析员也保持 uncertain / medium。总体不存在 benign_lean 与 malicious_lean 的正反方向冲突，但存在强度分歧：两位专家偏高风险，两位专家偏中等且强调证据不足。最终结论采用高风险判断，依据是页面确实收集凭证并位于高频钓鱼的加密货币金融场景，同时存在可疑的轻量版跳转脚本与较新的证书，这些特征在离线证据中形成了足够的风险叠加。需要明确说明：当前外部情报有限，结论主要依赖离线证据链，未能通过域名信誉、证书透明度或黑名单情报完成实证补强。 {'claim': 'medium', 'confidence': None, 'opinion': '综合 2 条证据，当前风险等级为 medium。'}

### 静态分析员（模型：`gemini-2.5-flash`）
{'claim': 'malicious_lean', 'confidence': 0.75, 'opinion': '该站点呈现数字货币兑换平台特征，但存在多个密码输入框、较新的TLS证书，以及基于 localStorage 和定时器的可疑轻量版跳转脚本，结合金融敏感场景，风险偏高，更偏向钓鱼或欺诈。'}

### 行为分析员（模型：`gemini-2.5-pro`）
{'claim': 'uncertain', 'confidence': 0.5, 'opinion': '页面行为未见自动重定向、恶意脚本加载或强制下载；核心是收集用户凭证的登录/注册交互。由于这类行为也可能属于正常交易站点，因此仅凭当前行为证据不能明确判恶，但在加密货币场景下风险较高。'}

### 情报分析员（模型：`gpt-4o-mini`）
{'claim': 'uncertain', 'confidence': 0.7, 'opinion': '当前网页未明确冒充特定品牌或组织，内容主要涉及数字货币兑换服务；外部情报仅能确认域名注册信息和TLS证书较新，证据不足以单独定性。'}

### 处置建议员（模型：`gemini-2.5-flash`）
{'claim': 'uncertain', 'confidence': 0.0, 'opinion': '该网站表现为数字货币兑换平台，但存在多个密码输入框、轻量版跳转脚本和较新的TLS证书，缺乏明确品牌信誉背书，建议在隔离环境复核并避免输入敏感信息。'}


### 主持人最终总结
基于静态检测结果、浏览器证据包以及四位专家意见，当前更倾向将该站点判定为高风险可疑金融/钓鱼页面，而不是普通良性交易站点。页面标题与可见内容均指向“数字货币兑换、买卖比特币”，表面上像加密货币交易平台；但页面同时存在4个密码输入框、仅19天前签发的TLS证书，以及一段使用 localStorage 和定时器、引导用户切换到“轻量版”路径 /zh/lite/ 的脚本。综合来看，这些特征并非单独即可定性为恶意，但在金融敏感场景下叠加后，风险显著升高。

四位专家中，静态分析员与处置建议员明确给出 high / malicious_lean 倾向，行为分析员则认为行为层面未见自动重定向、恶意脚本加载或强制下载，因此不宜仅凭当前观察直接定性为恶意，风险为 medium；情报分析员也保持 uncertain / medium。总体不存在 benign_lean 与 malicious_lean 的正反方向冲突，但存在强度分歧：两位专家偏高风险，两位专家偏中等且强调证据不足。最终结论采用高风险判断，依据是页面确实收集凭证并位于高频钓鱼的加密货币金融场景，同时存在可疑的轻量版跳转脚本与较新的证书，这些特征在离线证据中形成了足够的风险叠加。需要明确说明：当前外部情报有限，结论主要依赖离线证据链，未能通过域名信誉、证书透明度或黑名单情报完成实证补强。


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

- 总耗时：27.30 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 行为分析员 | 4.98 | 4360 | 421 | 4781 |
| 静态分析员 | 6.57 | 4244 | 416 | 4660 |
| 情报分析员 | 11.47 | 4063 | 283 | 4346 |
| 处置建议员 | 5.84 | 5053 | 572 | 5625 |
| 主持人 | 9.98 | 5643 | 1800 | 7443 |
