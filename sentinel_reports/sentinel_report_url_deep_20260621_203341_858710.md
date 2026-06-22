# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：14 条
- 高危证据：2 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260621_203258_434489.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260621_203258_434489.md

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
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': 'UZ', 'whois_creation_date': '2024-10-21 15:02:27+00:00', 'whois_age_days': 607}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 注册国家：`UZ`
- 域名注册时间：`2024-10-21 15:02:27+00:00`
- 域名注册天数：`607` 天

## 五、截图证据
- 未采集到截图证据。

## 六、风险证据
### 1. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`medium`
- 说明：密码表单提交与当前域名一致或为相对路径，可能为正常登录功能。
- 证据：`密码框数量: 4`
- 建议：确认域名归属和证书可信后再输入账号密码。

### 2. 高风险金融业务页面
- 规则：`DEEP_STATIC_FINANCIAL_RISK`
- 严重级别：`medium`
- 说明：页面涉及数字货币兑换业务，且包含多个密码输入框，属于高价值目标，容易成为钓鱼攻击的伪装对象。
- 证据：`页面标题为“数字货币兑换，买卖比特币”，包含4个密码输入框。`
- 建议：建议用户在进行任何资金操作前，核实该平台的监管资质及第三方可信度评价，避免在非官方或不可信的兑换平台输入敏感凭据。

### 3. 可疑的轻量版跳转逻辑
- 规则：`DEEP_STATIC_JS_REDIRECT_LOGIC`
- 严重级别：`low`
- 说明：页面内嵌脚本通过 localStorage 记录连接状态并强制引导用户跳转至 /lite/ 路径，该机制可能被用于绕过常规安全扫描或进行流量分流。
- 证据：`代码片段：if (cnf) { location.href = "/zh/lite/?confirm=1"; }`
- 建议：需关注 /lite/ 路径下的页面内容是否与主站一致，是否存在隐藏的恶意重定向或钓鱼表单。

### 4. 未发现品牌模仿
- 规则：`INTEL_BRAND_IMPERSONATION`
- 严重级别：`low`
- 说明：该页面未明显模仿任何特定品牌或组织，内容主要涉及数字货币兑换。
- 证据：`页面标题为'数字货币兑换，买卖比特币'，没有品牌标识。`
- 建议：继续监控该域名的活动，确保其不涉及恶意行为。

### 5. 域名注册信息
- 规则：`INTEL_INFRA_HOSTING`
- 严重级别：`medium`
- 说明：域名注册于2024年，注册商为NICENIC INTERNATIONAL GROUP CO., LIMITED，位于乌兹别克斯坦。
- 证据：`注册日期：2024-10-21，注册商：NICENIC INTERNATIONAL GROUP CO., LIMITED。`
- 建议：考虑该域名的注册时间较短，需警惕潜在的恶意活动。

### 6. 地理位置影响
- 规则：`INTEL_COVERAGE_GEO`
- 严重级别：`low`
- 说明：未发现因地理位置或网络环境导致的内容差异。
- 证据：`页面内容在不同环境下保持一致。`
- 建议：继续监控，确保无地域性内容变化。

### 7. 潜在的加密货币交易平台钓鱼网站
- 规则：`DEEP_BEHAVIOR_POTENTIAL_PHISHING`
- 严重级别：`high`
- 说明：页面呈现为一个加密货币交易平台，并包含多个密码输入框用于登录和注册。虽然没有观察到自动恶意行为，但此类网站是钓鱼攻击的常见伪装，旨在骗取用户的敏感账户信息和资金。其行为与一个合法的交易平台登录页面相似，使得用户难以分辨。
- 证据：`页面标题为'数字货币兑换，买卖比特币'，并包含4个密码输入字段，引导用户'进来'（登录）或'登记'（注册）。`
- 建议：强烈建议不要在该网站上输入任何个人信息、账户名或密码。除非能通过独立、可靠的渠道验证该网站的合法性，否则应立即关闭页面。

### 8. 高风险金融钓鱼特征
- 规则：`DEEP_ADVICE_FINANCIAL_PHISHING`
- 严重级别：`high`
- 说明：页面伪装成数字货币兑换平台，包含多个密码输入框，极易被用于窃取用户凭据或资金。
- 证据：`页面包含4个密码输入框，且业务涉及敏感的加密货币兑换。`
- 建议：严禁在页面输入任何敏感信息，建议将该域名列入高风险监控名单。

### 9. 基础设施信任度不足
- 规则：`DEEP_ADVICE_INFRA_TRUST`
- 严重级别：`medium`
- 说明：域名注册时间较短，且注册信息与此类金融服务平台的常规背景不符，缺乏可信背书。
- 证据：`域名注册于2024年10月，注册商位于乌兹别克斯坦。`
- 建议：在缺乏权威机构认证的情况下，不应信任该平台提供的任何金融服务。

### 10. 关注轻量版跳转逻辑
- 规则：`DEEP_ADVICE_REDIRECT_OBSERVATION`
- 严重级别：`low`
- 说明：页面内嵌的 JavaScript 跳转逻辑可能用于规避安全检测或针对特定用户进行分流。
- 证据：`代码片段：location.href = "/zh/lite/?confirm=1";`
- 建议：若需进一步分析，应重点排查 /zh/lite/ 路径下的内容，确认是否存在隐藏的恶意重定向。

### 11. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`medium`
- 说明：页面出现多个密码输入框，结合数字货币兑换场景，虽可能是正常登录功能，但也会显著抬高凭据被窃取的风险，整体应按高关注对象处理。
- 证据：`浏览器证据显示密码框数量为 4，且页面同时存在登录/注册导向文本。`
- 建议：在未验证站点身份与证书可信度前，不要输入任何账号、密码或验证码。

### 12. 轻量版页面跳转逻辑
- 规则：`DEEP_STATIC_JS_REDIRECT_LOGIC`
- 严重级别：`low`
- 说明：页面内嵌脚本会根据本地存储与连接状态提示跳转到轻量版路径。该行为本身不构成恶意，但在高风险金融站点中可作为分流或规避检测的辅助信号。
- 证据：`脚本中存在 location.href = "/zh/lite/?confirm=1" 的跳转逻辑。`
- 建议：如需继续分析，应重点检查 /zh/lite/ 下的内容是否与主站一致，是否存在隐藏表单或异常重定向。

### 13. 基础设施信任度不足
- 规则：`DEEP_ADVICE_INFRA_TRUST`
- 严重级别：`medium`
- 说明：域名注册时间较新，且注册信息缺少足够的可信背书；结合金融业务属性，整体信任度偏低。
- 证据：`WHOIS 显示注册于 2024-10-21，注册商为 NICENIC INTERNATIONAL GROUP CO., LIMITED，地区为 UZ。`
- 建议：将该域名视为低信任资产，需结合证书、黑名单、历史流量与交互验证进一步确认。

### 14. 潜在的加密货币交易平台钓鱼诱饵
- 规则：`DEEP_BEHAVIOR_POTENTIAL_PHISHING`
- 严重级别：`medium`
- 说明：页面呈现为加密货币交易平台并提供登录/注册入口，但缺少足够的动态恶意证据；更合理的结论是存在明显钓鱼风险，而非已确认恶意。
- 证据：`标题为“数字货币兑换，买卖比特币”，页面存在 4 个密码输入框与登录/注册导向。`
- 建议：不要在该站点输入任何敏感信息，优先通过独立渠道核验平台真实性。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包与四位专家意见，当前页面更符合“高风险金融/加密货币交易站点，具备钓鱼诱饵特征”的离线研判结论，而不是已证实的恶意脚本投递页。页面标题为“数字货币兑换，买卖比特币”，可见内容显示登录/注册导向、4 个密码输入框、1 个隐藏字段，以及一段用于提示“轻量版网站”的本地脚本跳转逻辑。静态链路中未见自动下载、外部脚本、meta refresh 或明显的恶意重定向；浏览器证据也未显示跳转链异常，最终停留在原站。外部情报仅提供 WHOIS 信息：注册商为 NICENIC INTERNATIONAL GROUP CO., LIMITED，注册于 2024-10-21，地区为 UZ，整体更支持“新注册、信任度不足”的风险判断。由于缺少域名信誉、证书透明度、黑名单和交互式验证结果，本次结论只能依赖离线证据。

四位专家的方向并不完全一致：静态分析员与处置建议员偏向 malicious_lean / 高风险钓鱼判断，行为分析员认为无法证实恶意、仅能判定为不确定，情报分析员则偏向 benign_lean，认为未见品牌冒充。由于 precomputed_claim_conflict 为 true，且意见中同时存在 malicious_lean、benign_lean 与 uncertain，属于明确冲突，不能简单平均。最终我采用“medium 风险、偏钓鱼/高风险金融诱饵”的结论：理由是页面确实存在金融交易场景、多个密码输入框、较新的注册信息与轻量版跳转脚本这些复合风险信号，但又缺少足以直接定性为恶意的动态证据或投递行为。因此应视为高关注对象，重点防范凭据窃取，而非直接认定为已确认恶意站点。 综合 1 条证据，当前风险等级为 medium；但由于专家意见存在冲突，应以离线证据为主进行保守判断。

### 静态分析员（模型：`gemini-2.5-flash`）
页面为数字货币兑换场景，包含 4 个密码输入框与本地轻量版跳转脚本，整体偏向高风险金融页面，存在钓鱼诱饵可能。

### 行为分析员（模型：`gemini-2.5-pro`）
未观察到自动恶意跳转或下载，页面更像交易平台登录/注册页；仅能判断为不确定，无法证实恶意。

### 情报分析员（模型：`gpt-4o-mini`）
当前版本采用离线规则研判，未见明确品牌冒充；若用于实战，仍需补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`gemini-2.5-flash`）
建议在隔离浏览器中复核最终域名，不在页面提交敏感信息；由于金融业务与短注册信息叠加，应按高风险对象处置。


### 主持人最终总结
基于静态检测结果、浏览器证据包与四位专家意见，当前页面更符合“高风险金融/加密货币交易站点，具备钓鱼诱饵特征”的离线研判结论，而不是已证实的恶意脚本投递页。页面标题为“数字货币兑换，买卖比特币”，可见内容显示登录/注册导向、4 个密码输入框、1 个隐藏字段，以及一段用于提示“轻量版网站”的本地脚本跳转逻辑。静态链路中未见自动下载、外部脚本、meta refresh 或明显的恶意重定向；浏览器证据也未显示跳转链异常，最终停留在原站。外部情报仅提供 WHOIS 信息：注册商为 NICENIC INTERNATIONAL GROUP CO., LIMITED，注册于 2024-10-21，地区为 UZ，整体更支持“新注册、信任度不足”的风险判断。由于缺少域名信誉、证书透明度、黑名单和交互式验证结果，本次结论只能依赖离线证据。

四位专家的方向并不完全一致：静态分析员与处置建议员偏向 malicious_lean / 高风险钓鱼判断，行为分析员认为无法证实恶意、仅能判定为不确定，情报分析员则偏向 benign_lean，认为未见品牌冒充。由于 precomputed_claim_conflict 为 true，且意见中同时存在 malicious_lean、benign_lean 与 uncertain，属于明确冲突，不能简单平均。最终我采用“medium 风险、偏钓鱼/高风险金融诱饵”的结论：理由是页面确实存在金融交易场景、多个密码输入框、较新的注册信息与轻量版跳转脚本这些复合风险信号，但又缺少足以直接定性为恶意的动态证据或投递行为。因此应视为高关注对象，重点防范凭据窃取，而非直接认定为已确认恶意站点。


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

- 总耗时：41.51 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 5.08 | 3904 | 520 | 4424 |
| 情报分析员 | 7.29 | 3758 | 400 | 4158 |
| 行为分析员 | 27.38 | 4267 | 372 | 4639 |
| 处置建议员 | 4.66 | 5086 | 509 | 5595 |
| 主持人 | 9.47 | 5649 | 1651 | 7300 |
