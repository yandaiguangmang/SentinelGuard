# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**95/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：11 条
- 高危证据：6 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_142734_157052.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_142734_157052.md

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
  - 大小：`596682` 字节
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

### 3. 可疑的连接速度检测与跳转逻辑
- 规则：`DEEP_STATIC_SUSPICIOUS_SCRIPT`
- 严重级别：`medium`
- 说明：页面包含一段通过 localStorage 记录连接状态并强制弹出 confirm 对话框诱导用户跳转至 /lite/ 路径的脚本。此类逻辑常被用于绕过安全检测或在特定网络环境下引导用户进入更易于实施钓鱼的简化页面。
- 证据：`脚本中包含: setTimeout(() => { ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：需进一步分析 /lite/ 路径下的页面内容，检查是否存在更明显的欺诈行为。

### 4. 高风险金融诱导用语
- 规则：`DEEP_STATIC_FINANCIAL_PHISHING_INDICATOR`
- 严重级别：`high`
- 说明：页面显眼位置包含“零手续费支付卢布账单”、“上传卢布QR码”等诱导性金融操作描述，此类操作极易被用于洗钱或非法资金转移，且缺乏正规金融机构的合规背书。
- 证据：`可见文本: “现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码”`
- 建议：严禁在该网站输入任何敏感金融信息或进行资产转账。

### 5. 域名注册信息分析
- 规则：`INTEL_INFRA_1`
- 严重级别：`medium`
- 说明：该域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，注册时间为 608 天，显示出相对年轻的状态。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 域名存在天数: 608`
- 建议：建议进一步调查该注册商的声誉及其与恶意活动的关联性。

### 6. TLS 证书分析
- 规则：`INTEL_INFRA_2`
- 严重级别：`medium`
- 说明：当前网站的 TLS 证书签发时间较短，可能影响其可信度。
- 证据：`证书签发于 20 天前。`
- 建议：建议结合其他证据综合判断该网站的安全性。

### 7. 延迟触发的重定向行为（沙箱规避）
- 规则：`DEEP_BEHAVIOR_DELAYED_REDIRECT`
- 严重级别：`high`
- 说明：页面包含一段 JavaScript 代码，在等待 20 秒后会弹窗提示用户网络缓慢，并尝试将用户重定向到“轻量版”页面（/zh/lite/?confirm=1）。这种基于时间的延迟执行常用于规避运行时间较短的自动化沙箱检测。
- 证据：`setTimeout(() => { ... cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：警惕此类延迟跳转行为，跳转后的页面可能包含真正的钓鱼表单或恶意内容，建议拦截该域名的访问。

### 8. 高风险加密货币欺诈诱饵
- 规则：`DEEP_BEHAVIOR_CRYPTO_SCAM_LURE`
- 严重级别：`high`
- 说明：页面以“数字货币兑换”、“买卖比特币”、“零手续费支付卢布账单”为诱饵，要求用户上传二维码或进行转账。结合页面粗糙的制作质量（JS代码未正确解析，直接暴露在可见文本中）和多个密码输入框，极有可能是虚假交易所或钓鱼网站。
- 证据：`页面标题为“数字货币兑换，买卖比特币”，可见文本包含“现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码”。`
- 建议：绝对不要在此类未经验证的平台上输入账号密码、助记词或进行任何资产转账，建议将其标记为欺诈网站。

### 9. 检测到沙箱规避行为
- 规则：`DEEP_ADVICE_BEHAVIOR_EVASION`
- 严重级别：`high`
- 说明：页面包含延迟20秒执行的 JavaScript 代码，试图通过弹窗诱导用户跳转至特定路径，这是典型的规避自动化安全检测的行为。
- 证据：`setTimeout 逻辑及 confirm 弹窗跳转代码`
- 建议：拦截该域名访问，防止用户被引导至更隐蔽的钓鱼页面。

### 10. 高风险金融欺诈诱导
- 规则：`DEEP_ADVICE_FINANCIAL_FRAUD`
- 严重级别：`critical`
- 说明：网站以“零手续费”、“上传卢布QR码”等诱导性金融操作为幌子，极易导致用户资产损失或参与洗钱活动。
- 证据：`页面可见文本中关于USDT余额扣除及QR码上传的描述`
- 建议：立即封禁，并建议用户不要在该站点进行任何形式的资产交互。

### 11. 凭据窃取风险
- 规则：`DEEP_ADVICE_CREDENTIAL_THEFT`
- 严重级别：`high`
- 说明：页面存在多个密码输入框，结合其欺诈性质，极大概率用于窃取用户账户凭据。
- 证据：`页面包含 4 个密码输入框`
- 建议：将该站点列入黑名单，防止凭据泄露。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包以及四位专家意见，当前目标网站应判定为高风险，整体更偏向 malicious_lean。证据显示该站点表面为“数字货币兑换，买卖比特币”页面，但可见文本中直接暴露了延迟20秒的脚本逻辑，随后可能弹出“网络很慢，是否使用轻版网站”的确认框并跳转到 /zh/lite/?confirm=1，这种时间延迟与引导跳转模式具有明显的规避检测特征。页面还出现“零手续费支付卢布账单”“上传卢布QR码”“直接从USDT余额中扣除”等高风险金融诱导语，并包含4个密码输入框和1个隐藏字段，结合其非主流加密货币兑换叙事，存在较强的凭据收集、资金诱导转移或钓鱼风险。外部情报仅显示域名注册于2024-10-21、证书签发约20天前，属于可疑但不足以单独定性的辅助信号；当前结论主要依赖离线证据链，而非外部威胁情报。四位专家中，静态分析员、行为分析员与处置建议员均明显倾向恶意，其中静态分析员和行为分析员直接给出 malicious_lean，处置建议员虽未给出明确恶意标签但建议 block；情报分析员则保持 uncertain、风险中等。由于方向上存在中度分歧，但高风险行为证据与金融诱导内容更强，最终采纳高风险/恶意倾向结论，而不采用中等风险的保守判断。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
认为该站点是数字货币兑换平台，但存在短期证书、多个密码框、连接速度检测与轻量版跳转脚本，以及高风险金融诱导语，倾向 malicious_lean，置信度 0.75。

### 行为分析员（模型：`gemini-2.5-pro`）
认为该网页具备加密货币诈骗或钓鱼站特征，重点依据是延迟20秒的重定向脚本、粗糙页面与多个密码输入框，倾向 malicious_lean，置信度 0.85。

### 情报分析员（模型：`gpt-4o-mini`）
认为网页未明显模仿特定品牌或组织，主要是数字货币交易站点，当前采用离线规则研判，风险提示为 medium，结论为 uncertain，置信度 0.7。

### 处置建议员（模型：`gemini-2.5-flash`）
认为该网站表现出明显欺诈特征，建议在隔离浏览器中复核并直接 block，虽 claim 为 uncertain，但风险提示为 critical，置信度 0.0。


### 主持人最终总结
基于静态检测结果、浏览器证据包以及四位专家意见，当前目标网站应判定为高风险，整体更偏向 malicious_lean。证据显示该站点表面为“数字货币兑换，买卖比特币”页面，但可见文本中直接暴露了延迟20秒的脚本逻辑，随后可能弹出“网络很慢，是否使用轻版网站”的确认框并跳转到 /zh/lite/?confirm=1，这种时间延迟与引导跳转模式具有明显的规避检测特征。页面还出现“零手续费支付卢布账单”“上传卢布QR码”“直接从USDT余额中扣除”等高风险金融诱导语，并包含4个密码输入框和1个隐藏字段，结合其非主流加密货币兑换叙事，存在较强的凭据收集、资金诱导转移或钓鱼风险。外部情报仅显示域名注册于2024-10-21、证书签发约20天前，属于可疑但不足以单独定性的辅助信号；当前结论主要依赖离线证据链，而非外部威胁情报。四位专家中，静态分析员、行为分析员与处置建议员均明显倾向恶意，其中静态分析员和行为分析员直接给出 malicious_lean，处置建议员虽未给出明确恶意标签但建议 block；情报分析员则保持 uncertain、风险中等。由于方向上存在中度分歧，但高风险行为证据与金融诱导内容更强，最终采纳高风险/恶意倾向结论，而不采用中等风险的保守判断。


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

- 总耗时：38.31 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 6.22 | 4254 | 521 | 4775 |
| 情报分析员 | 6.72 | 4071 | 282 | 4353 |
| 行为分析员 | 23.39 | 3961 | 2146 | 6107 |
| 处置建议员 | 3.80 | 5616 | 510 | 6126 |
| 主持人 | 11.12 | 5911 | 1575 | 7486 |
