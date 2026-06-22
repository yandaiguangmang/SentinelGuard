# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：6 条
- 高危证据：2 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_150616_572529.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_150616_572529.md

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
  - 大小：`596391` 字节
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
- 严重级别：`high`
- 说明：页面存在 4 个密码输入框，结合数字货币兑换场景与缺乏可信背景信息，更接近诱导用户提交凭证的风险模式，而不只是普通登录页。
- 证据：`密码框数量: 4；页面同时出现注册/登录相关文本。`
- 建议：在未核实平台合法性前，不要输入任何账号、密码或交易信息。

### 3. 可疑的页面加载速度检测与跳转逻辑
- 规则：`DEEP_STATIC_SUSPICIOUS_JS_BEHAVIOR`
- 严重级别：`medium`
- 说明：页面包含一段通过 setTimeout 和 localStorage 检测连接速度并强制弹出 confirm 对话框诱导跳转至 /lite/ 版本的脚本，此类逻辑常被用于绕过安全检测或在低带宽环境下隐藏恶意内容。
- 证据：`代码片段: setTimeout(() => { ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：需重点审查 /lite/ 路径下的页面内容，警惕其作为恶意载荷的入口。

### 4. 高风险金融诱导话术
- 规则：`DEEP_STATIC_FINANCIAL_PHISHING_INDICATOR`
- 严重级别：`high`
- 说明：页面显眼位置包含“零手续费”、“上传卢布QR码”等诱导性金融操作提示，此类话术常用于非法资金洗钱或诱导用户进行不可逆的加密货币转账。
- 证据：`可见文本: “现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码”`
- 建议：严禁在该网站输入任何敏感信息或进行资产转账。

### 5. 域名注册信息分析
- 规则：`INTEL_INFRA_1`
- 严重级别：`medium`
- 说明：该域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，域名创建于 2024 年 10 月 21 日，至今已有 608 天，显示出相对较长的存在时间。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 域名存在天数: 608`
- 建议：建议进一步调查该注册商的声誉及其与恶意活动的关联性。

### 6. 证书信息分析
- 规则：`INTEL_INFRA_2`
- 严重级别：`medium`
- 说明：当前证书的有效期较短，可能影响用户对该网站的信任度。
- 证据：`证书签发时间较短，建议结合其他证据综合判断。`
- 建议：建议用户在输入敏感信息前，确认域名的可信度和证书的有效性。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包与专家意见，目标站点 baksmany.net/zh/ 表现为一个数字货币兑换/交易平台页面，但同时具备多项高风险特征：页面包含 4 个密码输入框、1 个隐藏字段，且文本中出现“零手续费”“上传卢布QR码”等强诱导性金融话术；页面还内嵌一段通过 setTimeout、localStorage 与 confirm 逻辑引导用户跳转到 /zh/lite/ 的脚本。静态侧仅给出了“TLS 证书签发时间较短”和“页面包含密码输入框”两条中等风险线索，但结合浏览器证据中的金融诱导文案、登录/注册入口与可疑跳转逻辑，整体风险明显上升。外部情报仅能确认域名注册商与域名年龄，未提供足以证明其合法性的信誉信息，因此当前结论主要依赖离线证据。综合四位专家观点，静态分析员、行为分析员均明确倾向 malicious_lean，情报分析员保持 uncertain，处置建议员虽给出 critical 风险提示但 claim 为 uncertain；各方在方向上并非完全一致，但高风险判断占明显多数，且没有出现 benign_lean 的反向判断，因此最终采纳 high 风险结论，而不是中性平均。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
认为页面是典型数字货币兑换平台，但存在较短签发时间的 TLS 证书、4 个密码框，以及可疑的连接速度检测与跳转脚本；结合“零手续费”“上传卢布QR码”等话术，判断存在较高钓鱼/欺诈风险，倾向 malicious_lean，置信度 0.75。

### 行为分析员（模型：`gemini-2.5-pro`）
认为页面行为上像加密货币交易平台，未见自动重定向或下载等攻击行为，但其主要威胁是诱导用户输入凭证或转账；结合新证书与登录/注册结构，倾向 malicious_lean，置信度 0.7。

### 情报分析员（模型：`gpt-4o-mini`）
认为网页未明确冒充特定品牌或组织，主要是数字货币兑换服务；当前版本采用离线规则研判，若用于实战应补充域名信誉、证书透明度和黑名单情报，结论为 uncertain，置信度 0.7。

### 处置建议员（模型：`gemini-2.5-flash`）
认为网站伪装成数字货币兑换平台，含多个密码输入框、诱导性金融话术与可疑轻量版跳转逻辑，极大概率为钓鱼或诈骗网站；建议隔离环境复核最终域名，不要提交敏感信息。其 risk_hint 为 critical，但 claim 为 uncertain，confidence 为 0.0，recommended_action 为 block。


### 主持人最终总结
基于静态检测结果、浏览器证据包与专家意见，目标站点 baksmany.net/zh/ 表现为一个数字货币兑换/交易平台页面，但同时具备多项高风险特征：页面包含 4 个密码输入框、1 个隐藏字段，且文本中出现“零手续费”“上传卢布QR码”等强诱导性金融话术；页面还内嵌一段通过 setTimeout、localStorage 与 confirm 逻辑引导用户跳转到 /zh/lite/ 的脚本。静态侧仅给出了“TLS 证书签发时间较短”和“页面包含密码输入框”两条中等风险线索，但结合浏览器证据中的金融诱导文案、登录/注册入口与可疑跳转逻辑，整体风险明显上升。外部情报仅能确认域名注册商与域名年龄，未提供足以证明其合法性的信誉信息，因此当前结论主要依赖离线证据。综合四位专家观点，静态分析员、行为分析员均明确倾向 malicious_lean，情报分析员保持 uncertain，处置建议员虽给出 critical 风险提示但 claim 为 uncertain；各方在方向上并非完全一致，但高风险判断占明显多数，且没有出现 benign_lean 的反向判断，因此最终采纳 high 风险结论，而不是中性平均。


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

- 总耗时：37.81 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 3.65 | 4254 | 507 | 4761 |
| 情报分析员 | 6.57 | 4071 | 314 | 4385 |
| 行为分析员 | 20.29 | 3960 | 2063 | 6023 |
| 处置建议员 | 4.96 | 5370 | 163 | 5533 |
| 主持人 | 12.56 | 5344 | 1784 | 7128 |
