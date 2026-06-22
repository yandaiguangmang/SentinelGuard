# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：8 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_150042_440420.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_150042_440420.md

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
  - 大小：`596433` 字节
  - 视口：`{'width': 1440, 'height': 1600}`

## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 20 天前。
- 证据：`Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 高风险金融业务特征
- 规则：`DEEP_STATIC_FINANCIAL_PHISHING_INDICATOR`
- 严重级别：`high`
- 说明：页面明确宣传“零手续费支付卢布账单”、“上传卢布QR码”等涉及敏感资金流转的业务，且页面内存在 4 个密码输入框，极易被用于窃取用户支付凭证或账户信息。
- 证据：`密码框数量: 4; 文本内容: '现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。'`
- 建议：严禁在该站点输入任何个人账户信息或进行资金转账。

### 3. 可疑的页面加载监测与诱导跳转
- 规则：`DEEP_STATIC_SUSPICIOUS_JS_BEHAVIOR`
- 严重级别：`medium`
- 说明：页面包含一段 JavaScript 代码，通过 localStorage 监测加载速度并主动弹出 confirm 对话框诱导用户跳转至“轻量版”页面。此类行为常用于绕过安全检测或在特定网络环境下诱导用户进入更易于实施钓鱼的页面。
- 证据：`let TimerID = setTimeout(() => { ... if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000);`
- 建议：需警惕该站点通过轻量版页面进行进一步的凭证窃取或欺诈操作。

### 4. 域名注册信息分析
- 规则：`INTEL_INFRA_DOMAIN`
- 严重级别：`medium`
- 说明：该域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，注册时间为 608 天，显示出一定的存在时间，但并不算非常成熟。
- 证据：`注册商: NICENIC INTERNATIONAL GROUP CO., LIMITED; 域名存在天数: 608`
- 建议：建议进一步调查该注册商的声誉及其与恶意活动的关联性。

### 5. 证书信息分析
- 规则：`INTEL_INFRA_CERTIFICATE`
- 严重级别：`medium`
- 说明：该网站的 TLS 证书较新，签发于 20 天前，可能表明该网站在近期进行了更新或重新配置。
- 证据：`证书签发时间: 20 天前`
- 建议：建议监控该证书的使用情况，并结合其他证据进行综合判断。

### 6. 可疑的轻量版跳转逻辑
- 规则：`REVIEW_SUSPICIOUS_LIGHT_PAGE_REDIRECT`
- 严重级别：`high`
- 说明：页面脚本通过 localStorage 记录加载次数，并在 20 秒后弹窗诱导用户切换到轻量版页面；在当前高风险金融站点背景下，这类跳转更应按潜在规避检测或分流进入高风险页面处理。
- 证据：`setTimeout(... 20000)；confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); location.href = "/zh/lite/?confirm=1"。`
- 建议：在隔离环境中复核轻量版页面是否存在不同的表单、跳转或凭证收集行为。

### 7. 高风险金融业务宣传
- 规则：`REVIEW_HIGH_RISK_FINANCIAL_PITCH`
- 严重级别：`high`
- 说明：页面公开宣传“零手续费支付卢布账单”“直接从USDT余额中扣除”“上传卢布QR码”等资金流转话术，结合多语言入口和账户功能入口，整体更像高风险金融服务或诈骗型兑换站点，而非普通信息展示页。
- 证据：`visible_text_excerpt 中包含“零手续费支付卢布账单”“上传卢布QR码”“选择私人支付服务”。`
- 建议：若无法确认运营主体与支付合规资质，应直接回避交易并阻断访问。

### 8. 基础设施信息仅提供有限可信度线索
- 规则：`REVIEW_INFRASTRUCTURE_AWKWARDNESS`
- 严重级别：`medium`
- 说明：域名注册已约 608 天，TLS 证书约 20 天前签发。两项信息都不构成安全证明，仅表明站点并非纯粹一次性新域名，但也不能排除长期运营的欺诈站点或近期重配环境。
- 证据：`whois_creation_date: 2024-10-21T15:02:27Z；whois_age_days: 608；证书签发于 20 天前。`
- 建议：仅将其作为背景信息，不应据此降低对敏感输入和资金操作的防护等级。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
综合静态检测结果、browser_evidence 和各角色意见判断，该站点更符合“高风险数字货币交易/兑换站点，存在钓鱼或金融欺诈用途嫌疑”的特征，而非普通良性服务。静态侧已确认页面包含 4 个密码输入框、1 个隐藏字段，且首页文本直接出现“零手续费支付卢布账单”“上传卢布QR码”“选择私人支付服务”等高风险金融操作描述；浏览器证据未发现外部脚本或明显下载行为，但也未见足以证明其正规性的强支撑信号。TLS 证书较新（约 20 天前签发）与域名存在约 608 天，二者本身都不能证明安全性，只能说明该站点具备一定持续运营痕迹且证书近期更新。专家意见整体分歧不大：静态分析员给出 malicious_lean 且风险提示 high，行为分析员与情报分析员给出 medium / uncertain，处置建议员直接给出 critical 级防护建议。我们最终不采用中性折中结论，而是将风险上调至 high，依据是页面内容与交互结构同时具备金融诱导、凭证输入入口、以及可疑跳转逻辑三类风险信号，且当前结论主要建立在离线与静态证据上，外部情报不足以完成可信背书。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
页面表现为数字货币兑换平台，存在多个密码输入框、较新的 TLS 证书以及通过 localStorage 监测加载速度并诱导跳转至轻量版页面的脚本；结合“零手续费支付卢布账单”“上传卢布QR码”等高风险金融内容，倾向 malicious_lean，风险提示为 high，置信度 0.75。

### 行为分析员（模型：`gemini-2.5-pro`）
页面行为表现为数字货币交易平台，未观察到强制重定向或恶意软件下载等明显恶意行为，但该平台合法性存疑，可能用于窃取登录凭证和数字资产；风险提示为 medium，置信度 0.5。

### 情报分析员（模型：`gpt-4o-mini`）
网页未明显冒充特定品牌或组织，当前版本采用离线规则研判；域名注册时间 608 天，证书较新，整体仍属不确定，风险提示为 medium，置信度 0.7。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站伪装成数字货币兑换平台，结合多个密码输入框、可疑加载监测与跳转脚本以及高风险金融业务描述，建议封禁并严禁输入敏感信息；风险提示为 critical，置信度 0.0，recommended_action 为 block。


### 主持人最终总结
综合静态检测结果、browser_evidence 和各角色意见判断，该站点更符合“高风险数字货币交易/兑换站点，存在钓鱼或金融欺诈用途嫌疑”的特征，而非普通良性服务。静态侧已确认页面包含 4 个密码输入框、1 个隐藏字段，且首页文本直接出现“零手续费支付卢布账单”“上传卢布QR码”“选择私人支付服务”等高风险金融操作描述；浏览器证据未发现外部脚本或明显下载行为，但也未见足以证明其正规性的强支撑信号。TLS 证书较新（约 20 天前签发）与域名存在约 608 天，二者本身都不能证明安全性，只能说明该站点具备一定持续运营痕迹且证书近期更新。专家意见整体分歧不大：静态分析员给出 malicious_lean 且风险提示 high，行为分析员与情报分析员给出 medium / uncertain，处置建议员直接给出 critical 级防护建议。我们最终不采用中性折中结论，而是将风险上调至 high，依据是页面内容与交互结构同时具备金融诱导、凭证输入入口、以及可疑跳转逻辑三类风险信号，且当前结论主要建立在离线与静态证据上，外部情报不足以完成可信背书。


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

- 总耗时：29.58 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 4.58 | 4254 | 514 | 4768 |
| 情报分析员 | 8.00 | 4071 | 305 | 4376 |
| 行为分析员 | 17.92 | 3960 | 1610 | 5570 |
| 处置建议员 | 2.24 | 5307 | 152 | 5459 |
| 主持人 | 9.42 | 5242 | 1714 | 6956 |
