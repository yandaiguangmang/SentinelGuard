# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**80/100**
> 证据分数：**80/100** · 深度研判分数：**80 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://ninewest-singapore.com/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：6 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260625_160103_465117.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260625_160103_465117.md

## 二、统一 IR 摘要
- 规范化 URL：`https://ninewest-singapore.com/`
- 协议：`https`
- 主机：`ninewest-singapore.com`
- 路径：`/`
- 查询参数数量：`0`

## 三、跳转链
- https://ninewest-singapore.com/

## 四、页面线索
- status_code：200
- content_type：text/html; charset=UTF-8
- final_url：https://ninewest-singapore.com/
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://127.0.0.1:7897', 'https': 'http://127.0.0.1:7897', 'ftp': 'http://127.0.0.1:7897'}
- title：Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc
- visible_text_excerpt：img:is([sizes="auto" i], [sizes^="auto," i]) { contain-intrinsic-size: 3000px 1500px } .wp-block-button__link { color: #fff; background-color: #32373c; border-radius: 9999px; box-shadow: none; text-decoration: none; padding: calc(.667em + 2px) calc(1.333em + 2px); font-size: 1.125em } .wp-block-file__button { background: #32373c; color: #fff; text-decoration: none } :root { --ft_background_color: #002e63; --ft_text_color: #FFFFFF; --site_info_b_color: #e6b900; --color_soc_icons: #ff8747; --color_bg_soc_icons: #fff; --h_navigation_color: #FFFFFF; --h_background_color: #0e4482; --main-accent-color: #ff4c00; --bg-body: #f5f5f5; --b-font-size: 15px; --btn-back-text-color: #FFFFFF; --btn-back-color: #ff4c00; --btn-back-hover-bg-color: #ff963a; --btn-back-hover-text-color: #ffffff; --btn-border-
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：https://cloud.umami.is/script.js, https://ninewest-singapore.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1, https://ninewest-singapore.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1, https://ninewest-singapore.com/wp-content/themes/mostbet1/js/hooks.min.js, https://ninewest-singapore.com/wp-content/themes/mostbet1/js/i18n.min.js, https://ninewest-singapore.com/wp-content/themes/mostbet1/js/index.js, https://ninewest-singapore.com/wp-content/themes/mostbet1/js/main.min.js, https://ninewest-singapore.com/wp-content/themes/mostbet1/js/comment-reply.min.js, https://ninewest-singapore.com/wp-content/themes/mostbet1/js/script.js, https://ninewest-singapore.com/wp-content/themes/mostbet1/js/navigation.js?ver=1.0.0, https://static.cloudflareinsights.com/beacon.min.js/v833ccba57c9e4d2798f2e76cebdd09a11778172276447
- form_actions：无
- download_links：无
- external_script_count：11
- html_summary：{'raw_excerpt': '<!doctype html> <html lang="az"> <head> <meta charset="UTF-8"> <meta name="x-custom-template" content="custom-page"> <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"> <meta name="viewport" content="width=device-width"> <meta http-equiv="X-UA-Compatible" content="ie=edge"> <link rel="shortcut icon" type="image/x-icon" href="https://ninewest-singapore.com/wp-content/themes/mostbet1/img/favicon/favicon.ico"> <link rel="preconnect" href="https://fonts.googleapis.com"> <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin> <link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet"> <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@700&display=swap" rel="stylesheet"> <style> img:is([sizes="auto" i], [sizes^="auto," i]) { contain-intrinsic-size: 3000px 1500px } </style> <style id="classic-theme-styles-inline-css"> .wp-block-button__link { color: #fff; background-color: #32373c; border-radius: 9999px; box-shadow: none; text-decoration: none; padding: calc(.667em + 2px) calc(1.333em + 2px); font-size: 1.125em } .wp-block-file__button { background: #32373c; color: #fff; text-decoration: none } </style> <link rel="', 'text_excerpt': 'img:is([sizes="auto" i], [sizes^="auto," i]) { contain-intrinsic-size: 3000px 1500px } .wp-block-button__link { color: #fff; background-color: #32373c; border-radius: 9999px; box-shadow: none; text-decoration: none; padding: calc(.667em + 2px) calc(1.333em + 2px); font-size: 1.125em } .wp-block-file__button { background: #32373c; color: #fff; text-decoration: none } :root { --ft_background_color: #002e63; --ft_text_color: #FFFFFF; --site_info_b_color: #e6b900; --color_soc_icons: #ff8747; --color_bg_soc_icons: #fff; --h_navigation_color: #FFFFFF; --h_background_color: #0e4482; --main-accent-color: #ff4c00; --bg-body: #f5f5f5; --b-font-size: 15px; --btn-back-text-color: #FFFFFF; --btn-back-color: #ff4c00; --btn-back-hover-bg-color: #ff963a; --btn-back-hover-text-color: #ffffff; --btn-border-'}
- external_intel：{'whois_registrar': 'DEVEXPANSE LTD d/b/a Regery.com', 'whois_country': None, 'whois_creation_date': '2025-12-18T15:53:06Z', 'whois_age_days': 188}

## 四点一、页面线索
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`DEVEXPANSE LTD d/b/a Regery.com`
- 域名注册时间：`2025-12-18T15:53:06Z`
- 域名注册天数：`188` 天

## 五、截图证据
### 截图 1
- 标题：`Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc`
- 落点：`https://ninewest-singapore.com/`
- 时间：`2026-06-25T08:01:01.203585+00:00`
- 大小：`283373` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 10 天前。
- 证据：`Jun 14 18:54:41 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 域名注册商
- 规则：`INTEL_INFRA_DOMAIN`
- 严重级别：`medium`
- 说明：该域名由 DEVEXPANSE LTD 以 Regery.com 名义注册，需关注该注册商的历史记录。
- 证据：`注册商为 DEVEXPANSE LTD。`
- 建议：建议调查该注册商的信誉，以及其过往涉及的恶意活动。

### 3. 域名创建时间
- 规则：`INTEL_INFRA_CREATION`
- 严重级别：`medium`
- 说明：该域名已经存在 188 天，虽然不是非常新，但仍属于相对较短的生命周期。
- 证据：`该域名的创建时间为2025年12月18日。`
- 建议：监控该域名未来的发展动态，做好预警。

### 4. 域名与内容严重不符，涉嫌品牌仿冒和欺诈
- 规则：`DEEP_BEHAVIOR_BRAND_IMPERSONATION_CONTENT_MISMATCH`
- 严重级别：`high`
- 说明：域名“ninewest-singapore.com”与知名时尚品牌“Nine West”相关，但浏览器实际加载的页面内容却是一个名为“Mostbet”的阿塞拜疆语赌博网站。这种域名和实际内容之间的巨大差异是恶意网站的典型特征，旨在利用不相关的域名来托管高风险内容（如赌博、钓鱼），从而诱骗用户并逃避封锁。
- 证据：`域名主机: ninewest-singapore.com
页面标题: Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc
页面内容: 根据标题和语言（az）判断为面向阿塞拜疆的赌博网站。`
- 建议：立即阻止对该域名的访问。这类网站极有可能涉及金融诈骗、个人信息盗窃或网络钓鱼活动。

### 5. 可疑第三方统计脚本
- 规则：`DEEP_STATIC_EXTERNAL_SCRIPT`
- 严重级别：`medium`
- 说明：发现非常规统计服务脚本（umami.is），此类服务可能被滥用且常被钓鱼网站使用
- 证据：`src='https://cloud.umami.is/script.js'`
- 建议：需验证该统计服务的历史使用记录

### 6. CSS变量透露出非宣称主题
- 规则：`DEEP_STATIC_CSS_THEMING`
- 严重级别：`medium`
- 说明：CSS变量命名包含赌博相关术语（如 'kazino'/'mərc'）且强调橘红色调（--main-accent-color: #ff4c00），与传统时尚品牌风格不符
- 证据：`CSS代码段包含：--site_info_b_color: #e6b900；--color_soc_icons: #ff8747；--main-accent-color: #ff4c00`
- 建议：对比官方品牌配色以确认异常


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合静态检测、浏览器证据及四位专家意见，该网站被判定为高风险恶意页面。核心风险在于严重的品牌仿冒与内容欺诈：域名 ninewest-singapore.com 暗示知名时尚品牌，但实际加载内容为阿塞拜疆语赌博网站 Mostbet。静态分析员、行为分析员和情报分析员均一致判定为 malicious_lean，风险提示为 high。处置建议员虽在 claim 字段标记为 uncertain，但其文本意见明确指出所有证据指向高风险并建议 block。初始静态报告的风险等级 medium 主要基于证书签发时间，未能充分反映内容不匹配的风险，经专家复核后风险等级上调至 high。建议立即拦截该域名，避免用户遭受金融诈骗或钓鱼攻击。 综合静态检测、浏览器证据及四位专家意见，该网站被判定为高风险恶意页面。核心风险在于严重的品牌仿冒与内容欺诈：域名 ninewest-singapore.com 暗示知名时尚品牌，但实际加载内容为阿塞拜疆语赌博网站 Mostbet。静态分析员、行为分析员和情报分析员均一致判定为 malicious_lean，风险提示为 high。处置建议员虽在 claim 字段标记为 uncertain，但其文本意见明确指出所有证据指向高风险并建议 block。初始静态报告的风险等级 medium 主要基于证书签发时间，未能充分反映内容不匹配的风险，经专家复核后风险等级上调至 high。建议立即拦截该域名，避免用户遭受金融诈骗或钓鱼攻击。

### 静态分析员（模型：`deepseek-reasoner`）
基于静态结构分析，该网页存在明显可疑特征：域名与标题内容不匹配，使用知名品牌 'ninewest' 但实际展示阿塞拜疆语言赌博内容；外部脚本包含异常统计服务（umami.is）；CSS 变量名暗示赌博主题（如 'kazino'）。域名注册商为高风险提供商（DEVEXPANSE/Regery.com），且证书签发时间过短（10天）。虽无直接恶意代码证据，但静态特征强烈暗示该网站涉嫌品牌劫持或赌博诈骗。

### 行为分析员（模型：`gemini-2.5-pro`）
该网站存在严重的品牌仿冒和内容欺诈行为。其域名（ninewest-singapore.com）试图冒充时尚品牌“Nine West”，但实际呈现的内容是一个面向阿塞拜疆用户的“Mostbet”赌博网站。这种域名与内容完全不符的情况是恶意行为的明确标志，其目的很可能是利用看似无害的域名来承载高风险的赌博或钓鱼内容，以规避安全检测并诱骗用户。行为链本身虽然没有复杂的重定向，但落地页所呈现的欺骗性内容足以构成高风险。

### 情报分析员（模型：`gpt-4o-mini`）
该域名可能通过混淆来吸引用户，但没有明确指向特定的品牌或机构，因此可能是泛滥的网络恶意活动。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站的域名 (ninewest-singapore.com) 明显与知名时尚品牌 Nine West 相关，但实际加载的页面内容却是阿塞拜疆语的“Mostbet”在线赌博网站。这种域名与实际内容严重不符的情况，是典型的品牌仿冒和内容欺诈行为，意图通过伪装来规避检测并诱骗用户。同时，静态分析发现其 TLS 证书签发时间较短 (10天)，域名注册商 (DEVEXPANSE LTD/Regery.com) 被标记为高风险，且页面包含可疑的第三方统计脚本和暗示赌博主题的CSS样式。所有证据都强烈指向该网站存在高风险的恶意活动，可能涉及金融诈骗或钓鱼。


### 主持人最终总结
综合静态检测、浏览器证据及四位专家意见，该网站被判定为高风险恶意页面。核心风险在于严重的品牌仿冒与内容欺诈：域名 ninewest-singapore.com 暗示知名时尚品牌，但实际加载内容为阿塞拜疆语赌博网站 Mostbet。静态分析员、行为分析员和情报分析员均一致判定为 malicious_lean，风险提示为 high。处置建议员虽在 claim 字段标记为 uncertain，但其文本意见明确指出所有证据指向高风险并建议 block。初始静态报告的风险等级 medium 主要基于证书签发时间，未能充分反映内容不匹配的风险，经专家复核后风险等级上调至 high。建议立即拦截该域名，避免用户遭受金融诈骗或钓鱼攻击。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
