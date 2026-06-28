# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**85/100**
> 评分口径：URL 深度研判分数已综合证据分数，最终风险分数直接采用深度研判分数。
模型深度研判

## 一、检测结论
- 原始输入：`https://ninewest-singapore.com/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：5 条
- 高危证据：2 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260626_223646_699327.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260626_223646_699327.md

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
- external_intel：{'whois_registrar': 'DEVEXPANSE LTD d/b/a Regery.com', 'whois_country': None, 'whois_creation_date': '2025-12-18T15:53:06Z', 'whois_age_days': 189}

## 四点一、页面线索
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 注册商：`DEVEXPANSE LTD d/b/a Regery.com`
- 域名注册时间：`2025-12-18T15:53:06Z`
- 域名注册天数：`189` 天

## 五、截图证据
### 截图 1
- 标题：`Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc`
- 落点：`https://ninewest-singapore.com/`
- 时间：`2026-06-26T14:36:35.993226+00:00`
- 大小：`284652` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 11 天前。
- 证据：`Jun 14 18:54:41 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 域名注册信息分析
- 规则：`INTEL_INFRA_*`
- 严重级别：`medium`
- 说明：该域名由DEVEXPANSE LTD d/b/a Regery.com注册，存在189天，表明域名不是非常新，但也不算老旧。
- 证据：`域名注册商: DEVEXPANSE LTD d/b/a Regery.com，域名存在天数: 189。`
- 建议：建议继续观察该域名的使用情况及其潜在影响。

### 3. 域名与内容严重不符，涉嫌品牌仿冒和搜索引擎投毒
- 规则：`DEEP_BEHAVIOR_DECEPTIVE_CONTENT`
- 严重级别：`high`
- 说明：网站域名 `ninewest-singapore.com` 暗示其为时尚品牌“Nine West”的新加坡官方网站，但页面实际内容却是阿塞拜疆语的“Mostbet”博彩网站。这种域名与内容完全不匹配是典型的欺骗性行为，通常用于搜索引擎投毒（SEO Poisoning）或仿冒诈骗，旨在利用无辜的品牌域名吸引流量，然后将用户引导至博彩、诈骗或恶意软件下载页面。
- 证据：`最终URL: https://ninewest-singapore.com/
页面标题: "Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc"`
- 建议：立即阻止对该域名的访问。该网站具有高度欺骗性，可能导致用户财务损失或个人信息泄露。

### 4. 域名描述与实际内容不符
- 规则：`DEEP_STATIC_SUSPICIOUS_KEYWORD`
- 严重级别：`high`
- 说明：域名‘ninewest-singapore.com’暗示新加坡时尚品牌，但页面实际展示阿塞拜疆语赌博内容，包含大量赌博相关关键词（如Mostbet Onlayn Kazino）。
- 证据：`页面标题=‘Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc’；主题目录名=‘mostbet1’；CSS变量含‘--btn-back-color: #ff4c00’等赌博网站常见设计`
- 建议：应视为品牌伪装行为，无需其他证据即可判定其恶意性质。

### 5. 外部脚本来源与伪装主题矛盾
- 规则：`DEEP_STATIC_SCRIPT_CONTRADICTION`
- 严重级别：`medium`
- 说明：加载的umami.is脚本是赌博网站常用分析工具，云服务使用方式碎片化（cdn/beacon.min.js），进一步暴露实际运作性质。
- 证据：`script_srcs含‘https://cloud.umami.is/script.js’及Cloudflare Insight跟踪脚本`
- 建议：即使不考虑情报数据，静态特征也已构成判定支持。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合静态检测、浏览器证据及四位专家意见，最终判定该网页为高风险（high）。虽然主持人及情报分析员基于证书签发时间（11 天）和域名年龄（189 天）等基础设施指标给出了中等风险（medium）或不确定（uncertain）的初步判断，但静态分析员、行为分析员及处置建议员一致指出存在严重的‘域名与内容不符’问题：域名暗示为新加坡时尚品牌'Nine West'，实际内容却是阿塞拜疆语的'Mostbet'博彩网站。这种明显的品牌仿冒和搜索引擎投毒（SEO Poisoning）特征构成了实质性的欺诈风险，其危害性远高于单纯的证书新旧问题。因此，最终结论采纳高风险判定，建议阻断访问。 综合静态检测、浏览器证据及四位专家意见，最终判定该网页为高风险（high）。虽然主持人及情报分析员基于证书签发时间（11 天）和域名年龄（189 天）等基础设施指标给出了中等风险（medium）或不确定（uncertain）的初步判断，但静态分析员、行为分析员及处置建议员一致指出存在严重的‘域名与内容不符’问题：域名暗示为新加坡时尚品牌'Nine West'，实际内容却是阿塞拜疆语的'Mostbet'博彩网站。这种明显的品牌仿冒和搜索引擎投毒（SEO Poisoning）特征构成了实质性的欺诈风险，其危害性远高于单纯的证书新旧问题。因此，最终结论采纳高风险判定，建议阻断访问。

### 静态分析员（模型：`deepseek-reasoner`）
静态页面的结构和内容存在高度可疑的冲突。域名‘ninewest-singapore.com’暗示一个新加坡相关的时尚品牌，但页面实际显示的语言（阿塞拜疆语）、标题内容（涉及在线赌场）以及CSS样式中的变量命名（如mostbet1）均指向一个赌博网站。这种伪装行为是典型的欺诈网站特征。外部脚本中包含赌博分析工具（umami.is），Cloudflare跟踪脚本使用方式也与恶意网站常见手法一致。虽然证书不一致的证据已有标记，但静态结构本身已具备恶意判定依据。

### 行为分析员（模型：`gemini-2.5-pro`）
该网站存在严重的欺骗行为。其域名（ninewest-singapore.com）伪装成时尚品牌“Nine West”的新加坡站点，但实际呈现的内容却是针对阿塞拜疆用户的“Mostbet”博彩网站。这种域名与内容完全不匹配是典型的搜索引擎投毒（SEO Poisoning）或仿冒诈骗策略，旨在利用一个看似无害的域名来吸引流量，并将其引导至高风险的博彩或诈骗平台。虽然没有观察到直接的重定向或恶意软件下载，但这种蓄意的欺骗行为本身就构成了高度风险。

### 情报分析员（模型：`gpt-4o-mini`）
该网页似乎未明确仿冒任何特定品牌或组织，但其域名可能暗示与某些品牌相关。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站存在严重的欺骗行为。其域名 `ninewest-singapore.com` 伪装成知名时尚品牌 Nine West 的新加坡官方网站，但实际页面内容却是阿塞拜疆语的在线赌博平台“Mostbet”。这种域名与内容完全不符的情况是典型的搜索引擎投毒（SEO Poisoning）或品牌仿冒策略，旨在利用看似无害的域名吸引用户，然后将其引导至高风险的赌博网站。此外，该网站的 TLS 证书签发时间较短（11天前），域名注册时间也相对较新（189天），进一步增加了其可疑性。综合各项证据，该网站具有高度的欺骗性。


### 主持人最终总结
综合静态检测、浏览器证据及四位专家意见，最终判定该网页为高风险（high）。虽然主持人及情报分析员基于证书签发时间（11 天）和域名年龄（189 天）等基础设施指标给出了中等风险（medium）或不确定（uncertain）的初步判断，但静态分析员、行为分析员及处置建议员一致指出存在严重的‘域名与内容不符’问题：域名暗示为新加坡时尚品牌'Nine West'，实际内容却是阿塞拜疆语的'Mostbet'博彩网站。这种明显的品牌仿冒和搜索引擎投毒（SEO Poisoning）特征构成了实质性的欺诈风险，其危害性远高于单纯的证书新旧问题。因此，最终结论采纳高风险判定，建议阻断访问。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
