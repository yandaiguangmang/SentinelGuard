# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**90/100**
> 证据分数：**95/100** · 深度研判分数：**85 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://ninewest-singapore.com/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：6 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260625_165558_982007.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260625_165558_982007.md

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
- 时间：`2026-06-25T08:55:57.068530+00:00`
- 大小：`284858` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 10 天前。
- 证据：`Jun 14 18:54:41 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 域名注册商信息
- 规则：`INTEL_INFRA_REGISTRAR`
- 严重级别：`medium`
- 说明：域名由 DEVEXPANSE LTD d/b/a Regery.com 注册，具有一定的可信度，但仍需警惕其潜在的恶意目的。
- 证据：`注册商为DEVEXPANSE LTD d/b/a Regery.com`
- 建议：建议进一步调查该注册商下类似可疑域名的注册情况，以评估潜在威胁。

### 3. 域名注册时间分析
- 规则：`INTEL_INFRA_CREATION_DATE`
- 严重级别：`medium`
- 说明：该域名注册已有188天，相对年轻，需注意其持有者的意图和潜在的不良活动。
- 证据：`域名存在天数：188天`
- 建议：建议监测该域名的后续活动，尤其是在敏感事件或时段的表现。

### 4. TLS证书分析
- 规则：`INTEL_INFRA_CERTIFICATE`
- 严重级别：`medium`
- 说明：证书为近期签发，仅在10天前颁发，时间较短，这可能是为了掩盖恶意行为。
- 证据：`证书签发于10天前。`
- 建议：结合其他证据进行全面评估，特别是观察证书的未来有效性和变化。

### 5. 域名与品牌标识严重不符
- 规则：`DEEP_STATIC_MISMATCHED_BRANDING`
- 严重级别：`critical`
- 说明：域名构造混用了品牌名称（Nine West）与注册国家（新加坡），但页面实际内容却指向另一个品牌（Mostbet），该模式具有极高的恶意仿冒网站特征。
- 证据：`标题："Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc"; 域名："ninewest-singapore.com"`
- 建议：确认域名所有者的可信度，建议禁止访问并提升告警等级至高风险

### 6. 样式含非功能性超大尺寸预设及赌博相关关键词
- 规则：`DEEP_STATIC_SUSPICIOUS_STYLES`
- 严重级别：`medium`
- 说明：CSS样式中含有关键词如"Kazino"（阿塞拜疆语的赌场）和异常图片尺寸设置（intrinsic-size: 3000px 1500px），该组合在正常品牌官网中极不可能出现
- 证据：`CSS："contain-intrinsic-size: 3000px 1500px"; 文本片段："Mostbet Onlayn Kazino və Mərc"`
- 建议：提交至SDocs系统进行高优先级人工复核


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合分析表明，该网站存在严重的内容与域名不符问题。域名 `ninewest-singapore.com` 暗示其为时尚品牌 Nine West 的新加坡官网，但实际页面内容却是面向阿塞拜疆用户的 Mostbet 在线赌博平台。这种品牌冒用和误导性内容是典型的恶意推广或网站被篡改迹象。尽管静态分析最初因证书签发时间短仅评定为中等风险，但行为分析和深度静态分析一致指出这种欺骗性策略构成了高风险。处置建议员甚至建议直接拦截。因此，最终风险等级上调至高（high），主要依据为严重的品牌/内容不匹配及潜在的欺诈意图。 综合分析表明，该网站存在严重的内容与域名不符问题。域名 `ninewest-singapore.com` 暗示其为时尚品牌 Nine West 的新加坡官网，但实际页面内容却是面向阿塞拜疆用户的 Mostbet 在线赌博平台。这种品牌冒用和误导性内容是典型的恶意推广或网站被篡改迹象。尽管静态分析最初因证书签发时间短仅评定为中等风险，但行为分析和深度静态分析一致指出这种欺骗性策略构成了高风险。处置建议员甚至建议直接拦截。因此，最终风险等级上调至高（high），主要依据为严重的品牌/内容不匹配及潜在的欺诈意图。

### 静态分析员（模型：`deepseek-reasoner`）
静态证据分析显示，该网页存在明显的品牌误用和可疑域名特征。网站标题和文本中提到“Mostbet”，这通常是一个品牌名称，与域名“ninewest-singapore.com”的拼写字面含义不符，后者暗示该域名与新加坡的Nine West品牌相关。此类域名捏合品牌词的形式具有高风险，常见于钓鱼或虚假网站的模仿攻击。虽然TLS证书签发时间较短是一个中等风险指标，但因与域名捏合特征形成强关联，提高了风险置信度。

### 行为分析员（模型：`gemini-2.5-pro`）
该网站存在严重的内容与域名不符问题。域名 `ninewest-singapore.com` 暗示其为新加坡的一个时尚品牌网站，但实际页面内容是面向阿塞拜疆的 "Mostbet" 在线赌博平台。这种行为是典型的欺骗性策略，旨在利用看似无害的域名来推广高风险或非法的赌博内容。尽管在本次分析中未直接观察到恶意软件下载或钓鱼表单，但其核心行为是诱导用户访问一个与其预期完全不符的赌博网站，这本身就构成了恶意行为。

### 情报分析员（模型：`gpt-4o-mini`）
该网页似乎并没有清晰地模仿特定的品牌或组织，存在内容混淆的情形。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站存在严重的域名与内容不符问题。域名 `ninewest-singapore.com` 误导用户认为这是一个合法的Nine West时尚品牌网站，但实际内容却是针对阿塞拜疆用户的“Mostbet”在线赌博平台。这种行为是典型的欺骗和品牌冒用，旨在利用看似无害的域名诱导用户访问高风险或可能非法的赌博内容。尽管未发现直接的恶意软件或钓鱼表单，但其欺骗性质已构成高风险。此外，TLS证书签发时间较短，且页面中含有赌博相关关键词，进一步印证了其可疑性。


### 主持人最终总结
综合分析表明，该网站存在严重的内容与域名不符问题。域名 `ninewest-singapore.com` 暗示其为时尚品牌 Nine West 的新加坡官网，但实际页面内容却是面向阿塞拜疆用户的 Mostbet 在线赌博平台。这种品牌冒用和误导性内容是典型的恶意推广或网站被篡改迹象。尽管静态分析最初因证书签发时间短仅评定为中等风险，但行为分析和深度静态分析一致指出这种欺骗性策略构成了高风险。处置建议员甚至建议直接拦截。因此，最终风险等级上调至高（high），主要依据为严重的品牌/内容不匹配及潜在的欺诈意图。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
