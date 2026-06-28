# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**82/100**
> 证据分数：**80/100** · 深度研判分数：**85 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://ninewest-singapore.com/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：7 条
- 高危证据：3 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260625_171014_344697.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260625_171014_344697.md

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
- 时间：`2026-06-25T09:10:11.838231+00:00`
- 大小：`284835` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 10 天前。
- 证据：`Jun 14 18:54:41 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 域名注册信息分析
- 规则：`INTEL_INFRA_01`
- 严重级别：`high`
- 说明：该域名由DEVEXPANSE LTD d/b/a Regery.com注册，注册时间较短，存在潜在的恶意风险。
- 证据：`域名存在188天，注册商为DEVEXPANSE LTD d/b/a Regery.com，域名创建时间为2025-12-18。`
- 建议：建议监测该域名的后续活动，并查阅域名信誉及相关黑名单信息。

### 3. TLS证书分析
- 规则：`INTEL_INFRA_02`
- 严重级别：`medium`
- 说明：该域名的TLS证书在短期内签发，可能暗示不稳定性或假冒行为。
- 证据：`证书存在较短时间，与域名注册时间接近。`
- 建议：应加强对该域名及其服务的安全性评估，谨慎处理敏感数据。

### 4. 域名仿冒知名品牌，内容为赌博网站
- 规则：`DEEP_BEHAVIOR_BRAND_IMPERSONATION`
- 严重级别：`high`
- 说明：访问的域名 `ninewest-singapore.com` 疑似仿冒知名时尚品牌“Nine West”，但页面实际内容为名为“Mostbet”的在线赌博平台，且语言为阿塞拜疆语。这种域名与内容严重不匹配的行为是典型的品牌仿冒，旨在利用知名品牌的声誉欺骗用户，诱导其访问高风险的赌博网站。
- 证据：`域名: ninewest-singapore.com, 页面标题: "Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc" (在线赌博内容)`
- 建议：建议立即阻止对该域名的访问，因为它利用品牌仿冒进行欺诈性引流。

### 5. 高比例第三方脚本加载
- 规则：`DEEP_STATIC_THIRD_PARTY_SCRIPTS`
- 严重级别：`medium`
- 说明：页面加载的11个外部脚本中，包含第三方分析服务(umami.is)和CDN资源(cloudflareinsights.com)，存在数据泄露风险。
- 证据：`script_srcs包含：https://cloud.umami.is/script.js 及 cloudflareinsights.com资源`
- 建议：审查第三方脚本的隐私合规性。

### 6. 域名仿冒知名品牌，内容为赌博网站
- 规则：`BRAND_IMPERSONATION_HIGH`
- 严重级别：`high`
- 说明：访问的域名 `ninewest-singapore.com` 疑似仿冒知名时尚品牌
- 证据：`https://ninewest-singapore.com/`
- 建议：建议立即阻止对该域名的访问，因为它利用品牌仿冒进行欺诈性引流。

### 7. TLS 证书签发时间较短
- 规则：`CERT_RECENT_REEVAL`
- 严重级别：`medium`
- 说明：证书签发于 10 天前，结合域名注册仅 188 天，增加了网站的不稳定性风险。
- 证据：`Jun 14 18:54:41 2026 GMT; 域名创建时间 2025-12-18`
- 建议：建议结合其他证据综合判断，警惕短期证书用于欺诈。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合四位专家的分析，该网页被判定为高风险。核心风险在于域名 `ninewest-singapore.com` 与页面实际内容严重不符：域名暗示知名时尚品牌 综合 1 条证据，当前风险等级为 medium。

### 静态分析员（模型：`deepseek-reasoner`）
静态分析显示网站标题与真实品牌不符，且存在大量第三方脚本加载，但未发现明显的恶意代码或钓鱼特征。

### 行为分析员（模型：`gemini-2.5-pro`）
行为分析证实该网站存在恶意行为。网站域名`ninewest-singapore.com`明显仿冒时尚品牌

### 情报分析员（模型：`gpt-4o-mini`）
该域名并未明确模仿任何特定的品牌或组织，存在风险。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站存在显著的品牌仿冒和欺骗行为。域名`ninewest-singapore.com`意图模仿知名时尚品牌


### 主持人最终总结
综合四位专家的分析，该网页被判定为高风险。核心风险在于域名 `ninewest-singapore.com` 与页面实际内容严重不符：域名暗示知名时尚品牌


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
