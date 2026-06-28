# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**85/100**
> 评分口径：URL 深度研判分数已综合证据分数，最终风险分数直接采用深度研判分数。
模型深度研判

## 一、检测结论
- 原始输入：`https://ninewest-singapore.com/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：5 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260625_184235_868361.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260625_184235_868361.md

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
- 时间：`2026-06-25T10:42:34.374999+00:00`
- 大小：`284123` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 10 天前。
- 证据：`Jun 14 18:54:41 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 域名注册信息
- 规则：`INTEL_INFRA_DOMAIN_REGISTRATION`
- 严重级别：`medium`
- 说明：域名由DEVEXPANSE LTD d/b/a Regery.com注册，注册时间为188天。
- 证据：`域名注册商为DEVEXPANSE LTD，存在天数为188天。`
- 建议：建议持续监控该域名的活动，特别是观察后续的内容变化和潜在的品牌仿冒情况。

### 3. TLS证书信息
- 规则：`INTEL_INFRA_CERTIFICATE`
- 严重级别：`medium`
- 说明：当前TLS证书的签发时间较短，可能表明该网站近期建立。
- 证据：`证书签发于2026年6月14日，目前距离签发只有10天。`
- 建议：建议结合其他证据综合判断网站的安全性，并监控该证书后续的健康状态。

### 4. 域名与内容严重不符，涉嫌品牌仿冒和内容欺诈
- 规则：`DEEP_BEHAVIOR_DECEPTIVE_CONTENT`
- 严重级别：`high`
- 说明：网站域名 ninewest-singapore.com 暗示其为时尚品牌“玖熙”的新加坡站点，但实际页面内容却是关于阿塞拜疆语的在线赌博网站“Mostbet”。这种域名与内容严重不匹配的行为是典型的欺诈手段，旨在利用仿冒域名来吸引流量或进行钓鱼、推广等恶意活动。
- 证据：`浏览器最终加载的页面标题为“Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc”，语言为阿塞拜疆语（az），内容为在线赌博，而访问的域名为 ninewest-singapore.com。`
- 建议：建议立即封禁该域名。用户不应与该网站进行任何交互或提供任何信息。

### 5. 域名与页目标品牌深度对比结论：品牌严重失配
- 规则：`DEEP_STATIC_BRAND_MISMATCH`
- 严重级别：`medium`
- 说明：域名"ninewest-singapore.com"结构中不包含真正品牌名称"Nine West"；但页面标题显示为 Azerbaijani语言的赌博品牌"Mostbet" ，域名前缀（"ninewest"）与页面标题中公共前缀（"mostbet"）之间出现多语言不一致（英文 vs Azeri）。页面CSS中大量出现赌博类主题色（类赌场主题变量值）及深色系优势色块定义，此类多语言品牌失配高度异常。
- 证据：`标题="Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc"；域名="ninewest-singapore.com"；页CSS变量代码多次出现匹配类赌场平台 --btn-back-color: #ff4c00; --btn-back-hover-bg-color: #ff963a; 赌场及赌博网页普遍使用橙色系按钮。`
- 建议：建议结合页面捕获完整域跳转进一步对页面最终观感校验。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合静态检测、浏览器证据及四位专家意见，目标网页存在极高的欺诈风险。核心证据在于域名与内容的严重不符：域名'ninewest-singapore.com'暗示为时尚品牌'Nine West'的新加坡站点，但实际页面内容为阿塞拜疆语的在线赌博平台'Mostbet'。这种品牌仿冒行为是典型的网络欺诈特征。尽管静态分析员和部分处置意见在判定标签上显示为'uncertain'，但行为分析员和情报分析员基于内容 mismatch 给出了明确的'malicious_lean'判定，且处置建议员明确建议'block'。考虑到域名仿冒对用户的直接误导性和潜在的资金/信息风险，最终风险等级上调至'high'。此外，TLS 证书签发时间极短（10 天）及域名注册时长较短（188 天）进一步佐证了其可疑性。 综合静态检测、浏览器证据及四位专家意见，目标网页存在极高的欺诈风险。核心证据在于域名与内容的严重不符：域名'ninewest-singapore.com'暗示为时尚品牌'Nine West'的新加坡站点，但实际页面内容为阿塞拜疆语的在线赌博平台'Mostbet'。这种品牌仿冒行为是典型的网络欺诈特征。尽管静态分析员和部分处置意见在判定标签上显示为'uncertain'，但行为分析员和情报分析员基于内容 mismatch 给出了明确的'malicious_lean'判定，且处置建议员明确建议'block'。考虑到域名仿冒对用户的直接误导性和潜在的资金/信息风险，最终风险等级上调至'high'。此外，TLS 证书签发时间极短（10 天）及域名注册时长较短（188 天）进一步佐证了其可疑性。

### 静态分析员（模型：`deepseek-reasoner`）
从静态结构分析，目标网页存在明显的品牌误导嫌疑，其HTML结构与内容表现出赌博平台的典型特征。域名不包含目标品牌关键词，页标题、CSS变量颜色值等证据表明页面伪装真实度较低。目前证据无法支持恶意网页结论后版本总结恶意行为存在，但页面服务的与用户交互表单行为存在及动态跳转意图不明确。依照当前静态证据做出**uncertain**结论。

### 行为分析员（模型：`gemini-2.5-pro`）
该网站存在严重的欺骗性。其域名（ninewest-singapore.com）暗示与时尚品牌“玖熙”（Nine West）的新加坡业务相关，但实际加载的页面内容却是针对阿塞拜疆用户的在线赌博网站（Mostbet）。这种域名与内容完全不符的情况是典型的品牌仿冒和欺诈行为，旨在利用误导性域名吸引用户访问高风险的赌博内容。尽管在本次分析中未观察到自动跳转或恶意下载等行为，但其欺骗性的本质和所推广内容的性质使其具有高度风险。

### 情报分析员（模型：`gpt-4o-mini`）
该页面似乎没有明确仿冒任何特定品牌或组织，因为它的内容标题与常见的在线赌博和博彩主题相关，而没有直接与某一品牌关联。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站存在严重的欺骗性。其域名 `ninewest-singapore.com` 强烈暗示与时尚品牌“玖熙”（Nine West）的新加坡业务相关，但实际加载的页面内容却是针对阿塞拜疆用户的在线赌博网站“Mostbet”。这种域名与内容完全不符的情况是典型的品牌仿冒和欺诈行为，旨在利用误导性域名吸引用户访问高风险的赌博内容。尽管未观察到自动跳转或恶意下载等行为，但其欺骗性的本质和所推广内容的性质使其具有高度风险。此外，TLS证书签发时间较短（10天前）以及域名注册时间相对较新（188天）也增加了其可疑性。


### 主持人最终总结
综合静态检测、浏览器证据及四位专家意见，目标网页存在极高的欺诈风险。核心证据在于域名与内容的严重不符：域名'ninewest-singapore.com'暗示为时尚品牌'Nine West'的新加坡站点，但实际页面内容为阿塞拜疆语的在线赌博平台'Mostbet'。这种品牌仿冒行为是典型的网络欺诈特征。尽管静态分析员和部分处置意见在判定标签上显示为'uncertain'，但行为分析员和情报分析员基于内容 mismatch 给出了明确的'malicious_lean'判定，且处置建议员明确建议'block'。考虑到域名仿冒对用户的直接误导性和潜在的资金/信息风险，最终风险等级上调至'high'。此外，TLS 证书签发时间极短（10 天）及域名注册时长较短（188 天）进一步佐证了其可疑性。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
