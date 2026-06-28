# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**HIGH** · 风险分数：**78/100**
> 证据分数：**76/100** · 深度研判分数：**80 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://ninewest-singapore.com/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：5 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260625_145641_288926.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260625_145641_288926.md

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
- 时间：`2026-06-25T06:56:29.648081+00:00`
- 大小：`284691` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 10 天前。
- 证据：`Jun 14 18:54:41 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 域名注册信息分析
- 规则：`INTEL_INFRA_01`
- 严重级别：`medium`
- 说明：此域名由DEVEXPANSE LTD d/b/a Regery.com注册，其存在天数为188天，显示出相对年轻，这可能表明该域名用于特定目的而非长期拥有。
- 证据：`注册商为DEVEXPANSE LTD d/b/a Regery.com，域名存在188天，创建时间为2025-12-18。`
- 建议：建议密切监控该域名的使用情况，并查看其后续活动以判断是否存在恶意目的。

### 3. 域名与内容严重不符，涉嫌品牌仿冒和赌博引流
- 规则：`DEEP_BEHAVIOR_CONTENT_MISMATCH`
- 严重级别：`high`
- 说明：域名“ninewest-singapore.com”暗示其为时尚品牌“玖熙(Nine West)”的新加坡站点，但页面实际内容为阿塞拜疆语的“Mostbet”在线赌博网站。这种域名与内容完全不匹配的行为是典型的诱骗手段，旨在利用知名品牌或特定关键词的搜索流量，将用户引导至赌博等高风险内容。
- 证据：`浏览器截图和页面标题（“Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc”）均表明该页面是一个赌博网站，而其域名ninewest-singapore.com与内容完全无关。`
- 建议：建议立即阻止访问。此类网站通常用于黑帽SEO、非法赌博引流，并可能作为传播恶意软件或进行网络钓鱼的跳板。

### 4. CSS变量中隐藏博彩相关主题颜色
- 规则：`DEEP_STATIC_GAMING_CSS_VARS`
- 严重级别：`medium`
- 说明：可见文本提取的CSS代码块包含明确定义博彩网站主题的颜色变量（如--main-accent-color: #ff4c00为高亮橙色），和Nine West品牌主色调（深蓝/黑色系）无关联，属于低质量伪装的核心缺陷。
- 证据：`:root { --h_background_color: #0e4482; --main-accent-color: #ff4c00; --site_info_b_color: #e6b900 }`
- 建议：对CSS主题变量与品牌色进行模式匹配以提高伪装检测能力。

### 5. 可疑第三方脚本加载
- 规则：`DEEP_STATIC_TRACKING_SCRIPTS`
- 严重级别：`medium`
- 说明：使用云分析工具（umami.is）符合攻击者跟踪需求；加载CloudFlare Insights脚本却未在域前缀使用典型CloudFlare加速名称（如"cdn"），这类技术栈组合多见于伪装站点。
- 证据：`script_srcs=["https://cloud.umami.is/script.js", "https://static.cloudflareinsights.com/beacon.min.js/v833ccba57c9e4d2798f2e76cebdd09a11778172276447"]`
- 建议：建议在安全沙箱中复核这两个脚本的跟踪行为权重。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
综合分析表明，该网页存在高度的恶意欺骗风险。核心证据在于域名与内容的严重不符：域名'ninewest-singapore.com'暗示为时尚品牌 Nine West 的新加坡官网，但页面标题及实际内容均为阿塞拜疆语的'Mostbet'在线赌博平台。静态分析员、行为分析员及处置建议员均指出这是典型的品牌仿冒与非法引流行为。尽管情报分析员认为未识别出特定假冒目标且风险评级为中（medium），但多数专家（3/4）基于明确的域名/内容冲突判定为恶意（high/critical）。鉴于域名注册时间较短（188 天）且 TLS 证书签发时间极短（10 天），结合明显的'挂羊头卖狗肉'特征，最终判定风险等级为高（high），建议阻断访问。 综合分析表明，该网页存在高度的恶意欺骗风险。核心证据在于域名与内容的严重不符：域名'ninewest-singapore.com'暗示为时尚品牌 Nine West 的新加坡官网，但页面标题及实际内容均为阿塞拜疆语的'Mostbet'在线赌博平台。静态分析员、行为分析员及处置建议员均指出这是典型的品牌仿冒与非法引流行为。尽管情报分析员认为未识别出特定假冒目标且风险评级为中（medium），但多数专家（3/4）基于明确的域名/内容冲突判定为恶意（high/critical）。鉴于域名注册时间较短（188 天）且 TLS 证书签发时间极短（10 天），结合明显的'挂羊头卖狗肉'特征，最终判定风险等级为高（high），建议阻断访问。

### 静态分析员（模型：`deepseek-reasoner`）
静态证据分析表明，该网站存在恶意倾向。网站标题提到"Mostbet"并在开头使用金钱符号（⚡），但实际内容伪装为购物网站（Nine West是一家女装品牌）。从域名结构观察，其使用的二级域名具有强烈的品牌误导性（品牌名+地理名），且HTML语言设置为阿塞拜疆语（az），不符合新加坡商业网站的特征。网站加载时使用云分析工具（cloud.umami.is）并加载CloudFlare脚本，这是仿冒网站的常见手段；同时可见文本中的CSS规则文件过大，包含赌博主题颜色代码（如#002e63和#ff4c00）而与零售主题无关，属于典型的伪装核心缺陷。

### 行为分析员（模型：`gemini-2.5-pro`）
行为分析显示，该网站存在严重的欺骗性。尽管没有发生恶意跳转或自动下载等直接的攻击行为，但其核心行为模式是利用与内容完全不符的域名进行引流。域名“ninewest-singapore.com”暗示这是一个时尚品牌“Nine West”的新加坡官方网站，而页面实际内容却是阿塞拜疆语的“Mostbet”在线赌博平台。这种“挂羊头卖狗肉”的行为是典型的恶意引流和品牌仿冒，旨在欺骗用户访问高风险的赌博网站。因此，该网站存在高度的恶意意图。

### 情报分析员（模型：`gpt-4o-mini`）
该网页展示了与品牌相关的内容，但并未明确仿冒某一具体的可识别品牌或组织，因此没有识别出特定的假冒目标。网页的标题显示为"Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc"，与 "ninewest-singapore.com" 之间没有直接关联。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站存在严重的品牌仿冒和内容欺诈行为。其域名“ninewest-singapore.com”意图冒充知名时尚品牌Nine West在新加坡的官方网站，但实际页面内容、标题（“Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc”）以及HTML语言设置（阿塞拜疆语）均明确指出这是一个在线赌博平台“Mostbet”。这种域名与内容严重不符的“挂羊头卖狗肉”行为是典型的恶意引流，旨在欺骗用户访问高风险的赌博内容。此外，TLS证书签发时间短（10天前）和域名注册时间较短（188天）等静态特征，以及CSS样式中包含博彩主题颜色，进一步证实了其可疑性质。


### 主持人最终总结
综合分析表明，该网页存在高度的恶意欺骗风险。核心证据在于域名与内容的严重不符：域名'ninewest-singapore.com'暗示为时尚品牌 Nine West 的新加坡官网，但页面标题及实际内容均为阿塞拜疆语的'Mostbet'在线赌博平台。静态分析员、行为分析员及处置建议员均指出这是典型的品牌仿冒与非法引流行为。尽管情报分析员认为未识别出特定假冒目标且风险评级为中（medium），但多数专家（3/4）基于明确的域名/内容冲突判定为恶意（high/critical）。鉴于域名注册时间较短（188 天）且 TLS 证书签发时间极短（10 天），结合明显的'挂羊头卖狗肉'特征，最终判定风险等级为高（high），建议阻断访问。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
