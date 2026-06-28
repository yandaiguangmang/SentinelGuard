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
  - HTML：sentinel_reports/sentinel_report_url_static_20260625_214726_650766.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260625_214726_650766.md

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
- 时间：`2026-06-25T13:47:15.787736+00:00`
- 大小：`284168` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 10 天前。
- 证据：`Jun 14 18:54:41 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 注册商信息
- 规则：`INTEL_INFRA_REGISTRAR`
- 严重级别：`high`
- 说明：域名注册商为DEVEXPANSE LTD d/b/a Regery.com，该注册商通常用于承载可疑或匿名服务，其信誉不佳。
- 证据：`注册商为DEVEXPANSE LTD d/b/a Regery.com。`
- 建议：建议进一步调查该注册商以了解其信誉，并在必要时进行风险评估。

### 3. 域名创建时间
- 规则：`INTEL_INFRA_CREATION_DATE`
- 严重级别：`medium`
- 说明：该域名于188天前注册（即在2025年12月18日），显然是相对年轻的域名，这使得可信性降低。
- 证据：`域名创建时间为2025-12-18，存在天数为188天。`
- 建议：由于为新注册域名，需谨慎对待其信息来源和合法性。

### 4. TLS证书问题
- 规则：`INTEL_INFRA_CERTIFICATE`
- 严重级别：`medium`
- 说明：TLS证书为最近10天内签发，表明该网站可能缺乏长期稳定的安全性。
- 证据：`证书签发于2026年6月14日，签发时间较短。`
- 建议：建议结合其他安全措施审慎访问该网站。

### 5. 网站内容与域名严重不符，涉嫌品牌仿冒与欺诈
- 规则：`DEEP_BEHAVIOR_CONTENT_MISMATCH`
- 严重级别：`high`
- 说明：域名（ninewest-singapore.com）暗示为时尚品牌'Nine West'的新加坡站点，但页面实际内容为面向阿塞拜疆语用户的'Mostbet'在线赌博平台。这种挂羊头卖狗肉的行为是欺诈、网络钓鱼或黑帽SEO的常见策略。
- 证据：`域名: ninewest-singapore.com, 页面标题: 'Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc', 页面语言: 阿塞拜疆语 (az)。`
- 建议：立即阻止访问。此类网站旨在欺骗用户，可能导致用户财务损失或个人信息泄露。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
目标网站 `ninewest-singapore.com` 表现出强烈的欺诈和品牌仿冒特征。域名暗示与新加坡时尚品牌"Nine West"有关，但实际页面内容为阿塞拜疆语的在线赌博平台"Mostbet"。三位分析专家（情报、行为、静态）一致判定为 `malicious_lean` 且风险等级为 `high`，主要依据是域名与内容严重不符、包含赌博敏感关键词以及基础设施可疑（新签发证书、特定注册商）。处置建议员虽然 claim 为 `uncertain`，但风险提示为 `critical` 并建议拦截。初始静态报告评级为 `medium`，但基于专家深度分析的证据链（品牌仿冒 + 赌博），最终结论提升至 `high`。 目标网站 `ninewest-singapore.com` 表现出强烈的欺诈和品牌仿冒特征。域名暗示与新加坡时尚品牌"Nine West"有关，但实际页面内容为阿塞拜疆语的在线赌博平台"Mostbet"。三位分析专家（情报、行为、静态）一致判定为 `malicious_lean` 且风险等级为 `high`，主要依据是域名与内容严重不符、包含赌博敏感关键词以及基础设施可疑（新签发证书、特定注册商）。处置建议员虽然 claim 为 `uncertain`，但风险提示为 `critical` 并建议拦截。初始静态报告评级为 `medium`，但基于专家深度分析的证据链（品牌仿冒 + 赌博），最终结论提升至 `high`。

### 静态分析员（模型：`deepseek-reasoner`）
静态分析显示，页面的域名与标题存在强烈差异。域名 "ninewest-singapore.com" 暗示其为新加坡品牌网站，但实际标题 "Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc" 却指向阿塞拜疆语的线上赌场，属于高风险敏感主题。虽然未检测到明显恶意脚本或表单，但结合主题违规和域名误导特征，整体倾向于恶意。

### 行为分析员（模型：`gemini-2.5-pro`）
该网站存在明显的伪装和欺骗行为。域名`ninewest-singapore.com`暗示其与时尚品牌"Nine West"在新加坡的业务有关，但实际页面内容却是面向阿塞拜疆用户的"Mostbet"在线赌博网站。这种域名与内容严重不符的情况是典型的恶意行为，通常用于品牌仿冒、搜索引擎优化（SEO）欺诈或引诱用户参与不受管制的赌博活动，具有很高的风险。虽然在本次分析中未观察到自动重定向或恶意下载等直接的攻击行为，但其欺骗性的本质和赌博内容本身就构成了重大风险。

### 情报分析员（模型：`gpt-4o-mini`）
对九号西新加坡网站的情报归因与边界分析。该网址并未明显模仿特定的品牌或组织，而是显示为与Mostbet相关的在线赌博信息，显示的标题为"Mostbet AZ ⚡ 2026 Mostbet Onlayn Kazino və Mərc"。

### 处置建议员（模型：`gemini-2.5-flash`）
综合证据显示，该网站存在严重的品牌冒用和内容欺诈行为。域名`ninewest-singapore.com`伪装成“Nine West新加坡”时尚品牌官网，但实际内容和页面标题却明确指向阿塞拜疆语的“Mostbet”在线赌博平台。这种域名与内容严重不符的“挂羊头卖狗肉”行为是典型的欺诈手段，可能用于钓鱼、推广非法赌博或进行恶意搜索引擎优化。此外，该域名注册时间较短（188天），TLS证书也是近期签发（10天前），且注册商DEVEXPANSE LTD d/b/a Regery.com通常用于承载可疑或匿名服务，其信誉不佳，这些都进一步增加了其可疑性。尽管未检测到自动跳转或恶意下载等直接的攻击行为，但其本质上的欺骗性和赌博内容本身已构成高风险。


### 主持人最终总结
目标网站 `ninewest-singapore.com` 表现出强烈的欺诈和品牌仿冒特征。域名暗示与新加坡时尚品牌"Nine West"有关，但实际页面内容为阿塞拜疆语的在线赌博平台"Mostbet"。三位分析专家（情报、行为、静态）一致判定为 `malicious_lean` 且风险等级为 `high`，主要依据是域名与内容严重不符、包含赌博敏感关键词以及基础设施可疑（新签发证书、特定注册商）。处置建议员虽然 claim 为 `uncertain`，但风险提示为 `critical` 并建议拦截。初始静态报告评级为 `medium`，但基于专家深度分析的证据链（品牌仿冒 + 赌博），最终结论提升至 `high`。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
