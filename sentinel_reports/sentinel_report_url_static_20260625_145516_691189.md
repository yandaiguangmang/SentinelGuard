# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**MEDIUM** · 风险分数：**28/100**
> 证据分数：**0/100** · 深度研判分数：**- /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`https://ninewest-singapore.com/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：1 条
- 高危证据：0 条

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
- 时间：`2026-06-25T06:55:13.533115+00:00`
- 大小：`284639` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 10 天前。
- 证据：`Jun 14 18:54:41 2026 GMT`
- 建议：建议结合其他证据综合判断。


## 七、论坛式协同研判
### 主持人（模型：`unknown`）
综合 1 条证据，当前风险等级为 medium。

### 静态分析员（模型：`unknown`）
URL 结构层面关注：TLS 证书签发时间较短。

### 行为分析员（模型：`unknown`）
页面行为与跳转层面关注暂未发现明显异常。

### 情报分析员（模型：`unknown`）
当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`unknown`）
建议在隔离浏览器中复核最终域名，不在页面提交敏感信息。


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
