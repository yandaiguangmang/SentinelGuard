# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**MEDIUM** · 风险分数：**28/100**


## 一、检测结论
- 原始输入：`https://baksmany.net/zh/lite/?confirm=1`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：1 条
- 高危证据：0 条

## 二、统一 IR 摘要
- 规范化 URL：`https://baksmany.net/zh/lite/?confirm=1`
- 协议：`https`
- 主机：`baksmany.net`
- 路径：`/zh/lite/`
- 查询参数数量：`1`

## 三、跳转链
- https://baksmany.net/zh/lite/?confirm=1

## 四、页面线索
- status_code：200
- content_type：text/html; charset=UTF-8
- final_url：https://baksmany.net/zh/lite/?confirm=1
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://127.0.0.1:7897', 'https': 'http://127.0.0.1:7897', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- title：数字货币兑换，买卖比特币
- visible_text_excerpt：数字货币兑换，买卖比特币 :root { --button-background: #074234; --hf-background: #0b4f3f; --body-dark-background: #12795e; } 朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码 → 选择私人支付服务！ x 网站菜单 交易所 合作伙伴 储备 联系方式 AML 反馈 规则 FAQ 网站地图 名誉 登录 注册 普通版 交易所 反馈 合作伙伴 储备 联系方式 登录 注册 ZH Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 数字货币兑换，买卖比特币 我想给货币 我想获得货币 Telegram Bot Copyright © 2026 baksmany.net 交易所 反馈 合作伙伴 储备 联系方式 规则 AML FAQ 网站地图 名誉 登录 注册 普通版
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：/wschat/v3/client/init.js?v=15, https://static.cloudflareinsights.com/beacon.min.js/v833ccba57c9e4d2798f2e76cebdd09a11778172276447
- form_actions：无
- download_links：无
- external_script_count：1
- html_summary：{'raw_excerpt': '<!DOCTYPE html> <html lang="zh"> <head> <meta charset="UTF-8"> <meta http-equiv="X-UA-Compatible" content="IE=edge"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <meta name="format-detection" content="telephone=no"> <title>数字货币兑换，买卖比特币</title> <meta name="description" content="买卖比特币以及进行比特币兑换，提供了Baksmany.net兑换服务。 该交换器具有大量的储备，并提供了高速度的应用程序执行。" /> <meta name="keywords" content="交换器，比特币交换，比特币到qiwi，数字货币交换器，电子货币交换器，购买比特币，出售比特币" /> <meta name="theme-color" content="#0b4f3f" /> <style> :root { --button-background: #074234; --hf-background: #0b4f3f; --body-dark-background: #12795e; } </style> <link rel="stylesheet" href="/res/lite/css/normalize.css?v=15" /> <link rel="stylesheet" href="/res/lite/css/magnific-popup.css?v=15" /> <link rel="stylesheet" href="/res/lite/css/lite-style.css?v=15" /> <link rel="stylesheet" href="/res/lite/css/media.css?v=15" /> </head> <body class="bg-dark"> <div data-position=\'top\' class=\'rashalert\' data-id=\'20\'><div style=\'color:#fff;background: #0a352b;padding: 10px;font-size: 12px;\'><div class=\'container text-center\'>朋友们，抓住这个不容错过的机会！<br>现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。<br>只需上传卢布QR码 → <a href="https://baksmany.net/tg/?domain=baksmany_wall', 'text_excerpt': '数字货币兑换，买卖比特币 :root { --button-background: #074234; --hf-background: #0b4f3f; --body-dark-background: #12795e; } 朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码 → 选择私人支付服务！ x 网站菜单 交易所 合作伙伴 储备 联系方式 AML 反馈 规则 FAQ 网站地图 名誉 登录 注册 普通版 交易所 反馈 合作伙伴 储备 联系方式 登录 注册 ZH Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 数字货币兑换，买卖比特币 我想给货币 我想获得货币 Telegram Bot Copyright © 2026 baksmany.net 交易所 反馈 合作伙伴 储备 联系方式 规则 AML FAQ 网站地图 名誉 登录 注册 普通版'}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、截图证据
- 未采集到截图证据。

## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 19 天前。
- 证据：`签发时间: Jun  2 05:52:23 2026 GMT`
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
