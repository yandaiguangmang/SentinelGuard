# SentinelGuard 哨塔检测报告

> 模型深度研判报告 · 风险等级：**MEDIUM** · 风险分数：**45/100**

## 一、检测结论
- 原始输入：`https://www.google.com`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：13 条
- 高危证据：0 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260617_222349_770279.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260617_222349_770279.md

## 二、统一 IR 摘要
- 规范化 URL：`https://www.google.com/`
- 协议：`https`
- 主机：`www.google.com`
- 路径：`/`
- 查询参数数量：`0`

## 三、跳转链
- https://www.google.com/
- https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1781706256411467&usg=AOvVaw3KKcwpm-_5ctvGea0PYQW9

## 四、页面线索
- status_code：302
- content_type：text/html; charset=UTF-8
- final_url：https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1781706256411467&usg=AOvVaw3KKcwpm-_5ctvGea0PYQW9
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://10.250.167.176:7890', 'https': 'http://10.250.167.176:7890', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- redirect_location：https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1781706256411467&usg=AOvVaw3KKcwpm-_5ctvGea0PYQW9
- redirect_final_url：https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1781706256411467&usg=AOvVaw3KKcwpm-_5ctvGea0PYQW9
- title：302 Moved
- visible_text_excerpt：302 Moved 302 Moved The document has moved here .
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8"> <TITLE>302 Moved</TITLE></HEAD><BODY> <H1>302 Moved</H1> The document has moved <A HREF="https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1781706256411467&usg=AOvVaw3KKcwpm-_5ctvGea0PYQW9">here</A>. </BODY></HTML> ', 'text_excerpt': '302 Moved 302 Moved The document has moved here .'}

## 四点一、浏览器证据 / 截图
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、风险证据
### 1. 跨域跳转
- 规则：`REDIRECT_CROSS_DOMAIN`
- 严重级别：`medium`
- 说明：目标链接跳转到不同域名，存在被中转到钓鱼页或下载页的风险。
- 证据：`www.google.com -> www.google.com.hk`
- 建议：以最终域名为准判断可信度。

### 2. 检测到跨域跳转
- 规则：`DEEP_STATIC_REDIRECT_CROSS_DOMAIN`
- 严重级别：`medium`
- 说明：目标链接从 `www.google.com` 发生了HTTP 302跳转到 `www.google.com.hk`。尽管目标域名属于同一大型服务商，但跨域跳转机制可能被恶意利用进行钓鱼或重定向攻击。
- 证据：`初始域名: www.google.com, 跳转目标域名: www.google.com.hk`
- 建议：确认跳转链中所有域名的合法性与安全性，尤其关注最终落地页的真实性和内容。

### 3. URL中包含重定向参数
- 规则：`DEEP_STATIC_URL_REDIRECT_PARAMETER`
- 严重级别：`low`
- 说明：最终跳转URL `https://www.google.com.hk/url?...` 的查询参数中包含了 `q=https://www.google.com.hk/`，此参数指示了重定向的最终目标。这种参数化重定向是常见机制，但需警惕其是否指向非预期或恶意站点。
- 证据：`URL参数 'q' = 'https://www.google.com.hk/'`
- 建议：验证重定向参数指向的URL是否安全可靠，避免被诱导至恶意网站。

### 4. 服务器端自动跳转
- 规则：`DEEP_BEHAVIOR_AUTO_REDIRECT`
- 严重级别：`low`
- 说明：页面通过 HTTP 302 状态码触发了一次服务器端自动跳转。这种行为常见于网站的区域重定向、登录验证或短链接服务，但在恶意场景中也可能用于隐藏最终的钓鱼或恶意软件页面。
- 证据：`跳转链: https://www.google.com/ -> https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1781706256411467&usg=AOvVaw3KKcwpm-_5ctvGea0PYQW9`
- 建议：研判时应重点关注跳转链的最终落地页。对于此类知名服务的区域性跳转，通常可视为良性行为。

### 5. 区域化/合规跳转（同组织域）
- 规则：`DEEP_INTEL_ENV_GEOREDIR`
- 严重级别：`low`
- 说明：google.com 根据语言/区域策略跳转至 google.com.hk，并携带 hkredirect、hl 参数，属平台常见本地化分流而非恶意中转。
- 证据：`redirect_chain: https://www.google.com/ -> https://www.google.com.hk/url?...&pref=hkredirect&hl=zh-CN; status_code=302; title=302 Moved`
- 建议：以最终域名的主体归属与证书信誉为准进行判断；对同组织域（google.*）的区域化跳转降权处置，避免将其与恶意跨域中转混淆。

### 6. 代理/外网环境对观测结果的影响
- 规则：`DEEP_INTEL_PROXY_INFLUENCE`
- 严重级别：`medium`
- 说明：此次抓取通过代理完成，出口地可能触发不同的本地化与合规策略，直接决定跳转目标与页面形态。
- 证据：`fetch_mode=proxy; proxy_used=true; proxy_config=http(s)://10.250.167.176:7890; 最终 URL 位于 google.com.hk`
- 建议：在多种出口（受限内网、海外/VPN、不同地区）复核；记录与锁定与受害者一致的网络条件（DNS、SNI、Accept-Language、Geo-IP）。对受限环境须警惕运营商/网关注入与 DNS 污染。

### 7. Google /url 路由与跟踪参数的正确解读
- 规则：`DEEP_INTEL_GOOGLE_URL_ENDPOINT`
- 严重级别：`low`
- 说明：/url 端点用于跳出/跟踪，常见参数 q、usg、ust 等；若 q 指向第三方才可能产生外链跳转风险。本例 q 指向 https://www.google.com.hk/（同组织域）。
- 证据：`final_url: https://www.google.com.hk/url?...q=https://www.google.com.hk/&ust=...&usg=...; 组织内跳转`
- 建议：研判时解析 q 参数并校验域名归属；仅当 q 指向不受信第三方且伴随诱导行为时提高警惕。

### 8. 无活跃内容迹象（仅 302）
- 规则：`DEEP_INTEL_NO_ACTIVE_CONTENT`
- 严重级别：`low`
- 说明：当前仅返回 302 Moved，页面无脚本、无表单、无下载链接，未见主动交付负载或数据采集面。
- 证据：`status_code=302; external_script_count=0; password_forms=0; download_links=0; visible_text=“302 Moved … The document has moved here.”`
- 建议：执行交互式复核（跟随 302 至最终页面），再评估实际内容、脚本与第三方请求；在隔离环境中进行，不提交敏感信息。

### 9. 离线证据与浏览器证据包的边界说明
- 规则：`DEEP_INTEL_EVIDENCE_BOUNDARY`
- 严重级别：`low`
- 说明：离线规则侧重 URL/头部/跳转链特征，可能对“跨域”产生保守告警；本次浏览器证据包未渲染最终页，缺失证书、脚本执行、跨域请求、Cookie/存储与页面交互链路信息。
- 证据：`static_report 与 browser_evidence 均停留在首跳 302；无后续资源加载与渲染数据。`
- 建议：将离线结果作为初筛信号；补采完整 HAR/证书链/网络面板与截图，区分因地域/合规模块导致的正常分流与异常重定向，再做最终裁决。

### 10. 跨域跳转处置建议
- 规则：`DEEP_ADVICE_REDIRECT_DISPOSITION`
- 严重级别：`medium`
- 说明：页面发生跨域跳转，尽管当前跳转目标为知名域名，但此类行为可能被恶意利用进行钓鱼或传播恶意软件。当前页面仅为跳转页，未发现直接恶意行为或交互式元素。
- 证据：`原始URL: `https://www.google.com/`，最终跳转URL: `https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1781706256411467&usg=AOvVaw3KKcwpm-_5ctvGea0PYQW9`，页面标题: '302 Moved'，可见文本: '302 Moved The document has moved here .'`
- 建议：是否拦截: 否。当前跳转目标为知名域名，未发现直接恶意内容。是否隔离: 是。建议在隔离环境中访问最终跳转页面，以防范潜在的未知风险。是否沙箱复核: 是。建议对最终跳转页面进行沙箱复核，以确保其安全性，特别是当目标域名不熟悉时。是否留痕: 是。记录此跨域跳转行为，以便后续审计和风险分析。

### 11. 仅观察到 302 跳转页
- 规则：`BROWSER_302_ONLY`
- 严重级别：`low`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`status_code=302; title=302 Moved; visible_text=302 Moved 302 Moved The document has moved here .`
- 建议：结合静态报告进一步复核。

### 12. Google 体系内区域化重定向
- 规则：`GOOGLE_HK_REGIONAL_REDIRECT`
- 严重级别：`low`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`redirect_chain: https://www.google.com/ -> https://www.google.com.hk/url?...&pref=hkredirect&hl=zh-CN`
- 建议：结合静态报告进一步复核。

### 13. 证据边界限制
- 规则：`EVIDENCE_BOUNDARY_LIMITATION`
- 严重级别：`low`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`未渲染最终页；无证书、HAR、后续资源加载与交互数据`
- 建议：结合静态报告进一步复核。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包及四位专家意见综合裁决：该目标并未呈现典型恶意网页特征，更像是 Google 体系内的区域化/本地化重定向。证据显示从 https://www.google.com/ 发生 HTTP 302 跳转至 https://www.google.com.hk/url?...，且最终 URL 的 q 参数仍指向 google.com.hk 同组织域；页面仅返回“302 Moved”，未见脚本、表单、下载链接、隐藏输入或其他主动交付负载迹象。当前告警主要来自“跨域跳转”这一保守规则，在缺少最终落地页渲染、证书链、后续资源请求与交互行为证据的情况下，不能据此认定为钓鱼或恶意中转。需要明确的是，本次研判仅基于离线证据与代理抓取到的首个 302，外部情报、真实终端环境与完整浏览器交互链路不足，因此结论应视为低风险初筛结果，而非对最终页面的完整安全背书。 综合 1 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
初始 URL 发生 302 跨域跳转至 google.com.hk，但目标仍属 Google 生态；页面为标准 302 提示，无可疑脚本、表单或下载链接，属于需要关注但不构成明显恶意的重定向行为。

### 行为分析员（模型：`gemini-2.5-pro`）
页面行为核心是服务器端 HTTP 302 自动跳转，跳转链符合 Google 区域性重定向策略，未见恶意脚本、表单提交或下载触发，行为风险较低。

### 情报分析员（模型：`gpt-5`）
当前证据更符合 Google 的区域化/合规分流；受代理与出口环境影响较大。离线证据未渲染最终页，缺少证书、脚本执行、第三方请求等信息，应在与受害者一致的网络条件下复核。

### 处置建议员（模型：`gemini-2.5-flash`）
目标页虽为知名域名且未见直接恶意内容，但跨域跳转本身可能被滥用；建议不拦截、但在隔离环境中复核最终页面并留痕审计。


### 主持人最终总结
基于静态检测结果、浏览器证据包及四位专家意见综合裁决：该目标并未呈现典型恶意网页特征，更像是 Google 体系内的区域化/本地化重定向。证据显示从 https://www.google.com/ 发生 HTTP 302 跳转至 https://www.google.com.hk/url?...，且最终 URL 的 q 参数仍指向 google.com.hk 同组织域；页面仅返回“302 Moved”，未见脚本、表单、下载链接、隐藏输入或其他主动交付负载迹象。当前告警主要来自“跨域跳转”这一保守规则，在缺少最终落地页渲染、证书链、后续资源请求与交互行为证据的情况下，不能据此认定为钓鱼或恶意中转。需要明确的是，本次研判仅基于离线证据与代理抓取到的首个 302，外部情报、真实终端环境与完整浏览器交互链路不足，因此结论应视为低风险初筛结果，而非对最终页面的完整安全背书。


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
