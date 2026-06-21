# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**LOW** · 风险分数：**26/100**
> 证据分数：**35/100** · 深度研判分数：**17 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://www.google.com`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：21 条
- 高危证据：0 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260621_164226_307866.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260621_164226_307866.md

## 二、统一 IR 摘要
- 规范化 URL：`https://www.google.com/`
- 协议：`https`
- 主机：`www.google.com`
- 路径：`/`
- 查询参数数量：`0`

## 三、跳转链
- https://www.google.com/
- https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782031375068545&usg=AOvVaw3wCu2rnIaJJPPJXVN34S1w

## 四、页面线索
- status_code：302
- content_type：text/html; charset=UTF-8
- final_url：https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782031375068545&usg=AOvVaw3wCu2rnIaJJPPJXVN34S1w
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://10.250.167.176:7890', 'https': 'http://10.250.167.176:7890', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- redirect_location：https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782031375068545&usg=AOvVaw3wCu2rnIaJJPPJXVN34S1w
- redirect_final_url：https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782031375068545&usg=AOvVaw3wCu2rnIaJJPPJXVN34S1w
- title：302 Moved
- visible_text_excerpt：302 Moved 302 Moved The document has moved here .
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8"> <TITLE>302 Moved</TITLE></HEAD><BODY> <H1>302 Moved</H1> The document has moved <A HREF="https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782031375068545&usg=AOvVaw3wCu2rnIaJJPPJXVN34S1w">here</A>. </BODY></HTML> ', 'text_excerpt': '302 Moved 302 Moved The document has moved here .'}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 四点三、一致性验证
- 一致性分析结果：未获取到仲裁/一致性结果，但本次报告已显式展示缺失原因。
- 一致性分数：`-`
- 一致性等级：`-`
- 分歧点：未获取
- 被污染模块：未获取

## 五、截图证据
- 当前未采集到页面截图。

## 六、风险证据
### 1. 跨域跳转
- 规则：`REDIRECT_CROSS_DOMAIN`
- 严重级别：`medium`
- 说明：目标链接跳转到不同域名，存在被中转到钓鱼页或下载页的风险。
- 证据：`www.google.com -> www.google.com.hk`
- 建议：以最终域名为准判断可信度。

### 2. 正常的业务重定向
- 规则：`DEEP_BEHAVIOR_NORMAL_REDIRECT`
- 严重级别：`low`
- 说明：检测到的重定向链符合 Google 搜索引擎的区域化跳转特征，未发现异常的中间跳转节点或恶意参数注入。
- 证据：`重定向目标为 google.com.hk，且 URL 参数结构（sa=p, pref=hkredirect）符合 Google 内部跳转机制。`
- 建议：无需采取行动，判定为正常业务行为。

### 3. 常规重定向参数
- 规则：`DEEP_STATIC_URL_PARAMS`
- 严重级别：`low`
- 说明：跳转URL中包含明确的区域重定向标识参数（pref=hkredirect）及目标地址参数（q），参数键值对清晰，未见Base64等编码混淆或恶意注入载荷。
- 证据：`sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782031375068545&usg=AOvVaw3wCu2rnIaJJPPJXVN34S1w`
- 建议：属于正常的业务路由跳转参数，无需特殊处理。

### 4. HTML结构安全
- 规则：`DEEP_STATIC_HTML_SAFE`
- 严重级别：`low`
- 说明：页面HTML代码为极简的302跳转提示，不包含任何外部脚本引入（script标签）、表单提交（form标签）或自动下载行为，静态结构安全。
- 证据：`<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8"> <TITLE>302 Moved</TITLE></HEAD><BODY> <H1>302 Moved</H1> The document has moved <A HREF="...">here</A>. </BODY></HTML>`
- 建议：页面静态结构无风险，可正常放行。

### 5. 未发现对第三方品牌的仿冒，页面属于 Google 官方域名体系
- 规则：`INTEL_BRAND_NO_IMPERSONATION`
- 严重级别：`low`
- 说明：访问目标为 google.com，并发生到 google.com.hk 的区域化跳转，二者均为 Google 官方域名，未见仿冒他牌或钓鱼品牌要素。
- 证据：`域名链条：www.google.com → www.google.com.hk；均为 Google 品牌域名。`
- 建议：将该类链接按 Google 官方服务治理；在风控策略中以最终域名归属判断可信度。

### 6. 域名与注册信誉长期稳定
- 规则：`INTEL_INFRA_DOMAIN_REPUTATION`
- 严重级别：`low`
- 说明：google.com 为历史极久的核心域名，通常由 MarkMonitor 代管且注册主体为 Google LLC；google.com.hk 为 Google 在香港的官方域名，均具长期曝光与良好信誉。
- 证据：`公开 WHOIS/历史资料：google.com（注册年代久远，注册服务商常见为 MarkMonitor Inc.，注册组织为 Google LLC）；google.com.hk 为 Google 官方持有。`
- 建议：将 google.com / google.com.hk 置入高信誉清单，但仍以最终跳转落地页域名进行二次校验。

### 7. 证书与透明度生态符合预期
- 规则：`INTEL_INFRA_CERT_CHAIN`
- 严重级别：`low`
- 说明：Google 站点证书通常由 Google Trust Services（GTS）签发，广泛记录于 CT 日志，链路与配置符合大型互联网厂商实践。
- 证据：`公开资料：GTS 签发、CT 可查、多 SAN 配置为 Google 生态常见形态。`
- 建议：在证书监控中将 GTS 与 Google 相关 SAN 作为正常基线，关注异常颁发或不在 CT 的异常证书。

### 8. 托管与网络归属符合 Google 自有网络
- 规则：`INTEL_INFRA_ASN_HOSTING`
- 严重级别：`low`
- 说明：Google 相关域名通常在 AS15169（Google LLC）等自有自治系统与基础设施中提供服务。
- 证据：`公开 ASN 情报：AS15169 为 Google LLC 主体网络，承载大部分 Google 服务流量。`
- 建议：将 AS15169 识别为高信誉托管特征，但仍需对最终落地资源进行内容与行为校验。

### 9. 主流黑名单未见针对该主域的风险标注
- 规则：`INTEL_INFRA_BLACKLIST_STATUS`
- 严重级别：`low`
- 说明：google.com / google.com.hk 长期作为高信誉主域，通常不在主流恶意域名/钓鱼黑名单中被整体标注。
- 证据：`基于公开信誉与历次情报实践，并未见对上述主域的普遍封禁记录。`
- 建议：对高信誉主域保持放行策略，但需对通过其重定向指向的外部域名执行常规拦截/检测。

### 10. Google /url 重定向端点的常见滥用背景与本例评估
- 规则：`INTEL_INFRA_REDIRECTOR_PROFILE`
- 严重级别：`medium`
- 说明：Google 的 /url 端点历史上可能被用于“链接清洗/跳转中转”，但本例 q 参数指向 google.com.hk，同属官方域，未体现风险外联。
- 证据：`参数模式 sa、usg、ust、q 等为 Google 常见跟踪与重定向参数；q=https://www.google.com.hk/。`
- 建议：在网关/代理侧解析 Google 重定向参数，对最终 q 目标域名做白名单判断；如指向外部未知域名，计算风险分并触发人机校验或拦截。

### 11. 地理与语言偏好导致的呈现差异
- 规则：`INTEL_COVERAGE_GEO_VARIATION`
- 严重级别：`low`
- 说明：由于使用代理与区域偏好，google.com 返回 302 至 google.com.hk，hl=zh-CN、pref=hkredirect 等特征说明为区域化与语言定制行为。
- 证据：`最终链接包含 hl=zh-CN、pref=hkredirect、pval=yes 等参数；HTTP 302 响应为常见地域重定向。`
- 建议：在取证和监测中记录采集源 IP/地理位置；必要时分别在多地区出口复现，以排除由于地域差异导致的误报。

### 12. 离线抓取与浏览器呈现一致，但仍为 302 中间页
- 规则：`INTEL_COVERAGE_RENDER_GAP`
- 严重级别：`low`
- 说明：两套证据均显示为 302 中间页，未实际渲染最终落地内容；这对最终页面特征判断带来有限不确定性，但不影响对官方身份的判断。
- 证据：`标题与正文均为“302 Moved”，截图缺失且未加载最终页，仅获取到重定向页 HTML 片段。`
- 建议：如需更高置信度，可在相同地区网络条件下允许自动跟随 302 并完整加载落地页进行二次取证。

### 13. Google 官方区域重定向
- 规则：`DEEP_ADVICE_NORMAL_GOOGLE_REDIRECT`
- 严重级别：`low`
- 说明：页面从 www.google.com 跳转到 www.google.com.hk，参数结构与 Google 常见区域/语言跳转一致，整体符合正常服务行为。
- 证据：`redirect_chain 显示 www.google.com → www.google.com.hk；参数含 hl=zh-CN、pref=hkredirect、usg、ust。`
- 建议：默认可放行，但建议在网关侧继续记录此类重定向链，便于后续审计。

### 14. 最终落地页未完全展开
- 规则：`DEEP_ADVICE_FINAL_URL_UNDER_REVIEW`
- 严重级别：`low`
- 说明：当前仅抓取到 302 中间页，未实际加载最终落地内容，因此对最终页面展示只能做有限确认。
- 证据：`页面标题为 302 Moved，可见文本为 The document has moved here，截图数量为 0。`
- 建议：如业务场景要求更高确认度，可进行沙箱复核或在受控环境中跟随跳转检查最终页面。

### 15. 存在跨域跳转但不构成恶意证据
- 规则：`DEEP_ADVICE_CROSS_DOMAIN_REDIRECT_LOG`
- 严重级别：`low`
- 说明：检测到跨域跳转链路，但跳转目标仍属于 Google 官方域名，不体现常见钓鱼或下载器特征。
- 证据：`static_report 中标记 REDIRECT_CROSS_DOMAIN，目标为 www.google.com.hk。`
- 建议：建议保留跳转日志并对未来指向外部未知域名的同类链接加强监控。

### 16. 跨域跳转
- 规则：`REDIRECT_CROSS_DOMAIN`
- 严重级别：`medium`
- 说明：目标链接从 google.com 跳转到不同域名 google.com.hk，存在被中转的理论风险，应以最终域名为准判断可信度。
- 证据：`redirect_chain: https://www.google.com/ → https://www.google.com.hk/url?...`
- 建议：在策略上按最终域名归属进行信誉判断。

### 17. 正常的业务重定向
- 规则：`DEEP_BEHAVIOR_NORMAL_REDIRECT`
- 严重级别：`low`
- 说明：重定向特征与 Google 官方区域化跳转一致，无异常中间节点或恶意参数注入迹象。
- 证据：`参数 sa、pref=hkredirect、usg、ust、q 结构正常`
- 建议：视为正常业务行为。

### 18. HTML 结构安全
- 规则：`DEEP_STATIC_HTML_SAFE`
- 严重级别：`low`
- 说明：页面为标准 302 提示页，无外部脚本、表单或下载链接。
- 证据：`页面标题 302 Moved，HTML 片段简洁`
- 建议：静态结构无风险。

### 19. 未渲染最终落地页导致的不确定性
- 规则：`INTEL_COVERAGE_RENDER_GAP`
- 严重级别：`low`
- 说明：本次取证停留在 302 中间页，最终页面内容未知，带来有限不确定性。
- 证据：`screenshots_count=0，最终 URL 指向 /url 中间跳转`
- 建议：必要时允许自动跟随 302 并完整加载落地页复核。

### 20. 代理与地域偏好影响
- 规则：`INTEL_COVERAGE_GEO_VARIATION`
- 严重级别：`low`
- 说明：因代理/地域设置导致跳转至香港域 google.com.hk。
- 证据：`hl=zh-CN、pref=hkredirect、pval=yes`
- 建议：在多地区环境复现场景以减少误报。

### 21. Google /url 端点潜在被滥用情境（本例不适用）
- 规则：`INTEL_INFRA_REDIRECTOR_PROFILE`
- 严重级别：`medium`
- 说明：/url 历史上可能用于中转外部站点；本例 q 指向 google.com.hk，并无外联风险体现。
- 证据：`q=https://www.google.com.hk/`
- 建议：在网关侧解析 q 目标，若为外部未知域名则提高风险分并触发校验/拦截。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5`）
基于静态检测与浏览器取证的证据链，本次目标为 www.google.com，访问后发生到 www.google.com.hk 的 302 跨域重定向。静态报告给出风险等级为低、评分 17，唯一命中规则为跨域跳转（中等严重度），重定向链与浏览器证据一致：最终 URL 为 https://www.google.com.hk/url?...，页面仅呈现标准“302 Moved”提示，无脚本加载、无表单、无下载链接。重定向参数包含 sa、hl、pref=hkredirect、usg、ust、q 等，符合 Google 官方 /url 跳转端点的常见形态，推断为区域/语言偏好导致的正常业务跳转。四位分析角色中，静态、行为、情报均判断为良性倾向且低风险，处置建议员因未完全渲染落地页而建议监控，整体为轻微分歧但无方向性冲突。需要明确的是：当前未加载最终落地内容，亦未调用在线情报查询，结论主要依赖离线取证（静态与浏览器证据）及常识性信誉基线。综合判断：该链接属于 Google 官方域名体系内的正常区域化重定向，整体风险低。建议放行并保留日志，后续在网关侧持续解析 /url 的 q 目标域，若指向非 Google 外部域名再触发加强校验或拦截；如需更高置信度，可在相同地区网络条件下跟随跳转对最终落地页进行二次取证。 基于静态检测与浏览器取证的证据链，本次目标为 www.google.com，访问后发生到 www.google.com.hk 的 302 跨域重定向。静态报告给出风险等级为低、评分 17，唯一命中规则为跨域跳转（中等严重度），重定向链与浏览器证据一致：最终 URL 为 https://www.google.com.hk/url?...，页面仅呈现标准“302 Moved”提示，无脚本加载、无表单、无下载链接。重定向参数包含 sa、hl、pref=hkredirect、usg、ust、q 等，符合 Google 官方 /url 跳转端点的常见形态，推断为区域/语言偏好导致的正常业务跳转。四位分析角色中，静态、行为、情报均判断为良性倾向且低风险，处置建议员因未完全渲染落地页而建议监控，整体为轻微分歧但无方向性冲突。需要明确的是：当前未加载最终落地内容，亦未调用在线情报查询，结论主要依赖离线取证（静态与浏览器证据）及常识性信誉基线。综合判断：该链接属于 Google 官方域名体系内的正常区域化重定向，整体风险低。建议放行并保留日志，后续在网关侧持续解析 /url 的 q 目标域，若指向非 Google 外部域名再触发加强校验或拦截；如需更高置信度，可在相同地区网络条件下跟随跳转对最终落地页进行二次取证。

### 静态分析员（模型：`gemini-2.5-pro`）
静态分析未发现恶意特征。URL参数结构清晰，包含常规的区域重定向标识（如hkredirect），未见恶意混淆、注入载荷或可疑关键字。HTML内容为标准的302跳转页面，无恶意脚本、隐藏表单或可疑的下载链接。整体静态结构表现为良性。

### 行为分析员（模型：`gemini-2.5-flash`）
该行为链表现为标准的 Google 区域重定向逻辑。从 google.com 跳转至 google.com.hk 是基于地理位置或用户偏好的正常服务重定向，重定向参数中包含用于验证的 usg 等签名信息，未发现任何恶意脚本加载、自动下载或诱导性表单提交行为。该行为符合大型搜索引擎的正常业务逻辑。

### 情报分析员（模型：`gpt-5`）
综合外部情报与已知基础设施信息判断：该链接属于 Google 官方域名（google.com → google.com.hk 的区域化跳转），未发现对第三方品牌或机构的仿冒迹象。跳转目标仍在 Google 品牌体系内，/url 为 Google 搜索与重定向常用路径，参数 sa/usg/ust 等为常见的 Google 跟踪与校验参数形态，符合其正常业务特征。从公开信誉与基础设施侧看：google.com 长期由 Google/MarkMonitor 管理，证书通常由 Google Trust Services（GTS）签发，托管在 Google LLC 的 AS15169 等自有网络上，整体信誉高，未见广泛黑名单标注。需要注意的边界：本次采集使用代理并呈现到 google.com.hk 的 302 跳转，属于地理与语言偏好导致的呈现差异；离线抓取与浏览器呈现基本一致，但未渲染实际落地页内容（仅见 302 页），因此对于最终页面呈现仅能中高置信度推断为 Google 正常落地。综合来看，情报归因为“可信官方服务的区域化跳转”，总体风险低，但在策略层面仍应以最终域名为判断基准，防范少数场景中对 Google 重定向端点的滥用。

### 处置建议员（模型：`gpt-5.4-mini`）
综合页面行为、HTML结构和可见文本来看，该链接表现为 Google 官方域名体系内的正常区域化重定向，未见脚本、表单、下载、钓鱼引导或异常混淆特征。当前证据更符合合法业务跳转而非恶意页面，但由于存在跨域跳转与最终落地页未完整渲染，建议保留日志并在需要时做一次沙箱复核以确认最终跳转目标始终在 Google 官方域内。


### 主持人最终总结
基于静态检测与浏览器取证的证据链，本次目标为 www.google.com，访问后发生到 www.google.com.hk 的 302 跨域重定向。静态报告给出风险等级为低、评分 17，唯一命中规则为跨域跳转（中等严重度），重定向链与浏览器证据一致：最终 URL 为 https://www.google.com.hk/url?...，页面仅呈现标准“302 Moved”提示，无脚本加载、无表单、无下载链接。重定向参数包含 sa、hl、pref=hkredirect、usg、ust、q 等，符合 Google 官方 /url 跳转端点的常见形态，推断为区域/语言偏好导致的正常业务跳转。四位分析角色中，静态、行为、情报均判断为良性倾向且低风险，处置建议员因未完全渲染落地页而建议监控，整体为轻微分歧但无方向性冲突。需要明确的是：当前未加载最终落地内容，亦未调用在线情报查询，结论主要依赖离线取证（静态与浏览器证据）及常识性信誉基线。综合判断：该链接属于 Google 官方域名体系内的正常区域化重定向，整体风险低。建议放行并保留日志，后续在网关侧持续解析 /url 的 q 目标域，若指向非 Google 外部域名再触发加强校验或拦截；如需更高置信度，可在相同地区网络条件下跟随跳转对最终落地页进行二次取证。


### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
