# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**LOW** · 风险分数：**14/100**
> 证据分数：**22/100** · 深度研判分数：**6 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://www.google.com`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：4 条
- 高危证据：0 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260622_173436_582083.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260622_173436_582083.md

## 二、统一 IR 摘要
- 规范化 URL：`https://www.google.com/`
- 协议：`https`
- 主机：`www.google.com`
- 路径：`/`
- 查询参数数量：`0`

## 三、跳转链
- https://www.google.com/
- https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782120894981916&usg=AOvVaw3XoxVALNjSF1YV9kiW2JZo

## 四、页面线索
- status_code：302
- content_type：text/html; charset=UTF-8
- final_url：https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782120894981916&usg=AOvVaw3XoxVALNjSF1YV9kiW2JZo
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://10.250.167.176:7890', 'https': 'http://10.250.167.176:7890', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- redirect_location：https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782120894981916&usg=AOvVaw3XoxVALNjSF1YV9kiW2JZo
- redirect_final_url：https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782120894981916&usg=AOvVaw3XoxVALNjSF1YV9kiW2JZo
- title：302 Moved
- visible_text_excerpt：302 Moved 302 Moved The document has moved here .
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8"> <TITLE>302 Moved</TITLE></HEAD><BODY> <H1>302 Moved</H1> The document has moved <A HREF="https://www.google.com.hk/url?sa=p&hl=zh-CN&pref=hkredirect&pval=yes&q=https://www.google.com.hk/&ust=1782120894981916&usg=AOvVaw3XoxVALNjSF1YV9kiW2JZo">here</A>. </BODY></HTML> ', 'text_excerpt': '302 Moved 302 Moved The document has moved here .'}
- external_intel：{}

## 四点一、页面线索
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、截图证据
- 当前未采集到页面截图。

## 六、风险证据
### 1. 良性跨域重定向
- 规则：`REDIRECT_CROSS_DOMAIN`
- 严重级别：`medium`
- 说明：页面从 `www.google.com` 自动重定向到 `www.google.com.hk`。尽管是跨域重定向，但这属于谷歌服务内部常见的、用于区域定位或搜索跟踪的正常业务逻辑，不构成恶意风险。
- 证据：`重定向链：`https://www.google.com/` (初始请求) -> `https://www.google.com.hk/url?...` (最终URL，HTTP 302自动重定向)`
- 建议：此重定向属于正常业务逻辑，无需特别关注。

### 2. 离线模式无外部情报
- 规则：`INTEL_OFFLINE_MODE`
- 严重级别：`low`
- 说明：本次分析未接入 WHOIS、证书透明度等外部情报，域名归因和基础设施信誉评估缺失。
- 证据：`external_intel 字段为空`
- 建议：若需更精准研判，请开启网络连接并启用外部情报查询。

### 3. 良性的区域化重定向
- 规则：`DEEP_STATIC_BENIGN_REGIONAL_REDIRECT`
- 严重级别：`medium`
- 说明：页面从主域名（google.com）重定向至同一服务商的另一区域性域名（google.com.hk）。这是大型互联网服务为提供本地化体验而采取的常见且无害的做法，不构成安全风险。
- 证据：`重定向链: www.google.com -> www.google.com.hk`
- 建议：此类型重定向属于正常行为，无需担忧。

### 4. 页面无主动内容与可疑交互
- 规则：`NO_ACTIVE_CONTENT`
- 严重级别：`low`
- 说明：页面为标准 302 提示页，无脚本、无表单、无下载链接，降低了被动投递与钓鱼的风险可能性。
- 证据：`external_script_count=0；script_srcs=[]；password_forms=0；download_links=[]；form_actions=[]；visible_text=“302 Moved…”。`
- 建议：保持常规监控即可，无需额外隔离或阻断。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5`）
基于静态检测与浏览器取证一致显示：目标 https://www.google.com/ 返回标准 HTTP 302，跨域跳转至同一服务体系的区域化域名 https://www.google.com.hk/url?...。页面内容为“302 Moved”占位页，无脚本加载、无下载、无表单与隐藏字段，重定向链长度短（2段），未见可疑投递或利用特征。四位专家中，静态与行为分析员均以高置信度判定为良性倾向；情报与处置分析员在离线情报及审慎前提下给出“uncertain”但风险提示仍为低，未提出相反的恶意结论。综合来看，该跳转符合大型站点按地区分流/引导的常见业务逻辑，当前证据链不支持恶意结论，整体风险低。需要注意的是，本次评估未接入外部情报，建议在生产场景中补充域名信誉与证书透明度以进一步佐证，但这不改变本次“低风险”的总体判断。 综合 1 条证据，当前风险等级为 low。

### 静态分析员（模型：`gemini-2.5-pro`）
静态分析显示，目标URL为全球知名搜索引擎Google的主页。页面发生了从`google.com`到其香港区域域名`google.com.hk`的重定向。这种基于地理位置的区域化跳转是Google等大型跨国服务的标准操作，旨在为用户提供本地化内容。重定向URL的结构（包含`sa`, `q`, `usg`等参数）和页面内容（标准的302跳转页面）均符合Google的正常行为模式，未发现任何可疑或恶意元素。因此，从静态角度判断，该页面是良性的。

### 行为分析员（模型：`gemini-2.5-flash`）
该行为链展示了一个从 `www.google.com` 到 `www.google.com.hk` 的标准 HTTP 302 自动重定向。这是一个谷歌内部的重定向机制，通常用于将用户引导至其所在地区的域名，或用于搜索结果的追踪。分析过程中未发现任何恶意行为，例如复杂的重定向链、恶意脚本加载、诱导下载或表单提交。最终重定向的目的地仍然是谷歌的合法域名，因此该行为被判定为良性。

### 情报分析员（模型：`gpt-5`）
当前处于离线评估模式，未获取任何外部威胁情报（WHOIS、证书日志、黑名单等），无法进行域名归因或基础设施分析。本角色仅能基于其他分析员的结论进行逻辑交叉验证。外部情报字段 external_intel 为空，无法核验域名信誉、注册信息或证书透明度记录，也无法关联潜在攻击基础设施。就现有静态与行为证据而言：目标从 www.google.com 经 302 跳转至 www.google.com.hk，页面仅为移动提示，无密码表单、无脚本加载、无下载链接；这一模式与大型站点按地区进行重定向的常见行为相一致，并不呈现典型钓鱼要素。但在缺乏外部情报的前提下，仍无法确认最终域名与跳转链的信誉或是否存在被滥用情形。因此，本角色不对信誉做出结论，仅确认上述逻辑与其他分析员“低风险、跨域跳转”的判断相互印证。

### 处置建议员（模型：`gpt-5.4-mini`）
综合页面行为、HTML摘要和可见文本来看，该站点仅展示了标准的 302 重定向页面，从 www.google.com 跳转到同一服务体系下的 www.google.com.hk，未见脚本加载、下载、表单提交、隐藏输入或可疑交互。当前证据更符合正常的区域化跳转与站点引导行为，不表现出钓鱼、投递或恶意重定向特征。建议保留访问日志即可；若链接来源可信，可放行。若后续发现异常跳转链、证书异常或外部情报告警，再升级处置。


### 主持人最终总结
基于静态检测与浏览器取证一致显示：目标 https://www.google.com/ 返回标准 HTTP 302，跨域跳转至同一服务体系的区域化域名 https://www.google.com.hk/url?...。页面内容为“302 Moved”占位页，无脚本加载、无下载、无表单与隐藏字段，重定向链长度短（2段），未见可疑投递或利用特征。四位专家中，静态与行为分析员均以高置信度判定为良性倾向；情报与处置分析员在离线情报及审慎前提下给出“uncertain”但风险提示仍为低，未提出相反的恶意结论。综合来看，该跳转符合大型站点按地区分流/引导的常见业务逻辑，当前证据链不支持恶意结论，整体风险低。需要注意的是，本次评估未接入外部情报，建议在生产场景中补充域名信誉与证书透明度以进一步佐证，但这不改变本次“低风险”的总体判断。


### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
