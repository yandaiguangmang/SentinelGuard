# SentinelGuard 哨塔检测报告

> 模型深度研判报告 · 风险等级：**HIGH** · 风险分数：**70/100**

## 一、检测结论
- 原始输入：`https://www.baidu.com`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：10 条
- 高危证据：2 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260617_221222_755158.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260617_221222_755158.md

## 二、统一 IR 摘要
- 规范化 URL：`https://www.baidu.com/`
- 协议：`https`
- 主机：`www.baidu.com`
- 路径：`/`
- 查询参数数量：`0`

## 三、跳转链
- https://www.baidu.com/

## 四、页面线索
- status_code：200
- content_type：text/html
- final_url：https://www.baidu.com/
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://10.250.167.176:7890', 'https': 'http://10.250.167.176:7890', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- title：
- visible_text_excerpt：location.replace(location.href.replace("https://","http://"));
- password_forms：0
- hidden_inputs：0
- meta_refresh：0;url=http://www.baidu.com/
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<html> <head> <script> location.replace(location.href.replace("https://","http://")); </script> </head> <body> <noscript><meta http-equiv="refresh" content="0;url=http://www.baidu.com/"></noscript> </body> </html>', 'text_excerpt': 'location.replace(location.href.replace("https://","http://"));'}

## 四点一、浏览器证据 / 截图
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、风险证据
### 1. 页面包含自动跳转指令
- 规则：`PAGE_META_REFRESH`
- 严重级别：`medium`
- 说明：Meta refresh 可在用户无感知情况下跳转到其他页面。
- 证据：`0;url=http://www.baidu.com/`
- 建议：关注浏览器最终地址栏域名是否发生变化。

### 2. 页面强制将 HTTPS 降级为 HTTP
- 规则：`DEEP_STATIC_FORCED_HTTP_DOWNGRADE`
- 严重级别：`high`
- 说明：页面通过 JavaScript 代码和 `<noscript>` 标签内的 Meta Refresh 指令，明确指示浏览器将当前 HTTPS 连接降级为 HTTP 连接。这直接削弱了传输安全性，可能导致敏感信息泄露或被篡改。
- 证据：`JavaScript: `location.replace(location.href.replace("https://","http://"));`；Meta Refresh: `0;url=http://www.baidu.com/``
- 建议：警惕任何强制降级 HTTPS 的行为，即使目标域名看似合法。此类行为是典型的中间人攻击前置步骤，建议阻止访问或在严格隔离环境中进行复核。

### 3. 页面使用多种跳转机制
- 规则：`DEEP_STATIC_MULTIPLE_REDIRECT_MECHANISMS`
- 严重级别：`medium`
- 说明：页面同时使用了客户端 JavaScript (`location.replace`) 和 HTML `<noscript>` 标签内的 `meta refresh` 两种不同的跳转机制。这种多重机制可能旨在确保在不同浏览器环境（例如，JavaScript 被禁用时）或规避某些安全检测时，跳转行为仍能成功执行。
- 证据：`JavaScript `location.replace` 和 `<noscript><meta http-equiv="refresh"></noscript>``
- 建议：分析多种跳转机制的组合使用，尤其关注其跳转目标是否一致以及是否存在混淆或规避检测的意图。在动态分析中验证所有可能的跳转路径。

### 4. 页面执行HTTPS降级攻击
- 规则：`DEEP_BEHAVIOR_HTTPS_DOWNGRADE`
- 严重级别：`high`
- 说明：页面内嵌的JavaScript代码尝试将URL协议从 'https://' 替换为 'http://' 并立即跳转，同时在<noscript>标签内设置了Meta Refresh作为后备方案，同样指向HTTP地址。此行为旨在剥离TLS加密，使用户暴露在流量监听和篡改的风险之下。
- 证据：`JavaScript: location.replace(location.href.replace("https://","http://")); Meta Refresh: <meta http-equiv="refresh" content="0;url=http://www.baidu.com/">`
- 建议：立即阻断对该URL的访问。HTTPS降级是明确的恶意指标，不应信任任何由该页面发起或跳转到的后续页面。

### 5. 代理/链路环境差异可能导致内容改写伪像
- 规则：`DEEP_INTEL_ENV_PROXY_VARIANCE`
- 严重级别：`medium`
- 说明：静态与浏览器抓取均显示通过企业代理访问，返回的 HTML 含 HTTPS→HTTP 降级指令，这与目标常规行为不符，提示可能存在前向代理/中间盒插入或准入页改写。
- 证据：`proxy_used=true；proxy=10.250.167.176:7890；HTML 含 location.replace("https://","http://")`
- 建议：在无代理直连与不同外网/VPN 出口（境内/境外、不同 ASN）重复抓取并比对：DNS 应答、TLS 证书链/CT、一跳与完整重定向链、响应差异。对可疑代理链路进行 HAR/PCAP 采集与证书指纹核验。

### 6. 存在 HTTPS 降级重定向意图
- 规则：`DEEP_INTEL_DOWNGRADE_INTENT`
- 严重级别：`medium`
- 说明：页面内联脚本与 noscript meta 同时指向 http://www.baidu.com/，属于降级重定向模式，若为真实来源将削弱传输机密性与完整性。
- 证据：`JS: location.replace(location.href.replace("https://","http://"));；Meta: 0;url=http://www.baidu.com/；浏览器观察：最终为 https://www.baidu.com/`
- 建议：核验目标在不同出口下的 HSTS（是否预加载/头部 max-age）、证书链与 SAN；确认正常路径是否保持全站 HTTPS。若仅在特定链路出现降级，优先排查链路改写。

### 7. 离线证据与浏览器证据包的边界说明
- 规则：`DEEP_INTEL_EVIDENCE_BOUNDARY`
- 严重级别：`low`
- 说明：离线报告基于首包快照，限制 200KB，不执行脚本、不加载外部资源；浏览器证据包为一次受控渲染，仍在代理下，未覆盖多步交互与外链请求。二者仅反映采集当时、当节点的有限视角。
- 证据：`body_limited_to_bytes=200000；external_script_count=0；redirect_chain 仅含初始 URL`
- 建议：对关键信号（重定向、证书、HSTS、脚本行为）进行多轮交互复核：启用完整浏览器、记录 HAR/控制台日志/证书链，必要时补充 PCAP，确保证据可复现、可比对。

### 8. 外网/VPN 节点访问差异的研判要点
- 规则：`DEEP_INTEL_VPN_ACCESS_DIFFERENCES`
- 严重级别：`low`
- 说明：当目标依赖外网/VPN 访问时，DNS 解析、CDN 边缘、Geo/合规策略与证书链可能随出口节点改变，从而影响重定向、内容与安全标头呈现。
- 证据：`fetch_mode=proxy；browser_observation 指出自动跳转但最终仍为 HTTPS`
- 建议：建立“出口矩阵”基线：记录每个节点的 egress IP/ASN、解析器、SNI/TLS 指纹与首包差异；跨 CN 与海外节点对比抓取，标注差异来源（地域/运营商/代理）。

### 9. 环境元数据不一致可能导致误判
- 规则：`DEEP_INTEL_METADATA_INCONSISTENCY`
- 严重级别：`low`
- 说明：顶层元数据显示 proxy_enabled=false，但静态与浏览器证据均显示 proxy_used=true，存在记录不一致风险。
- 证据：`top-level proxy_enabled=false；static_report.proxy_used=true；browser_evidence.proxy_used=true`
- 建议：统一采集链路元数据，在每份证据中标注实际出口方式、代理配置与证书摘要，避免由配置标记与实际访问路径不符导致的结论偏差。

### 10. 页面存在客户端自动跳转逻辑
- 规则：`DEEP_ADVICE_CLIENT_SIDE_REDIRECT`
- 严重级别：`medium`
- 说明：页面HTML中包含JavaScript代码 `location.replace(location.href.replace("https://","http://"));` 和 `<noscript>` 标签内的 `<meta http-equiv="refresh" content="0;url=http://www.baidu.com/">`，尝试将当前HTTPS连接重定向至HTTP连接。尽管浏览器最终停留在原始HTTPS地址，但此类行为可能被恶意利用进行协议降级或重定向至其他恶意站点。
- 证据：`HTML摘要显示存在 `location.replace` 脚本和 `meta http-equiv="refresh"` 标签，均指向 `http://www.baidu.com/`。`
- 建议：不建议直接拦截该页面，因为其最终停留在原始HTTPS地址。但建议对该页面进行隔离访问，以防止潜在的协议降级风险。同时，强烈建议进行沙箱复核，以验证客户端脚本和Meta Refresh的实际执行效果和最终跳转目标。此事件应进行留痕，以便后续审计和分析。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、browser_evidence 以及四位专家意见，本样本应判定为“中等风险”，核心原因是页面存在明确的客户端自动跳转与 HTTPS→HTTP 协议降级意图：HTML 中同时包含 JavaScript `location.replace(location.href.replace("https://","http://"));` 和 `<noscript><meta http-equiv="refresh" content="0;url=http://www.baidu.com/"></noscript>`。这类行为会主动削弱 HTTPS 传输保护，理论上可为中间人攻击、流量窃听或内容篡改创造条件，因此不能视为普通页面行为。

不过，当前证据链也显示出明显的环境依赖和不确定性：browser_evidence 中最终 URL 仍为 `https://www.baidu.com/`，redirect_chain 未展示跨域跳转，且页面未见表单、下载、外链脚本等更强恶意特征。情报分析员指出，本次抓取发生在代理环境下，当前观测可能受到前向代理、链路改写、区域差异或准入页影响，离线证据与受控浏览器证据都只是单次快照，不能直接等同于真实公网环境下的最终表现。因此，现阶段更适合将其定性为“存在显著降级跳转风险的可疑页面”，而不是直接上调为高危恶意网页。

综合裁决：页面确实存在可验证的降级重定向代码，安全含义明确，但由于最终浏览器停留在 HTTPS、且缺乏进一步恶意载荷或外联证据，风险等级维持中等；建议在隔离环境中复核不同出口、不同网络条件下的证书链、HSTS 与重定向路径，再决定是否升级处置。 综合 1 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
页面存在显著安全风险：通过 JavaScript 与 noscript/meta refresh 两种机制强制将 HTTPS 降级为 HTTP，属于高度可疑行为特征，建议阻止访问或在严格隔离环境复核。

### 行为分析员（模型：`gemini-2.5-pro`）
页面执行 HTTPS 降级意图明确，属于典型的协议降级攻击特征；即使最终 URL 在沙箱中仍为 HTTPS，也不影响其高风险判断。

### 情报分析员（模型：`gpt-5`）
当前采集位于代理环境，存在链路改写或环境伪像可能；离线与浏览器证据均为定点快照，应在无代理直连及多出口环境复核后再做最终定论，现阶段维持中等风险。

### 处置建议员（模型：`gemini-2.5-flash`）
页面含客户端自动跳转逻辑，建议隔离访问并留痕复核最终跳转与脚本执行效果，不建议直接信任其页面行为。


### 主持人最终总结
基于静态检测结果、browser_evidence 以及四位专家意见，本样本应判定为“中等风险”，核心原因是页面存在明确的客户端自动跳转与 HTTPS→HTTP 协议降级意图：HTML 中同时包含 JavaScript `location.replace(location.href.replace("https://","http://"));` 和 `<noscript><meta http-equiv="refresh" content="0;url=http://www.baidu.com/"></noscript>`。这类行为会主动削弱 HTTPS 传输保护，理论上可为中间人攻击、流量窃听或内容篡改创造条件，因此不能视为普通页面行为。

不过，当前证据链也显示出明显的环境依赖和不确定性：browser_evidence 中最终 URL 仍为 `https://www.baidu.com/`，redirect_chain 未展示跨域跳转，且页面未见表单、下载、外链脚本等更强恶意特征。情报分析员指出，本次抓取发生在代理环境下，当前观测可能受到前向代理、链路改写、区域差异或准入页影响，离线证据与受控浏览器证据都只是单次快照，不能直接等同于真实公网环境下的最终表现。因此，现阶段更适合将其定性为“存在显著降级跳转风险的可疑页面”，而不是直接上调为高危恶意网页。

综合裁决：页面确实存在可验证的降级重定向代码，安全含义明确，但由于最终浏览器停留在 HTTPS、且缺乏进一步恶意载荷或外联证据，风险等级维持中等；建议在隔离环境中复核不同出口、不同网络条件下的证书链、HSTS 与重定向路径，再决定是否升级处置。


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
