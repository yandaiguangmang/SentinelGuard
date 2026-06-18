# SentinelGuard 哨塔检测报告

> 模型深度研判报告 · 风险等级：**MEDIUM** · 风险分数：**45/100**

## 一、检测结论
- 原始输入：`https://www.baidu.com`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：14 条
- 高危证据：0 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260617_224133_840520.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260617_224133_840520.md

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
- content_type：text/html; charset=utf-8
- final_url：https://www.baidu.com/
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://10.250.167.176:7890', 'https': 'http://10.250.167.176:7890', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- title：百度一下，你就知道
- visible_text_excerpt：百度一下，你就知道 #form .bdsug{top:39px}.bdsug{display:none;position:absolute;width:535px;background:#fff;border:1px solid #ccc!important;_overflow:hidden;box-shadow:1px 1px 3px #ededed;-webkit-box-shadow:1px 1px 3px #ededed;-moz-box-shadow:1px 1px 3px #ededed;-o-box-shadow:1px 1px 3px #ededed}.bdsug li{width:519px;color:#000;font:14px arial;line-height:25px;padding:0 8px;position:relative;cursor:default}.bdsug li.bdsug-s{background:#f0f0f0}.bdsug-store span,.bdsug-store b{color:#7A77C8}.bdsug-store-del{font-size:12px;color:#666;text-decoration:underline;position:absolute;right:8px;top:0;cursor:pointer;display:none}.bdsug-s .bdsug-store-del{display:inline-block}.bdsug-ala{display:inline-block;border-bottom:1px solid #e6e6e6}.bdsug-ala h3{line-height:14px;background:url(//www.baidu.com/img/sug_bd.p
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<!DOCTYPE html><!--STATUS OK--><html><head><meta http-equiv="Content-Type" content="text/html;charset=utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"><meta content="origin-when-cross-origin" name="referrer"><meta name="theme-color" content="#ffffff"><meta name="description" content="全球领先的中文搜索引擎、致力于让网民更便捷地获取信息，找到所求。百度超过千亿的中文网页数据库，可以瞬间找到相关的搜索结果。"><link rel="shortcut icon" href="https://www.baidu.com/favicon.ico" type="image/x-icon" /><link rel="search" type="application/opensearchdescription+xml" href="/content-search.xml" title="百度搜索" /><link rel="stylesheet" data-for="result" href="https://pss.bdstatic.com/r/www/static/font/cosmic/pc/cos-icon_3df378f.css"/><link rel="icon" sizes="any" mask href="https://www.baidu.com/favicon.ico"><link rel="dns-prefetch" href="//dss0.bdstatic.com"/><link rel="dns-prefetch" href="//dss1.bdstatic.com"/><link rel="dns-prefetch" href="//ss1.bdstatic.com"/><link rel="dns-prefetch" href="//sp0.baidu.com"/><link rel="dns-prefetch" href="//sp1.baidu.com"/><link rel="dns-prefetch" href="//sp2.baidu.com"/><link rel="dns-prefetch" href="//pss.bdstatic.com"/><link rel="apple-touch-icon-precomposed" href="https://psstatic.cdn.bcebos.com/vid', 'text_excerpt': '百度一下，你就知道 #form .bdsug{top:39px}.bdsug{display:none;position:absolute;width:535px;background:#fff;border:1px solid #ccc!important;_overflow:hidden;box-shadow:1px 1px 3px #ededed;-webkit-box-shadow:1px 1px 3px #ededed;-moz-box-shadow:1px 1px 3px #ededed;-o-box-shadow:1px 1px 3px #ededed}.bdsug li{width:519px;color:#000;font:14px arial;line-height:25px;padding:0 8px;position:relative;cursor:default}.bdsug li.bdsug-s{background:#f0f0f0}.bdsug-store span,.bdsug-store b{color:#7A77C8}.bdsug-store-del{font-size:12px;color:#666;text-decoration:underline;position:absolute;right:8px;top:0;cursor:pointer;display:none}.bdsug-s .bdsug-store-del{display:inline-block}.bdsug-ala{display:inline-block;border-bottom:1px solid #e6e6e6}.bdsug-ala h3{line-height:14px;background:url(//www.baidu.com/img/sug_bd.p'}

## 四点一、浏览器证据 / 截图
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、风险证据
### 1. 合法知名域名
- 规则：`DEEP_STATIC_001_LEGITIMATE_DOMAIN`
- 严重级别：`medium`
- 说明：目标URL的域名 (www.baidu.com) 是一个全球知名的合法搜索引擎服务提供商，具有高度可信度。
- 证据：`域名: www.baidu.com；DNS预取链接指向百度相关资产。`
- 建议：无需特殊处理，确认为合法域名。

### 2. URL结构规范，无异常参数
- 规则：`DEEP_STATIC_002_CLEAN_URL_STRUCTURE`
- 严重级别：`medium`
- 说明：URL结构简单，无复杂子域名、异常端口或路径，且未包含任何可疑的查询参数，降低了参数注入或重定向的风险。
- 证据：`URL: https://www.baidu.com/；查询参数为空。`
- 建议：URL结构无异常，符合预期。

### 3. 页面内容无恶意关键词或混淆
- 规则：`DEEP_STATIC_003_NO_SUSPICIOUS_CONTENT`
- 严重级别：`medium`
- 说明：页面标题、可见文本和HTML摘要内容与百度官方页面一致，未检测到任何常见的恶意关键词（如钓鱼、诈骗、病毒等）或编码混淆迹象。
- 证据：`页面标题: '百度一下，你就知道'；可见文本和HTML摘要内容正常，无混淆。`
- 建议：页面内容静态分析无风险。

### 4. 未发现可疑表单、下载或脚本线索
- 规则：`DEEP_STATIC_004_NO_MALICIOUS_INTERACTIONS`
- 严重级别：`medium`
- 说明：静态分析未发现页面包含密码表单、隐藏输入、可疑下载链接或外部恶意脚本，降低了数据窃取或恶意软件传播的风险。
- 证据：`password_forms: 0；hidden_inputs: 0；download_links: []；script_srcs: []；external_script_count: 0。`
- 建议：静态层面未发现交互式恶意载荷。

### 5. 取证环境使用代理导致可达性与呈现差异
- 规则：`DEEP_INTEL_ENV_PROXY_DIVERGENCE`
- 严重级别：`medium`
- 说明：本次抓取通过内网代理完成，复现场景若缺少外网/VPN会产生访问失败或内容差异（CDN/地域化/A/B），影响风险判断与可复现性。
- 证据：`page_summary.fetch_mode=proxy; proxy_used=true; proxy=10.250.167.176:7890; status=200; final_url=https://www.baidu.com/`
- 建议：在对比测试时固定出口节点与DNS，分别在有/无代理与不同地域VPN下复采并导出HAR；报告中标注出口IP/ASN与时间窗，确保结论可复现。

### 6. 品牌主域HTTPS直达，未见异常重定向
- 规则：`DEEP_INTEL_BRAND_DOMAIN_BASELINE`
- 严重级别：`low`
- 说明：目标为百度主域首页，HTTPS直达200，未观察到可疑跳转或钓鱼指纹，密码表单为0。
- 证据：`redirect_chain=[https://www.baidu.com/]; status_code=200; title=“百度一下，你就知道”; password_forms=0`
- 建议：将该页面视作低风险落地页，但对搜索结果外链逐一独立核验（检查重定向、证书与域名欺骗），避免在非必要页面提交敏感信息。

### 7. 离线规则与浏览器证据的边界与局限
- 规则：`DEEP_INTEL_EVIDENCE_BOUNDARY`
- 严重级别：`low`
- 说明：离线分析未接入外部威胁情报且以静态特征为主；浏览器证据是单次快照，当前脚本清单为空可能因抓取策略所致，无法代表动态加载全貌。
- 证据：`expert_opinions.情报分析员=“当前离线版本未接入外部威胁情报”；external_script_count=0; script_srcs=[]`
- 建议：针对动态站点补充分析：开启JS执行与完整网络捕获（HAR/JS堆栈/第三方请求清单），并与外部威胁情报交叉校验；必要时进行多时段、多地域二次取证。

### 8. 地域/CDN差异对资源域与内容的影响
- 规则：`DEEP_INTEL_CDN_GEO_VARIANCE`
- 严重级别：`low`
- 说明：页面声明对多个静态与服务域的DNS预取，实际加载可能因地域选择不同CDN节点，导致资源主机、证书链与指纹差异。
- 证据：`html中dns-prefetch包含：//dss0.bdstatic.com, //dss1.bdstatic.com, //ss1.bdstatic.com, //sp0.baidu.com, //sp1.baidu.com, //sp2.baidu.com, //pss.bdstatic.com`
- 建议：在目标环境放通上述资源域名与HTTPS流量；对关键取证任务在CN/非CN出口均进行采样，并校验TLS证书与内容哈希差异。

### 9. 全局代理标志与页面证据不一致的元数据风险
- 规则：`DEEP_INTEL_PROXY_FLAG_INCONSISTENCY`
- 严重级别：`low`
- 说明：顶层proxy_enabled=false，但页面与静态报告均显示实际使用了代理，可能造成取证路径误读。
- 证据：`root.proxy_enabled=false vs page_summary.proxy_used=true & browser_evidence.proxy_used=true`
- 建议：统一管线标注规范：在报告中显式记录是否用代理/VPN、出口IP与解析器；如有冲突，以页面级证据为准并在备注中说明。

### 10. 合法网站识别
- 规则：`DEEP_ADVICE_LEGITIMATE_SITE`
- 严重级别：`medium`
- 说明：目标URL 'https://www.baidu.com/' 是一个知名的合法搜索引擎网站。所有分析结果均表明该页面安全无害。
- 证据：`浏览器证据包中的页面行为、HTML摘要和可见文本快照均显示为百度首页的正常内容（标题：'百度一下，你就知道'，可见文本与百度主页一致）。静态分析未发现任何可疑的URL结构、脚本或重定向。专家意见也一致认为未发现明显高危特征。`
- 建议：允许正常访问。无需拦截、隔离或沙箱复核。建议正常留痕，作为常规访问记录。

### 11. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`www.baidu.com；https://www.baidu.com/；无异常参数、无异常端口、无可疑子域名。`
- 建议：按正常可信站点处理。

### 12. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`status_code=200；redirect_chain 仅含自身；password_forms=0；hidden_inputs=0；meta_refresh=[]；download_links=[]；external_script_count=0。`
- 建议：无需拦截或隔离。

### 13. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`title=“百度一下，你就知道”；HTML 摘要和可见文本均呈现百度首页特征。`
- 建议：可作为正常访问留痕。

### 14. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`未接入外部威胁情报；抓取通过代理完成；浏览器证据为单次快照。`
- 建议：如需更高置信度，补充多时段、多出口与完整 HAR 复核。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
综合静态检测结果、浏览器证据包与四位专家意见，目标 URL https://www.baidu.com/ 被一致判定为百度官网首页，未发现钓鱼、跳转劫持、恶意脚本、可疑表单、下载投递或编码混淆等风险特征。页面返回 200，最终地址未发生重定向，标题与可见文本均符合百度首页特征，HTML 摘要与常规官方站点一致，静态规则未命中异常项。当前结论仅基于离线证据与单次抓取快照；外部威胁情报未接入，且此次取证实际通过代理完成，故对地域化内容、动态脚本、后续搜索结果外链行为不作超出证据链的推断。总体裁决：低风险、可正常访问，但若进入搜索结果页或提交敏感信息，仍应按常规安全习惯复核目标域名与跳转链路。 未发现明显高危特征，仍建议结合链接来源和访问上下文复核。

### 静态分析员（模型：`gemini-2.5-flash`）
URL 结构未命中当前规则库中的明显异常项。

### 行为分析员（模型：`gemini-2.5-pro`）
未观察到可疑跳转或页面行为证据。

### 情报分析员（模型：`gpt-5`）
当前离线版本未接入外部威胁情报，结论基于本地规则。

### 处置建议员（模型：`gemini-2.5-flash`）
可正常访问，但不要在陌生页面提交敏感信息。


### 主持人最终总结
综合静态检测结果、浏览器证据包与四位专家意见，目标 URL https://www.baidu.com/ 被一致判定为百度官网首页，未发现钓鱼、跳转劫持、恶意脚本、可疑表单、下载投递或编码混淆等风险特征。页面返回 200，最终地址未发生重定向，标题与可见文本均符合百度首页特征，HTML 摘要与常规官方站点一致，静态规则未命中异常项。当前结论仅基于离线证据与单次抓取快照；外部威胁情报未接入，且此次取证实际通过代理完成，故对地域化内容、动态脚本、后续搜索结果外链行为不作超出证据链的推断。总体裁决：低风险、可正常访问，但若进入搜索结果页或提交敏感信息，仍应按常规安全习惯复核目标域名与跳转链路。


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
