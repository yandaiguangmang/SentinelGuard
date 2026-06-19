# SentinelGuard 哨塔检测报告

> 模型深度研判报告 · 风险等级：**HIGH** · 风险分数：**70/100**

## 一、检测结论
- 原始输入：`https://onlinebannbhd.iceiy.com/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：16 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260617_223310_147686.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260617_223310_147686.md

## 二、统一 IR 摘要
- 规范化 URL：`https://onlinebannbhd.iceiy.com/`
- 协议：`https`
- 主机：`onlinebannbhd.iceiy.com`
- 路径：`/`
- 查询参数数量：`0`

## 三、跳转链
- https://onlinebannbhd.iceiy.com/

## 四、页面线索
- status_code：200
- content_type：text/html
- final_url：https://onlinebannbhd.iceiy.com/
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://10.250.167.176:7890', 'https': 'http://10.250.167.176:7890', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- title：
- visible_text_excerpt：function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var a=toNumbers("f655ba9d09a112d4968c63579db590b4"),b=toNumbers("98344c2eee86c3994890592585b49f80"),c=toNumbers("cb7b90b46fc340080246bb6a4caec096");document.cookie="__test="+toHex(slowAES.decrypt(c,2,a,b))+"; max-age=21600; expires=Thu, 31-Dec-37 23:55:55 GMT; path=/"; location.href="https://onlinebannbhd.iceiy.com/?i=1"; This site requires Javascript to work, please enable Javascript in your browser or use a browser with Javascript support
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：/aes.js
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<html><body><script type="text/javascript" src="/aes.js" ></script><script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var a=toNumbers("f655ba9d09a112d4968c63579db590b4"),b=toNumbers("98344c2eee86c3994890592585b49f80"),c=toNumbers("cb7b90b46fc340080246bb6a4caec096");document.cookie="__test="+toHex(slowAES.decrypt(c,2,a,b))+"; max-age=21600; expires=Thu, 31-Dec-37 23:55:55 GMT; path=/"; location.href="https://onlinebannbhd.iceiy.com/?i=1";</script><noscript>This site requires Javascript to work, please enable Javascript in your browser or use a browser with Javascript support</noscript></body></html>', 'text_excerpt': 'function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var a=toNumbers("f655ba9d09a112d4968c63579db590b4"),b=toNumbers("98344c2eee86c3994890592585b49f80"),c=toNumbers("cb7b90b46fc340080246bb6a4caec096");document.cookie="__test="+toHex(slowAES.decrypt(c,2,a,b))+"; max-age=21600; expires=Thu, 31-Dec-37 23:55:55 GMT; path=/"; location.href="https://onlinebannbhd.iceiy.com/?i=1"; This site requires Javascript to work, please enable Javascript in your browser or use a browser with Javascript support'}

## 四点一、浏览器证据 / 截图
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、风险证据
### 1. JavaScript混淆与反分析机制
- 规则：`DEEP_STATIC_001`
- 严重级别：`high`
- 说明：页面加载后立即执行JavaScript代码，其中包含`slowAES.decrypt`函数和十六进制编码的字符串，用于解密并设置名为`__test`的Cookie。这种在客户端进行解密操作以设置Cookie的行为，是常见的混淆技术，旨在隐藏真实内容或验证客户端环境，以规避静态分析或反爬虫。
- 证据：`HTML中包含`<script>`标签，执行`slowAES.decrypt(c,2,a,b)`并设置`document.cookie`。`
- 建议：建议进行动态行为分析，观察解密后的内容和后续跳转页面的行为，以揭示其真实意图。

### 2. 客户端JavaScript强制跳转
- 规则：`DEEP_STATIC_002`
- 严重级别：`medium`
- 说明：在执行完解密和Cookie设置后，页面立即通过`location.href`将自身重定向到`https://onlinebannbhd.iceiy.com/?i=1`。这种即时且带有参数的自重定向，可能用于传递解密结果、触发后续逻辑或作为多阶段攻击的入口。
- 证据：`JavaScript代码中包含`location.href="https://onlinebannbhd.iceiy.com/?i=1";`。`
- 建议：关注跳转后的页面内容和行为，特别是`?i=1`参数可能带来的影响。

### 3. 页面标题缺失
- 规则：`DEEP_STATIC_003`
- 严重级别：`low`
- 说明：页面的`<title>`标签为空。对于大多数合法网站而言，页面标题是必不可少的，缺失标题可能表明页面内容不完整、临时性或旨在规避搜索引擎索引。
- 证据：`页面摘要中`title`字段为空。`
- 建议：结合其他可疑特征进行综合判断，单独此项风险较低。

### 4. 可疑的域名结构
- 规则：`DEEP_STATIC_004`
- 严重级别：`medium`
- 说明：域名`onlinebannbhd.iceiy.com`中的`onlinebannbhd`部分看起来像是随机生成或不具语义的子域名。结合页面存在的混淆和跳转行为，这种域名结构可能被用于快速部署和废弃的恶意活动。
- 证据：`URL `https://onlinebannbhd.iceiy.com/`。`
- 建议：对主域名`iceiy.com`进行历史查询和威胁情报关联，以评估其信誉度。

### 5. 页面使用JavaScript挑战和自动跳转
- 规则：`DEEP_BEHAVIOR_JS_CHALLENGE_REDIRECT`
- 严重级别：`medium`
- 说明：初始页面通过执行JavaScript代码来验证客户端环境。它进行了一次加密运算，将结果存入Cookie，然后立即使用`location.href`将浏览器重定向到带有查询参数的新地址。这是一种反自动化分析技术。
- 证据：`HTML源码中包含以下JavaScript代码片段：`document.cookie="__test="+toHex(slowAES.decrypt(c,2,a,b))+"; ...; location.href="https://onlinebannbhd.iceiy.com/?i=1";``
- 建议：建议对JavaScript跳转后的目标页面`https://onlinebannbhd.iceiy.com/?i=1`进行深入分析，以确定其真实内容和意图。此类技术常用于隐藏钓鱼、挂马等恶意页面。

### 6. 通过脚本加载和执行实现内容隐藏
- 规则：`DEEP_BEHAVIOR_SCRIPT_EVASION`
- 严重级别：`low`
- 说明：页面依赖于外部加载的`aes.js`脚本和内联脚本的成功执行才能进行后续跳转，初始HTML中没有可见的实质性内容。这种方式可以绕过无法执行JavaScript的简单扫描器。
- 证据：`页面HTML结构主要由`<script>`标签组成，`<noscript>`标签提示用户需要启用JavaScript。`
- 建议：在分析此类链接时，必须使用能够完整渲染页面和执行JavaScript的动态沙箱环境。

### 7. 检测到基于 slowAES 的 JS 闸门设置 __test Cookie 并重定向
- 规则：`DEEP_INTEL_JS_ANTIBOT_AES_COOKIE`
- 严重级别：`medium`
- 说明：页面通过引入 /aes.js 并执行 slowAES.decrypt 生成 __test Cookie，随后跳转到带有 ?i=1 的 URL。这是常见的反爬/反滥用闸门形态，也被滥用于对抗沙箱与安全扫描，实现内容分级与躲避审查。
- 证据：`document.cookie="__test="+toHex(slowAES.decrypt(c,2,a,b))+"; ..."; location.href="https://onlinebannbhd.iceiy.com/?i=1"; script src="/aes.js"`
- 建议：使用完整浏览器（非无头）、允许 JS/Cookie，保留会话后继续访问跳转页；优先使用住宅/移动网络且靠近目标受众地区的出口节点，抓取闸门之后的最终内容（DOM/网络请求/截图），再行定性。

### 8. 子域名疑似品牌误导与托管域不匹配
- 规则：`DEEP_INTEL_POTENTIAL_BRAND_MISLEAD_SUBDOMAIN`
- 严重级别：`medium`
- 说明：子域名“onlinebannbhd.iceiy.com”给人以金融/银行（bank/bhd/berhad）相关联想，但挂载在与品牌无明显关系的主域 iceiy.com 之下，且“bannbhd”疑似形近“bankbhd”，存在品牌混淆或投机命名风险。
- 证据：`hostname=onlinebannbhd.iceiy.com，页面标题为空且仅呈现 JS 闸门，无法验证真实品牌归属。`
- 建议：核验证书颁发对象与 SAN、WHOIS 与被动 DNS 历史、关联解析记录与托管商；结合外部威胁情报与钓鱼线索（投放渠道、诱饵文案）复核；如出现品牌滥用迹象，按钓鱼处置流程提升拦截策略。

### 9. 闸门后附加查询参数的自跳转模式
- 规则：`DEEP_INTEL_REDIRECT_PARAM_GATE`
- 严重级别：`low`
- 说明：通过设置 Cookie 后跳转到同域名加上 ?i=1 的 URL，用于标记已通过校验，避免重复挑战。这类自跳转本身并非恶意，但与反自动化策略结合时，常用于对抗无头抓取与简单扫描。
- 证据：`location.href="https://onlinebannbhd.iceiy.com/?i=1"`
- 建议：采集时保留并回放前序步骤（首包响应→设置 Cookie→重定向→最终页），确保抓到最终页面实体内容后再进行内容/IOC 识别。

### 10. 采集出口与环境差异可能导致页面分级呈现
- 规则：`DEEP_INTEL_ENVIRONMENT_DIFFERENCE_EGRESS`
- 严重级别：`medium`
- 说明：当前抓取使用代理模式，易被识别为数据中心/自动化来源而触发闸门；实际用户在住宅或目标地区网络下可能直接看到不同内容。该类差异会造成离线与浏览器证据均停留在闸门页，无法对真实页面定性。
- 证据：`fetch_mode=proxy, proxy_used=true；页面仅返回 JS 闸门与空标题，无业务内容。`
- 建议：在合规前提下使用目标地区（如疑似马来西亚）的住宅/移动出口复抓；设置常见 UA、禁用无头标记、允许 JS/Cookie/本地存储；记录出口 ASN、地理位置与时间窗口，确保可复现性。

### 11. 客户端JavaScript挑战与内部重定向
- 规则：`DEEP_ADVICE_JS_CHALLENGE`
- 严重级别：`medium`
- 说明：页面加载后立即执行JavaScript代码，包括调用`slowAES.decrypt`进行解密，设置名为`__test`的Cookie，并随后通过`location.href`将页面重定向至同一域名下的`https://onlinebannbhd.iceiy.com/?i=1`。这种客户端挑战机制常用于验证浏览器环境或进行机器人检测，但也可能被恶意网站利用以规避安全检测或延迟恶意载荷的加载。
- 证据：`HTML摘要和可见文本快照中包含`slowAES.decrypt(c,2,a,b))`和`location.href="https://onlinebannbhd.iceiy.com/?i=1";`代码段，且页面引用了`/aes.js`脚本。`
- 建议：建议对该页面进行沙箱复核，以观察在JavaScript执行并重定向后，最终呈现的页面内容和行为。如果重定向后出现可疑内容（如钓鱼表单、恶意下载、进一步的混淆或跳转），则应立即拦截并隔离。在未明确其最终目的前，用户应谨慎访问，避免提交任何敏感信息。

### 12. 页面标题为空
- 规则：`DEEP_ADVICE_EMPTY_TITLE`
- 严重级别：`low`
- 说明：该页面的HTML `<title>` 标签为空。虽然这本身不构成安全威胁，但通常一个完整的、合法的网页会包含有意义的标题。空标题可能表明页面内容不完整、是临时页面，或由自动化工具生成，这在某些情况下可能与低质量或可疑内容相关联。
- 证据：`静态报告和浏览器证据中`page_summary.title`和`page_signals.title`字段均为空。`
- 建议：此发现单独来看风险较低，但结合其他非标准行为（如JS挑战），建议提高警惕。在评估页面整体可信度时，可将其作为一个次要考量因素。

### 13. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`HTML/可见文本中直接包含 `document.cookie="__test="+toHex(slowAES.decrypt(c,2,a,b))...; location.href="https://onlinebannbhd.iceiy.com/?i=1";``
- 建议：结合静态报告进一步复核。

### 14. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：``title` 为空；`visible_text_excerpt` 主要是 JS 代码与 “This site requires Javascript to work...” 提示。`
- 建议：结合静态报告进一步复核。

### 15. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：``fetch_mode=proxy`、`proxy_used=true`，且页面未完成 JS/Cookie 后续验证。`
- 建议：结合静态报告进一步复核。

### 16. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`静态报告 `findings` 为空，浏览器证据中 `password_forms=0`、`download_links=[]`、`external_script_count=0`。`
- 建议：结合静态报告进一步复核。


## 六、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于当前静态抓取、浏览器证据包与专家意见，目标页面更像是一个 JS 闸门/反自动化验证页，而非已直接暴露恶意载荷的最终业务页。证据显示页面仅返回空标题 HTML，主体几乎只有 `/aes.js` 与内联脚本：通过 `slowAES.decrypt` 计算并写入 `__test` Cookie，随后立即重定向到同域 `/?i=1`。这类模式常见于反爬、反机器人或分级内容呈现，也可能被用于规避静态扫描和隐藏后续页面内容。当前离线证据未看到钓鱼表单、下载链接、外链跳转或明确恶意脚本注入，因此不能定性为高危恶意站点；但由于真实内容被 JS/Cookie 门槛遮蔽，且抓取环境使用代理模式，仍存在“对自动化与不同出口环境分流呈现”的可能，真实落地页面尚未被确认。结论：当前仅能在离线证据范围内判定为中等风险，建议在合规前提下使用完整浏览器、保留 Cookie 会话并切换更接近目标受众的出口环境复核重定向后的最终页面。 {'original': '未发现明显高危特征，仍建议结合链接来源和访问上下文复核。', 'summary': '倾向低风险，但强调需结合来源与上下文复核。'}

### 静态分析员（模型：`gemini-2.5-flash`）
{'original': 'URL 结构未命中当前规则库中的明显异常项。', 'summary': 'URL 本身未触发明显规则命中，但页面脚本行为另有可疑点。'}

### 行为分析员（模型：`gemini-2.5-pro`）
{'original': '未观察到可疑跳转或页面行为证据。', 'summary': '在当前证据范围内未见外部可疑跳转；但页面存在 JS 挑战式内部重定向。'}

### 情报分析员（模型：`gpt-5`）
{'original': '当前离线版本未接入外部威胁情报，结论基于本地规则。', 'summary': '结论仅基于离线证据与本地规则，缺少外部情报佐证。'}

### 处置建议员（模型：`gemini-2.5-flash`）
{'original': '可正常访问，但不要在陌生页面提交敏感信息。', 'summary': '可访问性不等于可信性，建议不要在未确认页面身份前输入敏感信息。'}


### 主持人最终总结
基于当前静态抓取、浏览器证据包与专家意见，目标页面更像是一个 JS 闸门/反自动化验证页，而非已直接暴露恶意载荷的最终业务页。证据显示页面仅返回空标题 HTML，主体几乎只有 `/aes.js` 与内联脚本：通过 `slowAES.decrypt` 计算并写入 `__test` Cookie，随后立即重定向到同域 `/?i=1`。这类模式常见于反爬、反机器人或分级内容呈现，也可能被用于规避静态扫描和隐藏后续页面内容。当前离线证据未看到钓鱼表单、下载链接、外链跳转或明确恶意脚本注入，因此不能定性为高危恶意站点；但由于真实内容被 JS/Cookie 门槛遮蔽，且抓取环境使用代理模式，仍存在“对自动化与不同出口环境分流呈现”的可能，真实落地页面尚未被确认。结论：当前仅能在离线证据范围内判定为中等风险，建议在合规前提下使用完整浏览器、保留 Cookie 会话并切换更接近目标受众的出口环境复核重定向后的最终页面。


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
