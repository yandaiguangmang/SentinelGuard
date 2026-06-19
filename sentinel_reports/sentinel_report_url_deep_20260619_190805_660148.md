# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**95/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.org/en`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：11 条
- 高危证据：7 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260619_190434_494415.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260619_190434_494415.md

## 二、统一 IR 摘要
- 规范化 URL：`https://baksmany.org/en`
- 协议：`https`
- 主机：`baksmany.org`
- 路径：`/en`
- 查询参数数量：`0`

## 三、跳转链
- https://baksmany.org/en

## 四、页面线索
- status_code：200
- content_type：text/html; charset=utf-8
- final_url：https://baksmany.org/en
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://127.0.0.1:7897', 'https': 'http://127.0.0.1:7897', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- title：Digital Currency Exchange, Buying and Selling Bitcoin
- visible_text_excerpt：(function(){try{var O=atob("YmFrc21hbnkubmV0").toLowerCase(),F="baksmany.org";function bad(u){try{var h=new URL(u,location.href).hostname.toLowerCase();return h===O||h.slice(-(O.length+1))==="."+O;}catch(e){return false;}}function toF(u){try{var a=new URL(u,location.href);var h=a.hostname.toLowerCase();if(h===O||h.slice(-(O.length+1))==="."+O){a.hostname=h.length>O.length?h.slice(0,-O.length)+F:F;return a.href;}}catch(e){}return u;}try{if(window.navigation&&navigation.addEventListener){navigation.addEventListener("navigate",function(e){try{if(e.cancelable&&e.destination&&bad(e.destination.url))e.preventDefault();}catch(_){}});}}catch(e){}try{var _loc=location;Object.defineProperty(_loc,"href",{get:function(){return window.location.toString();},set:function(u){if(!bad(u))Object.getOwnProper
- password_forms：4
- hidden_inputs：1
- meta_refresh：无
- script_srcs：/__lemmed_bm.js
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<!DOCTYPE html> <html lang="en"> <head><script src="/__lemmed_bm.js"></script><script data-navguard>(function(){try{var O=atob("YmFrc21hbnkubmV0").toLowerCase(),F="baksmany.org";function bad(u){try{var h=new URL(u,location.href).hostname.toLowerCase();return h===O||h.slice(-(O.length+1))==="."+O;}catch(e){return false;}}function toF(u){try{var a=new URL(u,location.href);var h=a.hostname.toLowerCase();if(h===O||h.slice(-(O.length+1))==="."+O){a.hostname=h.length>O.length?h.slice(0,-O.length)+F:F;return a.href;}}catch(e){}return u;}try{if(window.navigation&&navigation.addEventListener){navigation.addEventListener("navigate",function(e){try{if(e.cancelable&&e.destination&&bad(e.destination.url))e.preventDefault();}catch(_){}});}}catch(e){}try{var _loc=location;Object.defineProperty(_loc,"href",{get:function(){return window.location.toString();},set:function(u){if(!bad(u))Object.getOwnPropertyDescriptor(Location.prototype,"href").set.call(_loc,u);},configurable:true});}catch(e){}try{var LA=Location.prototype.assign;Location.prototype.assign=function(u){if(bad(u))return;return LA.apply(this,arguments);};}catch(e){}try{var LR=Location.prototype.replace;Location.prototype.replace=function', 'text_excerpt': '(function(){try{var O=atob("YmFrc21hbnkubmV0").toLowerCase(),F="baksmany.org";function bad(u){try{var h=new URL(u,location.href).hostname.toLowerCase();return h===O||h.slice(-(O.length+1))==="."+O;}catch(e){return false;}}function toF(u){try{var a=new URL(u,location.href);var h=a.hostname.toLowerCase();if(h===O||h.slice(-(O.length+1))==="."+O){a.hostname=h.length>O.length?h.slice(0,-O.length)+F:F;return a.href;}}catch(e){}return u;}try{if(window.navigation&&navigation.addEventListener){navigation.addEventListener("navigate",function(e){try{if(e.cancelable&&e.destination&&bad(e.destination.url))e.preventDefault();}catch(_){}});}}catch(e){}try{var _loc=location;Object.defineProperty(_loc,"href",{get:function(){return window.location.toString();},set:function(u){if(!bad(u))Object.getOwnProper'}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、截图证据
- 截图数量：`1` 张，完整图像请查看 HTML 报告。
- 截图 1：
  - URL：`https://baksmany.org/en`
  - 最终地址：`https://baksmany.org/en`
  - 大小：`666699` 字节
  - 视口：`{'width': 1440, 'height': 1600}`

## 六、风险证据
### 1. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`high`
- 说明：页面要求输入密码或类似凭据，若域名并非官方域名则存在钓鱼风险。
- 证据：`密码框数量: 4`
- 建议：仅在确认域名归属和证书可信后输入账号密码。

### 2. 检测到恶意混淆脚本
- 规则：`DEEP_STATIC_OBFUSCATION`
- 严重级别：`critical`
- 说明：页面头部嵌入了使用 atob 解码的混淆脚本，通过重写 Location.prototype.href、assign 和 replace 方法来控制页面跳转，这是典型的钓鱼网站用于规避检测或强制重定向的手段。
- 证据：`脚本中包含 atob("YmFrc21hbnkubmV0")，解码后为 'baksmany.net'，并对当前页面导航进行拦截。`
- 建议：立即阻断该域名的访问，并对相关脚本进行沙箱动态分析。

### 3. 高危钓鱼特征：凭据采集
- 规则：`DEEP_STATIC_PHISHING_INTENT`
- 严重级别：`high`
- 说明：页面包含 4 个密码输入框，且页面标题为“数字货币交易”，符合典型的金融类钓鱼网站特征，旨在诱导用户输入敏感账户信息。
- 证据：`页面存在 4 个密码输入框 (password_forms: 4)。`
- 建议：严禁在页面输入任何敏感信息，建议将该域名列入黑名单。

### 4. 可疑本地脚本引用
- 规则：`DEEP_STATIC_SUSPICIOUS_SCRIPT`
- 严重级别：`medium`
- 说明：页面引用了名为 /__lemmed_bm.js 的本地脚本，该命名方式常见于自动化生成的钓鱼模板，缺乏正规业务逻辑特征。
- 证据：`script_srcs: ['/__lemmed_bm.js']`
- 建议：对该 JS 文件进行静态逆向分析，提取其与后端通信的 API 接口。

### 5. 可能存在外网/VPN 依赖导致的环境差异
- 规则：`DEEP_INTEL_ENV_DIFFERENCE`
- 严重级别：`medium`
- 说明：该目标的可见页面与拦截行为可能受出口 IP、地区、DNS、代理链路或 VPN 节点影响；当前抓取结果仅代表所用代理环境下的观测，不代表所有网络环境一致。
- 证据：`fetch_mode=proxy；proxy_used=true；proxy_config 显示本次通过代理访问；页面返回 200 且内容完整可读。`
- 建议：在不同地区/不同出口 IP/直连与 VPN 条件下复测，比较标题、表单、脚本、跳转链与证书信息的一致性。

### 6. 浏览器证据包仅覆盖页面层与有限行为层
- 规则：`DEEP_INTEL_BROWSER_BOUNDARY`
- 严重级别：`medium`
- 说明：浏览器证据包可证明页面在当前抓取时的 HTML、标题、可见文本、密码框和脚本特征，但不能证明后台接口、登录后真实流程、账号归属或跨会话行为。
- 证据：`browser_evidence 提供 title、html_summary、visible_text_excerpt、password_forms=4、hidden_inputs=1、redirect_chain 等信息，但无后端接口与证书透明度数据。`
- 建议：补充域名 WHOIS、证书透明度日志、被动 DNS、黑名单命中、登录后跳转链和服务器端接口抓包。

### 7. 多密码输入框与金融主题标题叠加，具备凭据收集风险
- 规则：`DEEP_INTEL_PW_FORM_PHISHING`
- 严重级别：`high`
- 说明：页面标题指向数字货币交易主题，但页面包含 4 个密码输入框，结合站点名与脚本拦截特征，存在钓鱼或伪装登录页风险。
- 证据：`title="Digital Currency Exchange, Buying and Selling Bitcoin"；password_forms=4；hidden_inputs=1。`
- 建议：将其视为高风险凭据收集页面，阻断访问并避免输入任何账号、密码或 2FA 信息。

### 8. 页面内存在显式导航拦截/域名替换脚本
- 规则：`DEEP_INTEL_NAVGUARD_SCRIPT`
- 严重级别：`high`
- 说明：脚本对特定域名 baksmany.net 进行识别、阻断和替换到 baksmany.org，体现出对访问路径和跳转行为的强控制，可能用于规避外部访问或干扰取证。
- 证据：`visible_text_excerpt/raw_excerpt 中出现 atob("YmFrc21hbnkubmV0")、bad(u)、toF(u)、navigation.addEventListener("navigate")、Location.prototype.assign/replace 相关代码。`
- 建议：保留原始 HTML 与脚本证据，进一步分析脚本意图、跳转控制范围及是否存在恶意重定向。

### 9. 立即执行网络阻断
- 规则：`DEEP_ADVICE_BLOCK`
- 严重级别：`critical`
- 说明：页面包含恶意导航劫持脚本，且具备典型的钓鱼网站特征（伪装成加密货币交易所并诱导输入凭据）。
- 证据：`HTML 中存在 data-navguard 脚本，通过 atob 解码域名并重写 Location.prototype，具有极强的隐蔽性和恶意意图。`
- 建议：在防火墙或网关层面对 baksmany.org 执行域名阻断，防止用户访问。

### 10. 沙箱深度复核
- 规则：`DEEP_ADVICE_SANDBOX`
- 严重级别：`high`
- 说明：页面加载了外部脚本 /__lemmed_bm.js，该脚本可能包含进一步的恶意载荷或反调试逻辑。
- 证据：`script_srcs 包含 /__lemmed_bm.js，且页面存在 4 个密码输入框。`
- 建议：将该 URL 提交至自动化沙箱进行动态行为分析，重点监控其网络请求、Cookie 读取及键盘记录行为。

### 11. 留痕与溯源
- 规则：`DEEP_ADVICE_LOGGING`
- 严重级别：`medium`
- 说明：需保留当前证据包以供后续关联分析。
- 证据：`页面包含隐藏输入字段及复杂的 JS 混淆逻辑。`
- 建议：将该 URL 及相关 HTML 快照存入威胁情报库，并关联至同源的钓鱼攻击基础设施。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于当前静态检测结果与浏览器证据包，可将 https://baksmany.org/en 裁定为高置信度的钓鱼/凭据收集页面，风险等级上调至 critical。证据链显示：页面标题伪装为“Digital Currency Exchange, Buying and Selling Bitcoin”，但 HTML 中存在 4 个密码输入框和 1 个隐藏字段，明显符合金融类登录诱导特征；同时页面头部嵌入了带有 atob 解码、Location.prototype.href/assign/replace 重写、navigation 拦截等行为的导航控制脚本，脚本中还显式识别并屏蔽 baksmany.net，体现出强烈的访问控制、路径劫持或规避检测意图。浏览器证据包确认页面在代理环境下可访问且返回 200，未见外部跳转链，说明当前判定主要建立在离线抓取内容、页面结构与脚本行为之上。由于缺少域名信誉、证书透明度、后端接口与跨网络环境对照等外部情报，不能对真实业务归属做最终归因，但不影响对其“高风险钓鱼页面”的结论。综合四位专家意见，建议将该域名视为恶意或高度可疑站点，立即阻断访问，禁止输入任何账号、密码或验证码，并保留 HTML、脚本与证据包用于后续溯源和复核。 综合证据后认为当前风险等级为 high，但结合脚本控制与多密码框特征，最终应上调为 critical。

### 静态分析员（模型：`gemini-2.5-flash`）
页面存在极高钓鱼风险：伪装为数字货币交易平台，HTML 头部嵌入混淆脚本，使用 atob 解码并重写 Location 对象、拦截导航；页面内有 4 个密码输入框，符合加密货币账户凭据钓鱼特征。另发现 /__lemmed_bm.js 本地脚本，疑似自动化钓鱼模板或进一步载荷入口。

### 行为分析员（模型：`gemini-2.5-pro`）
受限于调用超时，未能输出完整动态结论；保留的摘要仅指出页面包含密码输入框，风险提示为 high。

### 情报分析员（模型：`gpt-5.4-mini`）
当前证据主要来自离线抓取与浏览器证据包；在所用代理环境下页面返回 200，标题与密码框、隐藏字段、导航拦截脚本均可见。需要说明该证据仅代表当前代理环境，不等价于所有网络环境下的真实业务形态。建议按高风险钓鱼/凭据收集页面处理，并在未补充域名信誉、证书透明度、黑名单等外部情报前，不输入任何账号密码或验证码。

### 处置建议员（模型：`gemini-2.5-flash`）
建议立即阻断访问，不输入账号密码，不下载或运行页面提供的文件，并保留链接与报告用于复核；同时建议对域名做网关/防火墙层阻断并送沙箱复核。


### 主持人最终总结
基于当前静态检测结果与浏览器证据包，可将 https://baksmany.org/en 裁定为高置信度的钓鱼/凭据收集页面，风险等级上调至 critical。证据链显示：页面标题伪装为“Digital Currency Exchange, Buying and Selling Bitcoin”，但 HTML 中存在 4 个密码输入框和 1 个隐藏字段，明显符合金融类登录诱导特征；同时页面头部嵌入了带有 atob 解码、Location.prototype.href/assign/replace 重写、navigation 拦截等行为的导航控制脚本，脚本中还显式识别并屏蔽 baksmany.net，体现出强烈的访问控制、路径劫持或规避检测意图。浏览器证据包确认页面在代理环境下可访问且返回 200，未见外部跳转链，说明当前判定主要建立在离线抓取内容、页面结构与脚本行为之上。由于缺少域名信誉、证书透明度、后端接口与跨网络环境对照等外部情报，不能对真实业务归属做最终归因，但不影响对其“高风险钓鱼页面”的结论。综合四位专家意见，建议将该域名视为恶意或高度可疑站点，立即阻断访问，禁止输入任何账号、密码或验证码，并保留 HTML、脚本与证据包用于后续溯源和复核。


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5.4-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
