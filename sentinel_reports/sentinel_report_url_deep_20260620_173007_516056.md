# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**95/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.org/en`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：11 条
- 高危证据：9 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260620_172926_013246.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260620_172926_013246.md

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
- 未采集到截图证据。

## 六、风险证据
### 1. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`high`
- 说明：页面要求输入密码或类似凭据，若域名并非官方域名则存在钓鱼风险。
- 证据：`密码框数量: 4`
- 建议：仅在确认域名归属和证书可信后输入账号密码。

### 2. 使用 Base64 编码混淆关键域名
- 规则：`DEEP_STATIC_JS_OBFUSCATION`
- 严重级别：`high`
- 说明：页面脚本中使用了 atob() 对域名进行解码，这是为了逃避基础的静态文本匹配检测，属于典型的恶意脚本隐藏手段。
- 证据：`代码片段: atob("YmFrc21hbnkubmV0")`
- 建议：此类混淆手段在正常业务中极少使用，建议直接拦截。

### 3. 浏览器导航劫持与 API 篡改
- 规则：`DEEP_STATIC_NAV_HIJACKING`
- 严重级别：`critical`
- 说明：页面通过重写 Location.prototype.href、assign 和 replace 方法，并监听 navigation 事件，强制限制用户的页面跳转行为，这是钓鱼网站防止用户跳转至安全页面的常用技术。
- 证据：`代码中包含 Object.defineProperty(_loc,"href",...) 及对 Location.prototype 的重写逻辑。`
- 建议：该行为严重破坏浏览器安全机制，属于恶意行为。

### 4. 页面包含多个密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`high`
- 说明：页面存在 4 个密码输入框，且伪装为数字货币交易平台，极易诱导用户输入敏感凭据。
- 证据：`password_forms: 4`
- 建议：严禁在该页面输入任何账号密码。

### 5. 缺乏品牌模仿
- 规则：`INTEL_BRAND_001`
- 严重级别：`medium`
- 说明：页面内容涉及数字货币交易，但没有明确的品牌或组织标识，可能导致用户混淆。
- 证据：`页面标题为 'Digital Currency Exchange, Buying and Selling Bitcoin'，但未提及任何具体品牌。`
- 建议：建议用户在输入任何敏感信息前确认网站的合法性和真实性。

### 6. 域名注册信息缺乏透明度
- 规则：`INTEL_INFRA_001`
- 严重级别：`high`
- 说明：未能获取域名的注册信息和证书透明度，增加了该域名的风险。
- 证据：`域名 baksmany.org 的注册信息未在可用情报源中找到。`
- 建议：建议对该域名进行进一步的信誉调查，并考虑将其列入黑名单。

### 7. 地理位置和网络环境的内容差异
- 规则：`INTEL_COVERAGE_001`
- 严重级别：`low`
- 说明：未发现因地理位置或网络环境导致的内容差异，页面内容在不同环境下保持一致。
- 证据：`通过代理访问时，页面内容与直接访问一致。`
- 建议：继续监测该页面在不同网络环境下的表现，确保没有潜在的欺诈行为。

### 8. 导航劫持以防止离开钓鱼页面
- 规则：`DEEP_BEHAVIOR_NAVIGATION_HIJACKING`
- 严重级别：`critical`
- 说明：页面内联脚本重写了浏览器的核心导航功能（如 location.href, location.assign）。它将 'baksman.net' 识别为目标域名，并阻止任何尝试导航到该域名的行为。这是一种旨在将用户困在当前钓鱼网站（baksmany.org）并阻止其访问真实网站的恶意技术。
- 证据：`脚本代码: `var O=atob("YmFrc21hbnkubmV0").toLowerCase(),F="baksmany.org";...; navigation.addEventListener("navigate",function(e){...e.preventDefault();...}); ... Object.defineProperty(_loc,"href",...); ... Location.prototype.assign=function(u){if(bad(u))return;...}``
- 建议：应立即阻止对该域名的访问。这种高级脚本技术表明攻击者具有较高的技术水平，其目的明确，即窃取敏感信息。

### 9. 使用 Base64 编码混淆关键域名
- 规则：`DEEP_STATIC_JS_OBFUSCATION`
- 严重级别：`high`
- 说明：脚本中使用 atob() 对域名进行解码，属于常见的混淆与隐藏行为，常用于规避静态检测。
- 证据：`atob("YmFrc21hbnkubmV0")`
- 建议：建议直接拦截并进一步审查。

### 10. 浏览器导航劫持与 API 篡改
- 规则：`DEEP_STATIC_NAV_HIJACKING`
- 严重级别：`critical`
- 说明：页面重写了 Location 相关方法并监听 navigation 事件，表现出限制用户跳转与阻止离开的行为。
- 证据：`Object.defineProperty(_loc,"href",...)、Location.prototype.assign/replace 重写、navigation.addEventListener("navigate",...)`
- 建议：该行为严重异常，建议阻断。

### 11. 页面内容与脚本特征可疑
- 规则：`BROWSER_PAGE_SUSPICION`
- 严重级别：`high`
- 说明：浏览器证据显示页面标题伪装为数字货币交易平台，可见文本却主要是导航拦截脚本，且存在多个密码框。
- 证据：`title=Digital Currency Exchange, Buying and Selling Bitcoin；password_forms=4；hidden_inputs=1；script_srcs=["/__lemmed_bm.js"]`
- 建议：结合凭据收集特征，应按高风险钓鱼处理。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果与浏览器证据包，当前页面应判定为高风险，且整体更偏向恶意钓鱼页面。证据链显示：页面标题伪装为“Digital Currency Exchange, Buying and Selling Bitcoin”，正文可见内容中嵌入了用于导航控制的脚本，脚本通过 Base64 解码得到相邻域名并重写浏览器导航相关 API（包括 navigation 事件、location.href、assign、replace），表现出明显的跳转拦截与页面锁定意图；同时页面存在 4 个密码输入框和 1 个隐藏字段，属于典型凭据收集特征。静态报告已给出 high 级别风险与 66 分，浏览器证据与其一致。当前结论主要依赖离线/本地抓取证据；由于可用外部情报不足，无法对域名信誉、证书透明度和黑名单命中做进一步交叉验证，但这并不削弱现有证据对钓鱼风险的指向。四个专家中，静态分析员、行为分析员、处置建议员均给出 malicious_lean，且置信度很高；情报分析员给出 uncertain，提示品牌模仿不明显且需补充情报。总体不存在方向性分歧到 benign_lean 的对立意见，因此最终维持 high 风险、偏恶意结论，并建议阻断访问，不输入任何账号密码。 综合 1 条证据，当前风险等级为 high。

### 静态分析员（模型：`gemini-2.5-flash`）
页面包含 Base64 混淆的域名与浏览器导航劫持脚本，并存在 4 个密码输入框，判定为典型钓鱼诱导页面，偏恶意。

### 行为分析员（模型：`gemini-2.5-pro`）
页面通过重写多种导航 API 阻止用户离开目标页面，结合多个密码输入框，判断为旨在窃取凭据的钓鱼页面。

### 情报分析员（模型：`gpt-4o-mini`）
目前更偏保守结论：未看到明确品牌模仿标识，外部情报不足，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`gemini-2.5-flash`）
建议立即阻断访问，不输入账号密码，不下载或运行页面提供的文件，并保留链接与报告用于复核。


### 主持人最终总结
基于静态检测结果与浏览器证据包，当前页面应判定为高风险，且整体更偏向恶意钓鱼页面。证据链显示：页面标题伪装为“Digital Currency Exchange, Buying and Selling Bitcoin”，正文可见内容中嵌入了用于导航控制的脚本，脚本通过 Base64 解码得到相邻域名并重写浏览器导航相关 API（包括 navigation 事件、location.href、assign、replace），表现出明显的跳转拦截与页面锁定意图；同时页面存在 4 个密码输入框和 1 个隐藏字段，属于典型凭据收集特征。静态报告已给出 high 级别风险与 66 分，浏览器证据与其一致。当前结论主要依赖离线/本地抓取证据；由于可用外部情报不足，无法对域名信誉、证书透明度和黑名单命中做进一步交叉验证，但这并不削弱现有证据对钓鱼风险的指向。四个专家中，静态分析员、行为分析员、处置建议员均给出 malicious_lean，且置信度很高；情报分析员给出 uncertain，提示品牌模仿不明显且需补充情报。总体不存在方向性分歧到 benign_lean 的对立意见，因此最终维持 high 风险、偏恶意结论，并建议阻断访问，不输入任何账号密码。


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。


## 九、分析性能统计

- 总耗时：33.58 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 5.21 | 3540 | 557 | 4097 |
| 情报分析员 | 6.96 | 3143 | 428 | 3571 |
| 行为分析员 | 23.15 | 3885 | 504 | 4389 |
| 处置建议员 | 3.34 | 4948 | 651 | 5599 |
| 主持人 | 7.08 | 5333 | 1481 | 6814 |
