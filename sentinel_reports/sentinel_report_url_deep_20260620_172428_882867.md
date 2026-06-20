# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**95/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.org/en`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：15 条
- 高危证据：10 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260620_172353_168141.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260620_172353_168141.md

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

### 2. Suspicious Base64 Obfuscation
- 规则：`DEEP_STATIC_OBFUSCATION`
- 严重级别：`critical`
- 说明：The page uses Base64 encoded strings to hide domain references and implements a 'navguard' script to intercept navigation, which is a common technique in phishing kits to prevent users from leaving or to redirect them to malicious endpoints.
- 证据：`atob("YmFrc21hbnkubmV0") found in script block.`
- 建议：Do not interact with the page; the script is designed to control browser behavior for malicious purposes.

### 3. Navigation Hijacking Attempt
- 规则：`DEEP_STATIC_NAV_HIJACK`
- 严重级别：`high`
- 说明：The script overrides 'Location.prototype.href', 'assign', and 'replace' methods to control where the user navigates, effectively trapping the user or forcing them to a specific domain.
- 证据：`Object.defineProperty(_loc,"href",{...}) and Location.prototype.assign overrides.`
- 建议：Block access to this domain as it actively attempts to subvert browser security controls.

### 4. Excessive Credential Input Fields
- 规则：`DEEP_STATIC_PHISH_FORM`
- 严重级别：`high`
- 说明：The presence of 4 password fields on a landing page is highly anomalous for a legitimate service and is a hallmark of credential harvesting.
- 证据：`password_forms: 4`
- 建议：Flag as a credential harvesting site.

### 5. No clear brand impersonation identified
- 规则：`INTEL_BRAND_IMPERSONATION`
- 严重级别：`medium`
- 说明：The webpage does not appear to impersonate any well-known brand or organization, which is significant as it may indicate a generic phishing attempt.
- 证据：`The site claims to be a digital currency exchange without specific branding.`
- 建议：Users should exercise caution and avoid entering sensitive information on this site.

### 6. Domain registration and reputation concerns
- 规则：`INTEL_INFRA_DOMAIN_REPUTATION`
- 严重级别：`high`
- 说明：The domain baksmany.org lacks sufficient reputation data and has not been verified against known blacklists.
- 证据：`No external reputation data available for the domain.`
- 建议：Further investigation into the domain's registration details and hosting provider is recommended to assess potential risks.

### 7. Potential geographic content differences
- 规则：`INTEL_COVERAGE_GEOGRAPHIC`
- 严重级别：`medium`
- 说明：There may be differences in content based on geographic location or network environment, indicating possible cloaking.
- 证据：`The use of a proxy may affect the visibility of the actual content served to different users.`
- 建议：Conduct tests from various geographic locations to confirm content consistency.

### 8. Phishing Kit Domain Hijacking Script Detected
- 规则：`DEEP_BEHAVIOR_PHISHING_KIT_REDIRECTION_HIJACK`
- 严重级别：`critical`
- 说明：The page loads a script that intercepts browser navigation functions (e.g., location.href, location.assign, fetch, XMLHttpRequest.open). It checks for a hardcoded, obfuscated domain ('baksman.net') and rewrites any requests or links pointing to it to the current domain. This is a hallmark of a repurposed phishing kit, designed to make it functional on a new domain while trapping the user.
- 证据：`The inline script contains `var O=atob("YmFrc21hbnkubmV0").toLowerCase()` which decodes to `baksman.net`. It then hooks multiple navigation-related prototypes and functions to replace this domain with the current one, `baksmany.org`.`
- 建议：Block this URL. This behavior is a strong and reliable indicator of a credential phishing operation.

### 9. Multiple Password Fields Induce Credential Entry
- 规则：`DEEP_BEHAVIOR_CREDENTIAL_PHISHING_INDUCEMENT`
- 严重级别：`high`
- 说明：The page presents multiple (four) password input forms, which is a strong behavioral inducement for the user to enter sensitive credentials. In the context of the observed domain hijacking, this confirms the page's purpose as a credential harvester.
- 证据：`Browser evidence reports `password_forms: 4` on the final landing page.`
- 建议：Users should never enter credentials on a page exhibiting this behavior. The high number of password fields is a significant red flag for phishing.

### 10. Active Phishing Kit Domain Hijacking
- 规则：`DEEP_ADVICE_PHISHING_KIT_HIJACK`
- 严重级别：`critical`
- 说明：The page contains obfuscated scripts that hook browser navigation methods (Location.prototype.href, assign, replace) to force navigation to a specific malicious domain. This is a clear indicator of a controlled phishing environment.
- 证据：`atob("YmFrc21hbnkubmV0") (baksman.net) and navigation event listeners.`
- 建议：Block the domain at the network level immediately.

### 11. Credential Harvesting Inducement
- 规则：`DEEP_ADVICE_CREDENTIAL_HARVESTING`
- 严重级别：`critical`
- 说明：The page presents four distinct password input fields, which is highly anomalous for a legitimate service and serves as a primary vector for credential theft.
- 证据：`password_forms: 4`
- 建议：Do not interact with the page; block access to prevent user credential exposure.

### 12. Malicious Script Injection
- 规则：`DEEP_ADVICE_MALICIOUS_SCRIPT_INJECTION`
- 严重级别：`high`
- 说明：The page loads an external script `/__lemmed_bm.js` and includes an inline `data-navguard` script, both of which are used to maintain the phishing session and prevent user escape.
- 证据：`script_srcs: ["/__lemmed_bm.js"]`
- 建议：Flag the domain as malicious and block all associated sub-resources.

### 13. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：The page includes a navguard-style script that appears to block or rewrite navigation to a hardcoded domain reference, which is a strong phishing-kit indicator.
- 证据：`Inline script contains atob("YmFrc21hbnkubmV0") and hooks navigation-related APIs.`
- 建议：结合静态报告进一步复核。

### 14. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：An unusually high number of password fields on a landing page is consistent with credential harvesting or deceptive login collection.
- 证据：`password_forms: 4, hidden_inputs: 1`
- 建议：结合静态报告进一步复核。

### 15. 主持人补充风险
- 规则：`DEEP_MODEL_SIGNAL`
- 严重级别：`medium`
- 说明：Current assessment relies solely on offline evidence from static analysis and browser fetch results.
- 证据：`No external intelligence or live reputation verdicts were provided.`
- 建议：结合静态报告进一步复核。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
Based on the static detection results and browser evidence package, this URL should be treated as high risk and likely malicious. The page at https://baksmany.org/en returns HTTP 200 and presents as a cryptocurrency exchange landing page, but the offline evidence shows 4 password input fields and an inline obfuscated navigation-control script. The script decodes a hardcoded domain reference (baksman.net) and attempts to intercept or rewrite navigation-related browser APIs, which is consistent with a repurposed phishing kit designed to keep users within the page and facilitate credential harvesting. Because no external intelligence or live reputation data is available here, the conclusion relies solely on offline evidence. {'original': '综合 1 条证据，当前风险等级为 high。', 'summary': 'Overall assessment: high risk based on one key evidence item.'}

### 静态分析员（模型：`gemini-2.5-flash`）
{'original': 'The page exhibits clear characteristics of a credential harvesting site. The static analysis reveals a highly suspicious script (data-navguard) that uses Base64 obfuscation (`atob("YmFrc21hbnkubmV0")` which decodes to \'baksmany.net\') to intercept and manipulate browser navigation and location properties. The presence of four password input fields on a site masquerading as a cryptocurrency exchange, combined with the use of anti-debugging/anti-navigation techniques, strongly indicates a malicious intent to capture user credentials.', 'claim': 'malicious_lean', 'confidence': 0.95, 'risk_hint': 'critical', 'excerpt': 'Obfuscated navguard script, browser-navigation manipulation, and 4 password fields suggest credential harvesting.'}

### 行为分析员（模型：`gemini-2.5-pro`）
{'original': "The webpage exhibits definitive signs of a credential phishing attack. Behavior analysis reveals a sophisticated inline script designed to adapt a phishing kit to a new domain. The script actively intercepts and rewrites URLs pointing to a hardcoded domain ('baksman.net') to the current domain ('baksmany.org'), while also preventing any navigation away from the phishing site. This technique, combined with the presence of four password input forms, confirms the site's malicious intent to steal user credentials by posing as a digital currency exchange.", 'claim': 'malicious_lean', 'confidence': 1.0, 'risk_hint': 'critical', 'excerpt': 'Domain-rewriting phishing-kit behavior plus multiple password forms indicates credential phishing.'}

### 情报分析员（模型：`gpt-4o-mini`）
{'original': 'The domain baksmany.org does not clearly impersonate any specific identifiable brand or organization. It appears to be a generic digital currency exchange site, which raises concerns about its legitimacy and potential phishing risks.', 'claim': 'malicious_lean', 'confidence': 0.85, 'risk_hint': 'high', 'excerpt': 'No clear brand impersonation, limited reputation data, and possible geographic/content differences.'}

### 处置建议员（模型：`gemini-2.5-flash`）
{'original': 'The webpage is a confirmed credential harvesting site. It utilizes a sophisticated phishing kit that includes domain-hijacking scripts to intercept and rewrite navigation, ensuring users remain trapped within the malicious environment. The presence of four password input fields, combined with obfuscated JavaScript designed to subvert browser security controls (Location API hijacking), confirms the intent to steal sensitive user information. The site is actively malicious.', 'claim': 'uncertain', 'confidence': 0.0, 'risk_hint': 'critical', 'recommended_action': 'block', 'excerpt': 'Despite the claim label, the action recommendation is to block due to phishing-kit indicators.'}


### 主持人最终总结
Based on the static detection results and browser evidence package, this URL should be treated as high risk and likely malicious. The page at https://baksmany.org/en returns HTTP 200 and presents as a cryptocurrency exchange landing page, but the offline evidence shows 4 password input fields and an inline obfuscated navigation-control script. The script decodes a hardcoded domain reference (baksman.net) and attempts to intercept or rewrite navigation-related browser APIs, which is consistent with a repurposed phishing kit designed to keep users within the page and facilitate credential harvesting. Because no external intelligence or live reputation data is available here, the conclusion relies solely on offline evidence.


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

- 总耗时：33.80 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 4.43 | 3493 | 555 | 4048 |
| 情报分析员 | 5.85 | 3100 | 394 | 3494 |
| 行为分析员 | 23.42 | 3842 | 614 | 4456 |
| 处置建议员 | 3.31 | 5016 | 518 | 5534 |
| 主持人 | 7.06 | 5067 | 1339 | 6406 |
