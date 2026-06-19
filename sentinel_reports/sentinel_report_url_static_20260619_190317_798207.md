# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**HIGH** · 风险分数：**56/100**


## 一、检测结论
- 原始输入：`https://baksmany.org/en`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：1 条
- 高危证据：1 条

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
  - 大小：`666861` 字节
  - 视口：`{'width': 1440, 'height': 1600}`

## 六、风险证据
### 1. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`high`
- 说明：页面要求输入密码或类似凭据，若域名并非官方域名则存在钓鱼风险。
- 证据：`密码框数量: 4`
- 建议：仅在确认域名归属和证书可信后输入账号密码。


## 七、论坛式协同研判
### 主持人（模型：`unknown`）
综合 1 条证据，当前风险等级为 high。

### 静态分析员（模型：`unknown`）
URL 结构层面关注：页面包含密码输入框。

### 行为分析员（模型：`unknown`）
页面行为与跳转层面关注：页面包含密码输入框。

### 情报分析员（模型：`unknown`）
当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`unknown`）
建议阻断访问，不输入账号密码，不下载或运行页面提供的文件，并保留链接与报告用于复核。


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
