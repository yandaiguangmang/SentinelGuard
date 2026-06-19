# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**LOW** · 风险分数：**0/100**

## 一、检测结论
- 原始输入：`https://onlinebannbhd.iceiy.com/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：0 条
- 高危证据：0 条

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
- 未发现明显风险项。

## 六、论坛式协同研判
### 主持人（模型：`unknown`）
未发现明显高危特征，仍建议结合链接来源和访问上下文复核。

### 静态分析员（模型：`unknown`）
URL 结构未命中当前规则库中的明显异常项。

### 行为分析员（模型：`unknown`）
未观察到可疑跳转或页面行为证据。

### 情报分析员（模型：`unknown`）
当前离线版本未接入外部威胁情报，结论基于本地规则。

### 处置建议员（模型：`unknown`）
可正常访问，但不要在陌生页面提交敏感信息。


## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
