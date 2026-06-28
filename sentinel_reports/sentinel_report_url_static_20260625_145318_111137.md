# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**LOW** · 风险分数：**0/100**
> 证据分数：**0/100** · 深度研判分数：**- /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`https://selffashion.shop/Pes/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：0 条
- 高危证据：0 条

## 二、统一 IR 摘要
- 规范化 URL：`https://selffashion.shop/Pes/`
- 协议：`https`
- 主机：`selffashion.shop`
- 路径：`/Pes/`
- 查询参数数量：`0`

## 三、跳转链
- https://selffashion.shop/Pes/
- https://selffashion.shop/cgi-sys/suspendedpage.cgi

## 四、页面线索
- status_code：302
- content_type：text/html
- final_url：https://selffashion.shop/cgi-sys/suspendedpage.cgi
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://127.0.0.1:7897', 'https': 'http://127.0.0.1:7897', 'ftp': 'http://127.0.0.1:7897'}
- redirect_location：https://selffashion.shop/cgi-sys/suspendedpage.cgi
- redirect_final_url：https://selffashion.shop/cgi-sys/suspendedpage.cgi
- title：302 Found
- visible_text_excerpt：302 Found @media (prefers-color-scheme:dark){body{background-color:#000!important}} 302 Found The document has been temporarily moved.
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<!DOCTYPE html> <html style="height:100%"> <head> <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" /> <title> 302 Found </title><style>@media (prefers-color-scheme:dark){body{background-color:#000!important}}</style></head> <body style="color: #444; margin:0;font: normal 14px/20px Arial, Helvetica, sans-serif; height:100%; background-color: #fff;"> <div style="height:auto; min-height:100%; "> <div style="text-align: center; width:800px; margin-left: -400px; position:absolute; top: 30%; left:50%;"> <h1 style="margin:0; font-size:150px; line-height:150px; font-weight:bold;">302</h1> <h2 style="margin-top:20px;font-size: 30px;">Found </h2> <p>The document has been temporarily moved.</p> </div></div></body></html> ', 'text_excerpt': '302 Found @media (prefers-color-scheme:dark){body{background-color:#000!important}} 302 Found The document has been temporarily moved.'}
- external_intel：{'crt_earliest_cert_date': '2024-08-13T00:00:00', 'crt_age_days': 681, 'crt_total_certs': 48}

## 四点一、页面线索
- 抓取模式：`proxy`
- 代理是否参与：`True`

### 外部情报
- 最早证书签发时间：`2024-08-13T00:00:00`
- 证书历史天数：`681` 天
- 证书总数：`48` 张

## 五、截图证据
- 当前未采集到页面截图。

## 六、风险证据
- 未发现明显风险项。

## 七、论坛式协同研判
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


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
