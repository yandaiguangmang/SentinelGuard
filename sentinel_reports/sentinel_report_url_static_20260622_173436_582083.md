# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**LOW** · 风险分数：**6/100**
> 证据分数：**6/100** · 深度研判分数：**- /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`https://www.google.com`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：1 条
- 高危证据：0 条

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
### 1. 跨域跳转
- 规则：`REDIRECT_CROSS_DOMAIN`
- 严重级别：`low`
- 说明：目标链接跳转到不同域名。
- 证据：`www.google.com -> www.google.com.hk`
- 建议：以最终域名为准判断可信度。


## 七、论坛式协同研判
### 主持人（模型：`unknown`）
综合 1 条证据，当前风险等级为 low。

### 静态分析员（模型：`unknown`）
URL 结构层面关注暂未发现明显异常。

### 行为分析员（模型：`unknown`）
页面行为与跳转层面关注：跨域跳转。

### 情报分析员（模型：`unknown`）
当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`unknown`）
可低风险访问，但仍需确认链接来源可信。


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
