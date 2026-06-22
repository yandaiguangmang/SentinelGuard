# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**MEDIUM** · 风险分数：**28/100**


## 一、检测结论
- 原始输入：`https://baksmany.net/zh`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：1 条
- 高危证据：0 条

## 二、统一 IR 摘要
- 规范化 URL：`https://baksmany.net/zh`
- 协议：`https`
- 主机：`baksmany.net`
- 路径：`/zh`
- 查询参数数量：`0`

## 三、跳转链
- https://baksmany.net/zh
- https://baksmany.net/zh/zh

## 四、页面线索
- status_code：302
- content_type：text/html; charset=UTF-8
- final_url：https://baksmany.net/zh/zh
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://127.0.0.1:7897', 'https': 'http://127.0.0.1:7897', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- redirect_location：/zh/zh
- redirect_final_url：https://baksmany.net/zh/zh
- title：
- visible_text_excerpt：
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '', 'text_excerpt': ''}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、截图证据
- 截图数量：`1` 张，完整图像请查看 HTML 报告。
- 截图 1：
  - URL：`https://baksmany.net/zh`
  - 最终地址：`https://baksmany.net/zh/zh`
  - 大小：`596121` 字节
  - 视口：`{'width': 1440, 'height': 1600}`

## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 19 天前。
- 证据：`签发时间: Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。


## 七、论坛式协同研判
### 主持人（模型：`unknown`）
综合 1 条证据，当前风险等级为 medium。

### 静态分析员（模型：`unknown`）
URL 结构层面关注：TLS 证书签发时间较短。

### 行为分析员（模型：`unknown`）
页面行为与跳转层面关注暂未发现明显异常。

### 情报分析员（模型：`unknown`）
当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`unknown`）
建议在隔离浏览器中复核最终域名，不在页面提交敏感信息。


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
