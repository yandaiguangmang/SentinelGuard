# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**LOW** · 风险分数：**0/100**


## 一、检测结论
- 原始输入：`https://baksmany.org/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：0 条
- 高危证据：0 条

## 二、统一 IR 摘要
- 规范化 URL：`https://baksmany.org/`
- 协议：`https`
- 主机：`baksmany.org`
- 路径：`/`
- 查询参数数量：`0`

## 三、跳转链
- https://baksmany.org/
- https://baksmany.org/en/

## 四、页面线索
- status_code：302
- content_type：text/html; charset=utf-8
- final_url：https://baksmany.org/en/
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://127.0.0.1:7897', 'https': 'http://127.0.0.1:7897', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- redirect_location：/en/
- redirect_final_url：https://baksmany.org/en/
- title：
- visible_text_excerpt：Found .
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<a href="/en/">Found</a>. ', 'text_excerpt': 'Found .'}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、截图证据
- 未采集到截图证据。

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
