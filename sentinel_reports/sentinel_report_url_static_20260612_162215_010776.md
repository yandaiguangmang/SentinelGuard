# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**HIGH** · 风险分数：**56/100**

## 一、检测结论
- 原始输入：`https://baksmany.org/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：1 条
- 高危证据：1 条

## 二、统一 IR 摘要
- 规范化 URL：`https://baksmany.org/`
- 协议：`https`
- 主机：`baksmany.org`
- 路径：`/`
- 查询参数数量：`0`

## 三、跳转链
- https://baksmany.org/

## 四、页面线索
- status_code：200
- content_type：text/html; charset=utf-8
- final_url：https://baksmany.org/
- body_limited_to_bytes：200000
- title：Digital Currency Exchange, Buying and Selling Bitcoin
- password_forms：4
- hidden_inputs：1
- meta_refresh：无
- script_srcs：/__lemmed_bm.js
- form_actions：无
- download_links：无
- external_script_count：0

## 五、风险证据
### 1. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`high`
- 说明：页面要求输入密码或类似凭据，若域名并非官方域名则存在钓鱼风险。
- 证据：`密码框数量: 4`
- 建议：仅在确认域名归属和证书可信后输入账号密码。


## 六、论坛式协同研判
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


## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面截图比对。
