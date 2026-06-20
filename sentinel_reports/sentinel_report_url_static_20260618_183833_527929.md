# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**MEDIUM** · 风险分数：**34/100**


## 一、检测结论
- 原始输入：`http://example.com/login?redirect=http://evil.test`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：3 条
- 高危证据：0 条

## 二、统一 IR 摘要
- 规范化 URL：`http://example.com/login?redirect=http://evil.test`
- 协议：`http`
- 主机：`example.com`
- 路径：`/login`
- 查询参数数量：`1`

## 三、跳转链
- http://example.com/login?redirect=http://evil.test

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要

## 五、风险证据
### 1. 未使用 HTTPS 加密
- 规则：`URL_NON_HTTPS`
- 严重级别：`medium`
- 说明：目标网址使用明文 HTTP，访问过程可能被窃听或篡改。
- 证据：`http://example.com/login?redirect=http://evil.test`
- 建议：优先访问 HTTPS 版本，不要在该页面输入账号、密码或验证码。

### 2. 包含敏感诱导关键词
- 规则：`URL_SENSITIVE_KEYWORD`
- 严重级别：`medium`
- 说明：URL 中出现登录、验证、支付或账号相关词汇，可能诱导用户提交敏感信息。
- 证据：`login`
- 建议：确认域名归属后再输入身份凭据或支付信息。

### 3. 包含跳转类参数
- 规则：`URL_REDIRECT_PARAM`
- 严重级别：`medium`
- 说明：URL 参数中包含常见跳转字段，可能被用于开放重定向或钓鱼落地页。
- 证据：`redirect`
- 建议：确认跳转参数指向的最终域名是否可信。


## 六、论坛式协同研判
### 主持人（模型：`unknown`）
综合 3 条证据，当前风险等级为 medium。

### 静态分析员（模型：`unknown`）
URL 结构层面关注：未使用 HTTPS 加密、包含敏感诱导关键词、包含跳转类参数。

### 行为分析员（模型：`unknown`）
页面行为与跳转层面关注暂未发现明显异常。

### 情报分析员（模型：`unknown`）
当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`unknown`）
建议在隔离浏览器中复核最终域名，不在页面提交敏感信息。


## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
