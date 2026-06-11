# SentinelGuard 哨塔检测报告

- 风险等级：high
- 风险分数：54/100
- 报告类型：静态检测报告
- 原始输入：http://example.com/login?redirect=http://evil.test
- 对象类型：url
- 状态：ready

## 统一 IR 摘要
- 规范化 URL：http://example.com/login?redirect=http://evil.test
- 协议：http
- 主机：example.com
- 路径：/login
- 参数数量：1

## 跳转链
- http://example.com/login?redirect=http://evil.test

## 页面线索
- 未获取页面内容线索。

## 风险证据
### 未使用 HTTPS 加密
- 规则：URL_NON_HTTPS
- 严重级别：medium
- 说明：目标网址使用明文 HTTP，访问过程可能被窃听或篡改。
- 证据：http://example.com/login?redirect=http://evil.test
- 建议：优先访问 HTTPS 版本，不要在该页面输入账号、密码或验证码。

### 包含敏感诱导关键词
- 规则：URL_SENSITIVE_KEYWORD
- 严重级别：medium
- 说明：URL 中出现登录、验证、支付或账号相关词汇，可能诱导用户提交敏感信息。
- 证据：login
- 建议：确认域名归属后再输入身份凭据或支付信息。

### 包含跳转类参数
- 规则：URL_REDIRECT_PARAM
- 严重级别：medium
- 说明：URL 参数中包含常见跳转字段，可能被用于开放重定向或钓鱼落地页。
- 证据：redirect
- 建议：确认跳转参数指向的最终域名是否可信。


## 协同研判
- **主持人**：综合 3 条证据，当前风险等级为 high。
- **静态分析员**：URL 结构层面关注：未使用 HTTPS 加密、包含敏感诱导关键词、包含跳转类参数。
- **行为分析员**：页面行为与跳转层面关注暂未发现明显异常。
- **情报分析员**：当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。
- **处置建议员**：建议阻断访问，不输入账号密码，不下载或运行页面提供的文件，并保留链接与报告用于复核。

## 扩展能力占位
- **small_program**：小程序检测能力已预留：后续将解析页面结构、授权请求、跳转关系与外链证据。
- **app**：应用软件检测能力已预留：后续将解析文件元数据、权限、字符串、启动项与远程通信线索。
