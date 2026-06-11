# SentinelGuard 哨塔检测报告

- 风险等级：high
- 风险分数：78/100
- 报告类型：模型深度检查报告
- 原始输入：http://example.com/login?redirect=http://evil.test
- 对象类型：url
- 状态：ready
- 关联静态 HTML 报告：sentinel_reports/sentinel_report_url_static_20260611_234833_959713.html
- 关联静态 Markdown 报告：sentinel_reports/sentinel_report_url_static_20260611_234833_959713.md

## 统一 IR 摘要
- 规范化 URL：http://example.com/login?redirect=http://evil.test
- 协议：http
- 主机：example.com
- 路径：/login
- 参数数量：1

## 跳转链
- http://example.com/login?redirect=http://evil.test

## 页面线索
- status_code：404
- content_type：text/html
- final_url：http://example.com/login?redirect=http://evil.test
- body_limited_to_bytes：200000
- title：Example Domain
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0

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

### 页面返回异常状态码
- 规则：PAGE_ERROR_STATUS
- 严重级别：low
- 说明：目标页面返回错误状态码，可能为失效链接、拦截页或临时页面。
- 证据：404
- 建议：结合来源渠道复核该链接是否仍有效。

### 重定向参数包含绝对外部链接
- 规则：DEEP_REDIRECT_PAYLOAD
- 严重级别：high
- 说明：redirect 参数值为 http://evil.test，是一个完整的绝对 URL。这是开放重定向漏洞利用的典型 payload，旨在将用户从可信域引流至攻击者控制的域名。
- 证据：redirect=http://evil.test
- 建议：后端应校验 redirect 参数是否为白名单域内的相对路径，禁止直接拼接外部绝对 URL。

### 使用保留顶级域名或保留域名
- 规则：DEEP_RESERVED_TLD_USAGE
- 严重级别：medium
- 说明：目标域名 example.com 和跳转域名 evil.test 均为 RFC 2606 规定的保留域名，不应出现在公网正式业务中。出现此类域名可能意味着本地 Host 篡改、内部网络攻击或测试环境泄露。
- 证据：hostname: example.com, redirect target: evil.test
- 建议：核查流量来源是否为内部网络，检查终端 Hosts 文件是否被篡改，确认是否为授权的安全测试。

### 登录路径返回 404 异常
- 规则：DEEP_LOGIN_PATH_404
- 严重级别：medium
- 说明：/login 路径通常对应存在的业务页面，返回 404 可能意味着钓鱼页面已被移除、链接失效或服务器配置错误。但这不影响 URL 本身构造的恶意意图。
- 证据：path: /login, status_code: 404
- 建议：即使页面不可用，也应将该 URL 特征加入阻断列表，防止未来页面恢复后造成危害。


## 模型深度研判
- **主持人**：URL 结构呈现典型的钓鱼与开放重定向攻击特征。尽管页面当前返回 404 状态，但 redirect 参数显式指向保留域名 evil.test，且主域 example.com 亦为保留域名，这种组合极大概率为恶意测试、内部威胁或钓鱼链路构造。建议维持高风险判定，不因 404 状态而放松警惕。 综合静态规则与深度研判，虽然页面状态为 404，但 URL 构造意图极其明显。保留域名的混用增加了可疑程度，风险等级维持 high，评分上调至 78 分。
- **静态分析员**：URL 结构层面存在三重风险：明文传输、敏感路径、开放重定向参数。特别是 redirect 参数直接暴露了攻击者的跳转意图。
- **行为分析员**：行为层面虽未观察到实际跳转（链长度为 1），但这是因为服务器返回了 404。若服务器修复 404 错误，该参数将立即生效导致用户被引流。
- **情报分析员**：受限于离线环境，无法查询域名信誉。但基于域名语义分析，example.com 与 evil.test 均为保留域名，公网出现此类组合极不正常，高度疑似恶意构造或内部测试。
- **处置建议员**：建议立即阻断该 URL 访问。即便当前页面不可用，其参数特征已构成威胁指标（IOC）。需排查内部网络是否存在配置错误或主机被篡改情况。

## 扩展能力占位
- **small_program**：小程序检测能力已预留：后续将解析页面结构、授权请求、跳转关系与外链证据。
- **app**：应用软件检测能力已预留：后续将解析文件元数据、权限、字符串、启动项与远程通信线索。
