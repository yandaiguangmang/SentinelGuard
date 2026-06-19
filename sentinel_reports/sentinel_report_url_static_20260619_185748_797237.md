# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**HIGH** · 风险分数：**70/100**


## 一、检测结论
- 原始输入：`http://example.com/login?redirect=http://evil.test`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：5 条
- 高危证据：2 条

## 二、统一 IR 摘要
- 规范化 URL：`http://example.com/login?redirect=http://evil.test`
- 协议：`http`
- 主机：`example.com`
- 路径：`/login`
- 查询参数数量：`1`

## 三、跳转链
- http://example.com/login?redirect=http://evil.test
- http://example.com/start

## 四、页面线索
- status_code：200
- content_type：text/html; charset=utf-8
- final_url：http://example.com/start
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://10.250.167.176:7890', 'https': 'http://10.250.167.176:7890'}
- title：Login
- visible_text_excerpt：Login download
- password_forms：1
- hidden_inputs：1
- meta_refresh：无
- script_srcs：无
- form_actions：/login
- download_links：tool.apk
- external_script_count：0
- html_summary：{'raw_excerpt': "<html><head><title>Login</title></head><body><form action='/login'><input type='password'><input type='hidden'><a href='tool.apk'>download</a></form></body></html>", 'text_excerpt': 'Login download'}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、截图证据
- 截图数量：`1` 张，完整图像请查看 HTML 报告。
- 截图 1：
  - URL：``
  - 最终地址：``
  - 大小：`0` 字节
  - 视口：`{}`

## 六、风险证据
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

### 4. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`high`
- 说明：页面要求输入密码或类似凭据，若域名并非官方域名则存在钓鱼风险。
- 证据：`密码框数量: 1`
- 建议：仅在确认域名归属和证书可信后输入账号密码。

### 5. 页面包含可疑下载链接
- 规则：`PAGE_DOWNLOAD_LINK`
- 严重级别：`high`
- 说明：页面包含可执行文件、脚本或压缩包下载入口。
- 证据：`tool.apk`
- 建议：不要直接打开下载文件，应先在隔离环境中检测。


## 七、论坛式协同研判
### 主持人（模型：`unknown`）
综合 5 条证据，当前风险等级为 high。

### 静态分析员（模型：`unknown`）
URL 结构层面关注：页面包含密码输入框、页面包含可疑下载链接、未使用 HTTPS 加密、包含敏感诱导关键词、包含跳转类参数。

### 行为分析员（模型：`unknown`）
页面行为与跳转层面关注：页面包含密码输入框、页面包含可疑下载链接。

### 情报分析员（模型：`unknown`）
当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`unknown`）
建议阻断访问，不输入账号密码，不下载或运行页面提供的文件，并保留链接与报告用于复核。


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
