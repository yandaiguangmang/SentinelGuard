# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**CRITICAL** · 风险分数：**92/100**
> 证据分数：**92/100** · 深度研判分数：**- /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`http://example.com/login?redirect=http://evil.test`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：3 条
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
- fetch_mode：direct
- proxy_used：False
- proxy_config：{}
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
- external_intel：{}

## 四点一、页面线索
- 抓取模式：`direct`
- 代理是否参与：`False`

## 五、截图证据
### 截图 1


## 六、风险证据
### 1. 可执行文件下载
- 规则：`PAGE_DOWNLOAD_EXECUTABLE`
- 严重级别：`critical`
- 说明：tool.apk
- 证据：`tool.apk`
- 建议：不要下载。

### 2. 域名与知名品牌高度相似
- 规则：`URL_BRAND_LOOKALIKE`
- 严重级别：`high`
- 说明：example.com 与 apple.com 相似度 0.80，可能为仿冒/抢注域名。
- 证据：`example.com vs apple.com`
- 建议：核实该域名是否为品牌官方注册，避免输入相关账号密码。

### 3. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`medium`
- 说明：密码表单提交与当前域名一致或为相对路径，可能为正常登录功能。
- 证据：`密码框数量: 1`
- 建议：确认域名归属和证书可信后再输入账号密码。


## 七、论坛式协同研判
### 主持人（模型：`unknown`）
综合 6 条证据，当前风险等级为 critical。

### 静态分析员（模型：`unknown`）
URL 结构层面关注：域名与知名品牌高度相似、可执行文件下载、包含敏感诱导关键词、包含跳转类参数、页面包含密码输入框。

### 行为分析员（模型：`unknown`）
页面行为与跳转层面关注：页面包含密码输入框、可执行文件下载。

### 情报分析员（模型：`unknown`）
当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`unknown`）
建议阻断访问，不输入账号密码，不下载或运行页面提供的文件，并保留链接与报告用于复核。


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
