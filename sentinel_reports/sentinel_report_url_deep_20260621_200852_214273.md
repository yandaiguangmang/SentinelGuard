# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**CRITICAL** · 风险分数：**95/100**
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：15 条
- 高危证据：7 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260621_200811_475840.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260621_200811_475840.md

## 二、统一 IR 摘要
- 规范化 URL：`https://baksmany.net/zh/`
- 协议：`https`
- 主机：`baksmany.net`
- 路径：`/zh/`
- 查询参数数量：`0`

## 三、跳转链
- https://baksmany.net/zh/

## 四、页面线索
- status_code：200
- content_type：text/html; charset=UTF-8
- final_url：https://baksmany.net/zh/
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://127.0.0.1:7897', 'https': 'http://127.0.0.1:7897', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- title：数字货币兑换，买卖比特币
- visible_text_excerpt：数字货币兑换，买卖比特币 (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem('slow_connection_detected')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem('slow_connection_detected', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( 'load', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码 → 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全书 常见问题 AML 我的申请单 设置 平衡 推
- password_forms：4
- hidden_inputs：1
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<!DOCTYPE html> <html lang="zh"> <head> <meta charset="UTF-8"/> <meta content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0" name="viewport"/> <meta content="ie=edge" http-equiv="X-UA-Compatible"/> <title>数字货币兑换，买卖比特币</title> <meta name="description" content="买卖比特币以及进行比特币兑换，提供了Baksmany.net兑换服务。 该交换器具有大量的储备，并提供了高速度的应用程序执行。" /> <meta name="keywords" content="交换器，比特币交换，比特币到qiwi，数字货币交换器，电子货币交换器，购买比特币，出售比特币" /> <meta name="format-detection" content="telephone=no"> <link rel="icon" href="/favicon-logo2.png"> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/chosen.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/style.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/exchangebox/select2/css/select2.min.css?v=15" /> <script> (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', () => clearInterval(', 'text_excerpt': '数字货币兑换，买卖比特币 (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。 只需上传卢布QR码 → 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全书 常见问题 AML 我的申请单 设置 平衡 推'}

## 四点一、APK 动态沙箱摘要
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、截图证据
- 截图数量：`1` 张，完整图像请查看 HTML 报告。
- 截图 1：
  - URL：`https://baksmany.net/zh/`
  - 最终地址：`https://baksmany.net/zh/`
  - 大小：`596894` 字节
  - 视口：`{'width': 1440, 'height': 1600}`

## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 19 天前。
- 证据：`签发时间: Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 页面包含密码输入框
- 规则：`PAGE_PASSWORD_FORM`
- 严重级别：`medium`
- 说明：页面要求输入密码或类似凭据。表单提交目标与当前域名一致或为相对路径，单独看属于常见站点功能（登录/评论/会员系统等），仍建议结合域名信誉综合判断。
- 证据：`密码框数量: 4`
- 建议：确认域名归属和证书可信后再输入账号密码。

### 3. 诱导性金融文案与高风险交互
- 规则：`DEEP_STATIC_SUSPICIOUS_CONTENT`
- 严重级别：`critical`
- 说明：页面包含“抓住这个不容错过的机会”、“零手续费”等典型的金融诱导性话术，结合页面内存在的4个密码输入框，极易诱导用户输入敏感凭据。
- 证据：`可见文本中包含：'朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单'`
- 建议：严禁在该站点输入任何账号密码或进行任何资金转账操作。

### 4. 极短的证书生命周期
- 规则：`DEEP_STATIC_CERT_AGE`
- 严重级别：`high`
- 说明：证书签发时间仅为19天前，对于涉及资金交易的平台而言，极短的证书生命周期是典型的欺诈站点特征。
- 证据：`签发时间: Jun 2 2026 (基于当前日期推算)`
- 建议：此类站点通常为短期存活的钓鱼平台，建议将其列入黑名单。

### 5. 未发现品牌模仿
- 规则：`INTEL_BRAND_IMPERSONATION`
- 严重级别：`low`
- 说明：该页面没有明显模仿任何特定品牌或组织，内容主要围绕数字货币交易。
- 证据：`页面标题和内容均未提及任何知名品牌。`
- 建议：建议继续监控该域名的活动以确认其合法性。

### 6. 域名注册信息缺乏
- 规则：`INTEL_INFRA_DOMAIN`
- 严重级别：`medium`
- 说明：未能获取到该域名的注册信息及其信誉数据，可能影响对其合法性的判断。
- 证据：`域名注册信息未在可用情报源中找到。`
- 建议：建议使用WHOIS查询工具进一步调查域名的注册信息。

### 7. 可能存在地理位置差异
- 规则：`INTEL_COVERAGE_GEOGRAPHIC`
- 严重级别：`medium`
- 说明：可能存在因地理位置或网络环境导致的内容差异，需注意潜在的内容隐藏或变更。
- 证据：`页面内容可能因用户的地理位置而有所不同，尤其是涉及支付服务时。`
- 建议：建议在不同网络环境下进行多次访问以确认内容一致性。

### 8. 页面伪装成加密货币交易所，诱导用户输入凭据
- 规则：`DEEP_BEHAVIOR_CRYPTO_PHISHING_INDICATION`
- 严重级别：`high`
- 说明：页面呈现为一个完整的加密货币交易平台，包含登录、注册功能，并设有四个密码输入框。这种设计旨在获取用户的登录密码、交易密码等多重凭据，是典型的加密货币钓鱼或投资诈骗手法。结合其较新的TLS证书，该网站具有很高的风险。
- 证据：`浏览器证据显示页面标题为“数字货币兑换，买卖比特币”，页面内容涉及USDT、比特币交易，并检测到4个密码输入框。无自动跳转或恶意下载行为，所有行为都围绕诱导用户在“平台”上进行操作和输入。`
- 建议：立即阻止访问该URL。切勿在该网站上输入任何个人信息、账户密码或进行任何充值操作。

### 9. 高风险钓鱼特征
- 规则：`DEEP_ADVICE_PHISHING_INTENT`
- 严重级别：`critical`
- 说明：页面包含4个密码输入框，且伴随典型的金融诱导性文案，旨在诱骗用户输入敏感凭据。
- 证据：`页面包含4个密码输入框，且文案中存在“抓住这个不容错过的机会”、“零手续费”等诱导性内容。`
- 建议：立即将该域名加入黑名单，禁止用户访问。

### 10. 证书生命周期异常
- 规则：`DEEP_ADVICE_CERT_RISK`
- 严重级别：`high`
- 说明：TLS证书签发时间仅为19天前，符合短期存活钓鱼站点的特征。
- 证据：`证书签发时间: Jun 2 2026`
- 建议：对该类新注册且涉及金融交易的站点采取严格拦截策略。

### 11. 建议持续监控
- 规则：`DEEP_ADVICE_MONITORING`
- 严重级别：`medium`
- 说明：虽然当前未发现恶意下载或自动跳转行为，但其钓鱼意图明显。
- 证据：`页面结构完整，主要通过诱导交互获取信息。`
- 建议：在安全网关层面记录所有访问该域名的日志，以便后续溯源。

### 12. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书较新，放在当前证据组合下更像是中到高风险辅助信号，而不是单独定性依据。
- 证据：`签发时间: Jun 2 05:52:23 2026 GMT`
- 建议：结合页面交互意图与域名信誉进一步核查，不要仅凭证书新旧直接放行。

### 13. 诱导性金融文案与高风险交互
- 规则：`DEEP_STATIC_SUSPICIOUS_CONTENT`
- 严重级别：`high`
- 说明：页面中出现“抓住这个不容错过的机会”“零手续费”等诱导性金融话术，与密码输入框并存时，整体风险显著升高。
- 证据：`可见文本包含：'朋友们，抓住这个不容错过的机会！ 现在你可以用零手续费支付卢布账单——直接从USDT余额中扣除。'`
- 建议：将其视为高风险诱导页面处理，禁止输入敏感信息并建议拦截访问。

### 14. 页面伪装成加密货币交易所，诱导用户输入凭据
- 规则：`DEEP_BEHAVIOR_CRYPTO_PHISHING_INDICATION`
- 严重级别：`high`
- 说明：页面外观和文案都围绕数字货币交易展开，但核心交互是引导用户提交凭据，属于高风险钓鱼/诈骗常见模式。
- 证据：`页面标题为“数字货币兑换，买卖比特币”，并检测到4个密码输入框；未见外部脚本、自动下载或强制跳转。`
- 建议：立即阻断访问，并记录访问日志用于后续溯源。

### 15. 域名注册与信誉情报不足
- 规则：`INTEL_INFRA_DOMAIN`
- 严重级别：`medium`
- 说明：当前缺少可用的 WHOIS、信誉或黑名单交叉验证信息，因此最终判断主要依赖离线页面证据。
- 证据：`可用情报源中未获取到该域名注册与信誉数据。`
- 建议：补充域名注册信息、证书透明度与信誉黑名单后再做进一步复核。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5.4-mini`）
基于静态检测结果、浏览器证据包以及四位专家意见，当前页面更符合“加密货币兑换/交易外观下的高风险钓鱼或投资诈骗站点”特征，而不是普通的合规业务页面。离线证据显示：页面标题为“数字货币兑换，买卖比特币”，可见文本中出现明显的金融诱导话术，如“抓住这个不容错过的机会”“零手续费”“直接从USDT余额中扣除”，同时检测到4个密码输入框和1个隐藏字段。TLS 证书签发时间较短，进一步增强了站点短期部署、快速更换的风险印象。当前未见外部情报或联网信誉数据可用于交叉验证，因此结论主要依赖离线证据。专家意见方面，静态分析员和处置建议员给出 malicious_lean/critical 方向，行为分析员给出 malicious_lean/high，情报分析员则偏向 benign_lean/medium；这说明存在明确方向冲突，且风险提示跨度超过两级。综合页面诱导性文案、密码框数量、金融交易语境和较新的证书信息，我最终采纳高风险恶意倾向判断，但不将其上升为已确认的恶意执行型样本，因为当前没有发现下载、自动跳转、外联脚本或明显的代码投递行为。建议在隔离环境中阻断访问，并禁止输入任何账号、密码或资产相关信息。 综合 2 条证据，当前风险等级为 medium。

### 静态分析员（模型：`gemini-2.5-flash`）
页面呈现为数字货币兑换平台，但存在短期证书与多个密码输入框等高风险特征，倾向判断为恶意倾向较强。

### 行为分析员（模型：`gemini-2.5-pro`）
页面行为主要围绕诱导用户输入多项密码凭据，符合伪装成加密货币交易所的钓鱼或诈骗平台特征。

### 情报分析员（模型：`gpt-4o-mini`）
当前版本主要依赖离线规则研判，未发现品牌模仿；缺乏域名注册与信誉情报，建议补充外部情报。

### 处置建议员（模型：`gemini-2.5-flash`）
建议在隔离浏览器中复核最终域名，不在页面提交敏感信息，并倾向直接阻断访问。


### 主持人最终总结
基于静态检测结果、浏览器证据包以及四位专家意见，当前页面更符合“加密货币兑换/交易外观下的高风险钓鱼或投资诈骗站点”特征，而不是普通的合规业务页面。离线证据显示：页面标题为“数字货币兑换，买卖比特币”，可见文本中出现明显的金融诱导话术，如“抓住这个不容错过的机会”“零手续费”“直接从USDT余额中扣除”，同时检测到4个密码输入框和1个隐藏字段。TLS 证书签发时间较短，进一步增强了站点短期部署、快速更换的风险印象。当前未见外部情报或联网信誉数据可用于交叉验证，因此结论主要依赖离线证据。专家意见方面，静态分析员和处置建议员给出 malicious_lean/critical 方向，行为分析员给出 malicious_lean/high，情报分析员则偏向 benign_lean/medium；这说明存在明确方向冲突，且风险提示跨度超过两级。综合页面诱导性文案、密码框数量、金融交易语境和较新的证书信息，我最终采纳高风险恶意倾向判断，但不将其上升为已确认的恶意执行型样本，因为当前没有发现下载、自动跳转、外联脚本或明显的代码投递行为。建议在隔离环境中阻断访问，并禁止输入任何账号、密码或资产相关信息。


### 专家模型映射
- 主持人：`gpt-5.4-mini`
- 静态分析员：`gemini-2.5-flash`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。


## 九、分析性能统计

- 总耗时：38.86 秒

| 角色 | 耗时 (秒) | 输入 Token | 输出 Token | 总 Token |
|------|-----------|------------|------------|----------|
| 静态分析员 | 3.86 | 3767 | 492 | 4259 |
| 情报分析员 | 5.39 | 3679 | 402 | 4081 |
| 行为分析员 | 24.88 | 4114 | 366 | 4480 |
| 处置建议员 | 5.64 | 5158 | 470 | 5628 |
| 主持人 | 8.33 | 5475 | 1557 | 7032 |
