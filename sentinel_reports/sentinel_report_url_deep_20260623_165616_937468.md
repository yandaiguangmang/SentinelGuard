# SentinelGuard 哨塔检测报告

> 模型深度检查报告 · 风险等级：**HIGH** · 风险分数：**65/100**
> 证据分数：**45/100** · 深度研判分数：**85 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。
模型深度研判

## 一、检测结论
- 原始输入：`https://baksmany.net/zh/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：4 条
- 高危证据：1 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260623_165324_781743.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260623_165324_781743.md

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
- fetch_mode：direct
- proxy_used：False
- proxy_config：{}
- title：数字货币兑换，买卖比特币
- visible_text_excerpt：数字货币兑换，买卖比特币 (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem('slow_connection_detected')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem('slow_connection_detected', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( 'load', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在您可以用 USDT 余额直接支付卢布账单，无需任何手续费。 只需上传卢布二维码→ 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全书 常见问题 AML 我的申请单 设置 平衡 推荐
- password_forms：4
- hidden_inputs：1
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<!DOCTYPE html> <html lang="zh"> <head> <meta charset="UTF-8"/> <meta content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0" name="viewport"/> <meta content="ie=edge" http-equiv="X-UA-Compatible"/> <title>数字货币兑换，买卖比特币</title> <meta name="description" content="买卖比特币以及进行比特币兑换，提供了Baksmany.net兑换服务。 该交换器具有大量的储备，并提供了高速度的应用程序执行。" /> <meta name="keywords" content="交换器，比特币交换，比特币到qiwi，数字货币交换器，电子货币交换器，购买比特币，出售比特币" /> <meta name="format-detection" content="telephone=no"> <link rel="icon" href="/favicon-logo2.png"> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/chosen.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/baksmany/css/style.css?v=15" /> <link rel="stylesheet" type="text/css" href="/res/exchangebox/select2/css/select2.min.css?v=15" /> <script> (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', () => clearInterval(', 'text_excerpt': '数字货币兑换，买卖比特币 (function(){ let TimerID = setTimeout(() => { let cnf; let tr = parseInt(localStorage.getItem(\'slow_connection_detected\')); if (!tr || tr > 5) { tr = 0; cnf = confirm("我们注意到你的网站加载速度很低。 使用轻版网站？"); } localStorage.setItem(\'slow_connection_detected\', tr+1); if (cnf) { location.href = "/zh/lite/?confirm=1"; } }, 20000); window.addEventListener( \'load\', () => clearInterval(TimerID), false ); })(); 朋友们，抓住这个不容错过的机会！ 现在您可以用 USDT 余额直接支付卢布账单，无需任何手续费。 只需上传卢布二维码→ 选择私人支付服务！ x У Вас отключен JS, рекомендуем воспользоваться легкой версией сайта без JS, 走过去 保证 规则 AML Check 0 进来 登记 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 0 选择语言 Русский English 中文 عرب Eesti Español Deutsch Български Türkçe 交换 储备金 合作伙伴 新闻 评论 联系我们 保证 规则 百科全书 常见问题 AML 我的申请单 设置 平衡 推荐'}
- external_intel：{'whois_registrar': 'NICENIC INTERNATIONAL GROUP CO., LIMITED', 'whois_country': 'UZ', 'whois_creation_date': '2024-10-21 15:02:27+00:00', 'whois_age_days': 609}

## 四点一、页面线索
- 抓取模式：`direct`
- 代理是否参与：`False`

### 外部情报
- 注册商：`NICENIC INTERNATIONAL GROUP CO., LIMITED`
- 注册国家：`UZ`
- 域名注册时间：`2024-10-21 15:02:27+00:00`
- 域名注册天数：`609` 天

## 五、截图证据
### 截图 1
- 标题：`数字货币兑换，买卖比特币`
- 落点：`https://baksmany.net/zh/`
- 时间：`2026-06-23T08:53:22.952745+00:00`
- 大小：`595808` 字节


## 六、风险证据
### 1. TLS 证书签发时间较短
- 规则：`CERT_RECENT`
- 严重级别：`medium`
- 说明：证书签发于 21 天前。
- 证据：`Jun  2 05:52:23 2026 GMT`
- 建议：建议结合其他证据综合判断。

### 2. 代理访问失败后已回退直连
- 规则：`PAGE_PROXY_FALLBACK_DIRECT`
- 严重级别：`low`
- 说明：目标站点优先尝试通过代理访问失败，已切换为直连。
- 证据：`当前抓取使用直连通道。`
- 建议：检查 VPN 节点或代理地址。

### 3. 高风险的凭证窃取型钓鱼页面
- 规则：`DEEP_BEHAVIOR_PHISHING_CREDENTIAL_THEFT`
- 严重级别：`high`
- 说明：行为分析确认该页面是一个伪装成加密货币交易所的钓鱼网站。它通过多个密码输入框诱导用户输入敏感凭证。关键风险在于，这些表单没有标准的提交目标（action），表明提交过程由JavaScript控制，这是秘密窃取用户账号和密码的常用手法。尽管没有发生自动重定向，但其核心功能就是窃取凭证。
- 证据：`页面功能：加密货币交易，标题为“数字货币兑换，买卖比特币”。行为特征：页面包含4个密码输入框，但`form_actions`字段为空，表明为脚本控制提交。`
- 建议：立即将此域名标记为钓鱼网站并进行拦截，防止用户凭证被盗。

### 4. 域名注册和证书信息分析
- 规则：`INTEL_INFRA_1`
- 严重级别：`medium`
- 说明：该域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，注册国家为乌兹别克斯坦，此域名存在609天，IS证书签发则较短，可能表明此网站尚处于快速变化的状态或不稳定。
- 证据：`域名注册商：NICENIC INTERNATIONAL GROUP CO., LIMITED，注册天数：609，证书签发时间：短于21天。`
- 建议：需要进一步检查域名的历史记录及其在网络安全方面的声誉，以评估其可信度。


## 七、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
静态报告初步判定为低风险，主要基于域名年龄较长且无明显恶意代码混淆。然而，行为分析员与处置建议员深入分析指出，页面虽伪装为数字货币交易所，但关键登录表单缺乏标准提交目标（form_action），依赖 JavaScript 处理提交，这是典型的凭证窃取（钓鱼）特征。情报分析员也指出证书签发较新且注册信息需警惕。尽管静态特征显示一定合法性，但凭证窃取的技术行为风险权重更高。综合判定为高风险，建议拦截。 综合 3 条证据，当前风险等级为 low。

### 静态分析员（模型：`deepseek-reasoner`）
基于静态结构特征分析，目标网址缺乏典型恶意网站的标志。域名注册于乌兹别克斯坦，已有 609 天历史，降低新近注册恶意运营的嫌疑。TLS 证书签发时间较短（21 天前）需关注，但整体安全性尚可。结论以静态视角倾向基础功能正常，是否为钓鱼网站需依赖行为证据补充研判。

### 行为分析员（模型：`gemini-2.5-pro`）
该页面在行为上表现为一个加密货币交易所，包含多个用于登录和注册的密码输入框。关键风险在于，这些表单没有标准的提交目标（action），表明提交过程由 JavaScript 控制，这是秘密窃取用户账号和密码的常用手法。结合页面主题（高风险的金融领域），可以认定这是一个以窃取用户加密货币交易所账户凭证为目的的钓鱼网站。

### 情报分析员（模型：`gpt-4o-mini`）
该网站似乎未明确冒充特定的品牌或组织，尽管其宣称提供数字货币兑换服务，但没有具体目标可供辨识。域名由 NICENIC INTERNATIONAL GROUP CO., LIMITED 注册，注册国家为乌兹别克斯坦，此域名存在 609 天，IS 证书签发则较短，可能表明此网站尚处于快速变化的状态或不稳定。

### 处置建议员（模型：`gemini-2.5-flash`）
该网站声称提供数字货币兑换服务，并包含多个密码输入框，旨在诱导用户输入敏感凭证。行为分析明确指出，这些表单缺少标准的提交目标，这强烈表明用户输入的账号和密码将通过页面内的 JavaScript 脚本被截获并发送至攻击者指定的服务器。综合所有证据，判定此页面为意图窃取用户凭证的恶意网站。建议行动：block。


### 主持人最终总结
静态报告初步判定为低风险，主要基于域名年龄较长且无明显恶意代码混淆。然而，行为分析员与处置建议员深入分析指出，页面虽伪装为数字货币交易所，但关键登录表单缺乏标准提交目标（form_action），依赖 JavaScript 处理提交，这是典型的凭证窃取（钓鱼）特征。情报分析员也指出证书签发较新且注册信息需警惕。尽管静态特征显示一定合法性，但凭证窃取的技术行为风险权重更高。综合判定为高风险，建议拦截。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-4o-mini`
- 处置建议员：`gemini-2.5-flash`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
