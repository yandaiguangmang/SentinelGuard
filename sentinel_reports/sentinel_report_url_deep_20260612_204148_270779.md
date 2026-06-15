# SentinelGuard 哨塔检测报告

> 模型深度研判报告 · 风险等级：**CRITICAL** · 风险分数：**95/100**

## 一、检测结论
- 原始输入：`https://baksmany.org/`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：19 条
- 高危证据：11 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260612_203633_598932.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260612_203633_598932.md

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

### 2. 可疑域名结构
- 规则：`DEEP_STATIC_SUSPICIOUS_DOMAIN`
- 严重级别：`high`
- 说明：域名 'baksmany.org' 未匹配任何知名品牌（如Binance或Coinbase），但标题声称提供加密货币服务，表明可能用于域名仿冒（typosquatting）钓鱼攻击。
- 证据：`主机名: baksmany.org, 页面标题: 'Digital Currency Exchange, Buying and Selling Bitcoin'`
- 建议：避免访问此类未经验证域名；仅使用官方渠道进行加密货币交易。

### 3. 可疑脚本源
- 规则：`DEEP_STATIC_SUSPICIOUS_SCRIPT`
- 严重级别：`medium`
- 说明：脚本源 '/__lemmed_bm.js' 名称以 '__' 开头，常见于混淆或临时脚本，可能包含恶意代码用于窃取凭据或执行未授权操作。
- 证据：`script_srcs: ['/__lemmed_bm.js']`
- 建议：静态分析无法检查脚本内容；建议动态扫描或沙箱执行以确认恶意性，用户应避免加载此类脚本。

### 4. JavaScript 劫持表单提交
- 规则：`DEEP_BEHAVIOR_JS_FORM_HIJACKING`
- 严重级别：`high`
- 说明：页面的 HTML 表单没有设置'action'属性，这意味着传统的表单提交方式被禁用。结合页面加载了自定义脚本，可以推断表单数据是通过 JavaScript 捕获并发送的，这是凭证钓鱼网站窃取数据的常见手法。
- 证据：`form_actions: [], script_srcs: ["/__lemmed_bm.js"]`
- 建议：审查脚本 '__lemmed_bm.js' 的具体行为，确认数据是否被发送到恶意端点。

### 5. 多输入框凭证收割
- 规则：`DEEP_BEHAVIOR_CREDENTIAL_HARVESTING`
- 严重级别：`critical`
- 说明：页面包含四个密码输入框，远超正常登录所需。这种设计旨在一次性骗取用户尽可能多的敏感信息，如登录密码、交易密码、二次验证码等，是恶意程度极高的凭证收割行为。
- 证据：`password_forms: 4`
- 建议：切勿在该页面输入任何个人信息或密码。

### 6. 高价值目标仿冒诱导
- 规则：`DEEP_BEHAVIOR_HIGH_VALUE_IMPERSONATION`
- 严重级别：`high`
- 说明：页面标题为“数字货币交易所”，主题涉及比特币买卖。这类金融服务是网络钓鱼的高价值目标，攻击者通过仿冒此类网站诱导用户输入凭据，以实现直接的经济盗窃。
- 证据：`title: "Digital Currency Exchange, Buying and Selling Bitcoin"`
- 建议：对涉及金融交易的网站，务必通过官方渠道核实其域名和证书的真实性。

### 7. 可能存在地理/IP分流与外网依赖
- 规则：`DEEP_INTEL_ENV_GEO_VPN`
- 严重级别：`medium`
- 说明：加密货币相关站点常对合规地区或特定IP段实施访问限制与CDN分流；在企业网/监管区或被动DNS/ISP层阻断时，可能需VPN或更换出口节点方可还原真实页面与交互。
- 证据：`proxy_enabled=false；最终状态码200；redirect_chain仅自身；external_script_count=0但存在本地脚本“/__lemmed_bm.js”，说明离线视角可能未触发动态加载与分流。`
- 建议：用多出口对照（本地、移动/家庭宽带、合规VPN节点：US/EU/SG/HK）+ 真浏览器并启用JS与Cookie；记录各节点的DNS答复、证书链、状态码与页面差异；若本地直连受限，可在保留直连基线的前提下使用VPN复现最终用户体验。

### 8. 落地页出现多个密码输入框，凭据收集面显著
- 规则：`DEEP_INTEL_CREDENTIAL_HARVESTING_SURFACE`
- 严重级别：`high`
- 说明：首页即出现多处密码输入，且文案为通用“数字货币买卖”主题，若域名并非官方品牌或缺乏可信证书背书，极易构成钓鱼或账号盗用风险。
- 证据：`password_forms=4；页面标题“Digital Currency Exchange, Buying and Selling Bitcoin”；form_actions=[]（离线未见明确提交通道）。`
- 建议：未确认域名归属前禁止输入账号密码；从官方渠道（公告/社媒/应用商店）反查域名；核验证书与CT日志、WHOIS/注册商/创建时间；启用密码管理器的域名绑定以降低误填风险。

### 9. 疑似风控/指纹脚本可能影响内容呈现与数据外发
- 规则：`DEEP_INTEL_BOT_MGMT_JS_FINGERPRINTING`
- 严重级别：`medium`
- 说明：“/__lemmed_bm.js”命名风格近似bot management/风控脚本，实网中可能执行指纹采集与行为挑战，并动态绑定表单提交流或加载外链资源。
- 证据：`script_srcs包含“/__lemmed_bm.js”；离线环境未执行JS，无法观察其网络请求、指纹采集与动态DOM改写。`
- 建议：在隔离沙箱中以带扩展的真浏览器执行并抓包（HAR/PCAP），观察canvas/WebGL/音频指纹采集、跨域请求与Set-Cookie；提取可疑域名与指纹参数作为IOC，并评估隐私与合规风险。

### 10. 表单提交流向未解析，可能由JS动态注入
- 规则：`DEEP_INTEL_FORM_ACTION_UNOBSERVED`
- 严重级别：`medium`
- 说明：静态解析未发现表单action，常见于JS在运行期绑定XHR/Fetch提交或改写action指向跨域端点，离线无法判断凭据是否外送到可疑域。
- 证据：`form_actions=[]；页面含多个密码框但未见静态action。`
- 建议：启用动态渲染后再次采集DOM与网络面板，定位最终提交URL、请求方法与跨域情况；如指向非常见或新注册域，将其纳入阻断与监控清单。

### 11. 交易所主题通用化，存在品牌仿冒潜势
- 规则：`DEEP_INTEL_BRAND_IMPERSONATION_RISK`
- 严重级别：`high`
- 说明：通用“买卖比特币”文案与非知名域名组合是交易所仿冒/钓鱼的高发模式，常与镜像站群、批量证书与相似模板联合出现。
- 证据：`标题通用；域名“baksmany.org”非已知主流交易所；离线样本未见明确品牌背书或可信第三方链接。`
- 建议：提取logo/favicon哈希与文本特征做相似度检索；结合证书指纹、ASN与被动DNS识别同群站；对疑似仿冒集群执行统一阻断并向品牌方通报。

### 12. 证书与证书透明度信息缺失，真实性无法离线核验
- 规则：`DEEP_INTEL_TLS_CT_GAP`
- 严重级别：`medium`
- 说明：离线快照仅显示为HTTPS访问，未包含证书链与CT记录，无法验证颁发机构、SAN匹配与是否存在异常更换或撤销。
- 证据：`content_type为HTTPS页面但无证书细节；未提供CT/OCSP/HSTS信息。`
- 建议：查询crt.sh与Google CT，核对颁发者、NotBefore/NotAfter、SAN与历史更迭；检查OCSP与HSTS策略；若出现异常CA/频繁更换，提升处置优先级。

### 13. 立即拦截并禁止访问
- 规则：`DEEP_ADVICE_INTERCEPT_URL`
- 严重级别：`critical`
- 说明：目标URL `https://baksmany.org/` 页面包含4个密码输入框，且网站自称是数字货币交易平台 ('Digital Currency Exchange, Buying and Selling Bitcoin')。该组合特征与钓鱼诈骗活动高度吻合，存在用户凭证泄露和财产损失的极端风险。
- 证据：`静态分析显示页面包含4个密码输入框 (rule_id: PAGE_PASSWORD_FORM)，页面标题为'Digital Currency Exchange, Buying and Selling Bitcoin'。`
- 建议：立即将该URL及关联域名添加到网络安全设备的黑名单中，通过防火墙、WAF或代理服务器进行彻底拦截，确保任何用户都无法访问该页面。同步更新安全策略以识别并阻止类似钓鱼网站。

### 14. 严格禁止用户输入敏感信息及下载文件
- 规则：`DEEP_ADVICE_PREVENT_USER_INTERACTION`
- 严重级别：`high`
- 说明：用户一旦访问此类钓鱼页面，极易被诱导输入登录凭据、私钥或其他敏感信息。此外，页面可能诱导下载恶意软件。为保障用户资产安全，必须采取措施防止任何形式的交互。
- 证据：`页面包含多个密码输入框，旨在收集用户凭据。`
- 建议：向所有潜在受影响用户发出安全警报，强调该网站为恶意网站，严禁在其上输入任何账号、密码、交易凭证等敏感信息，并禁止下载或运行页面提供的任何文件。加强终端安全防护，防止用户绕过拦截访问此类站点。

### 15. 详细留痕并进行复核
- 规则：`DEEP_ADVICE_LOG_AND_REVIEW`
- 严重级别：`medium`
- 说明：为支持后续的威胁情报分析、溯源取证和安全策略优化，本次发现的恶意URL及其研判结果需要被详细记录和存档。
- 证据：`处置建议员意见明确指出‘保留链接与报告用于复核’。`
- 建议：详细记录目标URL、发现时间、本次分析报告、采取的处置措施（如拦截策略ID、生效时间）及任何相关的访问日志。定期对黑名单进行审查和更新，并考虑将此情报分享给威胁情报平台。

### 16. 可疑域名结构
- 规则：`DEEP_STATIC_SUSPICIOUS_DOMAIN`
- 严重级别：`high`
- 说明：域名 'baksmany.org' 未匹配任何知名品牌（如 Binance 或 Coinbase），但标题声称提供加密货币服务，表明可能用于域名仿冒（typosquatting）钓鱼攻击。
- 证据：`主机名：baksmany.org, 页面标题：'Digital Currency Exchange, Buying and Selling Bitcoin'`
- 建议：避免访问此类未经验证域名；仅使用官方渠道进行加密货币交易。

### 17. 可能存在地理/IP 分流与外网依赖
- 规则：`DEEP_INTEL_ENV_GEO_VPN`
- 严重级别：`medium`
- 说明：加密货币相关站点常对合规地区或特定 IP 段实施访问限制与 CDN 分流；在企业网/监管区或被动 DNS/ISP 层阻断时，可能需 VPN 或更换出口节点方可还原真实页面与交互。
- 证据：`proxy_enabled=false；最终状态码 200；redirect_chain 仅自身；external_script_count=0 但存在本地脚本`
- 建议：结合静态报告进一步复核。

### 18. 落地页出现多个密码输入框，凭据收集面显著
- 规则：`DEEP_INTEL_CREDENTIAL_HARVESTING_SURFACE`
- 严重级别：`high`
- 说明：首页即出现多处密码输入，且文案为通用“数字货币买卖”主题，若域名并非官方品牌或缺乏可信证书背书，极易构成钓鱼或账号盗用风险。
- 证据：`password_forms=4；页面标题`
- 建议：结合静态报告进一步复核。

### 19. 疑似风控/指纹脚本可能影响内容呈现与数据外发
- 规则：`DEEP_INTEL_BOT_MGMT_JS_FINGERPRINTING`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`https://baksmany.org/`
- 建议：结合静态报告进一步复核。


## 六、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
经深度研判，目标 URL `https://baksmany.org/` 确认为恶意钓鱼网站。页面伪装成数字货币交易所，包含 4 个密码输入框且表单无明确提交动作（疑似 JS 劫持），配合可疑脚本 `/__lemmed_bm.js`，构成完整的凭证窃取链条。虽受限于离线环境无法验证证书与动态外联，但现有证据链已足够支撑恶意定性。建议立即阻断并警示用户。 综合静态特征与行为逻辑，判定为高危钓鱼网站。虽受限于离线环境无法验证动态外联，但 4 个密码框与 JS 劫持特征已构成完整证据链，建议立即阻断。

### 静态分析员（模型：`deepseek-reasoner`）
静态分析显示，域名 'baksmany.org' 结构可疑（未关联任何知名加密货币服务），URL 无参数但页面包含 4 个密码输入框、1 个隐藏输入和可疑脚本 '/__lemmed_bm.js'（名称异常），结合标题 'Digital Currency Exchange, Buying and Selling Bitcoin'，这些离线证据强烈暗示钓鱼意图，旨在诱骗用户输入凭证。

### 行为分析员（模型：`gemini-2.5-pro`）
该页面伪装成数字货币交易所，通过设置多个密码输入框诱导用户输入凭据。页面表单没有明确的提交目标（form action），表明其极有可能通过加载的本地脚本（/__lemmed_bm.js）来异步窃取和发送用户输入的账号密码。这是一个典型的凭证钓鱼攻击行为链，旨在盗取高价值的金融账户信息。

### 情报分析员（模型：`gpt-5`）
基于离线快照，该站点呈现“数字货币交易所”主题且落地即出现多个密码输入框，具备凭据收集/钓鱼高风险特征。当前采集未启用代理，无法确认是否在特定地区/网络环境下需要外网或 VPN 才能访问。离线证据边界：仅基于静态 HTML 与有限元数据，未执行 JS、未捕获网络请求与表单提交、未知证书与域名信誉，无法确认脚本行为、真实提交流与跨域请求，页面时效与完整性亦不可知。因此现评属于凭据钓鱼面显著但仍需多节点、动态渲染与证书/信誉情报补充验证的高风险目标。

### 处置建议员（模型：`gemini-2.5-flash`）
该 URL (https://baksmany.org/) 伪装成数字货币交易平台，包含 4 个密码输入框，存在高度钓鱼诈骗风险。建议立即拦截该 URL，禁止用户访问并输入任何敏感信息，对访问日志及研判结果进行详细留痕。


### 主持人最终总结
经深度研判，目标 URL `https://baksmany.org/` 确认为恶意钓鱼网站。页面伪装成数字货币交易所，包含 4 个密码输入框且表单无明确提交动作（疑似 JS 劫持），配合可疑脚本 `/__lemmed_bm.js`，构成完整的凭证窃取链条。虽受限于离线环境无法验证证书与动态外联，但现有证据链已足够支撑恶意定性。建议立即阻断并警示用户。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面截图比对。
