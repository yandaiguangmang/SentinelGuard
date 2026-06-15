# SentinelGuard 哨塔检测报告

> 模型深度研判报告 · 风险等级：**MEDIUM** · 风险分数：**45/100**

## 一、检测结论
- 原始输入：`https://h5.m.goofish.com/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：13 条
- 高危证据：0 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_url_static_20260613_182449_020929.html
  - Markdown：sentinel_reports/sentinel_report_url_static_20260613_182449_020929.md

## 二、统一 IR 摘要
- 规范化 URL：`https://h5.m.goofish.com/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1`
- 协议：`https`
- 主机：`h5.m.goofish.com`
- 路径：`/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1`
- 查询参数数量：`0`

## 三、跳转链
- https://h5.m.goofish.com/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1

## 四、页面线索
- status_code：200
- content_type：text/html; charset=utf-8
- final_url：https://h5.m.goofish.com/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1
- body_limited_to_bytes：200000
- title：
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：//g.alicdn.com/woodpeckerx/itrace-next/itrace.iife.js, https://o.alicdn.com/idlefish/idle-perf-sdk/index.js, //g.alicdn.com/??mtb/lib-promise/3.1.3/polyfillB.js,mtb/lib-env/1.9.11/env.js,mtb/lib-login/3.0.2/login.js,mtb/lib-windvane/3.0.7/windvane.js,idleFish-F2e/perf/appear-polyfill.js,code/npm/@ali/pcom-feloader/0.0.16/index.umd.js, //g.alicdn.com/code/lib/??react/18.3.1/umd/react.production.min.js,react-dom/18.3.1/umd/react-dom.production.min.js,lottie-web/5.5.10/lottie.min.js, //g.alicdn.com/??code/npm/@ali/fish-api/0.5.7/vendor.cjs.es5.production.js,code/npm/@ali/fish-api/0.5.7/index.js,code/npm/@ali/pnpm-uni--env/1.0.6/index.js,rax-pkg/universal-env/3.3.3/index.js,code/npm/@ali/pcom-fin-env/2.2.1/index.js,code/npm/@ali/pcom-fin-windvane/1.1.8/index.js,code/npm/@ali/pcom-fin-tools/2.5.2/index.js,code/npm/@ali/alimod-moyu-react-common-navbar/1.1.13/index.js,code/npm/@ali/alimod-moyu-moqie-react/1.0.23/index.js, https://g.alicdn.com/code/npm/@ali/moyu-project-act-react/1.6.0/pages/home/index.js
- form_actions：无
- download_links：无
- external_script_count：6

## 五、风险证据
### 1. 强依赖 App WebView 能力与运行态
- 规则：`DEEP_INTEL_APP_WEBVIEW_DEPENDENCY`
- 严重级别：`medium`
- 说明：页面加载了 WindVane 与 login 相关库，通常在闲鱼/手淘内嵌 WebView 环境下才能完整发挥功能。普通浏览器与离线采样无法复现端能力调用与登录后逻辑，导致风险面与真实行为可能被低估。
- 证据：`script_srcs 包含 //g.alicdn.com/mtb/lib-login/3.0.2/login.js、//g.alicdn.com/mtb/lib-windvane/3.0.7/windvane.js、https://o.alicdn.com/idlefish/idle-perf-sdk/index.js、@ali/fish-api 等。`
- 建议：在闲鱼/手淘 App WebView、登录态与匿名态下分别进行动态渲染与抓包（HAR/全链路日志），比对行为差异；使用一次性账号与受控设备，避免泄露主账号信息。

### 2. CDN 地域/出口差异可能影响呈现与安全评估
- 规则：`DEEP_INTEL_REGION_CDN_DEPENDENCY`
- 严重级别：`medium`
- 说明：阿里系 CDN 会根据出口 IP 和地域灰度发布或限流。不同网络（境内、境外、企业网、VPN）下脚本返回与可用性可能显著不同，影响对可疑行为与依赖链的判定。
- 证据：`外链主要来自 g.alicdn.com、o.alicdn.com，目标域为 h5.m.goofish.com；proxy_enabled=false，当前分析未经多出口对比。`
- 建议：在至少两个地域出口（CN 与非 CN）与有/无 VPN 条件下复测，记录 DNS 解析、TLS 证书链、资源哈希与状态码差异；保留完整 HAR 以比对脚本版本和接口响应。

### 3. 可能存在登录/权限门控导致的内容与行为差异
- 规则：`DEEP_INTEL_LOGIN_GATED_CONTENT`
- 严重级别：`medium`
- 说明：引入 login 组件与业务 API 封装，真实业务流程（活动权益、下单/跳转、账号拉新等）可能仅在登录后展示。离线静态快照无法覆盖该路径。
- 证据：`script_srcs 含 mtb/lib-login、@ali/fish-api、@ali/pcom-fin-* 等；静态报告显示未发现表单与跳转，但可能为未登录/未执行 JS 所致。`
- 建议：使用沙箱账号登录并进行最小可行交互，监控是否请求敏感权限、跳转外域或触发支付；对登录后新增的域名与脚本进行白/黑名单比对。

### 4. 前端依赖链较长的供应链风险
- 规则：`DEEP_INTEL_SUPPLY_CHAIN_SCRIPTS`
- 严重级别：`low`
- 说明：页面加载多份第三方/内源脚本（React、lottie、性能与埋点 SDK 等）。虽来源为阿里官方 CDN，理论风险较低，但依赖面较广，仍需关注版本与完整性。
- 证据：`脚本包含 react/18.3.1、react-dom/18.3.1、lottie-web/5.5.10、@ali/moyu-project-act-react/1.6.0 等共6处外部脚本。`
- 建议：在可控环境启用 CSP 与子资源完整性（SRI）策略进行验证；记录脚本指纹与版本并持续监测是否异常变更。

### 5. 埋点与性能采集可能涉及隐私上报
- 规则：`DEEP_INTEL_TELEMETRY_PRIVACY`
- 严重级别：`low`
- 说明：存在 itrace 与 idle-perf-sdk 等埋点/性能采集脚本，可能在动态运行时收集设备/环境指标，需在企业环境考虑隐私与合规。
- 证据：`脚本来源 //g.alicdn.com/woodpeckerx/itrace-next/itrace.iife.js、https://o.alicdn.com/idlefish/idle-perf-sdk/index.js。`
- 建议：在分析与取证时使用隔离网络与一次性设备/账号；通过代理审计上报目的域与数据字段，必要时在浏览器层面限制第三方请求。

### 6. 离线静态证据边界提示
- 规则：`DEEP_INTEL_OFFLINE_BOUNDARY`
- 严重级别：`low`
- 说明：当前结论基于静态 HTML 与资源列表，未执行 JS、未登录、未接入外部威胁情报，也未覆盖接口返回与运行时 DOM/事件行为，无法对登录后或地域化投放给出确定性判断。
- 证据：`static_report.score=0、risk_level=low，page_summary.status_code=200，external_script_count=6；expert_opinions 指出“未接入外部威胁情报”。`
- 建议：补充动态渲染与接口抓包、多网络出口对比、登录后路径复核，并接入威胁情报与域名信誉库联合评估。

### 7. 一般访问建议与敏感信息提交警示
- 规则：`DEEP_ADVICE_001`
- 严重级别：`low`
- 说明：页面未发现明显高危特征，可正常访问。但为防范潜在的钓鱼风险，建议用户在访问任何陌生页面时，避免提交个人敏感信息。
- 证据：`处置建议员意见："可正常访问，但不要在陌生页面提交敏感信息。"`
- 建议：用户可正常访问该页面，但应避免输入密码、银行卡号、身份证号等敏感信息。

### 8. 链接来源与访问上下文复核
- 规则：`DEEP_ADVICE_002`
- 严重级别：`low`
- 说明：尽管页面本身未发现明显恶意，但仍建议用户结合链接的来源和访问时的上下文信息进行复核，以确保安全性。
- 证据：`主持人意见："未发现明显高危特征，仍建议结合链接来源和访问上下文复核。"`
- 建议：在点击链接前，确认链接来源的可靠性；在访问页面时，留意页面内容是否与预期一致，避免被诱导操作。

### 9. 未发现明显高危特征
- 规则：`DEEP_ADVICE_003`
- 严重级别：`medium`
- 说明：系统未在目标页面中检测到明显的恶意代码、钓鱼表单或其他高危威胁特征。
- 证据：`主持人、静态分析员、行为分析员的综合判断。`
- 建议：无需立即拦截或隔离，但仍需保持警惕。

### 10. URL结构正常
- 规则：`DEEP_ADVICE_004`
- 严重级别：`medium`
- 说明：目标URL的结构符合常规模式，未触发URL异常检测规则。
- 证据：`静态分析员意见："URL 结构未命中当前规则库中的明显异常项。"`
- 建议：无需针对URL结构进行额外处置。

### 11. 无异常页面行为
- 规则：`DEEP_ADVICE_005`
- 严重级别：`medium`
- 说明：在行为分析过程中，未检测到自动跳转、恶意弹窗、文件下载或浏览器劫持等可疑页面行为。
- 证据：`行为分析员意见："未观察到可疑跳转或页面行为证据。"`
- 建议：无需进行沙箱复核或行为隔离。

### 12. 情报接入限制提示
- 规则：`DEEP_ADVICE_006`
- 严重级别：`low`
- 说明：本次分析基于本地规则和静态/行为分析结果，未集成外部威胁情报数据。这意味着如果该URL是新出现的威胁，可能未能及时识别。
- 证据：`情报分析员意见："当前离线版本未接入外部威胁情报，结论基于本地规则。"`
- 建议：建议在生产环境中接入实时威胁情报，以提升对未知威胁的检测能力。用户访问时应保持警惕，关注后续更新。

### 13. 前端依赖链较长的供应链风险
- 规则：`DEEP_INTEL_SUPPLY_CHAIN_SCRIPTS`
- 严重级别：`low`
- 说明：页面加载多份第三方/内源脚本（React、lottie、性能与埋点 SDK 等）。虽来源为阿里官方 CDN，理论风险较低，但依赖面较广，仍需关注版本与完整性。
- 证据：`脚本包含 react/18.3.1、react-dom/18.3.1、lottie-web/5.5.10、@ali/moyu-project-act-react/1.6.0 等共 6 处外部脚本。`
- 建议：在可控环境启用 CSP 与子资源完整性（SRI）策略进行验证；记录脚本指纹与版本并持续监测是否异常变更。


## 六、论坛式协同研判
### 主持人（模型：`qwen3.5-plus`）
经综合研判，目标 URL 为阿里巴巴闲鱼平台合法 H5 活动页，静态特征与脚本来源均可信，未发现恶意跳转或敏感表单，当前风险评级为低。但需明确，本次结论基于离线静态证据，未接入外部威胁情报，且页面强依赖 App WebView 环境与登录态，存在因网络出口或运行环境差异导致的行为不可见风险。建议允许访问，但需核实链接来源，避免在非官方环境下提交敏感信息。 未发现明显高危特征，仍建议结合链接来源和访问上下文复核。

### 静态分析员（模型：`deepseek-reasoner`）
静态证据分析显示 URL 结构正常：主机名为 h5.m.goofish.com（阿里巴巴旗下闲鱼平台的合法移动端子域名），路径/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1 包含随机页面 ID 但无非标准编码混淆或可疑关键词（如恶意字符串），无查询参数或跳转参数（redirect_chain 仅单条记录），脚本来源均为可信阿里 CDN（g.alicdn.com 和 o.alicdn.com），未发现隐藏输入、密码表单或元刷新行为。整体静态证据未触发规则库异常，风险较低。

### 行为分析员（模型：`gemini-2.5-pro`）
行为链分析显示，目标页面无任何跳转，为直接访问。页面加载的脚本均来自可信的关联 CDN（alicdn.com），未发现跨域加载可疑脚本的行为。页面静态结构中未包含表单提交或文件下载等敏感操作。综合判断，未见异常或恶意行为。

### 情报分析员（模型：`gpt-5`）
目标为阿里系 Goofish/闲鱼 H5 活动页。离线静态快照显示页面可直达且未见可疑跳转，但其运行强依赖阿里自有 CDN 与 App WebView 能力（WindVane、fish-api 等），实际呈现与风险面高度受“网络出口与运行环境”影响。关于外网/VPN 节点：1) CDN 选路与地域灰度：g.alicdn.com、o.alicdn.com 等会按出口 IP、地域与 AB 策略返回不同版本或限流，境外出口或企业内网可能出现资源降级/阻断，导致页面空白或功能缺失；反之使用国内/特定 VPN 节点时，脚本与接口可能完整加载，呈现与行为差异明显。2) 终端环境依赖：页面引入 windvane/login 等组件，常在闲鱼/手淘内嵌 WebView 执行并调用端能力；普通浏览器或离线抓取无法复刻登录、端桥接与后端接口调用。3) 会话与权限：未登录或非指定 IP 段可能仅返回占位内容，真实业务流程（下单、支付、拉活等）需登录后动态注入。以上差异意味着若必须通过外网/VPN 节点才能访问或完整渲染，应分别在“境内/境外、VPN/直连、App WebView/通用浏览器、登录/未登录”多维环境复核，避免因网络与环境不一致导致误判。当前离线证据的边界：本次为无代理与无动态执行的静态采样，仅看到首屏 HTML 与脚本清单，未执行 JS、未携带账号会话、未接入外部威胁情报、未抓取接口返回与 DOM 运行态，故无法判断登录后流程、区域化脚本分发、接口联动及可能的条件式投放行为；对供应链脚本安全性与隐私采集也仅能作一般性提示，不能给出确定性结论。

### 处置建议员（模型：`gemini-2.5-flash`）
允许访问，但建议用户谨慎对待，避免在陌生页面提交敏感信息，并结合链接来源和访问上下文进行复核。当前分析未发现明显恶意行为，但未接入外部威胁情报，建议保持警惕。


### 主持人最终总结
经综合研判，目标 URL 为阿里巴巴闲鱼平台合法 H5 活动页，静态特征与脚本来源均可信，未发现恶意跳转或敏感表单，当前风险评级为低。但需明确，本次结论基于离线静态证据，未接入外部威胁情报，且页面强依赖 App WebView 环境与登录态，存在因网络出口或运行环境差异导致的行为不可见风险。建议允许访问，但需核实链接来源，避免在非官方环境下提交敏感信息。


### 专家模型映射
- 主持人：`qwen3.5-plus`
- 静态分析员：`deepseek-reasoner`
- 行为分析员：`gemini-2.5-pro`
- 情报分析员：`gpt-5`
- 处置建议员：`gemini-2.5-flash`

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面截图比对。
