# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**LOW** · 风险分数：**7/100**
> 证据分数：**7/100** · 深度研判分数：**- /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpupv5xael.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：2 条
- 高危证据：0 条

## 二、统一 IR 摘要
- APK 文件：`tmpupv5xael.apk`
- 包名：`com.malmstein.yahnac`
- 版本名：`1.3.1`
- 版本号：`27`
- SHA256：`b34ee7bdbd6c9b034f38c7f3a27969445d5ebf351b92214356f4db16576275fd`
- 大小：`4125881` 字节
- 关键文件数：`60`

### APK 鲁棒性验证
- 鲁棒性分数：`0.0`
- 检测到的对抗技术：无
- 防沙箱：`False`
- 混淆：`False`
- 反射：`False`
- 动态加载：`False`

### APK 图结构分析
- 已检测到 APK 图结构数据，可在 HTML 报告中查看 CFG / FCG / API 调用图统计。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要

## 四点二、图结构分析
- 图结构状态：`回退生成`；原因：androguard_unavailable_or_parse_failed
### CFG / FCG / API 调用图
- CFG 节点数：`1`
- CFG 边数：`0`
- FCG 节点数：`2`
- FCG 边数：`1`
- FCG 密度：`0.1667`
- API 调用图节点数：`0`
- API 调用图边数：`0`
- API 总调用数：`0`
- 敏感 API 调用分布：network:0, payment:0, privacy:0, reflection:0, system:0
- API 调用明细：
  - `network`：0
  - `payment`：0
  - `privacy`：0
  - `reflection`：0
  - `system`：0

## 四点四、鲁棒性分析
- 对抗技术：无
- 鲁棒性分数：`0.0`
- 抗干扰能力评估：**弱**

## 五、风险证据
### 1. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。
- 证据：`manifest: AndroidManifest.xml; resource: res/anim-v21/design_bottom_sheet_slide_in.xml; resource: res/anim-v21/design_bottom_sheet_slide_out.xml; resource: res/anim/abc_fade_in.xml; resource: res/anim/abc_fade_out.xml; resource: res/anim/abc_grow_fade_in_from_bottom.xml; resource: res/anim/abc_popup_enter.xml; resource: res/anim/abc_popup_exit.xml; resource: res/anim/abc_shrink_fade_out_from_bottom.xml; resource: res/anim/abc_slide_in_bottom.xml; resource: res/anim/abc_slide_in_top.xml; resource: res/anim/abc_slide_out_bottom.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2249369597552 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>; Issuer=<asn1crypto.x509.Name 2249369598128 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>`
- 建议：核对签名证书是否符合官方发布习惯。


## 六、论坛式协同研判
### 主持人（模型：`unknown`）
综合 2 条证据，当前风险等级需要结合 APK 来源继续判断。

### 静态分析员（模型：`unknown`）
APK 静态证据关注暂未发现明显异常。

### 行为分析员（模型：`unknown`）
当前版本仅提供静态 APK 检测，未执行动态沙箱。

### 情报分析员（模型：`unknown`）
建议结合市场来源、签名证书与历史信誉进一步核验。

### 处置建议员（模型：`unknown`）
可低风险访问，但仍需确认链接来源可信。


## 六点一、角色结果说明
- **行为分析员**：该角色当前仅输出静态研判结果，原因是 APK 动态沙箱尚未执行或未接入。

## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
