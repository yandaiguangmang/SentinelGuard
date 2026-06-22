# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**LOW** · 风险分数：**7/100**
> 证据分数：**7/100** · 深度研判分数：**- /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmpujezxu06.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：2 条
- 高危证据：0 条

## 二、统一 IR 摘要
- APK 文件：`tmpujezxu06.apk`
- 包名：`com.jpstudiosonline.tipcalculator`
- 版本名：`1.0.0.9`
- 版本号：`9`
- SHA256：`c7e81cacd8a5def61b3f8b8ccfcd08683fcee25df08382130412f27b397b5a46`
- 大小：`2240949` 字节
- 关键文件数：`60`

### APK 鲁棒性验证
- 鲁棒性分数：`30.0`
- 检测到的对抗技术：动态加载
- 防沙箱：`False`
- 混淆：`False`
- 反射：`False`
- 动态加载：`True`

### APK 图结构分析
- 已检测到 APK 图结构数据，可在 HTML 报告中查看 CFG / FCG / API 调用图统计。

## 三、跳转链
- 未获取跳转链。

## 四、页面线索
- 未获取页面内容线索。

## 四点一、APK 动态沙箱摘要

## 四点二、图结构分析
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`74950`
- CFG 边数：`31734`
- FCG 节点数：`21972`
- FCG 边数：`51193`
- FCG 密度：`0.0000`
- API 调用图节点数：`15`
- API 调用图边数：`167078`
- API 总调用数：`167078`
- 敏感 API 调用分布：Ljava/lang/reflect/Field;->get:94558, Ljava/lang/reflect/Method;->invoke:58282, Ldalvik/system/DexClassLoader;-><init>:10609, Landroid/net/Uri;->parse:1307, Ljava/net/HttpURLConnection;->connect:1089, Ljava/lang/reflect/Field;->set:625, Ljava/lang/Runtime;->exec:267, Landroid/provider/Settings$Secure;->getString:236, Landroid/app/PendingIntent;->getActivity:40, Ljava/lang/ClassLoader;->loadClass:27, Landroid/content/Intent;->setPackage:24, Ljava/net/URL;->openConnection:6
- API 调用明细：
  - `Ljava/lang/reflect/Field;->get`：94558
  - `Ljava/lang/reflect/Method;->invoke`：58282
  - `Ldalvik/system/DexClassLoader;-><init>`：10609
  - `Landroid/net/Uri;->parse`：1307
  - `Ljava/net/HttpURLConnection;->connect`：1089
  - `Ljava/lang/reflect/Field;->set`：625
  - `Ljava/lang/Runtime;->exec`：267
  - `Landroid/provider/Settings$Secure;->getString`：236
  - `Landroid/app/PendingIntent;->getActivity`：40
  - `Ljava/lang/ClassLoader;->loadClass`：27
  - `Landroid/content/Intent;->setPackage`：24
  - `Ljava/net/URL;->openConnection`：6
  - `Landroid/location/LocationManager;->getLastKnownLocation`：4
  - `Landroid/telephony/TelephonyManager;->getDeviceId`：2
  - `Ljavax/crypto/Cipher;->doFinal`：2

## 四点三、函数风险热力图
> **🧯 函数风险热力图说明**：通过静态图结构与指令特征自动定位可疑函数密集区，分数越高表示越值得优先复核。

- 热力图函数数：`30`
- 最高风险函数：`Landroid/support/v7/widget/ActivityChooserView;->showPopupUnchecked(I)V`（100）
- 热力图说明：HTML 报告中将以 ECharts 条形热力图展示函数风险排序。

## 四点四、一致性验证
> **🔍 一致性分析说明**：仲裁器通过比较静态/行为/情报三方的评分差异判断结论一致性。
> 一致性越高，证据链越稳固；一致性低时需重点关注被标记的「疑似污染」模块。

- 一致性分析结果：未获取到仲裁/一致性结果，但本次报告已显式展示缺失原因。
- 一致性分数：`-`
- 一致性等级：`-`
- 分歧点：未获取
- 被污染模块：未获取

## 四点五、鲁棒性分析
> **🛡️ 鲁棒性分析说明**：检测 APK 是否使用了防沙箱、混淆、反射、动态加载等对抗技术。
> 鲁棒性分数越高，说明样本越可能使用了规避分析的手段；分数越低，表示样本相对透明。

- 对抗技术：动态加载
- 鲁棒性分数：`30.0`
- 抗干扰能力评估：**中**

## 五、截图证据
- 当前未采集到页面截图。

## 六、风险证据
### 1. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。
- 证据：`manifest: AndroidManifest.xml; signature: META-INF/CERT.RSA; signature: META-INF/CERT.SF; signature: META-INF/MANIFEST.MF; dex: classes.dex; resource: res/anim/abc_fade_in.xml; resource: res/anim/abc_fade_out.xml; resource: res/anim/abc_grow_fade_in_from_bottom.xml; resource: res/anim/abc_popup_enter.xml; resource: res/anim/abc_popup_exit.xml; resource: res/anim/abc_shrink_fade_out_from_bottom.xml; resource: res/anim/abc_slide_in_bottom.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2054536502336 b'0k1\x0b0\t\x06\x03U\x04\x06\x13\x02011\x0b0\t\x06\x03U\x04\x08\x13\x02Il1\x110\x0f\x06\x03U\x04\x07\x13\x08Westmont1\x120\x10\x06\x03U\x04\n\x13\tJpstudios1\x120\x10\x06\x03U\x04\x0b\x13\tJpstudios1\x140\x12\x06\x03U\x04\x03\x13\x0bJahn Dawoud'>; Issuer=<asn1crypto.x509.Name 2054536393440 b'0k1\x0b0\t\x06\x03U\x04\x06\x13\x02011\x0b0\t\x06\x03U\x04\x08\x13\x02Il1\x110\x0f\x06\x03U\x04\x07\x13\x08Westmont1\x120\x10\x06\x03U\x04\n\x13\tJpstudios1\x120\x10\x06\x03U\x04\x0b\x13\tJpstudios1\x140\x12\x06\x03U\x04\x03\x13\x0bJahn Dawoud'>`
- 建议：核对签名证书是否符合官方发布习惯。


## 七、论坛式协同研判
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


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
