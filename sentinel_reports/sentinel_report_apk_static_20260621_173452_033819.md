# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**MEDIUM** · 风险分数：**38/100**
> 证据分数：**38/100** · 深度研判分数：**- /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmppc4k0gpp.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：4 条
- 高危证据：1 条

## 二、统一 IR 摘要
- APK 文件：`tmppc4k0gpp.apk`
- 包名：`com.appple.app.email`
- 版本名：`1.12.20`
- 版本号：`12`
- SHA256：`e8595d59908040edaa9b2583a83b574d3ffa7bff468ba63472851ec782a2a6d6`
- 大小：`7108946` 字节
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
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`166859`
- CFG 边数：`70995`
- FCG 节点数：`48385`
- FCG 边数：`110726`
- FCG 密度：`0.0000`
- API 调用图节点数：`16`
- API 调用图边数：`353`
- API 总调用数：`353`
- 敏感 API 调用分布：Landroid/net/Uri;->parse:100, Ljava/lang/reflect/Method;->invoke:67, Ljava/lang/reflect/Field;->get:44, Landroid/content/Intent;->setPackage:37, Ljava/lang/Class;->forName:30, Ljava/lang/ClassLoader;->loadClass:14, Ljava/net/URL;->openConnection:14, Ljava/lang/reflect/Field;->set:13, Lorg/apache/http/client/HttpClient;->execute:9, Landroid/app/PendingIntent;->getActivity:8, Landroid/provider/Settings$Secure;->getString:5, Ljava/net/HttpURLConnection;->connect:5
- API 调用明细：
  - `Landroid/net/Uri;->parse`：100
  - `Ljava/lang/reflect/Method;->invoke`：67
  - `Ljava/lang/reflect/Field;->get`：44
  - `Landroid/content/Intent;->setPackage`：37
  - `Ljava/lang/Class;->forName`：30
  - `Ljava/lang/ClassLoader;->loadClass`：14
  - `Ljava/net/URL;->openConnection`：14
  - `Ljava/lang/reflect/Field;->set`：13
  - `Lorg/apache/http/client/HttpClient;->execute`：9
  - `Landroid/app/PendingIntent;->getActivity`：8
  - `Landroid/provider/Settings$Secure;->getString`：5
  - `Ljava/net/HttpURLConnection;->connect`：5
  - `Ljava/net/Socket;->connect`：4
  - `Ldalvik/system/DexClassLoader;-><init>`：1
  - `Ljava/lang/Runtime;->exec`：1
  - `Ljavax/crypto/Cipher;->doFinal`：1

## 四点三、一致性验证
- 一致性分析结果：未获取到仲裁/一致性结果，但本次报告已显式展示缺失原因。
- 一致性分数：`-`
- 一致性等级：`-`
- 分歧点：未获取
- 被污染模块：未获取

## 四点四、鲁棒性分析
- 对抗技术：无
- 鲁棒性分数：`0.0`
- 抗干扰能力评估：**弱**

## 五、截图证据
- 当前未采集到页面截图。

## 六、风险证据
### 1. 关键文件证据已提取
- 规则：`APK_KEY_FILES_REVIEWED`
- 严重级别：`low`
- 说明：已优先检查 APK 内部关键文件、签名文件、资源配置与代码承载文件，用于后续静态研判与深度分析。
- 证据：`manifest: AndroidManifest.xml; resource: assets/crashlytics-build.properties; resource: assets/downloading.html; resource: res/anim/slide_in_from_bottom.xml; resource: res/anim/slide_in_from_top.xml; resource: res/anim/slide_in_left.xml; resource: res/anim/slide_in_right.xml; resource: res/anim/slide_out_left.xml; resource: res/anim/slide_out_right.xml; resource: res/anim/slide_out_to_bottom.xml; resource: res/anim/slide_out_to_top.xml; resource: res/color/common_google_signin_btn_text_dark.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 存在敏感权限请求
- 规则：`APK_SUSPICIOUS_PERMISSION`
- 严重级别：`high`
- 说明：安装包请求了短信、联系人、录音、安装或辅助功能等高敏权限。
- 证据：`android.permission.READ_CONTACTS, android.permission.WRITE_CONTACTS`
- 建议：确认权限是否与业务功能一致，避免授予不必要权限。

### 3. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2024963385760 b'0x1\x0b0\t\x06\x03U\x04\x06\x13\x02841\x0e0\x0c\x06\x03U\x04\x08\x13\x05Hanoi1\x0e0\x0c\x06\x03U\x04\x07\x13\x05Hanoi1\x190\x17\x06\x03U\x04\n\x0c\x10appleinfo_studio1\x190\x17\x06\x03U\x04\x0b\x13\x10appleinfo studio1\x130\x11\x06\x03U\x04\x03\x13\nNguyen Hao'>; Issuer=<asn1crypto.x509.Name 2024963384272 b'0x1\x0b0\t\x06\x03U\x04\x06\x13\x02841\x0e0\x0c\x06\x03U\x04\x08\x13\x05Hanoi1\x0e0\x0c\x06\x03U\x04\x07\x13\x05Hanoi1\x190\x17\x06\x03U\x04\n\x0c\x10appleinfo_studio1\x190\x17\x06\x03U\x04\x0b\x13\x10appleinfo studio1\x130\x11\x06\x03U\x04\x03\x13\nNguyen Hao'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 4. 存在持久化或高权限组件线索
- 规则：`APK_PERSISTENT_COMPONENTS`
- 严重级别：`medium`
- 说明：组件名称显示可能存在开机自启、管理器或辅助功能相关入口。
- 证据：`com.fsck.k9.service.BootReceiver`
- 建议：检查这些组件是否会在后台持续运行或触发敏感动作。


## 七、论坛式协同研判
### 主持人（模型：`unknown`）
综合 4 条证据，当前风险等级需要结合 APK 来源继续判断。

### 静态分析员（模型：`unknown`）
APK 静态证据关注：存在敏感权限请求、存在持久化或高权限组件线索。

### 行为分析员（模型：`unknown`）
当前版本仅提供静态 APK 检测，未执行动态沙箱。

### 情报分析员（模型：`unknown`）
建议结合市场来源、签名证书与历史信誉进一步核验。

### 处置建议员（模型：`unknown`）
建议在隔离浏览器中复核最终域名，不在页面提交敏感信息。


## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
