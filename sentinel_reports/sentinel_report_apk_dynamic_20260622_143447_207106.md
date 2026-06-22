# SentinelGuard 哨塔检测报告

> APK 动态沙箱报告 · 风险等级：**MEDIUM** · 风险分数：**46/100**
> 证据分数：**70/100** · 深度研判分数：**45 /100**
> 评分口径：URL 采用 `0.5 × 证据分数 + 0.5 × 深度研判分数`；APK 采用 `0.4 × 证据分数 + 0.3 × 深度研判分数 + 仲裁修正 + 鲁棒性奖励`。


## 一、检测结论
- 原始输入：`C:\Users\lenovo\AppData\Local\Temp\tmp0i1o_x62.apk`
- 对象类型：`apk`
- 状态：`ready`
- 证据条数：29 条
- 高危证据：7 条
- 关联静态报告：
  - HTML：sentinel_reports/sentinel_report_apk_static_20260622_143125_743596.html
  - Markdown：sentinel_reports/sentinel_report_apk_static_20260622_143125_743596.md

## 二、统一 IR 摘要
- APK 文件：`tmp0i1o_x62.apk`
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
- device_id：emulator-5554
- package_name：com.malmstein.yahnac
- static_file_name：tmp0i1o_x62.apk
- resolve_activity：priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.malmstein.yahnac/.stories.NewsActivity
- pidof：13618
- granted_dangerous_permissions：ANDROID.PERMISSION.INTERNET, ANDROID.PERMISSION.ACCESS_NETWORK_STATE, ANDROID.PERMISSION.ACCESS_WIFI_STATE, ANDROID.PERMISSION.WAKE_LOCK
- post_install_files：./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk, ./product/app/talkback/talkback.apk, ./product/app/GoogleTTS/GoogleTTS.apk, ./product/app/Photos/Photos.apk, ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk, ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk, ./product/app/PixelThemesStub/PixelThemesStub.apk, ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk, ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk, ./product/app/GoogleContacts/GoogleContacts.apk, ./product/app/Drive/Drive.apk, ./product/app/LatinIMEGooglePrebuilt/LatinIMEGooglePrebuilt.apk, ./product/app/Camera2/lib/x86_64/libjni_tinyplanet.so, ./product/app/Camera2/lib/x86_64/libjni_jpegutil.so, ./product/app/Camera2/Camera2.apk, ./product/app/WallpapersBReel2018/lib/x86_64/libgdx.so, ./product/app/WallpapersBReel2018/lib/x86_64/libwallpapers-breel-2018-jni.so, ./product/app/WallpapersBReel2018/WallpapersBReel2018.apk, ./product/app/YouTube/YouTube.apk, ./product/app/MarkupGoogle/MarkupGoogle.apk
- persistent_services：{'accessibility': ['[com.google.android.googlequicksearchbox][com.google.android.as][com.android.chrome][com.google.android.youtube][com.google.android.contacts][com.google.android.deskclock][com.google.android.apps.wellbeing][com.google.android.inputmethod.latin][com.malmstein.yahnac][com.google.android.apps.nexuslauncher]}]'], 'device_policy': ['7: com.malmstein.yahnac'], 'notification': ['AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false']}
- install_success：True
- launch_success：True
- event_count：35
- logcat_excerpt_count：430
- network_hit_count：12
- runtime_window_seconds：12
- dynamic_json_path：`G:/project/code/information/apk_dynamic/20260622_143133_228460_com.malmstein.yahnac/dynamic_artifacts.json`
- dynamic_json_name：`dynamic_artifacts.json`
- dynamic_summary_path：`G:/project/code/information/apk_dynamic/20260622_143133_228460_com.malmstein.yahnac/dynamic_summary.json`
- dynamic_logcat_path：`G:/project/code/information/apk_dynamic/20260622_143133_228460_com.malmstein.yahnac/logcat_excerpt.txt`
- dynamic_output_dir：`G:/project/code/information/apk_dynamic/20260622_143133_228460_com.malmstein.yahnac`
- ui_trace_dir：`G:/project/code/information/apk_dynamic/20260622_143133_228460_com.malmstein.yahnac/ui_trace`
- ui_trace_paths：`['G:/project/code/information/apk_dynamic/20260622_143133_228460_com.malmstein.yahnac/ui_trace/com.malmstein.yahnac_launch_20260622_143133_228995.png', 'G:/project/code/information/apk_dynamic/20260622_143133_228460_com.malmstein.yahnac/ui_trace/com.malmstein.yahnac_evidence_20260622_143133_983425.png']`

## 四点二、图结构分析
- 图结构状态：`已生成`
### CFG / FCG / API 调用图
- CFG 节点数：`131441`
- CFG 边数：`56787`
- FCG 节点数：`37635`
- FCG 边数：`85716`
- FCG 密度：`0.0000`
- API 调用图节点数：`14`
- API 调用图边数：`288`
- API 总调用数：`288`
- 敏感 API 调用分布：Ljava/lang/reflect/Method;->invoke:81, Ljava/lang/reflect/Field;->get:74, Ljava/lang/reflect/Field;->set:33, Ljava/lang/Class;->forName:32, Landroid/net/Uri;->parse:23, Landroid/content/Intent;->setPackage:18, Ljava/lang/ClassLoader;->loadClass:11, Landroid/app/PendingIntent;->getActivity:5, Ljava/net/URL;->openConnection:3, Landroid/provider/Settings$Secure;->getString:2, Ljava/net/HttpURLConnection;->connect:2, Ljava/net/Socket;->connect:2
- API 调用明细：
  - `Ljava/lang/reflect/Method;->invoke`：81
  - `Ljava/lang/reflect/Field;->get`：74
  - `Ljava/lang/reflect/Field;->set`：33
  - `Ljava/lang/Class;->forName`：32
  - `Landroid/net/Uri;->parse`：23
  - `Landroid/content/Intent;->setPackage`：18
  - `Ljava/lang/ClassLoader;->loadClass`：11
  - `Landroid/app/PendingIntent;->getActivity`：5
  - `Ljava/net/URL;->openConnection`：3
  - `Landroid/provider/Settings$Secure;->getString`：2
  - `Ljava/net/HttpURLConnection;->connect`：2
  - `Ljava/net/Socket;->connect`：2
  - `Landroid/location/LocationManager;->getLastKnownLocation`：1
  - `Lorg/apache/http/client/HttpClient;->execute`：1

## 四点三、一致性验证
> **🔍 一致性分析说明**：仲裁器通过比较静态/行为/情报三方的评分差异判断结论一致性。
> 一致性越高，证据链越稳固；一致性低时需重点关注被标记的「疑似污染」模块。

- 一致性分数：`73`
- 一致性等级：`MEDIUM`
- 分歧点：static-behavior 差异 40 分, static-intelligence 差异 0 分, behavior-intelligence 差异 40 分
- 被污染模块：static, behavior, intelligence

## 四点四、鲁棒性分析
> **🛡️ 鲁棒性分析说明**：检测 APK 是否使用了防沙箱、混淆、反射、动态加载等对抗技术。
> 鲁棒性分数越高，说明样本越可能使用了规避分析的手段；分数越低，表示样本相对透明。

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
- 证据：`manifest: AndroidManifest.xml; resource: res/anim-v21/design_bottom_sheet_slide_in.xml; resource: res/anim-v21/design_bottom_sheet_slide_out.xml; resource: res/anim/abc_fade_in.xml; resource: res/anim/abc_fade_out.xml; resource: res/anim/abc_grow_fade_in_from_bottom.xml; resource: res/anim/abc_popup_enter.xml; resource: res/anim/abc_popup_exit.xml; resource: res/anim/abc_shrink_fade_out_from_bottom.xml; resource: res/anim/abc_slide_in_bottom.xml; resource: res/anim/abc_slide_in_top.xml; resource: res/anim/abc_slide_out_bottom.xml`
- 建议：结合 manifest、资源、签名与代码文件继续确认风险链条。

### 2. 签名证书信息需复核
- 规则：`APK_SIGNING_INFO`
- 严重级别：`low`
- 说明：签名主体与颁发者信息不完全一致，建议结合来源进一步核验。
- 证据：`Subject=<asn1crypto.x509.Name 2089465565776 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>; Issuer=<asn1crypto.x509.Name 2089465567744 b'0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x160\x14\x06\x03U\x04\x07\x13\rMountain View1\x100\x0e\x06\x03U\x04\n\x13\x07Android1\x100\x0e\x06\x03U\x04\x0b\x13\x07Android1\x100\x0e\x06\x03U\x04\x03\x13\x07Android1"0 \x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x13android@android.com'>`
- 建议：核对签名证书是否符合官方发布习惯。

### 3. 运行时暴露可疑网络线索
- 规则：`APK_DYNAMIC_NETWORK`
- 严重级别：`medium`
- 说明：logcat 中出现可疑网络地址、域名或远程连接线索，说明样本可能存在联网行为。
- 证据：`https://play.googleapis.com/play/log; https://play.googleapis.com/play/log/timestamp; settings.get.glo; package.install; vmdl1024738686.tmp`
- 建议：后续可结合抓包或代理进行复核。

### 4. 疑似动态载荷释放
- 规则：`APK_DYNAMIC_PAYLOAD_DROP`
- 严重级别：`high`
- 说明：运行后在应用目录或临时目录中发现 dex、jar、apk、so、zip 等可疑落地文件。
- 证据：`./product/app/ModuleMetadataGoogle/ModuleMetadataGoogle.apk; ./product/app/talkback/talkback.apk; ./product/app/GoogleTTS/GoogleTTS.apk; ./product/app/Photos/Photos.apk; ./product/app/SoundPickerPrebuilt/SoundPickerPrebuilt.apk; ./product/app/PrebuiltDeskClockGoogle/PrebuiltDeskClockGoogle.apk; ./product/app/PixelThemesStub/PixelThemesStub.apk; ./product/app/WebViewGoogle-Stub/WebViewGoogle-Stub.apk; ./product/app/YouTubeMusicPrebuilt/YouTubeMusicPrebuilt.apk; ./product/app/GoogleContacts/GoogleContacts.apk`
- 建议：建议结合文件哈希、反编译和后续加载日志确认是否存在动态加载或脱壳行为。

### 5. 发现持久化或高危服务注册线索
- 规则：`APK_DYNAMIC_PERSISTENT_SERVICE`
- 严重级别：`high`
- 说明：运行时系统服务状态中出现无障碍、设备管理器或通知相关注册线索。
- 证据：`[com.google.android.googlequicksearchbox][com.google.android.as][com.android.chrome][com.google.android.youtube][com.google.android.contacts][com.google.android.deskclock][com.google.android.apps.wellbeing][com.google.android.inputmethod.latin][com.malmstein.yahnac][com.google.android.apps.nexuslauncher]}]; 7: com.malmstein.yahnac; AppSettings: com.malmstein.yahnac (10174) importance=NONE userSet=false`
- 建议：建议重点复核是否存在无障碍滥用、设备管理器驻留或通知监听行为。

### 6. 设备策略管理器滥用
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_POLICY_ABUSE`
- 严重级别：`critical`
- 说明：应用在运行时注册为设备策略管理应用，可能用于锁定屏幕、清除数据或阻止卸载。
- 证据：`dynamic_summary.persistent_services.device_policy: 7: com.malmstein.yahnac`
- 建议：立即卸载该应用，并检查设备是否存在未授权的管理员权限配置。

### 7. 辅助功能服务驻留
- 规则：`DEEP_APK_BEHAVIOR_ACCESSIBILITY_INJECTION`
- 严重级别：`critical`
- 说明：应用试图通过辅助功能服务获取系统 UI 交互权限，这是恶意软件进行屏幕抓取、键盘记录或自动点击的典型行为。
- 证据：`dynamic_summary.persistent_services.accessibility: 包含 com.malmstein.yahnac`
- 建议：禁止该应用获取辅助功能权限，并排查是否存在敏感信息泄露。

### 8. 高频反射调用敏感 API
- 规则：`DEEP_APK_BEHAVIOR_REFLECTION_ABUSE`
- 严重级别：`medium`
- 说明：静态分析显示大量 `Ljava/lang/reflect/Method;->invoke` 调用，结合动态日志，推测其通过反射绕过 Android 系统 API 限制以执行恶意功能。
- 证据：`api_call_counts_top: Ljava/lang/reflect/Method;->invoke (81次)`
- 建议：对代码中的反射逻辑进行脱壳与深度逆向分析。

### 9. 异常系统调用尝试
- 规则：`DEEP_APK_BEHAVIOR_UNAUTHORIZED_SHELL_ACCESS`
- 严重级别：`high`
- 说明：动态日志显示应用在尝试执行 shell 命令时触发了 SELinux 权限拒绝，表明其试图越权访问系统底层资源。
- 证据：`logcat: avc: denied { getopt } for scontext=u:r:system_server:s0 tcontext=u:r:shell:s0`
- 建议：检查应用是否存在提权漏洞利用代码。

### 10. 使用 Android TESTKEY/通用证书签名，存在完整性与来源风险
- 规则：`DEEP_APK_INTEL_SIGNATURE_TESTKEY`
- 严重级别：`medium`
- 说明：APK 内包含 META-INF/TESTKEY.*，证书 Subject/Issuer 为 Android/android@android.com，属于通用测试密钥，常见于开发/演示构建，非正式发行签名。该特征提升被重打包/非官方构建的可能性。
- 证据：`META-INF/TESTKEY.SF / TESTKEY.RSA；certificate_subject=Android/android@android.com；certificate_sha256=a926b583f366f927c70ebc69c962520307c09f271a229bff5f15fe41efee42dc`
- 建议：勿直接投产使用；到官方商店/可信源获取发布版，核对签名指纹与历史版本一致性；若仅用于内部测试，请标注并限制分发。

### 11. 来源渠道不明(临时目录侧载)需做信誉校验
- 规则：`DEEP_APK_INTEL_SOURCE_CHANNEL_RISK`
- 严重级别：`medium`
- 说明：样本来自本机临时目录并经侧载安装，无法确认供应链与分发可信度；结合 TESTKEY 签名，需重点排除非官方重打包可能。
- 证据：`original_input=C:\Users\lenovo\AppData\Local\Temp\tmp0i1o_x62.apk；package_name=com.malmstein.yahnac；sha256=b34ee7bdbd6c9b034f38c7f3a27969445d5ebf351b92214356f4db16576275fd`
- 建议：到官方商店/开发者仓库核验版本名1.3.1与版本码27、证书指纹及哈希；在企业侧仅允许来自白名单仓库的安装包。

### 12. 权限基线较低，与阅读类应用相符
- 规则：`DEEP_APK_INTEL_PERMISSION_MINIMAL`
- 严重级别：`low`
- 说明：仅请求网络与唤醒锁等常规权限，未请求通讯录、短信、存储写入、定位等敏感权限。API 图谱虽出现 LocationManager 引用，但在未声明定位权限情况下无法实际获取定位。
- 证据：`permissions=[INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, WAKE_LOCK,…]；api_graph包含 LocationManager.getLastKnownLocation`
- 建议：继续在长时动态分析中观察是否尝试访问需运行时授权的敏感接口，以防后续版本权限提升。

### 13. 集成 Firebase/Google 组件，存在常规遥测上报
- 规则：`DEEP_APK_INTEL_GOOGLE_SERVICES_TELEMETRY`
- 严重级别：`low`
- 说明：Manifest 中包含 Firebase Crash/Measurement 相关 Service/Receiver；动态日志可见与 play.googleapis.com 的日志/时间戳交互，符合常见遥测行为。
- 证据：`services=[AppMeasurementService, FirebaseCrashSenderService,…]；network_hits包含 https://play.googleapis.com/play/log`
- 建议：合规场景下评估遥测合规性；若需限制外联，在网络侧对 Google 遥测域名进行策略控制或在配置中关闭相关上报。

### 14. 短窗动态沙箱未见可归因的恶意行为，但样本量与归因有限
- 规则：`DEEP_APK_INTEL_DYNAMIC_BEHAVIOR_OBS`
- 严重级别：`low`
- 说明：安装/启动成功，约12秒窗口内记录12次网络命中，多为系统/Google 组件访问；未见可确认由目标应用发起的可疑连接或异常持久化。沙箱将常规权限误标为危险，并展示了可疑“accessibility/device_policy”列表，实则 Manifest 未发现相应组件，疑为环境噪声。
- 证据：`runtime_window_seconds=12；network_hit_count=12；persistent_services.device_policy 列表含 com.malmstein.yahnac 但 Manifest 未见 DeviceAdminReceiver`
- 建议：延长运行时并加入真实交互，按 UID/进程抓包归因，复核是否存在设备管理/无障碍声明与实际启用不一致情形。

### 15. 反射调用主要来自兼容/支持库，未见恶意装载迹象
- 规则：`DEEP_APK_INTEL_REFLECTION_USAGE_LIB`
- 严重级别：`low`
- 说明：反射相关调用计数较高，但与 AppCompat/Support/CustomTabs 等常见库模式一致，稳健性摘要未指示动态加载/混淆对抗行为。
- 证据：`api_call_counts_top: Method.invoke=81, Field.get=74；robustness_summary: dynamic_loading_detected=false, obfuscation_detected=false`
- 建议：常规关注即可；如后续出现与反射配套的动态加载(如 DexClassLoader/PathClassLoader 非常规用法)再提升警戒。

### 16. 自定义内容提供器需确认导出与权限控制
- 规则：`DEEP_APK_INTEL_PROVIDER_SURFACE_CHECK`
- 严重级别：`low`
- 说明：存在自定义 Provider(com.malmstein.yahnac.data.HNewsProvider)。未见导出策略细节，需核查是否 export=false 或有读写权限门控，避免数据面被滥用。
- 证据：`providers 包含 com.malmstein.yahnac.data.HNewsProvider`
- 建议：人工复核 AndroidManifest.xml 中 provider 的 exported 与读/写权限；如为导出，确保 least-privilege 权限与调用方校验。

### 17. 包名与已知应用命名相符但需外部信誉佐证
- 规则：`DEEP_APK_INTEL_APP_IDENTITY_REPUTATION`
- 严重级别：`low`
- 说明：包名 com.malmstein.yahnac 与社区常见的 Hacker News 客户端命名一致，但仅凭离线样本无法确认与官方发布的二进制一致。
- 证据：`package_name=com.malmstein.yahnac；version_name=1.3.1；version_code=27`
- 建议：在官方商店/开发者主页检索同包名，核对版本信息与签名指纹；对比本地样本 SHA256 是否与官方发布匹配，以排除重打包。

### 18. 动态运行结果显示应用可正常安装并启动，未见明显破坏性行为
- 规则：`DEEP_APK_ADVICE_001`
- 严重级别：`low`
- 说明：沙箱中安装成功、启动成功，运行窗口内未出现崩溃、提权、横向移动或明显恶意落地行为；日志更接近普通应用启动与系统服务交互。
- 证据：`install_success=true; launch_success=true; event_count=35; runtime_window_seconds=12; logcat 中主要为 PackageManager/DexOpt/MediaSession 等系统常规日志`
- 建议：可暂不定性为恶意，但应继续保留样本并做更长时长的行为复核，重点观察后台持久化、异步联网与后续交互。

### 19. 存在高频反射与类加载调用，需警惕混淆或动态行为
- 规则：`DEEP_APK_ADVICE_002`
- 严重级别：`medium`
- 说明：静态图谱中 Method.invoke、Field.get/set、Class.forName、ClassLoader.loadClass 调用频繁，属于常见的反射/动态装载特征，虽然未发现明显动态加载或混淆告警，但仍增加研判不确定性。
- 证据：`top_api_call=Ljava/lang/reflect/Method;->invoke; 反射调用统计：Method.invoke=81, Field.get=74, Field.set=33, Class.forName=32, ClassLoader.loadClass=11`
- 建议：建议继续沙箱复核反射路径和类装载路径，确认是否仅为框架/兼容库使用；如来源不可信，建议阻断安装到生产终端。

### 20. 具备网络访问与持久化服务能力，需监控联网行为
- 规则：`DEEP_APK_ADVICE_003`
- 严重级别：`medium`
- 说明：权限包含 INTERNET、ACCESS_NETWORK_STATE、ACCESS_WIFI_STATE、WAKE_LOCK，且动态沙箱出现 12 次网络命中；同时存在 Firebase/Measurement 相关组件，说明应用具备持续联网与后台服务能力。
- 证据：`permissions 包含 android.permission.INTERNET / ACCESS_NETWORK_STATE / ACCESS_WIFI_STATE / WAKE_LOCK；network_hit_count=12；services 含 AppMeasurementService、FirebaseInstanceIdService；network_hits 出现 https://play.googleapis.com/play/log 等联网痕迹`
- 建议：建议在隔离网络下继续复核联网目的与域名白名单，必要时阻断外联到非业务域；生产环境可先限制分发范围。

### 21. 签名证书信息异常感知，需核对发布链路
- 规则：`DEEP_APK_ADVICE_004`
- 严重级别：`medium`
- 说明：证书主体与颁发者信息呈现 Android 测试签名风格，且静态结果中特别提示需复核签名证书是否符合官方发布习惯；这不必然代表恶意，但会显著影响可信度。
- 证据：`signature 文件含 META-INF/TESTKEY.SF、META-INF/TESTKEY.RSA；certificate_subject/certificate_issuer 显示 android@android.com 风格测试证书；static finding=APK_SIGNING_INFO`
- 建议：应核验是否为开发测试包、第三方重打包或非官方渠道样本；在证书未确认前，不建议直接对外分发。

### 22. 样本名称与组件看似对应已知开源应用，但来源仍需确认
- 规则：`DEEP_APK_ADVICE_005`
- 严重级别：`low`
- 说明：包名 com.malmstein.yahnac、版本 1.3.1、组件命名与普通资讯类应用一致，动态解析到主 Activity 为 com.malmstein.yahnac/.stories.NewsActivity，整体更像正常应用构件。
- 证据：`package_name=com.malmstein.yahnac; version_name=1.3.1; version_code=27; resolve_activity=com.malmstein.yahnac/.stories.NewsActivity; activities/services/providers 符合常规应用结构`
- 建议：若来源为官方或可信市场，可降级处置为低风险留样；若来源为未知渠道，仍建议做二次沙箱复核并保留留痕。

### 23. 动态沙箱时长偏短，结论仍应保守
- 规则：`DEEP_APK_ADVICE_006`
- 严重级别：`medium`
- 说明：当前运行窗口仅 12 秒，足以观察到安装与启动，但不足以覆盖延迟触发、定时任务、事件驱动或条件触发型行为。
- 证据：`runtime_window_seconds=12; logcat_excerpt_count=430; event_count=35`
- 建议：建议延长沙箱观察时长并增加交互测试、重启测试、断网/恢复网络测试；在复核完成前保留样本与日志证据。

### 24. 使用 Android TESTKEY 签名
- 规则：`DEEP_APK_STATIC_001`
- 严重级别：`medium`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`证书主体/发行者包含 android@android.com；META-INF/TESTKEY.*；certificate_sha256=a926b583f366f927c70ebc69c962520307c09f271a229bff5f15fe41efee42dc`
- 建议：比对官方渠道（如商店/官网/F-Droid）同版本证书指纹与文件哈希，确认是否为非官方重签名或开发构建。

### 25. 设备策略/辅助功能驻留指控（待证实）
- 规则：`DEEP_APK_BEHAVIOR_DEVICE_POLICY_ACCESSIBILITY`
- 严重级别：`high`
- 说明：模型认为该目标存在额外风险线索。
- 证据：`行为分析员报告 persistent_services.device_policy/accessibility 包含 com.malmstein.yahnac；静态分析未报告对应清单项，其他动态证据缺失，沙箱仅运行约12秒`
- 建议：复现并核验：检查 Manifest 是否存在 DeviceAdminReceiver/AccessibilityService；在有交互的长时运行中观测注册与授权流程，一旦证实应立即阻断安装与分发。

### 26. 仲裁器发现意见分歧
- 规则：`APK_ARBITRATION_DISCREPANCY`
- 严重级别：`medium`
- 说明：多角色分析结果存在差异，需要结合冲突点继续复核。
- 证据：`static-behavior 差异 40 分; static-intelligence 差异 0 分; behavior-intelligence 差异 40 分`
- 建议：优先复核分歧较大的证据链与可疑角色输出。

### 27. 仲裁器标记疑似污染模块
- 规则：`APK_ARBITRATION_COMPROMISED`
- 严重级别：`high`
- 说明：仲裁器识别到可能被污染或偏离的分析模块。
- 证据：`static; behavior; intelligence`
- 建议：重点检查这些模块对应的证据来源和模型输出。

### 28. 仲裁一致性评分
- 规则：`APK_ARBITRATION_CONSISTENCY`
- 严重级别：`medium`
- 说明：仲裁器计算得到的分析一致性评分。
- 证据：`73`
- 建议：将该评分作为后续人工复核的重要参考。

### 29. 鲁棒性评分
- 规则：`APK_ROBUSTNESS_SCORE`
- 严重级别：`low`
- 说明：鲁棒性验证得到的综合评分。
- 证据：`0.0`
- 建议：鲁棒性分数越低，通常表示越不容易被规避分析；分数越高，越需要重点关注。


## 七、论坛式协同研判
### 主持人（模型：`gpt-5`）
基于四位专家的现有结论，我们判定该样本总体为中风险：其功能与第三方 Hacker News 客户端（Yahnac）相符，静态未见高危权限或异常组件，短窗动态亦主要与 Google/Play/Firebase 服务通信，缺乏明确恶意行为证据。当前提升风险的核心在于以 Android TESTKEY 签名、来源不明（临时目录侧载），存在被二次打包或非官方构建的供应链完整性隐患。行为分析员报告的“设备策略管理器滥用/辅助功能驻留”等高危行为尚未得到静态清单与其他动态证据的印证，且沙箱运行仅约 12 秒、可能存在环境噪声，暂不据此上调至高危。综合来看，更可能是非官方/开发版或重签名构建的正常应用，短期不具备明确破坏性，但需在受控环境下复核签名与行为：1) 与官方渠道比对证书/哈希确保一致性；2) 复现并核验是否真实注册 Device Admin/Accessibility 服务及其触发条件；3) 按 UID 归属监控流量以排除隐蔽回连。一旦确认签名/来源异常或复核证实高危驻留行为，应立即阻断分发与安装。此研判仅基于已提供的四位专家输出，后续结论需结合进一步取证验证。

### 静态分析员（模型：`gemini-2.5-pro`）
模型返回原始内容（非标准JSON）: ```json
{
  "opinion": "综合静态与动态沙箱证据，该APK推测为常规的Hacker News第三方客户端（Yahnac）。静态分析未发现高危权限，组件多为标准的Firebase/Google分析服务及常规业务Activity。动态沙箱印证了其网络通信主要集中在Google Play服务日志上报，未见恶意行为。主要风险点在于使用了Android默认测试签名（testkey），表明其可能为调试版或非官方重打包版本，整体研判为低风险。",
  "risk_hint": "low",
  "additional_findings": [
    {
      "rule_id": "DEEP_APK_STATIC_001",
      "title": "使用Android默认测试签名",
      "severity": "medium",
      "description": "APK签名证书的Subject和Issuer均为'android@android.com'，这是AOSP源码编译时默认的testkey。正规应用通常使用开发者专属的私钥签名。",
      "evidence": "certificate_subject 包含 'android@android.com'",
      "recommendation": "确认APK的获取渠道。如果来自第三方应用市场或论坛，可能存在被植入广告或恶意代码的二次打包风险，建议与官方哈希进行比对。"
    },
    {
      "rule_id": "DEEP_APK_STATIC_002",
      "title": "常规业务组件与动态行为印证",
      "severity": "low",
      "description": "静态提取的Provider（HNewsProvider）和Firebase组件与应用功能定位相符。动态沙箱运行期间仅触发了基础的Google服务通信，未发现与恶意远控、隐私窃取相关的API滥用或异常网络连接。",
      "evidence": "静态包含 com.malmstein.yahnac.data.HNewsProvider 及 FirebaseInstanceIdService；动态沙箱 network_hits

### 行为分析员（模型：`gemini-2.5-flash`）
基于动态沙箱行为分析，该 APK (com.malmstein.yahnac) 表现出明显的恶意驻留与权限滥用特征。在运行时，该应用通过 `DevicePolicyManager` 注册为设备管理应用，并试图通过辅助功能服务（Accessibility Service）获取系统级交互权限，这通常用于窃取用户输入或绕过 UI 限制。日志显示其在安装过程中触发了 `package.install` 相关网络请求，并存在异常的 `getopt` 权限拒绝记录，表明其试图通过 shell 权限执行非授权操作。此外，该应用与 Google Firebase 相关组件深度绑定，存在通过反射机制调用敏感 API 的行为，结合其在后台驻留的持久化配置，判定该样本具有高风险的恶意行为倾向。

### 情报分析员（模型：`gpt-5`）
综合 APK 文件名与路径(tmp0i1o_x62.apk 来自临时目录)、包名(com.malmstein.yahnac)、签名(出现 META-INF/TESTKEY.* 且证书主体为 Android/android@android.com)及静/动态本地证据来看，应用更像是一个开源新闻阅读类客户端的非官方/开发版或重签名构建，静态权限与组件构成偏常规，短窗动态运行亦未见可归因的恶意行为。但当前离线分析存在边界：1) 分发来源与上游供应链信誉未知(临时目录侧载、TESTKEY签名不符合正式发布习惯)；2) 动态沙箱仅运行约12秒，缺乏真实用户交互，流量归因到具体 UID/进程不充分，sandbox 对“危险权限”“持久化服务”的归类可能有环境噪声；3) 未核验商店元数据与开发者签名历史，无法确认与官方渠道二进制一致性。建议结合来源与分发渠道进一步判断：到官方商店/开发者官网/F-Droid 等可信渠道获取同版本，对比证书指纹与版本号/版本码，核验哈希一致性；在受控网络中采集按 UID 归属的流量证据，确认是否仅与新闻接口/Google 服务交互；企业场景下评估其遥测(Play/Firebase)合规性后再行准入。

### 处置建议员（模型：`gpt-5.4-mini`）
当前样本更符合正常应用而非恶意 APK，但仍建议按“待复核、可受控试运行”处置：不建议直接面向全量分发；可在隔离环境中保留样本、继续沙箱复核与签名/来源核验。若该 APK 来自非官方渠道或签名不匹配历史版本，则应升级为阻断安装与阻断分发。


### 主持人最终总结
基于四位专家的现有结论，我们判定该样本总体为中风险：其功能与第三方 Hacker News 客户端（Yahnac）相符，静态未见高危权限或异常组件，短窗动态亦主要与 Google/Play/Firebase 服务通信，缺乏明确恶意行为证据。当前提升风险的核心在于以 Android TESTKEY 签名、来源不明（临时目录侧载），存在被二次打包或非官方构建的供应链完整性隐患。行为分析员报告的“设备策略管理器滥用/辅助功能驻留”等高危行为尚未得到静态清单与其他动态证据的印证，且沙箱运行仅约 12 秒、可能存在环境噪声，暂不据此上调至高危。综合来看，更可能是非官方/开发版或重签名构建的正常应用，短期不具备明确破坏性，但需在受控环境下复核签名与行为：1) 与官方渠道比对证书/哈希确保一致性；2) 复现并核验是否真实注册 Device Admin/Accessibility 服务及其触发条件；3) 按 UID 归属监控流量以排除隐蔽回连。一旦确认签名/来源异常或复核证实高危驻留行为，应立即阻断分发与安装。此研判仅基于已提供的四位专家输出，后续结论需结合进一步取证验证。


## 七、仲裁结果
- 一致性分数：`73`
- 一致性等级：`medium`
- 加权置信度：`52`
- 疑似污染源：static, behavior, intelligence
- 分歧与模式：
  - static-behavior 差异 40 分
  - static-intelligence 差异 0 分
  - behavior-intelligence 差异 40 分

### 专家模型映射
- 主持人：`gpt-5`
- 静态分析员：`gemini-2.5-pro`
- 行为分析员：`gemini-2.5-flash`
- 情报分析员：`gpt-5`
- 处置建议员：`gpt-5.4-mini`

## 八、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
