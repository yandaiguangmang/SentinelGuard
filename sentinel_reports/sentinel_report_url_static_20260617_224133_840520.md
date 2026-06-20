# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**LOW** · 风险分数：**0/100**

## 一、检测结论
- 原始输入：`https://www.baidu.com`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：0 条
- 高危证据：0 条

## 二、统一 IR 摘要
- 规范化 URL：`https://www.baidu.com/`
- 协议：`https`
- 主机：`www.baidu.com`
- 路径：`/`
- 查询参数数量：`0`

## 三、跳转链
- https://www.baidu.com/

## 四、页面线索
- status_code：200
- content_type：text/html; charset=utf-8
- final_url：https://www.baidu.com/
- body_limited_to_bytes：200000
- fetch_mode：proxy
- proxy_used：True
- proxy_config：{'http': 'http://10.250.167.176:7890', 'https': 'http://10.250.167.176:7890', 'detection_http': 'http://10.250.167.176:7890', 'detection_https': 'http://10.250.167.176:7890'}
- title：百度一下，你就知道
- visible_text_excerpt：百度一下，你就知道 #form .bdsug{top:39px}.bdsug{display:none;position:absolute;width:535px;background:#fff;border:1px solid #ccc!important;_overflow:hidden;box-shadow:1px 1px 3px #ededed;-webkit-box-shadow:1px 1px 3px #ededed;-moz-box-shadow:1px 1px 3px #ededed;-o-box-shadow:1px 1px 3px #ededed}.bdsug li{width:519px;color:#000;font:14px arial;line-height:25px;padding:0 8px;position:relative;cursor:default}.bdsug li.bdsug-s{background:#f0f0f0}.bdsug-store span,.bdsug-store b{color:#7A77C8}.bdsug-store-del{font-size:12px;color:#666;text-decoration:underline;position:absolute;right:8px;top:0;cursor:pointer;display:none}.bdsug-s .bdsug-store-del{display:inline-block}.bdsug-ala{display:inline-block;border-bottom:1px solid #e6e6e6}.bdsug-ala h3{line-height:14px;background:url(//www.baidu.com/img/sug_bd.p
- password_forms：0
- hidden_inputs：0
- meta_refresh：无
- script_srcs：无
- form_actions：无
- download_links：无
- external_script_count：0
- html_summary：{'raw_excerpt': '<!DOCTYPE html><!--STATUS OK--><html><head><meta http-equiv="Content-Type" content="text/html;charset=utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"><meta content="origin-when-cross-origin" name="referrer"><meta name="theme-color" content="#ffffff"><meta name="description" content="全球领先的中文搜索引擎、致力于让网民更便捷地获取信息，找到所求。百度超过千亿的中文网页数据库，可以瞬间找到相关的搜索结果。"><link rel="shortcut icon" href="https://www.baidu.com/favicon.ico" type="image/x-icon" /><link rel="search" type="application/opensearchdescription+xml" href="/content-search.xml" title="百度搜索" /><link rel="stylesheet" data-for="result" href="https://pss.bdstatic.com/r/www/static/font/cosmic/pc/cos-icon_3df378f.css"/><link rel="icon" sizes="any" mask href="https://www.baidu.com/favicon.ico"><link rel="dns-prefetch" href="//dss0.bdstatic.com"/><link rel="dns-prefetch" href="//dss1.bdstatic.com"/><link rel="dns-prefetch" href="//ss1.bdstatic.com"/><link rel="dns-prefetch" href="//sp0.baidu.com"/><link rel="dns-prefetch" href="//sp1.baidu.com"/><link rel="dns-prefetch" href="//sp2.baidu.com"/><link rel="dns-prefetch" href="//pss.bdstatic.com"/><link rel="apple-touch-icon-precomposed" href="https://psstatic.cdn.bcebos.com/vid', 'text_excerpt': '百度一下，你就知道 #form .bdsug{top:39px}.bdsug{display:none;position:absolute;width:535px;background:#fff;border:1px solid #ccc!important;_overflow:hidden;box-shadow:1px 1px 3px #ededed;-webkit-box-shadow:1px 1px 3px #ededed;-moz-box-shadow:1px 1px 3px #ededed;-o-box-shadow:1px 1px 3px #ededed}.bdsug li{width:519px;color:#000;font:14px arial;line-height:25px;padding:0 8px;position:relative;cursor:default}.bdsug li.bdsug-s{background:#f0f0f0}.bdsug-store span,.bdsug-store b{color:#7A77C8}.bdsug-store-del{font-size:12px;color:#666;text-decoration:underline;position:absolute;right:8px;top:0;cursor:pointer;display:none}.bdsug-s .bdsug-store-del{display:inline-block}.bdsug-ala{display:inline-block;border-bottom:1px solid #e6e6e6}.bdsug-ala h3{line-height:14px;background:url(//www.baidu.com/img/sug_bd.p'}

## 四点一、浏览器证据 / 截图
- 抓取模式：`proxy`
- 代理是否参与：`True`

## 五、风险证据
- 未发现明显风险项。

## 六、论坛式协同研判
### 主持人（模型：`unknown`）
未发现明显高危特征，仍建议结合链接来源和访问上下文复核。

### 静态分析员（模型：`unknown`）
URL 结构未命中当前规则库中的明显异常项。

### 行为分析员（模型：`unknown`）
未观察到可疑跳转或页面行为证据。

### 情报分析员（模型：`unknown`）
当前离线版本未接入外部威胁情报，结论基于本地规则。

### 处置建议员（模型：`unknown`）
可正常访问，但不要在陌生页面提交敏感信息。


## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。
- **apk**：当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。
