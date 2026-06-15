# SentinelGuard 哨塔检测报告

> 静态检测报告 · 风险等级：**LOW** · 风险分数：**6/100**

## 一、检测结论
- 原始输入：`https://h5.m.goofish.com/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1`
- 对象类型：`url`
- 状态：`ready`
- 证据条数：1 条
- 高危证据：0 条

## 二、统一 IR 摘要
- 规范化 URL：`https://h5.m.goofish.com/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1`
- 协议：`https`
- 主机：`h5.m.goofish.com`
- 路径：`/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1`
- 查询参数数量：`0`

## 三、跳转链
- https://h5.m.goofish.com/wow/moyu/moyu-project/act-react/pages/kN1ISxUuu8G1

## 四、页面线索
- 未获取页面内容线索。

## 五、风险证据
### 1. 页面访问失败
- 规则：`PAGE_FETCH_FAILED`
- 严重级别：`low`
- 说明：检测器无法访问目标页面，可能是网络错误、证书问题或目标主动阻断。
- 证据：`('Connection aborted.', ConnectionResetError(10054, '远程主机强迫关闭了一个现有的连接。', None, 10054, None))`
- 建议：在隔离网络环境中复测，并结合域名结构风险判断。


## 六、论坛式协同研判
### 主持人（模型：`unknown`）
综合 1 条证据，当前风险等级为 low。

### 静态分析员（模型：`unknown`）
URL 结构层面关注暂未发现明显异常。

### 行为分析员（模型：`unknown`）
页面行为与跳转层面关注：页面访问失败。

### 情报分析员（模型：`unknown`）
当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。

### 处置建议员（模型：`unknown`）
可低风险访问，但仍需确认链接来源可信。


## 七、扩展信息
- **web**：当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面截图比对。
