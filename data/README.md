# 数据说明（首版20案）

> **v2说明**：本目录的20条案例及114条保存件索引是首版历史基线，不代表新[Issue #4](https://github.com/Sisu-z/persona-commerce-research/issues/4)匿名/不露脸商业人设研究已采到合格样本。新任务遵循[新版方法](../docs/methodology.md)与[现场SOP](../docs/field-method-v2.md)，原始记录不得因文件存在而冒充新证据。


`cases.jsonl` 每行一个主体，正文以 `document` 指向的案例为准。字段包括 ID、原采集 ID、类别、观察日期、P 路径层级、T 成交实证层级、价格记录、来源及证据档案标识。不同商品放各自价格行，`conditions` 不能丢弃；不得只抽金额作现价排行榜。`paid_or_delivered_by_researcher` 与 `premium_causality_verified` 本轮全部为 false。

`evidence.jsonl` 是私有档案的完整性清单：匿名档案 ID、SHA-256、字节数、类型与观察日期。只证明保存件的一致性，不证明网页、自述或商业结论正确，也不是可公开下载的原文库。私有对应表在本地，公共来源 URL 可以复访。

`category` 的 china/expert/builder 是本轮分工来源，不是市场分类或排名。P/T 定义见 [研究方法](../docs/methodology.md)。外部平台自带的等级、作者规模、聚合购买数均不直接转换为 T2；本轮没有 T2。

原始页面可能晚于/早于搜索快照，浏览器也可能显示区域化币种或先出现初始化的0。本轮以明确标出的动态补核为准，保留冲突原因，不将不同时间/币种/商品合成一个价梯。
