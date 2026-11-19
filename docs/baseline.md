# 检测与决策离线基线

旧版：`bd78bc566e0e7c4879efe230b183f21f14ed026a`，PTD `4.1.0`。改动前直接调用旧 `PromptThreatDetector.analyze` 和 `PersonaMatcher.analyze`，人设参数留空。下面是两个检测器的原始返回，不代表真实 AstrBot 是否阻断，也没有调用模型、工具或发送消息。

新版：PTD `5.0.0`。`tests/test_policy.py` 的 `BENIGN_SAMPLES` 保留同一组输入。默认待机、无显式人设、不带已有手动限制。

| 样例 | 旧版规则分 / 等级（线索） | 旧版人设动作 | 新版规则分 / 检查 | 四模式决策 |
| --- | --- | --- | --- | --- |
| 猫为什么会喵喵叫 | 0 / none | block | 0 / 完成 | 放行 |
| 求函数的上限和下限 | 0 / none | suggest | 0 / 完成 | 放行 |
| 普通昵称 | 0 / none | none | 0 / 完成 | 放行 |
| 正常角色互动 | 2 / low（猫娘） | suggest | 0 / 完成 | 放行 |
| JSON 围栏与消息对象文档 | 9 / medium（三反引号、系统 JSON、代码块） | none | 0 / 完成 | 放行 |
| curl 命令解释 | 7 / medium（命令拉取、curl http） | none | 0 / 完成 | 放行 |
| HTML 注释说明 | 0 / none | none | 0 / 完成 | 放行 |
| 防注入与系统提示词泄露讨论 | 5 / low（字形混淆） | none | 0 / 完成 | 放行 |
| 正常 Base64 文本 | 0 / none | none | 0 / 完成 | 放行 |

复验：在插件目录运行 `python -B -m unittest discover -s tests -p test_policy.py -v`。编码、去重和预算测试使用无害文本与临时测试规则；四模式、复核故障与处罚用人工构造的证据状态验证。不对旧版复现越权，不以本基线估算总体误报率或漏检率。

本地复验：Windows、CPython 3.11.4，16 项通过，测试进程报告 `0.009s`。这是整组离线单测耗时，不是 AstrBot 或模型调用延迟。

## 接入契约

- `detection.PromptThreatDetector().analyze(prompt, config=config)`，或 `analyze_sources({"prompt": prompt, "extra_text:0": extra_text}, config=config)`。每个键应是由调用方生成的来源标签，每个值是独立文本块；不拼接来源或改写输入。仅输入已确认属于本轮的非可信文本。规则分是去重后的启发式权重，不是概率。
- `detect_encoded` 默认开启，关闭只关解码，不关闭规范化或基础规则。旧 `sanitize_enabled` 不再影响扫描，也不会触发原文删改。`anti_harassment_enabled` 默认开启，只控制 `advisories`，不参与风险评分、技术复核触发或处罚。
- `persona_policy.PersonaMatcher().analyze(prompt, persona_name=name, config=config)`。只认可调用方提供的明确策略名；未知、缺失或只出现在自由文本中都不匹配。`persona_enabled` 和 `persona_sensitivity` 仅影响人设建议；结果不得作为技术越权证据。
- `policy.decide(analysis, config, *, is_private=False, observing=False, hard_block=None, exempt=False, review=None, replacement_available=False)`。若返回 `review_required=True`，调用方须复核并再次传入同一请求的分析与配置，再执行最终动作。不要把 `pending` 当成已完成的决策。
- `review` 传 `{"status": "safe"/"confirmed", "confidence": 0.0}`（数字为有限的 0～1），或 `{"status": "failed"/"unavailable", "fault": "timeout"}`。适配层须先严格解析模型响应，将 `ReviewResult.status` 的 `injection` 映射为 `confirmed`、`error` 映射为 `fault`。`fault` 是固定类别，不传原始异常、模型理由或秘密。`is_private` 由宿主事件源计算；`hard_block` 仅接受宿主或有效手动限制的可信原因。
- `action` 是 `allow`、`harden`、`replace` 或 `block`。观察期间只记录 `would_action`，硬限制仍优先。`replacement_available=True` 仅在调用方已验证整份独立替代请求能完整隔离原输入时传入，否则 `scorch` 降级为 `block`。
- `auto_ban=True` 表示决策条件满足，执行方仍须验证当前用户可归责且替换或阻断已执行，才可记自动处罚。决策要求显式启用、检查完成、模型确认技术注入、非观察，且仅限 `intercept` / `scorch`。纯规则命中、故障、人设建议、`sentry` / `aegis` 加固、已有硬限制都不新增处罚。

## 检查未完成与覆盖边界

默认预算为 16,384 输入字符、32 个来源、16,384 累计解码字节、4,096 gzip 输出字节、32 个候选、3 层解码和 100 ms 协作式时间上限。规范化和解码只用于副本。`status=incomplete` 及 `incomplete_reasons` 必须与规则分分开记录；单次正则或解码操作不由计时器强制中断。

不完整时 `sentry` 加固并继续，其余模式阻断（观察时仅记原动作）。即使复核返回安全，也不证明未检查的部分安全。默认审查故障策略允许仅因 `active` 触发且检查完整、无可疑证据的请求继续；严格策略对需要复核的故障请求阻断。`aegis` 需要的复核若被禁用也明确报告不可用；`sentry` 不发起复核。

该检测器只覆盖调用方传入的文本副本；没有检查系统提示、旧历史、媒体、检索页面、工具定义、工具结果或实际执行。结构、代码围栏、普通链接和编码格式本身不计风险；对引用和非直接表达没有完整的语义识别。真实 AstrBot 调用次数、主模型／工具执行阻断及隔离、Dashboard 和升级行为不在本离线基线内。
