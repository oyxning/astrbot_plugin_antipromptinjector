# AstrBot 4.29.4 宿主验证

先测候选目录，再生成安装包。目录门禁通过前不打包；目录通过也不等同于安装包验收通过。

## 本机运行

在当前会话根目录执行。只读复用已有源码和依赖，不安装依赖；运行时配置、SQLite、临时目录及插件副本都在 `host-run/directory-*`。每次运行使用独立目录；卸载只删除其中的插件副本。

```powershell
$env:ASTRBOT_HOST_SOURCE = (Resolve-Path ./AstrBot-4.29.4).Path
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONPATH = $env:ASTRBOT_HOST_SOURCE
python -B -m pytest -q -rs -p no:cacheprovider -p asyncio -o asyncio_default_fixture_loop_scope=function plugin/tests/test_host.py
```

请先激活已具备宿主、pytest 和 pytest-asyncio 依赖的 Python 环境。这组测试不启动真实消息平台、浏览器或收费模型；插件监听和依赖安装会被测试阻止。禁用 bytecode 和 pytest 缓存。

## 断言与范围

| 用例 | 通过条件 |
| --- | --- |
| 不加载候选的宿主正常对照 | `ProcessStage` → 主 Agent → 替身 provider 调用两次，期间真实工具执行器调用本地计数工具一次。 |
| 候选目录加载 / 重载 / 卸载 | 真实 `PluginManager` 从临时插件目录加载；重载只绑定一个请求 hook，切换到新实例，旧 handler 不残留、旧任务结束；卸载移除模块、handler 和副本，退出临时任务。真实 Dashboard 插件分发在加载和重载后都能调用 `GET /antipromptinjector/overview`，重载后路径与方法无重复、旧回调不残留，卸载后路由表清空且同一路径返回未找到。 |
| 主请求硬阻断与放行 | 同一条普通文本，按临时作用域黑名单区分用户。真实分发记录显示 `intercept_llm_request` 执行成功；阻断时主 provider 和工具均为零，放行时主 provider 两次、工具一次。 |
| 复核与决策 | 同一条普通文本，独立假复核 provider 分别返回确认和安全判定。确认时只调用复核 provider，主 provider 与工具为零；安全时正常继续。 |
| 钩子顺序与取消 | 在请求钩子前后注册优先级 `999` 和 `-1001` 的空处理器。普通请求必须按 `999 → -1000 → -1001` 分发；复核被取消时，后置处理器、主模型和工具均不运行。 |

真实分发器、主 Agent 构建、runner 和工具执行器未替换。替身用于 provider、平台发送及外围服务（人设选择、会话、知识库和统计等）。Dashboard 测试直接调用宿主插件分发，注入已登录用户名，不打开监听端口，也不测试登录中间件。本验证不衡量检测准确率，不复现旧实现，不覆盖远端 Agent。

复核确认与放行用例在临时宿主配置关闭时间提醒，以单独验证纯文本路径。运行时只可复核能和事件原文对应的 prompt；来源未确认的附加块不出站、不作处罚证据。附加块本身命中且需要复核时，记录 `source_not_reviewable`。

## 安装包复验

目录轮全过且正式 ZIP 可用后，在同一 PowerShell 会话设置 `ASTRBOT_HOST_PACKAGE` 为 ZIP 的绝对路径，再执行上面的 pytest 命令。第二轮从 `host-run/package-*` 下的副本调用真实 `PluginManager.install_plugin_from_file()`，再执行相同的请求、路由和生命周期检查；宿主可消费这份临时 ZIP，不会删除原包。本轮不自行构建 ZIP。

## 当前结果

- AstrBot `4.29.4`：阻断时主 provider `0` 次、工具 `0` 次；正常对照主 provider `2` 次、计数工具 `1` 次；复核确认时独立复核 provider `1` 次且无工具，主 provider 和计数工具均为 `0`。Dashboard 路由卸载已验证。
- 有两条弃用告警，来自宿主的 `audioop` 和插件的 `register_star` 装饰器。
- ZIP 轮使用同一组断言。验收报告单列交付包的 SHA-256 和实跑结果；不以目录轮代替 ZIP 轮。
