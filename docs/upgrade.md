# 原地升级

停用旧插件后，在原安装目录替换插件文件，不要新建第二个插件目录或改名。保留 AstrBot 的 `data/config` 和插件数据目录。安装或回滚前，建议额外备份这两处数据。

## 迁移与恢复

- AstrBot v4.29.4 以插件的安装目录名定位 `data/config/<目录名>_config.json`，不是用插件的展示名称。模块导入时必须先调用 `prepare_legacy_config(Path(get_astrbot_config_path()) / f"{Path(__file__).parent.name}_config.json")`。宿主随后按 schema 补全并清除已移除字段；在构造函数中才备份来不及。
- 如果旧配置包含会被移除的字段，首次导入对其做字节级备份：`<目录名>_config.json.antipromptinjector-v1.bak`。备份保留原配置、旧名单、任意自定义字段及原 WebUI 的登录材料。它不是可下载附件，不要上传、提交、分享或放入安装包。
- 保留有效的防护模式、复核、封禁、人设和诊断设置。新安装默认 `sentry`、不开启自动封禁；升级保留有效的 `auto_blacklist` 值，但它只允许在技术注入已确认且确实执行替换或阻断后生效。观察、加固、人设偏差、仅规则可疑和审查失败不触发自动封禁。
- 不再读取独立 WebUI、旧签名锁和原文净化配置。旧 WebUI 的地址、端口、密码和登录令牌不用于 Dashboard。旧的人设开关和敏感度只是专项策略的参数，没有明确匹配策略时不起作用。未识别的自定义旧字段只保留在备份，不假装已映射到新功能。
- 插件数据目录的 `antipromptinjector-state.json` 保存新版名单、观察到期时间和诊断记录。成功写入后，以该文件为准，重复加载不会重新导入旧名单；状态写入失败时可保留备份重试。旧版仅存在内存中的诊断无法恢复。
- 回滚时先停用插件。保留新版状态文件作为独立备份，再将 `.bak` 恢复到原配置文件路径并还原旧版源码。旧版不会读取新版状态。再次升级仍以已存在的新版状态为准；只有明确要重新执行一次原始迁移时，才在停用状态下移开新版状态文件。

## 名单与诊断

- 新名单按平台、机器人实例、用户和可选会话匹配；不指定会话表示仅同一平台和实例内通用。名单豁免不授予管理权限，也不解除手动封禁。到期后不再匹配，永久项的到期时间为 `null`。
- 旧黑名单没有平台或实例信息。未认领且未到期时，继续沿用旧版纯用户 ID 的跨平台、跨实例、跨会话匹配，以免升级中断已有封禁；同号冲突可移除该旧项或认领到确定范围。旧白名单保留记录但不会按纯 ID 自动豁免。确认身份后可认领到指定范围。认领会移除对应旧项；期限不重算。
- 默认诊断只收有限的本轮用户文本摘录和命中片段。过滤常见凭据、URL、邮箱和异常文本；不接受系统提示或工具原文作为用户摘录。复核理由和决策理由同样裁剪并脱敏。启发式脱敏不能识别任意无标记的密钥，调用方不得传入已知秘密或原始错误响应。
- 统计按保留窗口分别计算放行、加固、替换、阻断、实际新增封禁、审查失败。容量调小后只返回新容量内的记录，下次新增诊断时从磁盘裁掉超额项。清除诊断不改名单、观察或配置。

## 主流程和设置中心

- 主流程通过 `PluginState(config, data_dir)` 使用宿主的 `AstrBotConfig`。`settings` 是有效设置快照。复核使用 `review_timeout_seconds`（1–60）、`review_max_concurrency`（1–16）、`review_max_chars`（256–8192）。三个覆盖开关为 `protect_group_chat`、`protect_private_chat` 和 `scan_extra_text`；它们不解除前置权限和封禁限制。
- 名单使用 `Identity(platform, instance, user, session=None)`；`identity_from_event(event, user=..., session_scope=...)` 从事件构建身份。`match_list(kind, identity)` 返回匹配条目或 `None`；`list_entries(kind=None, pending=True)` 返回旧名单；管理层可调用 `put_entry`、`remove_entry`、`remove_legacy`、`adopt_legacy`。这些方法不代替调用方鉴权。
- `set_observation(minutes)` 只更新到期时间，`0` 结束观察。观察期间运行时保持只记录，不修改持久模式。到期无须执行恢复写入。
- `config_view()` 返回 `config`、`revision`、`effective`、`status`、`invalid_settings` 和观察到期时间。`save_settings(patch, revision)` 只接受 schema 字段；`RevisionConflict` 表示旧页面或宿主配置已变化，应重新读取。如果原生配置已保存但当前实例仍是旧值，状态为 `reload_required`；应完成宿主重载后重试。成功保存但可选应用回调失败则返回 `apply_failed`，配置已落盘，有效设置仍为应用前值。重新应用或重载后再确认生效。Web 字段和上下限以 `state.SCHEMA` / `state.BOUNDS` 为准，不单独维护一套范围。
- `record()`、`records()`、`stats()`、`clear_records()` 共用同一诊断数据。试算不调用任何写接口。传给 `record()` 的 `request_id` 应是本轮独有的随机 ID，不要使用会话、用户 ID 或消息原文代替。
