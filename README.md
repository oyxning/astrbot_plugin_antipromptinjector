# Anti-Prompt Injector · AstrBot 提示词安全插件

![License](https://img.shields.io/badge/License-AGPL--3.0-red.svg)
![PTD Core](https://img.shields.io/badge/PTD-3.0-brightgreen.svg)
[![GitHub Repo](https://img.shields.io/badge/GitHub-astrbot__plugin__antipromptinjector-black.svg)](https://github.com/oyxning/astrbot_plugin_antipromptinjector)

<p align="center">
  <img src="https://raw.githubusercontent.com/oyxning/oyxning/refs/heads/main/AntiPromptInjectorlogo.png" alt="AntiPromptInjector Banner" width="100%" style="border-radius: 8px;" />
</p>

> Anti-Prompt Injector 为 AstrBot 提供提示词注入防护方案，通过 Prompt Threat Detector (PTD) 核心、LLM 复核与自动封禁链路，抵御越狱、系统覆盖、角色调教等攻击手法。

---

## ✨ v3.4 亮点

- **人设冲突检测**：集成 `persona_core` 与 `PersonaMatcher`，新增 `persona_enabled` / `persona_sensitivity` 配置；在分析日志中记录 `persona_action`、`persona_score`、`persona_reason`，并与核心严重级别协同映射为拦截动作。
- **三级拦截策略**：在拦截模式下根据人设动作与风险级别执行 `block / revise / suggest` 三级策略，进一步提升可控性与可解释性。
- **观察模式临时切换**：新增指令 `切换观察模式 <分钟>`，可临时切至哨兵模式，倒计时结束后自动恢复拦截模式，便于灰度与问题定位。
- **WebUI 筛选与导出**：仪表盘新增筛选区块，支持按用户/群/严重级别/触发/动作/关键词/时间范围筛选；新增导出端点 `/export/incidents.csv` 与 `/export/analysis.csv`，导出数据包含动作与人设字段。
- **日志字段扩展**：拦截事件与分析日志新增 `action_taken` 字段；分析日志新增人设相关字段，便于审计与追溯。
- **默认防护模式**：默认模式调整为 `intercept`（拦截模式），更贴近审计与合规要求。
- **版本号**：插件版本升级至 `v3.5.1`。

---


## 🛡️ 四象防御模式

| 模式 | 标签 | 特性 | 推荐场景 |
| --- | --- | --- | --- |
| 哨兵 | `sentry` | 启发式巡航 + 自动加固，性能最佳 | 内部环境、低延迟业务 |
| 神盾 | `aegis` | 启发式 + LLM 复核，兼顾准确率 | 常规生产环境 |
| 焦土 | `scorch` | 判定风险即改写提示词 | 高风险公开场景 |
| 拦截 | `intercept` | 命中风险直接终止事件 | 合规审计、必须拒绝的请求 |

---

## 🕹️ WebUI 功能

- 登录保护：`/设置WebUI密码 <新密码>` 后启用；支持会话超时、可选 `webui_token`。
- 核心状态：PTD 版本、防护模式、LLM 策略、自动封禁统计等一览。
- 快捷操作：快速切换模式、启停 LLM、清空拦截/日志数据。
- 审查设置：在仪表盘直接配置审查 `供应商/模型`，并一键开启/关闭防骚扰检测。
- 名单管理：黑白名单增删、剩余封禁时长显示。
- 实时审计：拦截事件 + 分析日志记录命中规则、得分、触发源；导出数据包含 `action_taken` 与人设相关字段。
- 筛选与导出：支持按用户/群/严重级别/触发/动作/关键词/时间范围筛选，并导出 CSV（`/export/incidents.csv`、`/export/analysis.csv`）。

访问 `http://127.0.0.1:18888`，如端口被占用会自动改用备选端口并在日志提示。

---

## 🔧 常用指令

| 指令 | 权限 | 说明 |
| --- | --- | --- |
| `/反注入帮助` | 全员 | 查看全部指令 |
| `/反注入统计` | 管理员 / 白名单 | 输出启发式、LLM 命中与自动封禁统计 |
| `/切换防护模式` | 管理员 | 在四种模式间轮换 |
| `切换观察模式 <分钟>` | 管理员 | 临时切为哨兵模式，结束后自动恢复拦截 |
| `/LLM分析状态` | 管理员 | 输出当前模式 / LLM 配置示意图 |
| `/开启LLM注入分析` | 管理员 | LLM 复核切换为活跃 |
| `/关闭LLM注入分析` | 管理员 | 关闭 LLM 复核 |
| `/设置审查LLM <供应商> [模型]` | 管理员 | 设置复核使用的 Provider/模型（留空=默认） |
| `/开启防骚扰` | 管理员 | 开启性骚扰/辱骂/霸凌检测与拦截 |
| `/关闭防骚扰` | 管理员 | 关闭骚扰检测（保留日志但不计入拦截评分） |
| `/拉黑 <ID> [分钟]` | 管理员 | 手动封禁，0 代表永久 |
| `/解封 <ID>` | 管理员 | 解除封禁 |
| `/查看黑名单` | 管理员 | 查看黑名单与剩余时长 |
| `/添加防注入白名单ID <ID>` | 管理员 | 加入白名单 |
| `/移除防注入白名单ID <ID>` | 管理员 | 移除白名单 |
| `/查看防注入白名单` | 管理员 / 白名单 | 查看白名单成员 |
| `/设置WebUI密码 <新密码>` | 管理员 | 更新 WebUI 登录密码，清除旧会话 |
| `/查看管理员状态` | 全员 | 查看自身权限标签 |

---

## ⚙️ 配置字段（`_conf_schema.json`）

- `defense_mode`：`sentry / aegis / scorch / intercept`
- `auto_blacklist`：启用自动拉黑（默认 `true`）
- `blacklist_duration`：自动封禁时长（分钟，0=永久）
- `llm_analysis_mode`：`active / standby / disabled`
- `llm_analysis_private_chat_enabled`：私聊是否复核
- `review_provider` / `review_model`：审查 LLM 的供应商与模型（留空使用默认）
- `anti_harassment_enabled`：启用防性骚扰/辱骂/霸凌检测与拦截
- `incident_history_size`：WebUI 中保留的历史条数
- `webui_host` / `webui_port`：控制台监听地址，端口冲突时会自动递增
- `webui_password_*` / `webui_session_timeout`：由插件自动维护，无需手动修改

---

## 🚀 部署建议

1. 安装插件并重启 AstrBot，确认日志出现加载成功提示。
2. 发送越狱类提示词验证启发式拦截；在 WebUI 查看拦截事件与分析日志。
3. 使用 `/设置WebUI密码` 更新登录凭证，开启安全防线。
4. 结合 `/反注入统计` 与 WebUI 统计对照，确保数据一致。
5. 若需公网访问，请结合反向代理、VPN 或额外鉴权机制。

---

## 🤝 反馈渠道

- 官方文档：https://docs.astrbot.app/
- GitHub Issues：https://github.com/oyxning/astrbot_plugin_antipromptinjector
- QQ 反馈群：【AstrBot Plugin 猫娘乐园】https://qm.qq.com/q/dBWQXCpwnm

如果 Anti-Prompt Injector 帮你挡下了某一次提示词入侵，别忘了给仓库点个 ⭐️ 支持！
