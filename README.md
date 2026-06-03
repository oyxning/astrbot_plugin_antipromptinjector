# Anti-Prompt Injector

<div align="center">

![License](https://img.shields.io/badge/License-AGPL--3.0-red.svg) ![PTD Core](https://img.shields.io/badge/PTD-4.1-brightgreen.svg) ![AstrBot](https://img.shields.io/badge/Platform-AstrBot-8b5cf6.svg) [![GitHub](https://img.shields.io/badge/GitHub-Repository-black.svg)](https://github.com/oyxning/astrbot_plugin_antipromptinjector)

</div>

<p align="center">
  <img src="https://raw.githubusercontent.com/oyxning/oyxning/refs/heads/main/AntiPromptInjectorlogo.png" alt="AntiPromptInjector Banner" width="100%" style="border-radius: 8px;" />
</p>

<div align="center">

**AstrBot 提示词注入纵深防御方案。**  
多层特征检测 · LLM 辅助复核 · 自动化封禁闭环 · 可视化运维面板

</div>

---

## 设计哲学

> **防御到位，不挡路。** —— 在不妨碍正常对话体验的前提下，提供生产级提示词注入防护。

Anti-Prompt Injector 不是简单的关键词黑名单，而是一套**分层检测 → 语义复核 → 策略响应**的完整安全链路。每一条用户消息在抵达 LLM 之前，都须依次通过 PTD 启发式引擎与可选 LLM 协审的双重验证，最终由策略引擎裁定处置动作。

---

## 架构总览

```
  用户输入
     │
     ▼
┌─────────────────────────────────┐
│   PTD 4.1  ·  启发式检测引擎    │  ←  第一层：检测
│─────────────────────────────────│
│  正则特征匹配    (28+)          │
│  关键词权重      (120+)         │
│  编码解码器      (6 种)         │
│  模式评分        (0-100)        │
└──────────────┬──────────────────┘
               │  得分 ≥ 阈值
               ▼
┌─────────────────────────────────┐
│   LLM 协审引擎  （可选）        │  ←  第二层：复核
│─────────────────────────────────│
│  语义分析                       │
│  上下文评估                     │
│  威胁确认                       │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│   策略引擎                      │  ←  第三层：响应
│─────────────────────────────────│
│  静默加固  ·  Silent Harden     │
│  复核确认  ·  Confirm & Harden  │
│  内容替换  ·  Replace Content   │
│  立即拒绝  ·  Immediate Reject  │
└─────────────────────────────────┘
```

| 层级 | 组件 | 职责 |
|:---:|------|------|
| L1 | **Prompt Threat Detector 4.1** | 多模特征加权评分、编码载荷解码、对抗模式识别 |
| L2 | **LLM 协审** | 语义级威胁二次确认，消除启发式误报 |
| L3 | **策略引擎** | 分级防御动作调派、自动拉黑、事件审计 |

---

## 威胁覆盖矩阵 · PTD 4.1

PTD 4.1 维护 **28+ 正则特征**、**120+ 关键词权重**、**6 种编码解码器**，覆盖 13 类攻击家族：

| # | 攻击分类 | 覆盖技术 | 级别 |
|:--:|----------|---------|:----:|
| 1 | **直接注入** | 系统指令覆盖、角色冒充、指令劫持 | `严重` |
| 2 | **间接注入** | 跨提示注入、外部内容投毒、RAG 文档注入 | `严重` |
| 3 | **越狱攻击** | Skeleton Key、DAN 递归、祖母漏洞、道德绑架、对抗性后缀 | `严重` |
| 4 | **Promptware** | C2 信标回连、命令与控制中继、多阶段杀伤链 | `高危` |
| 5 | **多 Agent 攻击** | 编排器注入、Agent 间载荷传播、MCP 采样注入 | `高危` |
| 6 | **令牌利用** | MetaBreak 特殊 Token 注入、`<丨im_start丨>` 绕过、endoftext 占位 | `严重` |
| 7 | **编码逃逸** | Base64 / Gzip、ROT13、ASCII Smuggling、Unicode 标签、零宽字符、Hex/URL | `高危` |
| 8 | **低资源语言** | 韩语、越南语、印尼语、日语 —— 利用安全对齐盲区 | `高危` |
| 9 | **混淆变形** | Leet-speek 字形替换、Unicode 同形字、不可见字符夹带 | `中危` |
| 10 | **记忆投毒** | 持久化 Agent 记忆注入、对话状态污染 | `高危` |
| 11 | **数据外泄** | Markdown 图片 URL 泄漏、输出转发、凭据提取 | `严重` |
| 12 | **骚扰检测** | 性骚扰识别、辱骂 / 霸凌 / 胁迫 | `高危` |
| 13 | **仇恨言论** | 定向仇恨生成、民族 / 宗教偏见煽动（中英双语） | `严重` |

### 编码解码器

`ROT13` · `Base64` · `URL-encode` · `Unicode escape` · `Hex escape` · `ASCII Smuggling tags`

---

## 四象防御模式

四种运行模式，WebUI 一键切换或指令轮换：

| 模式 | 键值 | 行为链路 | 适用场景 |
|------|:----:|---------|----------|
| **静默加固** | `sentry` | 检测风险 → 仅加固系统指令，对话无感 | 低延迟、容忍少量误报 |
| **复核确认** | `aegis` | 检测风险 → LLM 二次确认 → 加固 | 安全与体验兼顾 |
| **内容替换** | `scorch` | 检测风险 → 替换用户原文为拒绝提示 | 公开服务、严格屏蔽 |
| **立即拒绝** | `intercept` | 检测风险 → 终止事件，数据不达 LLM | 合规审计、强制拒绝 |

> `intercept` 模式下额外启用**三级角色递进策略**：`建议修正 → 驳回请求 → 拒绝服务`。

---

## 快速部署

```bash
# 市场安装 或 手动克隆
git clone https://github.com/oyxning/astrbot_plugin_antipromptinjector

# 重启 AstrBot，PTD 核心自动初始化
# 设置面板密码（可选）
/设置WebUI密码 <你的密码>
```

默认面板 `http://127.0.0.1:18888`，端口冲突自动递增。

> Docker：`_conf_schema.json` 中设置 `webui_host: "0.0.0.0"`，Origin 校验自动适配宿主机访问地址。

---

## 指令手册

| 指令 | 权限 | 说明 |
|------|:----:|------|
| `/反注入帮助` | 全员 | 查看全部指令 |
| `/反注入统计` | 管理员 | 启发式、LLM 与自动封禁统计 |
| `/切换防护模式` | 管理员 | 四种模式轮换 |
| `/切换观察模式 <分钟>` | 管理员 | 临时静默加固，到时自动恢复 |
| `/LLM分析状态` | 管理员 | 当前模式与 LLM 配置总览 |
| `/开启LLM注入分析` | 管理员 | 启用 LLM 复核 |
| `/关闭LLM注入分析` | 管理员 | 关闭 LLM 复核 |
| `/设置审查LLM <供应商> [模型]` | 管理员 | 配置复核 LLM 后端 |
| `/开启防骚扰` | 管理员 | 启用骚扰 / 辱骂 / 霸凌检测 |
| `/关闭防骚扰` | 管理员 | 关闭骚扰检测 |
| `/拉黑 <ID> [分钟]` | 管理员 | 手动封禁（0 = 永久） |
| `/解封 <ID>` | 管理员 | 解除封禁 |
| `/查看黑名单` | 管理员 | 黑名单与剩余时长 |
| `/添加防注入白名单ID <ID>` | 管理员 | 加入白名单 |
| `/移除防注入白名单ID <ID>` | 管理员 | 移除白名单 |
| `/查看防注入白名单` | 管理员 / 白名单 | 白名单成员 |
| `/设置WebUI密码 <密码>` | 管理员 | 设置面板登录密码 |
| `/查看管理员状态` | 全员 | 自身权限标签 |

> **权限模型** — 管理类指令严格限定 AstrBot 全局管理员。白名单用户免检放行，但不可操作安全控制项。

---

## WebUI 控制台

```
http://127.0.0.1:18888
```

| 模块 | 能力 |
|------|------|
| **身份认证** | HMAC 加盐 PBKDF2 / SHA-256 哈希，会话超时，可选 Token 访问 |
| **实时概览** | PTD 版本 · 防御模式 · LLM 策略 · 封禁计数 · 拦截统计 |
| **策略控制** | 一键切换防御模式 / 启停 LLM / 开关骚扰检测 |
| **名单管理** | 黑白名单 CRUD，剩余封禁时长显示 |
| **审计日志** | 拦截事件与分析记录，含级别、得分、触发源、角色动作 |
| **筛选导出** | 用户 / 群 / 级别 / 触发 / 动作 / 关键词 / 时间范围多维筛选；CSV 导出 |
| **视觉主题** | 暗色 / 亮色双主题，渐变背景、毛玻璃面板、悬浮动画 |

---

## 配置参数

通过 AstrBot WebUI 或 `_conf_schema.json` 编辑：

| 字段 | 类型 | 默认值 | 说明 |
|------|:----:|--------|------|
| `defense_mode` | enum | `intercept` | 当前防御策略 |
| `auto_blacklist` | bool | `true` | 注入检测后自动拉黑 |
| `blacklist_duration` | int | `60` | 自动封禁时长（分钟，0 = 永久） |
| `llm_analysis_mode` | enum | `standby` | LLM 复核触发策略 |
| `llm_analysis_private_chat_enabled` | bool | `false` | 私聊启用 LLM 复核 |
| `review_provider` | str | `""` | 审查 LLM 供应商（空 = 默认） |
| `review_model` | str | `""` | 审查 LLM 模型（空 = 默认） |
| `anti_harassment_enabled` | bool | `true` | 骚扰 / 辱骂 / 霸凌检测 |
| `sanitize_enabled` | bool | `true` | 非严重威胁提示词净化 |
| `persona_enabled` | bool | `true` | 人设一致性校验 |
| `persona_sensitivity` | float | `0.7` | 人设匹配严格度（0.1–1.0） |
| `incident_history_size` | int | `100` | 拦截历史保留条数 |
| `webui_host` | str | `127.0.0.1` | 面板监听地址 |
| `webui_port` | int | `18888` | 面板端口（冲突自动递增） |

> `webui_password_*`、`webui_session_timeout`、`webui_token` 由插件自动维护。

---

## 社区

[官方文档](https://docs.astrbot.app/) · [GitHub Issues](https://github.com/oyxning/astrbot_plugin_antipromptinjector) · [QQ 群：AstrBot Plugin 猫娘乐园](https://qm.qq.com/q/dBWQXCpwnm)

如果本插件曾为你的部署挡住过一次提示词注入，不妨点个 ⭐。
