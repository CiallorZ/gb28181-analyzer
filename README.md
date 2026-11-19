# GB28181 Analyzer

[![CI](https://github.com/CiallorZ/gb28181-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/CiallorZ/gb28181-analyzer/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-42%20passed-brightgreen)](backend/tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Vue](https://img.shields.io/badge/vue-3.5-42b883)](https://vuejs.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**网络抓包分析工具 · 协议与流媒体质量诊断**

上传 PCAP/PCAPNG 抓包，自动解析 SIP 信令、SDP 协商、RTP 媒体流与 PS 封装，
重建点播会话，计算媒体质量指标，识别异常并给出可追溯证据的诊断结论，
最终把 RTP 载荷还原成可播放的视频。

> 定位：**通用网络抓包分析**打底（SIP / RTP / RTCP / TCP 流重组），
> 再针对视频联网场景下钻到 SDP 协商、PS 封装与视频编码还原。
> 对 GB/T 28181（2016 / 2022）做了专项适配，但不限于此。

---

## 快速开始

### 环境要求

| 依赖 | 版本 | 说明 |
|---|---|---|
| Python | 3.10+ | 后端 |
| Node.js | 18+ | 前端构建 |
| tshark | 4.x | 抓包读取（Wireshark 自带） |
| ffmpeg | 6.x+ | 视频重建（不装则只能看编码参数，不能出画面） |

### 启动后端

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt

python -m uvicorn app.main:app --host 127.0.0.1 --port 8788 --reload
```

后端启动后：

- API 文档：http://127.0.0.1:8788/api/v1/docs
- 健康检查：http://127.0.0.1:8788/api/v1/health

### 启动前端

```bash
cd frontend
npm install
npm run dev
```

打开 http://localhost:5173

前端 dev server 已配置代理，`/api` 自动转发到 `127.0.0.1:8788`。

### 生产构建

```bash
cd frontend
npm run build          # 产物在 dist/
```

把 `dist/` 交给任意静态服务器，或让 Nginx 反代到后端。

---

## 技术栈与选型说明

PRD 推荐 Go + PostgreSQL + Docker Compose。本项目实际采用：

| 层 | PRD 推荐 | 实际采用 | 调整原因 |
|---|---|---|---|
| 后端 | Go + Gin | **Python + FastAPI** | 已有 2886 行经真实抓包验证的 GB28181 解析逻辑（SIP 对话重建、SDP 解析、RTP 序列号回绕、RFC4571 重组），迁移到 Go 需全部重写并重新验证，风险与工期都不划算。FastAPI 同样提供 OpenAPI。 |
| 数据库 | PostgreSQL | **SQLite**（schema 兼容 PG） | 部署环境无 Docker 与 PG，无法验证交付物能否运行。SQLite 开箱即用；模型定义与 PG 兼容，切库只需改 `DATABASE_URL`。 |
| 前端 | Vue3 + Naive UI | **Vue3 + 自研设计系统** | 专业分析工具需要高信息密度布局，Naive UI 的组件默认间距偏大。图表用 ECharts，时序图用原生 SVG。 |
| 部署 | Docker Compose | **直接运行 / 后续补 Compose** | 当前环境无 Docker，提供 Compose 文件但无法实测，故标注为未验证。 |

**未采纳 Go 的关键理由**：协议解析的难点不在语言性能，而在协议细节的正确性
（GB28181 的 SDP `y=` 字段、TCP 被动模式端口语义、RTP 序号回绕、PS 参数集对齐）。
这些逻辑已用三个真实抓包反复验证并修复过 14 个具体缺陷，重写等于把这些坑再踩一遍。

---

## 架构

```
抓包文件
   │
   ├─ 1. 文件信息       parsers/capture.py       capinfos + 魔数识别
   ├─ 2. 报文索引       parsers/capture.py       流式，不入内存
   ├─ 3. SIP 解析       parsers/sip_parser.py    自研，不依赖 tshark
   ├─ 4. SDP 解析       parsers/sip_parser.py    含 y=/f=/setup 扩展
   ├─ 5. 会话重建       parsers/session_builder.py
   ├─ 6. RTP 分析       parsers/rtp_analyzer.py  UDP + RFC4571/TCP
   ├─ 7. 媒体关联       parsers/session_builder.py
   ├─ 8. 诊断           services/diagnosis.py    规则引擎
   └─ 9. 入库           services/analyzer.py
```

### 目录结构

```
backend/
  app/
    api/           路由（tasks / sessions / diagnostics）
    core/          配置、数据库
    models/        SQLAlchemy 实体
    parsers/       capture / sip_parser / session_builder / rtp_analyzer
    schemas/       Pydantic 契约
    services/      analyzer（编排）/ diagnosis（规则引擎）
  tests/          单元与集成测试
  migrations/     版本化迁移（待补）
frontend/
  src/
    api/           axios 客户端
    stores/        Pinia
    views/         6 个页面
    styles/        设计系统
data/
  uploads/        上传的抓包
  analyzer.db     SQLite 数据库
```

---

## 关键实现说明

### 为什么不用 tshark 的 rtp 解码器

实测 `tshark -Y rtp` 对国标常见的 **TCP 承载 RTP（RFC4571）** 返回 0 个包。
即使加 `-d tcp.port==8808,rtp` 也只能识别部分。

本项目自己实现：

1. 导出所有 TCP 段（seq + payload）
2. 按 seq 拼接，空洞补零
3. **扫描对齐偏移**（抓包起点往往不在包边界上，实测偏移 1158 / 1829 字节）
4. 按 `[2字节长度][RTP包]` 逐帧解析

### SDP 协商端口的坑

国标 TCP 模式下：

```
INVITE offer:  m=video 8808 TCP/RTP/AVP 96   ← 我方监听端口
200 OK answer: m=video 9    TCP/RTP/AVP 96   ← 9 表示"我主动连你"
```

如果只看 answer 的端口（9），永远匹配不到实际连接的 8808。
关联逻辑必须**优先用 offer 端口**，并把 0/9 视为占位值。

### RTP 序号回绕

16 位序号会回绕。直接比较会误判大量丢包。

实现按到达顺序展开成 32 位：相邻差值超出 (-32768, 32768) 视为回绕。
实测修复后 tcp0 从 4.4s/101 帧变成 8.88s/201 帧。

### 信令状态 vs 媒体状态

PRD 核心要求：**SIP 200 OK 不等于媒体成功，更不等于用户看到画面**。

数据模型上分两个独立字段：

- `signal_status`: success / failed / incomplete / unknown
- `media_status`: received / no_media / undecodable / unknown

前端分别展示，不合并成一个"成功/失败"。

### 算不出来就留空

所有指标字段可为 `NULL`。前端显示「无法计算」或「—」，**绝不显示 0**。

例如没有媒体流时，`avg_first_media_latency` 是 `null`，
Dashboard 显示「无法计算」而不是 `0s`。

---

## 界面结构

**单入口 + 瀑布式**：一次上传，结果按分析层次逐层展开。

```
上传抓包
   ↓ 自动分析
┌──────────────────────────────────────────┐
│ 1 分析总览   7 个 KPI + 3 张分布图        │
│ 2 SIP 信令   会话表 + 阶段条 + 梯形图     │
│ 3 RTP 媒体   码率/抖动趋势 + 流质量卡     │
│ 4 视频编码   PS/ES 解封装结果 + 编码表    │
│ 5 智能诊断   按严重度排序的结论卡         │
│ 6 原始报文   预览 + 跳转完整查看器        │
└──────────────────────────────────────────┘
```

顶部有**滚动导航**，滚动时自动高亮当前所在节。
每一节可折叠，带编号，形成阅读节奏。

深入页（从瀑布内链接进入）：

| 页面 | 用途 |
|---|---|
| `/sip` | SIP 梯形图（缩放、点击定位）、阶段耗时、消息详情 |
| `/media` | 码率/抖动/丢包三图、流对比、指标口径说明 |
| `/diagnostics` | 规则命中统计、证据等级、可展开诊断 |
| `/packets` | 三栏报文查看器（列表 / 协议树或十六进制 / 字段） |
| `/sessions/:id` | 单会话详情（时序 + 媒体 + 诊断联动） |

### 明暗主题

- 默认深色，一键切换浅色
- 所有图表通过 `alma-theme-changed` 事件重绘（ECharts 不跟随 CSS 变量）
- 品牌色自适应：深色用 `#D70D19`，浅色用 `#C00B16`（对比度更高）

### 视频编码分析与画面还原（M08）

从 RTP 载荷一路解到可播放画面，不依赖第三方解析库：

```
RTP 载荷 → PS (Pack/PES) → ES (NAL) → H.264/H.265 → MP4
```

| 环节 | 实现 |
|---|---|
| PS 解封装 | 识别 Pack Header / PSM / PES，提取视频与音频 ES |
| 编码识别 | H.264（NAL 1/5/7/8）vs H.265（NAL 1/19/20/32/33/34） |
| SPS 解析 | 完整 Exp-Golomb 解码，取分辨率/Profile/Level |
| 帧结构 | I/P 帧计数、关键帧数、帧大小分布 |
| **参数集对齐** | 抓包常从 GOP 中间开始，扫描首个 SPS/PPS 所在的 PS 包，从那里解码 |
| **画面还原** | ffmpeg 转 H.264 MP4，容错解码，前端可直接播放 |
| **并行转码** | 多流同时转码（3 并发），总耗时降为 1/4 |

**实测**：`1280×960 25.17fps`、`1280×720 25fps`，浏览器 `readyState=4` 可直接播放。

**为什么必须做参数集对齐**：抓包起点不在 GOP 边界时，开头的 P 帧没有参考帧，
进入解码器会报 `PPS id out of range` 并被全部丢弃，还会连带后续画面异常。
从参数集处开始解码就能恢复正常。

## DeepSeek AI 分析

顶栏「AI 分析」打开右侧抽屉：

1. **首次使用**引导配置 API Key（只存本机 `data/ai_config.json`）
2. **深度思考**：展开思考过程动画（4 步），流式生成排查报告
3. **报告**：Markdown 渲染，支持复制与重新分析
4. **继续追问**：带上下文的多轮对话，流式输出

### 安全边界

- 只发送**解析后的结构化摘要**（会话、流、诊断结论）
- **绝不发送抓包原始字节**
- Key 不回传前端明文（只给 `****末四位`）
- Key 可用环境变量 `DEEPSEEK_API_KEY` 提供（优先于配置文件，不落盘）；落盘的
  `data/ai_config.json` 权限为 0600（POSIX；Windows 不支持权限位，请自行限制目录访问）
- **网关地址白名单**：API Key 会随请求发往 `base_url` 指向的主机，因此默认只允许
  `https://api.deepseek.com`。使用其他 OpenAI 兼容网关需在服务端设置
  `AI_BASE_URL_ALLOWLIST=host1,host2` 后重启；明文 http 另需 `AI_ALLOW_INSECURE_HTTP=1`。
  请求不跟随重定向，避免 Key 被带到第三方

### 模型兼容性（踩过的坑）

`deepseek-flash` 默认开启 thinking 模式，只输出 `reasoning_content`，
`content` 字段为空 —— 前端会看到「模型没有返回内容」。

必须在请求体显式关闭：

```python
'thinking': {'type': 'disabled'}
```

关闭后 thinking 模式也不支持 `temperature` 等采样参数，故不传这些字段。

## 部署安全说明

本服务**没有账号体系**，定位是本机或可信内网的单用户工具。

| 机制 | 行为 | 相关配置 |
|---|---|---|
| Host 头校验 | 仅监听本机（默认 `HOST=127.0.0.1`）时，只接受 `localhost` / `127.0.0.1` 作为 Host，防 DNS rebinding；对外监听时不限制 | `ALLOWED_HOSTS=a.example.com,b.example.com` |
| Origin 校验 | 带 `Origin` 的 POST/PUT/PATCH/DELETE 必须同源或在 CORS 白名单内，防第三方网页发起 CSRF | `CORS_ORIGINS` |
| 上传校验 | 校验文件头魔数（pcap 微秒/纳秒、pcapng），不符直接 400，不落盘 | — |

经 Nginx 等反向代理对外提供服务时：

- 对外暴露前请设置 `ALLOWED_HOSTS` 为实际域名；
- 代理需透传 `Host`（`proxy_set_header Host $host;`）并同时设置
  `X-Forwarded-Host` / `X-Forwarded-Proto`，否则同源判定可能失败，也可把站点
  来源加入 `CORS_ORIGINS`；
- **不要**把无认证的服务直接暴露到公网，请在代理层加认证（Basic Auth、SSO 等）。

## API 一览

统一前缀 `/api/v1`，完整文档见 `/api/v1/docs`。

### 任务与文件

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/tasks/upload` | 上传抓包，创建任务 |
| GET | `/tasks` | 任务列表（分页/筛选） |
| GET | `/tasks/{id}` | 任务详情 |
| POST | `/tasks/{id}/analyze` | 触发分析（异步） |
| POST | `/tasks/{id}/cancel` | 取消 |
| DELETE | `/tasks/{id}` | 删除 |
| GET | `/tasks/{id}/overview` | 分析总览 |

### 会话

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/tasks/{id}/sessions` | 会话列表 |
| GET | `/sessions/{id}` | 会话详情 |
| GET | `/sessions/{id}/sip` | 关联 SIP 消息 |
| GET | `/sessions/{id}/timeline` | 时间线（信令+媒体+诊断） |
| GET | `/sessions/{id}/media` | 媒体流 |
| GET | `/sessions/{id}/metrics` | 指标时间序列 |
| GET | `/sessions/{id}/diagnostics` | 会话诊断 |

### 诊断与报文

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/tasks/{id}/diagnostics` | 诊断列表 |
| GET | `/tasks/{id}/rule-stats` | 规则命中统计 |
| GET | `/tasks/{id}/packets` | 报文索引（多条件过滤） |
| GET | `/packets/{id}` | 报文详情（协议树 + 十六进制） |

---

## 诊断规则

| 规则 | 名称 | 等级 |
|---|---|---|
| SIP-001 | INVITE 超时无响应 | Critical |
| SIP-003 | SIP 失败响应 | Critical |
| SIP-008 | BYE 未收到最终响应 | Warning |
| SDP-003 | SSRC 不一致 | Warning |
| MED-001 | 信令成功但未发现 RTP | Critical |
| MED-002 | RTP 序号缺口 | Critical/Warning/Info |
| MED-003 | RTP 抖动异常 | Warning/Critical |
| MED-004 | 媒体长时间静默 | Warning |
| MED-005 | RTP 时间戳异常 | Warning |
| MED-007 | BYE 后仍有媒体传输 | Warning |
| MED-008 | 视频重建失败 | Warning |
| CAP-001 | 抓包局限 | Warning/Unknown |

每条诊断包含：规则 ID、严重级别、**证据等级**（confirmed/suspected/insufficient）、
观测证据、可能原因、建议排查、关联报文。

### 证据等级的意义

- **confirmed** — 报文直接证明（如收到 4xx 响应）
- **suspected** — 间接推断（如信令成功但无媒体，可能是端口不通也可能是抓包点问题）
- **insufficient** — 证据不足（如 TCP 承载的序号缺口）

---

## 已知限制（P0）

这些是**能力边界**，不是 bug，界面上如实标注：

1. **未实现 PS/ES 解封装**（P1）—— 只统计到 RTP 层，不提取视频帧
2. **未实现视频重建与预览**（P1）—— `rebuild_path` 恒为空
3. **未实现 RTCP 分析** —— 数据模型已留字段
4. **未实现设备拓扑图**（M11）—— 端点数据已入库，前端未画
5. **未实现报告导出**（M13）—— API 未提供
6. **未实现分片上传** —— 当前单请求上传，2GB 上限
7. **未验证 PostgreSQL 与 Docker** —— 环境不具备
8. **TCP 承载媒体的到达时间**是插值估算，非精确值

---

## 测试

```bash
cd backend
.venv\Scripts\python -m pytest tests/ -v
```

测试样本说明见 `tests/README.md`。

---

## 开发约定

- API 统一 `/api/v1/` 前缀
- 所有异步任务可查询状态
- 长任务不阻塞 HTTP 请求（独立线程）
- 外部程序调用一律列表传参，不用 `shell=True`
- 上传文件不执行，只读解析
- 抓包原始内容不外发

---

## 变更记录

### v1.0.0-P0（当前）

- 完整的「上传 → 解析 → 会话 → 指标 → 诊断 → 报文 → 展示」闭环
- SIP/SDP/RTP 全部自研解析
- 支持 UDP 与 TCP(RFC4571) 两种承载
- 11 条诊断规则，带证据等级
- 6 个前端页面，含 SIP 时序图与媒体趋势图
- 三栏报文查看器（列表 / 协议树 / 十六进制）
