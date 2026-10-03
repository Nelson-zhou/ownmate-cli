# OwnMate CLI / MCP

手机扫码授权的电脑连接器：读取你批准的记录，或把创建、修改提醒的加密指令交给获批手机处理。电脑本地解密，供你选择的脚本或 MCP Host 使用；OwnMate 不内置或托管 AI。

[OwnMate 官网与 App 下载入口](https://www.ownmate.space/)

## 安装

从[官方 Releases](https://github.com/Nelson-zhou/ownmate-cli/releases)下载与你系统匹配的 CLI 压缩包及 SHA-256 校验文件。发布资产支持 Linux x64、macOS Apple Silicon、Windows x64；不需要管理员权限。解压到自己的用户目录，MCP 配置可直接使用程序的绝对路径，无须修改系统 PATH。

Linux/macOS 用 `sha256sum -c 文件名.sha256` 或 `shasum -a 256 -c 文件名.sha256` 校验；Windows 用 `Get-FileHash 文件名.zip -Algorithm SHA256` 与校验文件对拍。校验值只能确认文件完整性，不能替代签名：本版 CLI 未签名、未公证，仍是预览发布。Linux 可信授权需要可用的 Secret Service / keyring。

也可从公开源码构建。需要 Rust stable（edition 2024），Linux 构建另需 pkg-config 和 libdbus-1-dev：

```sh
git clone https://github.com/Nelson-zhou/ownmate-cli.git
cd ownmate-cli
cargo install --locked --path ownmate-core/crates/mcp-cli
ownmate-mcp --version
ownmate-mcp help
ownmate-mcp pair --name "My computer"
```

默认 API 为 `https://api.ownmate.space`。源码支持和 CI 通过不代表手机、生产 API 与全部权限组合已完成验收；提醒写入还需要服务端开关及支持该能力的 App。

## 手机授权

在 App「设置 → 设备与外部访问」扫码，核对名称、六位码和公钥指纹，由你在手机确认。三项权限独立选择，默认不勾选：

| 手机选择 | 实际权限 | 能做什么 |
| --- | --- | --- |
| 提醒事项：读 | `reminders:read` | 读取提醒及完成历史 |
| 提醒事项：写 | `reminders:write` | 创建、修改计划字段及查询本授权自己的操作回执 |
| 记录本：读 | `journals:read` + `fragments:read` | 读取正式记录和今日瞬间 |

写权限不隐含读权限，不允许完成、取消完成、删除、恢复、改 owner 或改记录正文。旧授权不扩权；需要新能力时重新扫码批准。只写客户端修改已有事项仍须显式提供真实 ID 和版本，不能自动读取补齐。

- 临时授权：最多 30 分钟，仅当前 `pair` 进程有效，不落盘；通过该进程的 MCP stdio 使用。
- 信任设备：连接凭据进入 macOS Keychain、Windows Credential Manager 或 Linux keyring，后续终端命令可用；可在 App 撤销。

## 提醒专用命令

先读取程序随附的字段规范，或离线检查请求：

```sh
ownmate-mcp reminders schema
ownmate-mcp reminders validate create --input - <<'JSON'
{
  "requestId": "sample_book_list_001",
  "title": "整理想读的书单",
  "notes": "按自己的节奏完成。",
  "due": {"kind": "none"},
  "recurrence": "NONE"
}
JSON
```

`validate` 不联网、不读凭据或记录、不保存或回显输入。`shape_valid` 和 `submitted=false` 只表示字段及本地语义检查通过；授权、真实时区、当前版本和手机应用仍未验证。[完整字段规范和合成示例](ownmate-core/crates/mcp-cli/src/reminder-interface-v1.json)也用于 MCP Tools 的 inputSchema。

将相同格式的 JSON 通过标准输入交给真实写命令：

```sh
ownmate-mcp reminders create --input - < create-request.json
ownmate-mcp reminders update REMINDER_ID --input - < update-request.json
ownmate-mcp reminders request-status REQUEST_ID
```

标题、备注只通过 stdin JSON 或 MCP 结构化 arguments 传入，不放进进程参数。每次只处理一个事项，不接受批量数组。

| 字段 | 规则 |
| --- | --- |
| `requestId` | 必填；16–128 个 ASCII 字母、数字、`_` 或 `-`。自己生成并保存稳定 ID，不放私人信息；重试原样复用 |
| `title` | 创建必填；非空白，最多 200 UTF-16 单位，emoji 可能占两个单位 |
| `notes` | 可省略；最多 65536 UTF-16 单位。创建省略为空；更新省略保持，空字符串清空 |
| `due` | 创建必填；明确为 `{"kind":"none"}`，或 `date` 的 `date`/`timeZone`，或 `dateTime` 的 `at`/`timeZone` |
| `recurrence` | 创建必填；`NONE`、`DAILY`、`WEEKLY`；无日期只能 `NONE` |
| `reminderId` / `expectedVersion` | 更新必填；使用读取或自己的已应用回执返回的真实 ID 与不透明 `rv1:` 版本，原样提交 |
| `patch` | 更新必填且至少一项；只允许 `title`、`notes`、`due`、`recurrence`，省略保持，拒绝 `null` |

更新请求示意（占位 ID 和版本必须换成真实返回值）：

```json
{
  "requestId": "sample_book_update_001",
  "reminderId": "REAL_REMINDER_ID",
  "expectedVersion": "REAL_VERSION_FROM_READ_OR_OWN_RECEIPT",
  "patch": {"notes": "优先整理已经收藏的书。"}
}
```

各层未知字段及状态、完成时间、Document、附件、owner 等均拒绝。清除已有日期用 `due.kind=none`，重复事项还须同时设 `recurrence=NONE`。手机再次核对当前版本和合并后的组合；人工修改、完成或删除会阻止旧请求覆盖。

新赋值日期须在指定时区的今天至未来 90 天。`date` 使用有效 `YYYY-MM-DD`，沿 App 当前默认 09:00 排程；`dateTime.at` 是带明确偏移的 RFC3339，秒为 `00`，如 `2026-10-04T20:30:00+08:00`，另需 `timeZone: "Asia/Shanghai"`。不猜自然语言、偏移或缺失时区。仅改已有远期事项的标题/备注不受新日期范围限制。

读取需要提醒读权限：

```sh
ownmate-mcp reminders list --filter today --status PENDING --time-zone Asia/Shanghai
ownmate-mcp reminders list --filter overdue --time-zone UTC
ownmate-mcp reminders list --filter range --from 2026-10-01 --through 2026-10-07 --time-zone UTC
ownmate-mcp reminders list --filter noDate
ownmate-mcp reminders read REMINDER_ID
```

`filter` 支持 `all`、`today`、`overdue`、`range`、`noDate`；`status` 可为 `PENDING` 或 `COMPLETED`。范围包含首尾自然日；日期型逾期按所选自然日判断，具体时刻按当前时间判断，无日期不算逾期。

提醒专用查询读完云端全部授权分页，再本地筛选。返回真实 URI、版本、实际时区、范围边界及抓取时间；`consistentSnapshot=false`、`phoneLastSyncedAt=null`。抓取时间不等于手机同步时间，手机未上传的变化不在结果中。循环游标、重复身份或解密失败会报错。

UTC 内建，各平台可用；IANA 自然日查询需要本机 TZif 数据。Linux/macOS 使用系统 zoneinfo，Windows 未内建完整 IANA 数据库，无法解析时明确拒绝查询。写入尽可能预验时区与偏移；缺数据时只做保守日期检查，由手机最终验证真实 ZoneId、90 天边界和 DST，不能当作完整跨平台 IANA 支持。

## 如何判断写入结果

获批手机在 App 前台消费指令。手机离线只排队；没有远程唤醒或每日调度服务，也不保证后台立即处理。固定期限最多 24 小时，临时授权还受其原到期时间限制。

| 返回证据 | 含义 |
| --- | --- |
| `status: queued` | 服务端接收指令，手机尚未确认保存 |
| `status: applied` | 获批手机已在事务中保存事项与操作收据 |
| `syncVisibility: visible` | 本次结果版本已云端可读，不代表其它手机已收到 |
| `notificationStatus: scheduled` | 有排程证据，不保证系统准点响铃 |

保存 `requestId` 及回执。超时或 `queued` 后查询同一请求，重试复用原 JSON 与 ID；客户端复用固定密文、nonce 和期限，不延长期限，也不因超时生成新 ID。`429` 返回 `retryAfter`，不会自动循环重试。只写回执仅含本请求的 ID、阶段、期限、结果版本和安全原因码；不透露已有事项全文、历史或冲突时当前版本。

服务端按账号共享限额，换 token、重新配对或更换空间不重置：突发 5 次、任意滚动 60 秒 20 次、滚动 24 小时创建 50 / 修改 200、单事项修改 5、排队或保留槽 50。App 手工操作不受这些外部限额影响。

## 其它记录查询

以下终端命令需要可信授权，输出批准范围的明文：

```sh
ownmate-mcp list
ownmate-mcp read ENTRY_ID
ownmate-mcp read ownmate://reminders/REMINDER_ID
ownmate-mcp query --contains 工作 --tag 生活
ownmate-mcp query --from 2026-09-01 --through 2026-09-30
```

分类 URI：`ownmate://journal/ID`、`ownmate://fragments/ID`、`ownmate://reminders/ID`、`ownmate://reminder-completions/ID`。未授权类型不会请求网络。通用 `query` 在本机解密筛选；关键词字面匹配，标签精确匹配，组合条件同时满足，日期首尾包含。正式记录/瞬间沿已有当地自然日，提醒/完成历史用 UTC 日；今日提醒请使用上面的专用命令。

计数是资源数。精确匹配发生次与轮次的完成瞬间会标注 `sameEventAs`，但保留两份来源；旧瞬间缺轮次时不猜关联。缺失日期不补造，也不匹配日期筛选。

## MCP Host

可信授权后配置 stdio；未加入 PATH 时把 `command` 换成程序绝对路径：

```json
{"mcpServers":{"ownmate":{"command":"ownmate-mcp","args":["mcp"]}}}
```

分类 Resources 支持 `resources/list` 和 `resources/read`。Tools 为 `reminders_list`、`reminders_read`、`reminders_create`、`reminders_update`、`reminders_request_status`，只按实际批准的 scope 与写身份暴露，每次调用再次鉴权。临时模式可由 Host 直接启动 `ownmate-mcp pair`，并在 stderr 查看配对二维码；凭据仅留在该进程内。

## 隐私与撤销

服务端传密文与包裹的 DEK，CLI 本地校验 AES-GCM、身份及载荷。官方投影不输出媒体原文件、响铃设备身份或 Context，但字段投影不是密码学隔离：持有 DEK 与原始密文的自定义客户端可能解析地点、天气等 Context。只授权可信软件。不会授予 MEK、普通账户登录或普通同步写权。

可信模式仅将重试用的加密指令缓存在用户私有目录，最多 512 条；不缓存标题、备注明文、明文摘要、DEK 或 token。Unix 使用目录 0700 / 文件 0600；Windows 按当前用户 SID 设置并检查 ACL，失败拒绝写入。临时模式仅内存缓存。Windows ACL、三平台系统凭据库及真实 MCP Host 仍需环境验收。

`ownmate-mcp disconnect` 删除本机凭据；还须在 App 撤销才能阻止云端后续访问。撤销和到期不能收回外部软件已复制的内容；已经取得短执行许可的在途指令可能完成，已保存事项不会自动回滚。不要把记录、token 或密钥放进公开 Issue。见 [SECURITY.md](SECURITY.md)。

## 开发与许可

```sh
cd ownmate-core
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release -p ownmate-mcp
```

CI 在 Linux、macOS、Windows 执行检查并产出对应压缩包与校验值。它不代替真实扫码、手机离线/重启、生产 Mongo 竞态、双设备同步与系统响铃验收。本仓仅公开连接器、必需 Rust 校验模块及合成契约，不含 App 或后端源码、私有配置或主项目历史。源码 Apache-2.0，依赖见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
