# OwnMate CLI / MCP

电脑上的只读连接器：手机扫码授权，电脑本地解密，再交给你选择的脚本或 MCP Host。OwnMate 不内置或托管 AI。

## 下载 OwnMate App

[OwnMate 官网](https://www.ownmate.space/) — 了解 OwnMate 并获取 App 下载入口。

[Android 安装包](https://github.com/Nelson-zhou/ownmate-cli/releases/tag/ownmate-app-preview-20261002) — 官方签名的非 debug 预发布 APK，尚未在应用商店上架。此仓库仅公开 CLI/MCP 源码和 App 安装包，不包含 App 主项目源码。

已有用户安装前请核对安装包来源并保留恢复凭证。若系统提示签名不一致，不要卸载或清除原 App 数据；debug 测试版与发布版签名不同，不能直接覆盖安装。

这是源码预览版，构建产物尚未签名。正式记录的生产临时配对曾通过抽样验证；新增瞬间、提醒与完成历史需要新版 App 和服务端，尚未完成生产端到端验收。

## 安装与授权

安装 Rust stable（edition 2024）；Linux 还需要 pkg-config 和 libdbus-1-dev。

```sh
git clone https://github.com/Nelson-zhou/ownmate-cli.git
cd ownmate-cli
cargo install --locked --path ownmate-core/crates/mcp-cli
ownmate-mcp --version
ownmate-mcp help
ownmate-mcp pair --name "My computer"
```

在 App「设置 → 账户 → 设备与外部访问」扫码，核对名称、六位码和公钥指纹。授权必须由你在手机确认。

- 临时授权：30 分钟，仅当前 pair 进程有效，不落盘，通过该进程的 MCP stdio 读取。
- 信任设备：凭据进入系统凭据库，后续命令可用，可在 App 撤销。
- 正式记录、今日瞬间、提醒分别明确授权；旧授权仍只读正式记录，不自动扩权。完成历史与提醒共用 reminders:read。

## 终端查询

以下命令需要可信授权，会输出已授权明文，请只在自己选择的软件里使用。

```sh
ownmate-mcp list
ownmate-mcp read ENTRY_ID
ownmate-mcp read ownmate://reminders/REMINDER_ID
ownmate-mcp query --contains 工作
ownmate-mcp query --from 2026-09-01 --through 2026-09-30
ownmate-mcp query --contains 工作 --tag 生活
```

分类 URI：ownmate://journal/ID、ownmate://fragments/ID、ownmate://reminders/ID、ownmate://reminder-completions/ID。未授权类型不会请求网络。

查询下载全部授权密文并在本机解密筛选，不是服务端搜索。关键词字面匹配，标签精确匹配，组合条件同时满足；日期首尾包含。正式记录和瞬间使用已有的当地自然日，提醒使用到期时间的 UTC 日，完成历史使用完成时间的 UTC 日，不猜造缺失时区。

结果包含类型计数、空文字/缺失日期计数和稳定引用。缺失日期不补造，日期筛选时不匹配。计数是资源数，不是独立生活事件数：精确匹配发生次与轮次的完成瞬间会标注 sameEventAs，但保留两份来源；旧瞬间没有轮次时不猜测关联。循环游标、跨页重复身份或解密失败会报错，不静默丢记录。

## MCP

可信授权后，为 stdio MCP Host 配置：

```json
{"mcpServers":{"ownmate":{"command":"ownmate-mcp","args":["mcp"]}}}
```

仅 resources/list、resources/read；没有写入 Tools、Prompts 或订阅。

## 安全边界

服务端传密文与包裹的 DEK，CLI 本地校验 AES-GCM、身份及载荷。官方投影不输出附件、响铃设备身份或 Context，但**字段投影不是密码学隔离**：持有 DEK 与原始密文的自定义客户端可能解析地点、天气等 Context。只授权可信软件。不会授予 MEK、普通账户登录或同步写权。

撤销和过期阻止后续读取，不能收回已复制内容。不要把记录、token 或密钥放进公开 Issue。详见 [SECURITY.md](SECURITY.md)。

## 开发与许可

```sh
cd ownmate-core
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release -p ownmate-mcp
```

CI 覆盖 Linux、macOS、Windows。仅公开连接器、必需 Rust 校验模块及合成契约，不含 App、后端、生产配置或私人主仓库历史。源码 Apache-2.0，依赖见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
