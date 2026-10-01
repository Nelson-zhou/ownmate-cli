# OwnMate CLI / MCP

> 让你选择的软件，在你明确授权后，只读访问你自己的 OwnMate 文字日记。

OwnMate CLI 是一个本地连接器。它通过手机扫码取得授权，在电脑上解密用户自己的云端日记密文，
再通过标准 MCP Resources 或 CLI 交给用户选择的软件使用。

OwnMate 不提供、内置或托管 AI，也不判断外部软件是不是 AI。用户可以把连接器交给脚本、搜索与
归档工具、MCP Host，或者自己选择的 AI 助手；OwnMate 只负责安全、通用、可撤销的数据接口。

> [!IMPORTANT]
> 这是可从源码构建的 CLI/MCP 预览版。生产配对接口尚未启用；当前需要可用的测试服务与 Android 扫码授权。
> GitHub Actions 在 Linux、macOS、Windows 上运行检查并提供构建产物；这些产物目前没有平台代码签名。

## 拉取和安装

安装 Rust stable（支持 edition 2024）后执行：

```bash
git clone https://github.com/Nelson-zhou/ownmate-cli.git
cd ownmate-cli
cargo install --locked --path ownmate-core/crates/mcp-cli
ownmate-mcp --version
ownmate-mcp help
```

可信设备配对后，可直接在终端使用：

```bash
ownmate-mcp list
ownmate-mcp read ENTRY_ID
```

这两个命令会把已授权的明文 JSON 输出到终端，请只在自己选择的终端或脚本中使用。
临时配对只在当前进程内有效，请通过 `pair` 进程的 MCP stdio 使用。

许可证为 Apache-2.0。发布范围仅包含连接器和必需的记录校验模块。

## 一句话连接你的日记

独立仓库发布后，把这句话发给支持终端和 MCP 的助手：

> 帮我从 OwnMate 官方仓库安装 OwnMate CLI，并添加到当前 MCP Host。按照仓库 README 的安装契约
> 校验官方 Release；安装完成后显示配对二维码，让我用 OwnMate App 扫码授权。

未来可以附上官方仓库地址：

```text
帮我安装并配置 OwnMate CLI/MCP：
https://github.com/Nelson-zhou/ownmate-cli
```

助手可以完成下载、校验、安装和 MCP 配置，但不能替用户授权。最终一步始终由用户本人在 OwnMate
App 中核对客户端名称、六位核对码和公钥指纹，再选择临时授权或信任设备。

## 它能做什么

| 能力 | v1 行为 |
|---|---|
| 查看已保存日记 | 只读 `saved + active` 的文字日记 |
| 连接 MCP Host | 通过 stdio 提供 `resources/list` 与 `resources/read` |
| 临时使用 | 绝对有效期 30 分钟，进程退出后需重新扫码 |
| 信任设备 | 凭据只进入操作系统凭据库，可在 App 中撤销 |
| 本地解密 | DEK 和日记明文不交给 OwnMate 后端 |

v1 明确不提供日记写入、删除、草稿、回收站、媒体、附件、位置、天气、提醒状态或普通账号能力。
MCP 不声明 Tools、Prompts 或订阅能力。

## 工作方式

```text
用户选择的软件 / MCP Host
          │
          │ stdio · Resources only
          ▼
     ownmate-mcp
          │
          │ HTTPS · 只读外部访问 token
          ▼
OwnMate External Access API ─────► Journal 密文
          ▲
          │ ECDH + HKDF + AES-GCM 包裹的 DEK
          │
OwnMate App 扫码并由用户确认
```

服务端只保存公钥、token hash、wrapped DEK 和 Journal 密文，看不到日记明文、DEK、CLI 私钥或恢复
密钥。CLI 在本机完成信封校验、密文解密、canonical Journal 校验和字段白名单投影。

## 从源码构建

在当前 OwnMate monorepo 根目录执行：

```bash
cargo build --release --manifest-path ownmate-core/Cargo.toml -p ownmate-mcp
```

产物位于：

```text
ownmate-core/target/release/ownmate-mcp
```

开发环境也可以直接运行：

```bash
cargo run --manifest-path ownmate-core/Cargo.toml -p ownmate-mcp -- help
```

独立仓库发布后，本节将替换为官方 Release 和签名安装器。正式安装流程必须支持 macOS、Windows、
Linux，并满足“用户目录安装、无需管理员权限、不静默修改 PATH、校验来源与完整性”。

## 首次配对

```bash
ownmate-mcp pair --name "My Mac"
```

CLI 会把二维码、六位核对码和短公钥指纹写到 stderr，避免污染 MCP stdout。随后在 Android App 打开：

```text
设置 → 账户 → 设备与外部访问 → 扫码授权
```

确认终端与手机显示的信息一致，然后选择：

- **仅本次使用（30 分钟）**：不把会话材料写入磁盘或系统凭据库；当前进程退出或到期后需重新扫码。
- **信任此设备**：后续读取所需凭据只写入 macOS Keychain、Windows Credential Manager 或 Linux
  系统 keyring；可在 App 中随时撤销。

二维码不包含 `pairingSecret`、token、公钥正文、DEK 或日记数据。手机会从后端取回完整客户端公钥，
再次核对公钥指纹后才允许授权。

## 添加到 MCP Host

可信设备完成一次配对后，将以下配置添加到支持 stdio MCP 的 Host：

```json
{
  "mcpServers": {
    "ownmate": {
      "command": "/absolute/path/to/ownmate-mcp",
      "args": ["mcp"]
    }
  }
}
```

重新启动 Host 后，它应当发现 OwnMate Resources，资源 URI 为：

```text
ownmate://journal/{entryId}
```

临时模式需要 MCP Host 直接启动 `ownmate-mcp pair`，并让用户从 Host 的 stderr 或日志面板看到二维码。
如果 Host 不展示 stderr，请先在普通终端使用可信模式完成配对，再配置 `ownmate-mcp mcp`。

## 给安装助手的执行契约

公开仓库发布后，自动安装 OwnMate CLI 的助手必须遵循以下约定：

1. 先无副作用检查操作系统、CPU 架构、已有版本和 MCP Host 配置，不先下载或修改文件。
2. 明确展示将安装的版本、官方 HTTPS 来源、目标路径和会修改的 MCP 配置，得到用户同意后再执行。
3. 只读取 OwnMate 官方 Release manifest，并校验最终下载 host、文件大小、SHA-256、代码签名和二进制
   自报版本；任一不匹配立即停止。
4. 安装到用户目录，不使用 `sudo`，不修改系统级 PATH，不覆盖来源不明的同名二进制。
5. MCP 配置只写入用户指定的 Host；写入前备份原配置，保持其他 MCP Server 不变。
6. 安装成功后运行无敏感信息的状态检查，再启动 `ownmate-mcp pair`；必须由用户本人在手机上批准。
7. 不读取、回显或记录 pairing secret、token、DEK、系统凭据库内容和日记正文。
8. 验收只确认 MCP Resources 可列出和读取；不得尝试添加写能力，也不得把正文上传给未获用户选择的服务。

在官方 manifest、签名产物和安装脚本发布前，任何助手都不得把源码构建伪装成“官方一键安装”。

## 本地联调

CLI 默认连接：

```text
https://api.ownmate.space
```

只允许 HTTPS；本地开发保留 loopback HTTP 例外：

```bash
ownmate-mcp pair --base-url http://127.0.0.1:3000
```

也可以设置：

```bash
export OWNMATE_API_BASE_URL=http://127.0.0.1:3000
```

非 loopback 的 `http://` 地址会被拒绝。不要把生产 token、DEK 或 pairing secret 写进环境变量、配置
文件或命令行参数。

## 断开与撤销

删除本机系统凭据库中的连接材料：

```bash
ownmate-mcp disconnect
```

`disconnect` 只影响当前电脑。要立即阻止该客户端继续从云端拉取，还必须在 App 的“设备与外部访问”
中撤销对应授权。

反过来，App 撤销后，服务端会立即拒绝旧 access/refresh token，即使电脑上仍有缓存凭据。授权到期或
撤销只能阻止后续拉取，无法远程删除外部软件已经复制的数据。

## 数据与隐私边界

CLI 只读取同时满足以下条件的 Journal：

- `payloadVersion >= 3`
- `recordState == saved`
- `lifecycle.state == active`
- AES-GCM AAD、canonical Journal 和 `entryId` 验证通过

MCP 输出只包含：

- `entryId`
- `occurredAt`
- `timezone`
- `title`
- `text`
- `tags`
- `mood`
- 裁剪后的 `stateOfMind`

位置、天气、Asset、附件对象 ID、文件名、checksum、结果/提醒 Entity ID、provenance、同步和设备元数据
不会进入 MCP。

可信记录只包含后续读取所需的 DEK、Grant ID、access/refresh token 和 API 地址，并且只保存在系统
凭据库中。P-256 配对私钥只存在于首次配对进程，解开 DEK 后不持久化；临时模式不持久化任何会话
字段。

## 常见问题

### OwnMate 是不是在提供 AI 分析？

不是。OwnMate 只提供用户授权的数据连接器。用户选择什么软件、是否使用 AI、如何处理读取到的数据，
由用户与外部软件自行决定。

### 为什么不能直接输入 OwnMate 密码？

CLI 不需要、也不应该获得用户密码。配对使用一次性 P-256 密钥和手机端确认，只授予范围更窄的
`journals:read` 权限。

### 为什么 AI 助手不能自动完成全部流程？

下载安装可以自动化，但读取私人日记的最终授权必须由用户在 App 中确认。助手不能代替用户核对设备
和授予权限。

### MCP Host 看不到资源怎么办？

先确认 App 已完成同步。旧 v1/v2 Journal 需要由新版 App 重推为带 `recordState` 的 payload v3；草稿、
回收站和包含非法 canonical 数据的记录不会出现。

### 系统凭据库不可用怎么办？

确认当前桌面会话的 Keychain、Credential Manager 或 keyring 已解锁。无法使用凭据库时，可以改用
不持久化的 30 分钟临时模式。

### 配对或临时授权过期怎么办？

二维码五分钟后过期，临时授权绝对有效期为 30 分钟，均不能刷新延长；重新运行 `pair` 并扫码即可。

## 开发验证

```bash
cargo fmt --manifest-path ownmate-core/Cargo.toml --all -- --check
cargo clippy --manifest-path ownmate-core/Cargo.toml -p ownmate-mcp --all-targets -- -D warnings
cargo test --manifest-path ownmate-core/Cargo.toml -p ownmate-mcp
```

跨平台协议、Android 信封和后端测试入口：

```bash
node --test cloudrun/test/external-access.unit.test.js
bash scripts/check-cross-platform-contracts.sh
./gradlew :core:data:testDebugUnitTest --tests 'com.ownmate.core.data.security.*'
./gradlew :feature:settings:testDebugUnitTest
```

协议与威胁模型见：

- `docs/architecture/external-access-v1/README.md`
- `adr/0014-user-authorized-external-access.md`

## 独立仓库发布前清单

- 确定官方 GitHub organization、仓库地址和项目许可证。
- 从 monorepo 做干净导出，不携带 App、后端、生产配置或历史密钥。
- 发布 macOS Apple Silicon / Intel、Windows x64、Linux x64 / arm64 签名二进制。
- 提供官方 HTTPS manifest、大小、SHA-256、签名和可回滚版本信息。
- 提供不需要管理员权限、不修改 PATH 的 Agent 安装 Skill。
- 在 macOS Keychain、Windows Credential Manager、Linux keyring 和真实 MCP Host 完成验收。
- 发布 `SECURITY.md`、漏洞报告渠道、支持版本和安全更新策略。
- 在真实 Mongo、会员墙、撤销、到期、密码重置和账号删除链路通过前保持生产开关关闭。
