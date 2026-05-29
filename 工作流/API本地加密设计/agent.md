# oc-keysafe 程序设计文档 v1.0

> 契约式规范，code agent 实施需逐项对齐。涉及 DPAPI、PowerShell 5.1+、opencode `{file:...}` 占位符。

## 1. 项目定位

为 opencode 第三方 provider 的 API Key 提供 Windows 单用户的本地加密存储与按需解密。
用户通过统一 CLI 完成 add / list / get / update / rename / remove / run / check / install-config。
opencode 启动时通过 `{file:...}` 读取运行时明文，启动器（run）负责解密、释放、清理。

### 非目标
- 不做云同步、不引入主密码 / 密钥派生
- 不跨用户、不跨电脑迁移（DPAPI 边界）
- 不修改 opencode 二进制

### 运行约束
- Windows 10 1607+，PowerShell 5.1+
- 不依赖管理员权限、不依赖外部二进制

## 2. 文件布局

| 路径 | 用途 |
|------|------|
| `$env:USERPROFILE\.config\opencode\keys\` | 持久化密文目录 |
| `keys\<name>.key.enc` | 单条 DPAPI 密文（单行 hex） |
| `keys\meta.json` | 元数据索引 |
| `$env:LOCALAPPDATA\oc-keysafe\runtime\` | 运行时明文目录 |
| `runtime\<name>.key` | 运行时明文（UTF-8 no-BOM, 无尾换行） |
| `runtime\.lock` | 单实例 PID 锁 |

写完成后调用 `Set-Acl` 移除 BUILTIN\Users / Everyone 读权限，仅保留当前用户 SID。

## 3. 数据结构

### 3.1 meta.json
```json
{
  "version": 1,
  "createdAt": "<ISO8601>",
  "keys": {
    "<name>": {
      "createdAt": "<ISO8601>",
      "updatedAt": "<ISO8601>",
      "note": "<string?>",
      "fingerprint": "<sha256-of-plaintext-utf8-trim, 前16 hex>"
    }
  }
}
```

`<name>`：`^[a-zA-Z0-9._-]{1,64}$`

### 3.2 .lock
```json
{ "pid": 1234, "startedAt": "<ISO8601>" }
```

## 4. 命令规范

### 4.1 通用约定

退出码：

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 未分类错误 |
| 2 | 参数错误 |
| 3 | 名称已存在 |
| 4 | 名称不存在 |
| 5 | DPAPI 加/解密失败或 fingerprint 不符 |
| 6 | 锁冲突 |
| 7 | opencode 子进程非 0（透传） |

写操作前必须校验 meta.json schema，损坏拒绝写并提示备份。

### 4.2 `init`
建目录、写空 meta.json、设 ACL。已存在则幂等。

### 4.3 `add <name> [--note "..."] [--from-clipboard|--from-stdin]`
- 默认 `Read-Host -AsSecureString`（屏幕不回显）
- `--from-clipboard`：读 `Get-Clipboard`，完成后 `Set-Clipboard -Value $null`
- `--from-stdin`：管道输入，仅脚本集成
- 重名 → 3
- 写 `<name>.key.enc` 与 meta 条目（含 fingerprint）

### 4.4 `list [--json]`
表格：`name | createdAt | note | fingerprint(short)`。
**绝不解密、绝不显示 key 值**。

### 4.5 `get <name> [--copy|--reveal]`
- 默认遮罩：`sk-xx****xxxx`（前 4 后 4）
- `--reveal`：完整输出，需二次确认（输入 `yes`）
- `--copy`：写剪贴板，启动后台 job，60s 后 `Set-Clipboard -Value $null`
- 解密失败 → 5

### 4.6 `remove <name> [--yes]`
默认要求二次确认输入完整 name；`--yes` 跳过。删除 .enc + meta 条目。

### 4.7 `rename <old> <new>`
校验 new 合法且不存在 → 改文件名 → 改 meta key（保留 createdAt，更新 updatedAt）。

### 4.8 `update <name> [--note "..."] [--from-...]`
仅改 note 不重新加密；改 key 走 add 流程，更新 fingerprint 与 updatedAt。

### 4.9 `run [-- <opencode 参数...>]` ★ 核心
生命周期顺序：

1. 检查 `.lock`，若 pid 进程仍存活 → 6
2. 清空 runtime 目录、重建、Set-Acl
3. 遍历 meta.keys：DPAPI 解密 → 校验 fingerprint → `[IO.File]::WriteAllText($p, $plain, [Text.UTF8Encoding]::new($false))`
4. fingerprint 不符 → 5（提示密文损坏）
5. 写 .lock（含当前 PID）
6. `Start-Process opencode -ArgumentList $rest -Wait -NoNewWindow`
7. **finally 必须执行**：清空 runtime + 删 .lock
8. 透传 opencode exit code

清理钩子双保险：
- try/finally
- `Register-EngineEvent PowerShell.Exiting -Action { Cleanup-Runtime }`

### 4.10 `check`
体检并输出 ✓/✗：
- DPAPI 可用性（加密+解密一段固定文本，比对一致）
- keys/runtime 目录存在性 + ACL
- `opencode` 在 PATH
- opencode.json 是否存在 `{file:<RUNTIME_DIR>...}` 引用

### 4.11 `install-config [--provider <id>] [--key <name>]`
- 备份 `opencode.json` 为 `.bak.<yyyyMMddHHmmss>`
- 将 `provider.<id>.options.apiKey` 改写为
  `"{file:<RUNTIME_DIR_FORWARD_SLASH>/<name>.key}"`
- provider 不存在 → 4，不创建
- 路径必须用正斜杠或双反斜杠避免 JSON 转义

## 5. 核心算法

### 5.1 加密
```powershell
function Protect-Key([string]$plain) {
  $sec = ConvertTo-SecureString -String $plain -AsPlainText -Force
  return ConvertFrom-SecureString -SecureString $sec   # DPAPI CurrentUser
}
```

### 5.2 解密
```powershell
function Unprotect-Key([string]$enc) {
  $sec  = ConvertTo-SecureString -String $enc
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
```

### 5.3 fingerprint
```powershell
function Get-Fingerprint([string]$plain) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($plain.Trim())
  $hash  = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
  return ([BitConverter]::ToString($hash) -replace '-','').Substring(0,16).ToLower()
}
```

### 5.4 运行时清理
```powershell
function Clear-Runtime {
  if (Test-Path $RuntimeDir) {
    Get-ChildItem $RuntimeDir -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
  }
}
```
不做 secure-erase，依赖 NTFS 不会持久暴露明文（SSD wear-leveling 下任何 secure-erase 都不可靠，干脆不做误导）。

## 6. opencode 集成

### 6.1 路径常量
- `RUNTIME_DIR` = `$env:LOCALAPPDATA\oc-keysafe\runtime`
- 写入 opencode.json 时**展开为绝对路径并使用正斜杠**
- 例：`C:/Users/YC-NB-028/AppData/Local/oc-keysafe/runtime/bytecat-kiro.key`

### 6.2 opencode.json 片段
```json
{
  "provider": {
    "kiro": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://codecdn.bytecatcode.org/v1",
        "apiKey": "{file:C:/Users/<USER>/AppData/Local/oc-keysafe/runtime/bytecat-kiro.key}"
      }
    }
  }
}
```

### 6.3 opencode `{file:...}` 行为契约
- 仅展开 `~`（用户家目录），不展开 `$env:` / `%VAR%`
- 文件不存在 → opencode 报 provider init 错误
- 文件内容会被原样使用（含尾随空白），故 §4.9-3 强制 no-trailing-newline

## 7. 安全模型

### 7.1 受保护
- 静态磁盘失窃 / 同机器其他用户：DPAPI CurrentUser 边界
- 误提交 git：keys 与 runtime 均不在项目目录
- 剪贴板长期残留：`get --copy` 60s 自动清

### 7.2 不能保护
- 同账户进程注入 / SYSTEM：可读运行时明文
- opencode 进程内存 dump：明文已在堆上
- Windows Credential Roaming + 漫游账户：DPAPI 主密钥可能漂移

### 7.3 明文驻留时长
- 仅 `run` 的 opencode 子进程生命周期内
- `get --reveal`：屏幕一次性输出
- `get --copy`：剪贴板 60s

## 8. 错误处理边界

| 异常 | 行为 |
|------|------|
| meta.json JSON 解析失败 | 拒绝所有写操作，建议 `oc-keysafe check --repair`（v2） |
| .enc 解密成功但 fingerprint 不符 | run 时该条标 broken 并跳过，退出 5 |
| DPAPI 失败（账户变更/机器变更） | 提示用户重新 add，列出所有受影响 name |
| .lock 存在但 pid 不存在 | 视为残留，自动清理后继续 |
| opencode 不在 PATH | run 退出 7，建议执行 `opencode --version` 验证 |

## 9. 测试用例（Pester 5）

| ID | 场景 | 期望 |
|----|------|------|
| T01 | add → list | 条目出现，无 key 值泄漏 |
| T02 | add 同名 | 退出 3 |
| T03 | add → get --reveal | 与原输入一致 |
| T04 | 篡改 .enc 一字节 → run | 退出 5 |
| T05 | remove → list | 不含该条 |
| T10 | run 正常退出 | runtime 清空，退出 0 |
| T11 | run 中 Ctrl+C | runtime 清空 |
| T12 | run 实例存在再次 run | 退出 6 |
| T20 | install-config 正常 | apiKey 路径正确，bak 生成 |
| T21 | install-config provider 缺失 | 退出 4，文件不变 |

## 10. 路由骨架

```powershell
[CmdletBinding()]
param(
  [Parameter(Position=0)][string]$Cmd,
  [Parameter(ValueFromRemainingArguments)][string[]]$Rest
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\modules\paths.ps1"
. "$PSScriptRoot\modules\crypto.ps1"
. "$PSScriptRoot\modules\storage.ps1"
. "$PSScriptRoot\modules\runtime.ps1"
. "$PSScriptRoot\modules\config.ps1"

switch ($Cmd) {
  'init'           { Invoke-Init    @Rest }
  'add'            { Invoke-Add     @Rest }
  'list'           { Invoke-List    @Rest }
  'get'            { Invoke-Get     @Rest }
  'update'         { Invoke-Update  @Rest }
  'rename'         { Invoke-Rename  @Rest }
  'remove'         { Invoke-Remove  @Rest }
  'run'            { Invoke-Run     @Rest }
  'check'          { Invoke-Check   @Rest }
  'install-config' { Invoke-Install @Rest }
  default          { Show-Usage; exit 2 }
}
```

## 11. 交付物

- `oc-keysafe.ps1` 主入口
- `modules/{paths,crypto,storage,runtime,config}.ps1`
- `tests/*.Tests.ps1`（Pester 5，覆盖 §9 全表）
- `README.md` 5 分钟上手
- `install.ps1` 注册 `$PROFILE` 别名 `oc` → `oc-keysafe`
