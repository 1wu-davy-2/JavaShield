# 工具授权

工具授权回答的是「谁能使用 JavaShield 构建器、能用哪些功能、每月能构建几次」，与随产物交付的 `jshield.lic` 是两套独立的许可证。

| | 工具许可证 | 产品许可证 |
| --- | --- | --- |
| 文件 | 本机状态目录下的 `tool-license.json` | 产物同目录的 `jshield.lic` |
| 控制对象 | 构建器 | 受保护应用 |
| 校验位置 | CLI / Maven 插件 / 将来的 GUI | 运行时 agent |
| 签名者 | 你的 Ed25519 根密钥 | 每次构建的 `signing_key` |
| 典型字段 | edition、features、每月构建数、绑定机器 | build_id、到期日、应用绑定机器 |

两层可以同时存在：构建者用 Pro 工具许可证，给客户签发的应用仍按 `jshield.lic` 限制到期与机器。

---

## 1. 默认试用

没有安装工具许可证时，构建器自动进入本地试用：

- **14 天**、**3 次构建**（从第一次真正构建开始计时，`license status` 不会启动计时）；
- 支持 stub 模式、`--no-embed`、全部密码套件、`--integrity protected|off`、产品有效期 / 版本 / JVM 范围 / `--exclude`；
- 不允许 `--in-place`、`--integrity full`、`--customer`、`--bind` / `--bind-first-run`；
- 不允许 `issue`（`license-issuance` 是付费功能）；
- 构建失败也扣一次额度，不退还。

试用天数与次数可在**未嵌入公钥的源码构建**中用环境变量覆盖（便于开发和 CI）：

```bash
export JAVASHIELD_TRIAL_DAYS=14
export JAVASHIELD_TRIAL_BUILDS=3
```

正式发布嵌入 `root.pub` 后会忽略这两个变量。状态文件里记录的试用策略也不会超过当前配置：读取时取“状态值”和“当前策略”的较小值，避免旧状态或手工修改放大试用期。

显式开发模式：

```bash
export JAVASHIELD_DEV=1
```

`JAVASHIELD_DEV` 只在**没有嵌入公钥**的源码构建中生效；正式发布嵌入信任根后，设置该变量不会解锁任何功能。

---

## 2. 状态目录

优先级：

1. JVM 属性 `-Djavashield.home=...`
2. 环境变量 `JAVASHIELD_HOME`
3. Windows：`%APPDATA%\JavaShield`
4. 其他平台：`~/.javashield`

| 文件 | 用途 | 保护 |
| --- | --- | --- |
| `tool-license.json` | 已安装的工具许可证（签名文档） | 签名 + 文件权限 600（POSIX） |
| `trial.json` | 试用开始日期、已构建次数、最近构建日期 | HMAC-SHA256 完整性校验 |
| `quota.json` | 许可证当月已用构建数 | HMAC-SHA256 完整性校验 |
| `install.json` | 需要激活的许可证在本机的激活记录 | HMAC-SHA256 完整性校验 |
| `state.lock` | 跨进程串行化试用/配额/激活状态更新 | 空文件，仅用于 `FileLock` |
| `revocations.json` | 已安装的撤销列表（根密钥签名） | Ed25519 |

状态文件被修改会得到 `state_invalid`。并发构建会先取得 `state.lock` 再重新读取并写回计数，避免两个 CLI/Maven 进程同时读到旧值而少扣额度。试用状态中的日期明显超前，或配额月份早于状态记录，会按时钟回拨处理。

本地 HMAC 的密钥由机器码派生，只能发现误改和损坏；能写状态目录的用户也能重算，直接删除文件同样可以重置试用或配额。它是**完整性校验**，不是防破解的 DRM；服务端登记与心跳在后续阶段实现。

---

## 3. 工具许可证格式

```json
{
  "format": "jshield-tool-license/1",
  "payload": {
    "product": "javashield",
    "license_id": "JS-UA5Y-G4HZ-Y2FW",
    "customer": "ACME",
    "edition": "pro",
    "features": ["cli", "gradle", "license-issuance", "maven", "war"],
    "seats": 1,
    "max_activations": 0,
    "max_builds_per_month": 100,
    "bind_mode": "any",
    "fingerprints": [],
    "activation_required": false,
    "issued": "2026-11-14T09:00:00Z",
    "not_before": "2026-11-14",
    "expires": "2027-11-14",
    "grace_days": 0,
    "revocation_epoch": 0,
    "notes": null
  },
  "signature": "<Base64(Ed25519)>"
}
```

签名：

```
message   = "jshield-tool-license-v1:" || canonical_json(payload)
signature = Ed25519-Sign(root_seed, message)
```

字段：

| 字段 | 含义 |
| --- | --- |
| `license_id` | 唯一编号，撤销与配额按它统计；缺省签发为 `JS-XXXX-XXXX-XXXX` |
| `customer` | 客户名称，只写入构建密钥，不写入交付清单 |
| `edition` | `trial` / `pro` / `enterprise` / `oem`，仅作为 `features` 缺省值 |
| `features` | 显式功能列表，**签名后的列表优先于 edition** |
| `seats` / `max_activations` | 预留字段，P0 不做并发席位与激活次数限制 |
| `max_builds_per_month` | 自然月构建上限；`0` 表示不限 |
| `bind_mode` | `any` 或 `fixed`；`fixed` 时必须至少有一个 `fingerprints` |
| `fingerprints` | 允许的机器码，与 `javashield fingerprint` 输出一致 |
| `activation_required` | 需要先执行 `license install` 生成 `install.json` |
| `not_before` / `expires` | UTC 日期；`expires=null` 表示永久 |
| `grace_days` | 到期后的宽限天数 |
| `revocation_epoch` | 预留的撤销版本号，P0 只按 `license_id` 命中撤销列表 |
| `notes` | 备注，仅展示 |

根密钥文件：

```json
{
  "format": "jshield-root-key/1",
  "seed": "<Base64 32B>",
  "public_key": "<Base64 32B>",
  "created": "2026-11-14T09:00:00Z"
}
```

`root.key` 必须离线保管，绝不提交、绝不随构建器发布。`root.pub` 是公开的，可以嵌入发布物。

---

## 4. 功能矩阵

| 功能 | Trial | Pro | Enterprise | OEM |
| --- | --- | --- | --- | --- |
| `cli` / `maven` / `gradle` | ✓ | ✓ | ✓ | ✓ |
| `license-issuance`（`issue` 续签产品许可证） |  | ✓ | ✓ | ✓ |
| `war` |  | ✓ | ✓ | ✓ |
| `offline-activation` |  |  | ✓ | ✓ |
| `ci` |  |  | ✓ | ✓ |
| `native-runtime` |  |  | ✓ | ✓ |
| `gui` |  |  | ✓ | ✓ |
| `oem` |  |  |  | ✓ |

说明：

- P0 已经实际拦截的是 `cli`、`maven`、`license-issuance` 以及试用构建策略；
- `gradle`、`war`、`offline-activation`、`ci`、`native-runtime`、`gui`、`oem` 先进入许可证字段，供后续模块直接使用，不代表当前版本已经实现对应能力；
- WAR 构建目前仍被 `JarBuilder` 明确拒绝（0.2 计划）。

---

## 5. 命令

### 查看与安装

```bash
javashield license status
javashield license status --license /path/to/tool-license.json
javashield license install --license tool-license.json
javashield license deactivate
```

- `status` 在不可用时返回退出码 1（适合 CI 脚本），可用时返回 0；
- `install` 会校验签名、日期、机器绑定、激活与撤销，然后写入状态目录；
- 配额耗尽时仍允许安装（续期或下月自动恢复），只打印警告；
- `deactivate` 只删除 `tool-license.json` 与 `install.json`，保留试用与配额状态。

### 签发

```bash
# 生成根密钥
javashield license-admin init-root --out root-keys

# 签发 Pro 许可证
javashield license-admin issue \
  --key root-keys/root.key \
  --out pro.json \
  --customer "ACME" \
  --edition pro \
  --max-builds 100 \
  --expires 2027-12-31

# 只开放部分功能（显式列表优先于 edition）
javashield license-admin issue --key root-keys/root.key --out maven-only.json \
  --edition pro --feature maven --max-builds 200

# 绑定固定机器
javashield license-admin issue --key root-keys/root.key --out fixed.json \
  --edition pro --bind fixed --fingerprint <machine-id>

# 查看
javashield license-admin show --license pro.json --public-key root-keys/root.pub
```

`issue` 的默认值：

| 参数 | 默认 |
| --- | --- |
| `--license-id` | 随机 `JS-XXXX-XXXX-XXXX` |
| `--edition` | `pro` |
| `--features` | 按 edition 展开 |
| `--max-builds` | `0`（不限） |
| `--max-activations` | `0`（不限） |
| `--seats` | `1` |
| `--bind` | 有 `--fingerprint` 时为 `fixed`，否则 `any` |
| `--not-before` | 今天（UTC） |
| `--expires` | 一年后；显式 `never` 表示永久 |
| `--activation-required` | 否 |

### 撤销

```bash
javashield license-admin revoke \
  --key root-keys/root.key \
  --license-id JS-UA5Y-G4HZ-Y2FW \
  --epoch 1 \
  --out revocations.json

javashield license install --license pro.json
javashield license revocations --file revocations.json
javashield license status
```

撤销列表是根密钥签名的文档；验签失败的列表会被忽略，避免用坏文件制造拒绝服务。

---

## 6. 状态码

| code | 含义 |
| --- | --- |
| `development` | `JAVASHIELD_DEV=1` 且未嵌入公钥 |
| `trial` | 试用可用 |
| `ok` | 许可证有效 |
| `trial_expired` | 试用天数或次数用尽 |
| `expired` / `not_yet_valid` | 许可证过期 / 尚未生效 |
| `license_invalid` | 文件缺失、JSON 损坏、格式或签名错误 |
| `activation_required` | 需要本机激活记录 |
| `machine_mismatch` | 绑定机器不匹配 |
| `revoked` | 命中撤销列表 |
| `feature_missing` | 许可证不含当前功能 |
| `quota_exhausted` | 当月构建额度用尽 |
| `trial_limit` | 试用不支持当前构建选项 |
| `state_invalid` | 本地状态被修改、损坏、日期超前或时钟回拨 |
| `state_io` | 状态目录读写失败，或无法取得 `state.lock` |

脚本应依赖 `code`，不要匹配提示文案。

---

## 7. 构建水印

每次成功通过工具授权后：

- 签名清单增加公开的 `tool_license` 字段：`tool`、`tool_version`、`license_id`、`edition`、`trial`；
- 构建密钥增加完整水印：额外包含 `customer`、`machine`、`builds_used`、`quota_limit` 与许可证到期日。

客户名称、机器码和配额计数**不会**进入随包发布的清单，只留在构建密钥里。公开水印在清单签名覆盖范围内，篡改会导致启动校验失败。

示例（清单）：

```json
"tool_license": {
  "edition": "pro",
  "license_id": "JS-UA5Y-G4HZ-Y2FW",
  "tool": "javashield 0.1.0",
  "tool_version": "0.1.0",
  "trial": false
}
```

---

## 8. 信任根与发布

源码构建可以临时信任一把公钥：

```bash
export JAVASHIELD_TOOL_PUBLIC_KEY="$(cat root-keys/root.pub)"
```

正式发布必须把公钥嵌入工具，防止用户用环境变量替换信任根：

```bash
# 默认读取仓库根目录的 root-keys/root.pub
mvn -Pembedded-tool-key clean package

# 公钥在别处时显式指定目录（绝对路径）
mvn -Pembedded-tool-key -Djavashield.tool.publicKeyDir=/secure/root-keys clean package
```

该 profile 会把 `root.pub` 复制到 `com/javashield/tool/root.pub`。加载顺序是：

1. 嵌入的 `root.pub`（存在即优先，环境变量不能覆盖）
2. `-Djavashield.tool.publicKey`
3. `JAVASHIELD_TOOL_PUBLIC_KEY`
4. 都没有 → 无公钥，许可证按未验签加载（仅适合源码 / 内网开发）

发布检查清单：

- [ ] `root.key` 在离线介质或 HSM 中，未进入仓库和构建机
- [ ] 发布包内存在 `com/javashield/tool/root.pub`
- [ ] 用 `javashield license-admin show --license <样例> --public-key <root.pub>` 验证签名
- [ ] `JAVASHIELD_DEV=1` 无法解锁发布包
- [ ] 构建器状态目录不随发布物打包

---

## 9. 安全边界与后续

P0 的目标是让授权链路「能用、可验收」，不是绝对防破解：

- 本机状态用派生于机器码的 HMAC 封装，能发现误改和损坏，但密钥不是秘密，删除文件也可以重置试用；真正的额度控制需要 P1 服务端；
- 并发构建通过 `state.lock` 串行化读改写，避免同一台机器上的 CLI / Maven 少扣配额；
- `activation_required` 的 P0 激活记录是本机的，离线可用，但没有服务端次数控制；
- 机器绑定只能阻止未绑定机器直接运行构建器，不能阻止改机器码或补丁；`-Djshield.machine.id` 是部署/CI 辅助开关，交付给不可信客户前应通过发布流程移除或改用签名激活；
- 官方发布嵌入信任根后，环境变量无法替换密钥，`JAVASHIELD_DEV` 和试用天数/次数覆盖变量也会失效。

后续阶段：

1. **P1**：试用登记（PyShield 现有服务端增加 `product=javashield` 与 `JS-` 序列号）；
2. **P2**：在线/离线激活、心跳、撤销同步、CI 授权；
3. **P3**：GUI、原生密钥模块、安装包。
