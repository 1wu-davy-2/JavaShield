# JavaShield 格式规范

版本 0.1，对应 `format: 2`（许可证）与 `format: 1`（清单）。所有十六进制为小写，所有 Base64 为 RFC 4648 标准字母表。

---

## 1. 信封 `JSX1`

```
偏移  长度  字段
0     4     MAGIC = "JSX1" (0x4A 0x53 0x58 0x31)
4     1     version = 1
5     1     cipher id
6     1     nonce length = 12
7     1     tag length (16 或 32)
8     12    nonce（随机）
20    N     ciphertext
20+N  16/32 tag
```

| cipher id | 名称 | 依赖 |
| --- | --- | --- |
| 1 | AES-256-GCM | JDK 8+，需 256 位密钥策略 |
| 2 | ChaCha20 + HMAC-SHA256 | 纯 Java，零依赖 |
| 3 | ChaCha20-Poly1305 | JDK 11+ |

AAD 计算：

```
AAD = 信封头部 8 字节 || "jshield:class:" || build_id || ":" || internal_name
```

头部也参与认证，所以修改 cipher id 或版本号会导致解密失败。

### 密钥派生

```
envelope_material = HKDF-SHA256(key, salt="jshield-envelope-v1", info="encryption", L=64)
encryption_key    = material[0..32)
mac_key           = material[32..64)

class_key = HKDF-SHA256(build_key,
                        salt=SHA256("jshield-class-v1" + internal_name),
                        info="jshield-class-key", L=32)
```

ChaCha20 + HMAC 使用 encrypt-then-MAC：

```
ciphertext = ChaCha20(encryption_key, nonce, plaintext, counter=1)
tag        = HMAC-SHA256(mac_key, header || aad || ciphertext)
```

AEAD 模式由 JCA 输出 `ciphertext || tag`，写盘时拆成两段，与 Python 侧布局一致。

### 压缩

明文在加密前先 `Deflater(level=9)`，解密后 `Inflater`。这样密文大小接近 jar 原本的压缩体积，实测 jar 增量约 5%。

---

## 2. 许可证 `jshield.lic`

文件是 Base64 文本（每 76 列换行），解码后是 `JSX1` 信封，明文为 canonical JSON。

### 加密密钥

```
license_key = HKDF-SHA256(master_key,
                          salt=SHA256("jshield-license-v1" + build_id),
                          info="jshield-license-key", L=32)
AAD         = "jshield:license:" + build_id
```

### 载荷

```json
{
  "format": 2,
  "product": "javashield",
  "build_id": "0123456789abcdef",
  "build_key": "<Base64 32B>",
  "cipher": "aesgcm",
  "jvm": "8-21",
  "created": "2026-11-14T02:49:38.442Z",
  "not_before": "2026-11-14",
  "expires": "2027-12-31",
  "grace_days": 14,
  "fingerprints": ["b4272c2f3e023fb9f9bd5046268a43ef"],
  "customer": "ACME",
  "edition": "enterprise",
  "bind_first_run": false,
  "signature": "<Base64 64B>"
}
```

字段说明：

| 字段 | 含义 |
| --- | --- |
| `format` | 固定 2，变更即拒绝 |
| `product` | 固定 `javashield`，防止跨产品复用 |
| `build_id` | 16 位十六进制，与 agent 配置、清单一致 |
| `build_key` | 32 字节，用于派生每个类的密钥 |
| `cipher` | 仅记录构建时选择的套件 |
| `jvm` | 仅文档用途，不参与校验 |
| `created` | 签发时间（UTC ISO-8601） |
| `not_before` | 生效日期，允许 1 天时钟误差 |
| `expires` | 到期日；`null` 表示永久 |
| `grace_days` | 到期后的宽限天数，0–3650 |
| `fingerprints` | 允许的机器码；空数组表示任意机器 |
| `customer` | 客户标识 |
| `edition` | 版本标识 |
| `bind_first_run` | 首次启动时写入绑定记录 |
| `signature` | Ed25519 签名，覆盖除自身外的全部字段 |

### 签名

```
message = "jshield-license-v2:" || canonical_json(payload 去掉 signature)
signature = Ed25519-Sign(signing_key, message)
```

canonical JSON 规则：对象键按 `String.compareTo` 升序；无空格换行；非 ASCII 一律 `\uXXXX`（小写）；整数用十进制；不含浮点数。

---

## 3. 清单 `META-INF/jshield-manifest.json`

```json
{
  "format": 1,
  "tool": "javashield 0.1.0",
  "build_id": "0123456789abcdef",
  "cipher": "aesgcm",
  "integrity": "protected",
  "classes": {
    "com/acme/Foo": {
      "stub": "com/acme/Foo.class",
      "payload": "META-INF/jshield/p/ab12cd34ef56ab78cd90ef12.bin",
      "stub_sha256": "…",
      "payload_sha256": "…",
      "plain_sha256": "…"
    }
  },
  "files": {},
  "tool_license": {
    "tool": "javashield 0.1.0",
    "tool_version": "0.1.0",
    "license_id": "JS-UA5Y-G4HZ-Y2FW",
    "edition": "pro",
    "trial": false
  },
  "signature": "<Base64 64B>"
}
```

- `stub` / `payload` 是 jar 条目路径；in-place 模式下两者相同。
- `plain_sha256` 是原始 class 的哈希，用于审计，不参与启动校验。
- `files` 预留给 `--integrity full` 的数据文件校验。
- `tool_license` 可选，由构建器授权写入；只含公开字段，客户名、机器码与配额计数留在构建密钥。
- 签名前缀为 `jshield-manifest-v1:`。

---

## 4. 构建密钥 `*.jshield-secret.json`

```json
{
  "format": 2,
  "product": "javashield",
  "build_id": "0123456789abcdef",
  "cipher": "aesgcm",
  "integrity": "protected",
  "jvm": "8-21",
  "created": "2026-11-14T02:49:38.442Z",
  "customer": "ACME",
  "output": "dist/app.jar",
  "license": "dist/jshield.lic",
  "master_key": "<Base64 32B>",
  "build_key": "<Base64 32B>",
  "signing_key": "<Base64 32B seed>",
  "public_key": "<Base64 32B>",
  "tool_license": {
    "tool": "javashield 0.1.0",
    "tool_version": "0.1.0",
    "license_id": "JS-UA5Y-G4HZ-Y2FW",
    "edition": "pro",
    "trial": false,
    "customer": "ACME",
    "machine": "b4272c2f3e023fb9f9bd5046268a43ef",
    "builds_used": 1,
    "quota_limit": 100,
    "expires": "2027-11-14"
  }
}
```

`signing_key` 是 Ed25519 的 32 字节 seed，`issue` 与 `verify` 都依赖它。泄漏等同于泄漏该构建的最高权限，必须离线保存，并设置文件权限为 600（POSIX 下程序会自动设置）。

`tool_license` 可选，是构建器授权的完整水印；老版本构建密钥没有该字段，解析时视为不存在。

---

## 5. agent 配置 `jshield-agent.properties`

```properties
product=javashield
build_id=0123456789abcdef
cipher=aesgcm
master_key=<Base64(XOR(master_key, keystream))>
public_key=<Base64 32B>
manifest=META-INF/jshield-manifest.json
```

`master_key` 的混淆流：

```
seed      = SHA256("jshield-agent-v1:" + build_id)
keystream = HKDF-SHA256(seed, salt="jshield-agent-v1", info=build_id, L=32)
stored    = Base64(master_key XOR keystream)
```

这只是让 `strings` 看不到明文，不是密码学保护。

---

## 6. 绑定记录 `.jshield-binding.json`

放在受保护 jar 同目录（可用 `-Djshield.binding` 覆盖）。

```json
{
  "build_id": "0123456789abcdef",
  "fingerprint": "b4272c2f3e023fb9f9bd5046268a43ef",
  "bound_at": "2026-11-14T02:52:31.835Z",
  "mac": "<Hex HMAC-SHA256>"
}
```

```
binding_key = HKDF-SHA256(build_key, salt="jshield-binding-v1", info=build_id, L=32)
mac         = HMAC-SHA256(binding_key, build_id + "|" + fingerprint + "|" + bound_at)
```

首次启动绑定只允许写入持久路径。系统临时目录、`_MEI*` 解压目录等易失位置会被拒绝；只读部署可用 `-Djshield.binding` 指向持久路径。删除记录仍会重置绑定，这是离线首次绑定无法消除的边界。

---

## 7. 时钟状态 `~/.jshield/<build_id>.state`

时钟状态保留两个副本：

```
~/.jshield/<build_id>.state
~/.jshield/<build_id>.state.bak
~/.jshield/<build_id>.state.lock
```

```json
{
  "build_id": "0123456789abcdef",
  "last_seen": "2026-11-14",
  "mac": "<Hex HMAC-SHA256>"
}
```

```
state_key = HKDF-SHA256(build_key, salt="jshield-state-v1", info=build_id, L=32)
mac       = HMAC-SHA256(state_key, build_id + "|" + last_seen)
```

读取时两份都校验：

- 两份都缺失：视为首次运行，写入两份；
- 一份缺失、损坏或不可读：用另一份修复两份；
- 两份日期不一致：取较新的日期并重写两份；
- 两份都无效：拒绝启动。

今天早于 `last_seen - 1 天` 判定为时钟回拨；`last_seen` 晚于今天 7 天视为异常状态。状态目录不可写时默认拒绝启动；只读部署可显式设置 `-Djshield.state.volatile=true` 或 `JSHIELD_ALLOW_VOLATILE_STATE=1` 降级为尽力而为。状态目录可用 `-Djshield.state.dir` 覆盖。锁文件用于跨进程串行化“读-改-写”，避免并发启动互相覆盖。

---

## 8. 机器码

```
machine_id = hex(SHA256(raw))[0:32]
```

`raw` 的来源：

| 平台 | 来源 |
| --- | --- |
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`，失败回退卷序列号，再回退主机名 + MAC |
| Linux | `/etc/machine-id`，其次 `/var/lib/dbus/machine-id` |
| macOS | `ioreg` 的 `IOPlatformUUID` |
| 兜底 | `os.name|os.arch|hostname|第一个非回环 MAC` |

该算法与 PyShield 完全一致，同一台机器在两个产品中的机器码相同，可共用一个签发后台。可用 `-Djshield.machine.id=<id>` 覆盖（便于 CI 与锁定环境）。

---

## 9. 工具许可证与本地状态

### 9.1 工具许可证 `tool-license.json`

```json
{
  "format": "jshield-tool-license/1",
  "payload": {
    "product": "javashield",
    "license_id": "JS-UA5Y-G4HZ-Y2FW",
    "customer": "ACME",
    "edition": "pro",
    "features": ["cli", "license-issuance", "maven"],
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
  "signature": "<Base64 64B>"
}
```

签名：

```
message = "jshield-tool-license-v1:" || canonical_json(payload)
```

字段语义、edition 与功能矩阵见 [工具授权](tool-license.md)。

### 9.2 根密钥

```json
{
  "format": "jshield-root-key/1",
  "seed": "<Base64 32B>",
  "public_key": "<Base64 32B>",
  "created": "2026-11-14T09:00:00Z"
}
```

`root.key` 只应离线保存；发布物只嵌入 `root.pub`（32 字节 Base64 或 hex），路径为
`com/javashield/tool/root.pub`。

### 9.3 本地状态

`trial.json`、`quota.json`、`install.json` 使用统一的封装：

```json
{
  "format": "jshield-state/1",
  "purpose": "quota",
  "payload": {
    "format": "jshield-quota/1",
    "license_id": "JS-UA5Y-G4HZ-Y2FW",
    "month": "2026-11",
    "used": 1,
    "machine": "b4272c2f3e023fb9f9bd5046268a43ef",
    "updated": "2026-11-14T09:10:00Z"
  },
  "signature": "<Hex HMAC-SHA256>"
}
```

```
state_key = SHA256("jshield-state-key-v1|" + purpose + "|" + machine_id)
message   = "jshield-state-v1:" + purpose + "|" + canonical_json(payload)
signature = HMAC-SHA256(state_key, message)
```

`purpose` 为 `trial`、`quota` 或 `install`。HMAC 只提供篡改证据与跨机器复制限制；删除文件仍可重置本地试用。

### 9.4 撤销列表 `revocations.json`

```json
{
  "format": "jshield-revocations/1",
  "payload": {
    "revoked": ["JS-UA5Y-G4HZ-Y2FW"],
    "epoch": 1,
    "updated": "2026-11-14T09:20:00Z"
  },
  "signature": "<Base64 64B>"
}
```

签名前缀为 `jshield-revocations-v1:`。验签失败的列表会被忽略，避免用坏文件制造拒绝服务。
