# JavaShield 执行计划

> 版本：0.1 · 2026-11-14
> 定位：面向 JVM 服务端程序的商业级字节码保护与授权交付工具。复刻 PyShield 已验证的「密钥体系 + 许可体系 + 商业流程」，运行时与构建器按 JVM 特性重新实现。

---

## 1. 产品定义

### 1.1 解决什么问题

企业把 Java 程序（Spring Boot fat jar、WAR、普通可执行 jar）交付到客户机房后，面临三件事：

1. **源码/字节码泄露**：`unzip` + CFR/JADX 即可还原业务逻辑；
2. **交付失控**：包被复制到未授权机器、超期使用、客户拖欠尾款仍能跑；
3. **续期成本高**：改一个到期日就要重新打包、重新走一次上线流程。

JavaShield 的答案是：构建期把业务 class 加密，运行期由 agent 在类加载前解密；授权用 Ed25519 签名的离线许可证，续期只替换一个 `jshield.lic`，不重新打包。

### 1.2 非目标

- 不做绝对不可破解的 DRM。同进程内 agent 链、JVMTI、heap dump 都能拿到明文，这一点在文档里必须写清楚。
- 不做 Android / Dex 保护（DexGuard/R8 的领域）。
- 不做第三方依赖 jar 的加密（没有收益，只增加兼容风险）。
- 不做在线 KMS 实时解密（运维失败模式不可接受），最多做到 native 密钥分片。

### 1.3 与 PyShield 的关系

| 维度 | 复用方式 |
| --- | --- |
| 密钥派生、AEAD 信封 | 同一套设计，换 magic 与域前缀 |
| 许可证模型（到期/宽限/绑定/客户/签发日） | 同一套字段，增加 `product` |
| 签名清单、SHA-256 校验、可变文件规则 | 同一套 JSON 结构 |
| 机器指纹算法 | 完全一致，两端许可证后台可共用 |
| 工具授权、试用登记、深链回传 | 后续阶段直接复用 Python 服务端 |
| 构建器、运行时 | **全部重写**，语言与机制不同 |

---

## 2. 竞品取舍

调研结论落在设计里，取长弃短要写明白，否则后面会反复摇摆。

| 来源 | 取什么 | 丢什么 |
| --- | --- | --- |
| **XJar** | 自定义加载器解密、启动器隐藏密钥的思路 | Go 启动器（多平台产物）、整 jar 加密（Boot 打不开）、密钥进命令行 |
| **ClassFinal** | agent + ClassFileTransformer 的成熟路径、对 Spring 的兼容意识 | 清空方法体（破坏堆栈/调试）、密码走 `-pwd`、密码错静默降级 |
| **ClassGuard** | native 持密钥的 L3 档位、拒绝调试器的思路 | 只支持自家引导器、许可字段过于简单 |
| **DashO** | 识别 Spring Boot 清单（`Spring-Boot-Classes`）、按类派生密钥 | 编译期改写（内存里始终明文） |
| **Stringer** | 字符串/资源加密作为第二层、完整性校验 | 白盒密码的高成本实现 |
| **Virbox** | 虚拟化仅用于核心方法的分层思路 | VME 的高门槛与覆盖面 |
| **ProGuard/R8** | 作为可选的第二层（混淆 + 裁剪），保留 mapping | 不把它们当加密 |
| **PyShield** | 信封、许可证、清单、首绑、时钟回拨、试用 | 模块 stub、Python 运行时 |

一句话：**加密用 agent，密钥靠许可，续期靠换文件，强度分层不吹牛。**

---

## 3. 总体架构

```
                    ┌──────────────────────────────────────┐
                    │            javashield-cli            │
                    │  build / issue / verify / inspect    │
                    └───────────────┬──────────────────────┘
                                    │ 调用
                    ┌───────────────▼──────────────────────┐
                    │            builder 层                │
                    │ JarReader → ClassPlan → StubWriter   │
                    │          → Encryptor → JarWriter     │
                    └───────────────┬──────────────────────┘
                                    │ 产出
        ┌───────────────────────────▼───────────────────────────┐
        │  app.jar（stub + META-INF/jshield/p/*.bin）            │
        │  jshield-agent.jar（或内嵌到 app.jar 根）              │
        │  jshield.lic · app.jshield-secret.json                │
        └───────────────────────────┬───────────────────────────┘
                                    │ 运行时
                    ┌───────────────▼──────────────────────┐
                    │         javashield-agent             │
                    │  premain/agentmain → LicenseGate     │
                    │  → ManifestVerifier → Index →        │
                    │  ShieldTransformer → decrypt → JVM   │
                    └──────────────────────────────────────┘
```

模块划分：

| 模块 | 职责 | 依赖 |
| --- | --- | --- |
| `javashield-core` | 信封、HKDF、ChaCha20、Ed25519、JSON、许可证、清单、指纹、密钥派生 | 零依赖 |
| `javashield-tool` | 构建器授权：工具许可证、试用/配额、状态存储、水印 | core |
| `javashield-agent` | `premain`/`agentmain`、许可闸门、清单校验、payload 索引、transformer | core |
| `javashield-builder` | ASM stub、jar 重写、加密与清单 | core + ASM |
| `javashield-cli` | 命令行、签发/校验、工具授权与离线签发 | builder + tool |
| `javashield-maven-plugin` | package 阶段自动加密与工具授权闸门 | builder + tool |

---

## 4. 密钥体系

```
构建时生成：
  master_key (32B) ── 注入 agent.properties（混淆存储，L1/L2）
      │ HKDF(salt=SHA256("jshield-license-v1"+build_id), info="jshield-license-key")
      ▼
  license_key ── 加密 jshield.lic ── 内含 build_key
                                        │ HKDF(salt=SHA256("jshield-class-v1"+internalName),
                                        │      info="jshield-class-key")
                                        ▼
                                   class_key（每个类独立）

  signing_key（只在构建方 / secret.json）──签名──> jshield.lic + manifest
  signing_public_key（agent 内置）──────验签──> 拒绝伪造与篡改
```

设计要点：

- **每个类独立密钥**：单类泄露不影响全局；AAD 绑定 `build_id + 类名`，密文不可移植。
- **build_key 不落盘明文**：只存在于加密后的 `jshield.lic`，而 lic 必须 Ed25519 验签才被信任。
- **agent 是构建产物的一部分**：每个构建注入独立的 master_key / 公钥 / build_id，避免「一套 agent 通吃所有构建」导致的密钥复用。
- **L3 档位（M6）**：master_key 拆成 agent 分片 + JNI 分片，native 库按平台编译。

---

## 5. 数据格式

### 5.1 信封 `JSX1`

```
MAGIC "JSX1"   4B
version        1B
cipher id      1B   1=AES-256-GCM 2=ChaCha20+HMAC-SHA256 3=ChaCha20-Poly1305
nonce_len      1B   固定 12
tag_len        1B   16 或 32
nonce         12B
ciphertext     N B  （内容是 deflate 压缩后的 class）
tag        16/32 B

AAD = 头部 8 字节 + "jshield:class:<build_id>:<internalName>"
```

- 统一 12 字节 nonce、tag 追加在密文末尾，与 JCA 的输出布局天然一致；
- 解封失败统一抛 `ShieldCryptoException("invalid or corrupted data")`，不区分原因；
- 先 `Deflater(level 9)` 再加密，抵消 jar 压缩失效带来的体积膨胀（实测可压回 +5% 左右）。

### 5.2 许可证 `jshield.lic`

```json
{
  "format": 2,
  "product": "javashield",
  "build_id": "16 位十六进制",
  "build_key": "Base64",
  "cipher": "aesgcm",
  "jvm": "8-21",
  "created": "2026-11-14T02:00:00Z",
  "not_before": "2026-11-14",
  "expires": "2027-12-31",
  "grace_days": 14,
  "fingerprints": ["..."],
  "customer": "客户名称",
  "edition": "enterprise",
  "signature": "Base64"
}
```

签名对象：去掉 `signature` 后按 key 排序的 canonical JSON，前缀 `jshield-license-v2:`；签名字节再放回 `signature`；整体用 `license_key` 做 AEAD 加密后写文件。文件外层是 Base64 文本，便于邮件传输。

### 5.3 清单 `META-INF/jshield-manifest.json`

```json
{
  "format": 1,
  "tool": "javashield 0.1.0",
  "build_id": "...",
  "cipher": "aesgcm",
  "integrity": "protected",
  "classes": {
    "com/acme/Foo": {
      "stub": "com/acme/Foo.class",
      "payload": "META-INF/jshield/p/ab12....bin",
      "stub_sha256": "...",
      "payload_sha256": "...",
      "plain_sha256": "..."
    }
  },
  "files": {"jshield-agent.jar": {"sha256": "...", "size": 123}},
  "signature": "..."
}
```

签名前缀 `jshield-manifest-v1:`。agent 在注册 transformer 前完成验签与哈希校验；校验失败直接终止启动。

### 5.4 构建密钥 `*.jshield-secret.json`

保存 `master_key`、`build_key`、`signing_key`、`public_key`、`build_id`、cipher、integrity、产物路径、创建时间。**绝不随包发布**，`issue` 与 `verify` 都依赖它。

### 5.5 agent 配置 `jshield-agent.properties`

```properties
product=javashield
build_id=...
cipher=aesgcm
master_key=<base64(xor(sha256 stream))>
public_key=<base64>
manifest=META-INF/jshield-manifest.json
```

---

## 6. 构建流水线

```
1. 识别输入
   ├─ 目录（classes/）→ 直接遍历
   ├─ jar → 判断是否 Spring Boot fat jar（MANIFEST 有 Spring-Boot-Classes / Start-Class）
   └─ war → WEB-INF/classes + WEB-INF/lib
2. 生成加密计划
   ├─ 包含规则：默认 `BOOT-INF/classes/**`、`WEB-INF/classes/**`、根 `**.class`
   ├─ 排除规则：module-info.class、META-INF/versions/**（v1 暂不支持 multi-release）、
   │            jshield 自身类、用户 --exclude 的包
   └─ 模式：stub（默认，Spring 友好）/ in-place（体积小，非 Spring）
3. 逐类处理
   ├─ 读原始字节 → 校验 CAFEBABE → ASM 取 internalName
   ├─ deflate → AEAD seal → 写 META-INF/jshield/p/<hash>.bin
   ├─ ASM 生成元数据 stub（保留签名/注解/泛型/异常表，清空方法体）
   └─ 记录 stub/payload/plain 三个 SHA-256
4. 写回 jar
   ├─ 复制非目标条目
   ├─ 替换 class 条目
   ├─ 写清单
   └─ 可选：内嵌 agent 类 + Launcher-Agent-Class
5. 生成许可证与构建密钥
6. 自检：用生成的 agent 在临时目录跑一次 `-javaagent` 冒烟（可 --no-smoke 关闭）
```

失败策略：任一环节失败不产出半成品，输出目录使用临时目录 + 原子移动。

---

## 7. 运行时流水线

```
premain / agentmain
  ├─ 读 jshield-agent.properties（-Djshield.config > classpath 资源 > agent jar 同级）
  ├─ 校验 JVM 版本落在 jvm 字段范围内
  ├─ 定位应用 jar（-Djshield.app > sun.java.command > CodeSource）
  ├─ 读清单 → Ed25519 验签 → 校验受保护条目 SHA-256
  ├─ 读许可证（-Djshield.license > JSHIELD_LICENSE > jar 同级）
  │    → license_key 解封 → Ed25519 验签 → build_id 匹配
  ├─ 校验 not_before（容差 1 天）、expires + grace_days、fingerprints
  ├─ 首次启动绑定（若启用）：读/写 .jshield-binding.json（HMAC）
  ├─ 时钟回拨检测：~/.jshield/<build_id>.state（HMAC + last_seen）
  ├─ 建立 internalName → payload 条目 索引
  └─ addTransformer(ShieldTransformer)

transformer.transform(loader, name, ...)
  ├─ name 不在索引 → return null
  ├─ 命中 → 读 payload → AEAD open → inflate → 返回明文
  └─ 失败 → 抛 IllegalStateException（类加载失败，不降级）
```

线程安全：transformer 会被并发调用；索引只读，payload 读取加锁或使用线程安全的 `JarFile` 访问封装。缓存最近 N 个类，避免重复解密（同一类通常只加载一次）。

---

## 8. 打包适配矩阵

| 形态 | 加密范围 | 启动方式 | 风险 |
| --- | --- | --- | --- |
| 普通可执行 jar | 根 `**.class` | `java -jar`（内嵌 agent） | 低 |
| Spring Boot fat jar | `BOOT-INF/classes/**` | `java -jar` | 中：需 stub 模式；Boot 3.2 nested jar 需实测 |
| WAR | `WEB-INF/classes/**` | Tomcat `CATALINA_OPTS=-javaagent:...` | 中：webapp loader 资源查找 |
| 模块化 jar | 除 `module-info.class` | `--module-path` | 高：v1 不支持，明确报错 |
| 依赖 jar | 默认不加密 | — | 无 |

---

## 9. 许可与商业流程

### 9.1 两层授权（沿用 PyShield）

| 层级 | 作用 | 文件 |
| --- | --- | --- |
| 工具授权 | 谁能用 JavaShield 构建、能用哪些功能、每月几次 | `~/.javashield/tool-license.json` |
| 产物授权 | 受保护程序能在哪台机器、跑到什么时候 | `jshield.lic` |

### 9.2 续期

`issue` 读取 `*.jshield-secret.json`，只重签许可证，不重新加密业务包。默认继承原许可证的到期日、绑定模式、指纹与客户标识，只覆盖显式参数。

### 9.3 试用

P0 已实现**离线本地试用**：首次真正构建时写入 HMAC 状态的开始日期，14 天 / 3 次构建，无需联网；`license status` 不会启动计时。试用策略与付费版共用 `ToolTrialPolicy`，CLI 与 Maven 插件行为一致。

P1 复用 PyShield 的试用登记服务：首次启动生成 `JS-XXXX-XXXX-XXXX` 序列号 → 官网申请 → 服务端签发试用许可 → 深链或轮询回传。协议保持一致，仅在 payload 增加 `product=javashield`。

### 9.4 版本划分

| 版本 | 能力 |
| --- | --- |
| Trial | stub 模式、全部密码套件、14 天 / 3 次构建；禁 in-place、full、客户水印、机器绑定 |
| Pro | in-place + stub、full 完整性、客户水印、机器绑定、产物签发 |
| Enterprise | 在线/离线激活、CI 授权、时钟保护、OEM 白标、native 密钥模块、GUI |

---

## 10. 兼容性、性能与安全边界

### 10.1 兼容性

- agent/core 以 **Java 8 字节码**发布，可运行在 8/11/17/21/25；
- 构建器需要 JDK 11+（ASM 9.6 与 CLI 自身）；
- Spring Boot 3.2+ 的 `LaunchedClassLoader` 只做 transformer，不继承、不替换；
- `module-info.class`、`META-INF/versions/**` 保持明文；
- 签名 jar（jarsigner）与加密互斥，需在加密后再签名或不签名。

### 10.2 性能

- AES-GCM 走 AES-NI，解密吞吐 1–3 GB/s，类加载开销可忽略；
- 主要成本是 jar 随机读 IO：用单个 `JarFile` + 加锁缓存，避免重复打开；
- 大包（5000 类 / 30MB 字节码）冷启动增量目标 < 150ms。

### 10.3 威胁模型

| 攻击 | 结果 | 对策 |
| --- | --- | --- |
| 解压 + 反编译 | 只能看到 stub，方法体是 `throw LinkageError` | 核心能力 |
| 不挂 agent 直接跑 | `ClassFormatError` / `LinkageError` | fail-closed |
| 再挂一个 javaagent | 可拿到解密后字节 | 启动参数自检、`-XX:+DisableAttachMechanism`、L3 |
| JVMTI / heap dump | 可拿到明文与密钥 | 密钥分片、解密后擦除、native |
| 替换清单/许可证 | 验签失败 | Ed25519 |
| 把包复制到别的机器 | 指纹/首绑校验失败 | 绑定 |

**对外表述统一为：提高逆向与扩散成本，不是绝对 DRM。**

---

## 11. 里程碑与验收标准

| 里程碑 | 范围 | 验收标准 |
| --- | --- | --- |
| **M0 骨架**（本次） | 多模块工程、执行计划、格式规范 | `mvn -q -DskipTests package` 通过 |
| **M1 密码与许可** | 信封、HKDF、ChaCha20、Ed25519、JSON、许可证、清单、指纹 | 单元测试全绿；RFC 8032 / RFC 8439 向量通过；篡改必失败 |
| **M2 构建器** | jar/war 扫描、ASM stub、加密、回写、清单、secret | 能把 demo jar 加密成可运行产物 |
| **M3 运行时** | agent、许可闸门、索引、transformer | 加密 jar 能启动；无 agent 必失败；错许可必失败 |
| **M4 CLI 与文档** | build/issue/verify/inspect/fingerprint/selftest | 一条命令完成构建与续期；README/runbook 可照做 |
| **M5 框架适配** | Spring Boot fat jar、WAR、Maven 插件 | 真实 Boot 3.x 项目启动、扫描、Actuator 正常 |
| **M6 商业化** | 工具授权、试用、GUI、native 密钥模块 | P0：工具授权 + 本地试用 + 构建水印；P1/P2：与 PyShield 共用签发后台、激活与撤销；试用→付费闭环 |

当前进度在本文末尾维护。

---

## 12. 测试策略

| 层级 | 内容 |
| --- | --- |
| 单元 | 信封往返/AAD/篡改、Ed25519 向量、JSON canonical 稳定性、许可证日期边界、清单哈希 |
| 契约 | 同一份 fixture 在 Python 侧与 Java 侧生成的 canonical JSON / 信封可互认（M4） |
| 集成 | demo jar 加密 → 启动 → 输出比对；无 agent / 错 key / 换包 均失败 |
| 兼容 | JDK 8/11/17/21 各跑一次 demo；Spring Boot 2.7 / 3.2 各一次 |
| 回归 | 每次发布前跑 `verify` 校验清单与许可证 |

---

## 13. 风险登记册

| 风险 | 影响 | 概率 | 应对 |
| --- | --- | --- | --- |
| Spring 组件扫描读不到元数据 | 高 | 中 | stub 模式保注解与签名；M5 用真实项目验证 |
| Boot 3.2 nested jar 定位 payload 失败 | 高 | 中 | 优先从清单+JarFile 读；回退 `loader.getResource` |
| JDK 21+ 动态 attach 限制 | 中 | 低 | 只支持启动期 `-javaagent` / `Launcher-Agent-Class` |
| 客户现场忘记挂 agent | 中 | 中 | 内嵌 agent + 启动即失败，错误信息明确 |
| 加密后无法调试 | 中 | 高 | `-Djshield.debug=1` 关闭保护；保留行号 |
| 大包启动变慢 | 低 | 低 | 索引 + 缓存 + 基准测试 |
| 密钥被从 agent 提取 | 高 | 中 | L3 native 分片；文档明确边界 |

---

## 14. 工程约定

- Java 8 语法与 API（`--release 8`），不引入 Lombok、不引入日志框架；
- core 与 tool 零第三方依赖；CLI 通过 builder 引入 ASM；
- 所有对外错误信息中文/英文各一条？——统一英文短句，文档中文；
- 提交粒度按模块，commit message 用 `feat/fix/docs/test/chore` 前缀；
- 版本号 `0.x` 期间不保证许可证格式兼容，`1.0` 后冻结。

---

## 15. 进度

- [x] M0 骨架与执行计划
- [x] M1 密码与许可：信封、HKDF、ChaCha20、Ed25519、JSON、许可证、清单、指纹（48 个 core 测试）
- [x] M2 构建器：jar 扫描、ASM stub、加密、回写、清单、secret（含 4 个集成测试）
- [x] M3 运行时：agent、许可闸门、索引、transformer（JDK 11 实测通过）
- [x] M4 CLI 与文档：build/issue/verify/inspect/fingerprint/selftest、README、格式规范、运维手册
- [x] M5a Spring Boot 3.2.12 fat jar 回归（组件扫描、DI、配置绑定、Actuator；修复 STORED 嵌套 jar 与目录条目）
- [x] M5b Maven 插件（package 阶段 protect、agent 内嵌、密钥归档、幂等构建）
- [ ] M5c WAR（需 webapp loader 懒初始化）、Spring Boot 2.7 / 3.3 回归、Gradle 插件
- [x] M6a 工具授权 P0：`javashield-tool` 模块、离线工具许可证、试用/月度配额、状态码、CLI/Maven 闸门、构建水印、撤销列表、离线签发命令（34 个 tool 测试）
- [ ] M6b 试用登记（P1）与在线/离线激活、心跳、撤销同步、CI 授权（P2）
- [ ] M6c GUI、native 密钥模块、安装包（P3）

### 0.1 实测记录（JDK 11 + JDK 17）

| 场景 | 结果 |
| --- | --- |
| stub 模式 + 内嵌 agent，`java -jar` | 正常启动，注解反射可用 |
| in-place 模式 + 内嵌 agent | 正常启动 |
| stub 模式不挂 agent | `LinkageError`，启动即失败 |
| 篡改任意 class 条目 | `class integrity check failed`，`verify` 报哈希不一致 |
| 换构建的许可证 | `licence cannot be decrypted for this build` |
| 过期许可证 | `licence expired on ...` |
| 宽限期内的过期许可证 | 放行 |
| 续期（只替换 lic） | 新到期日生效，无需重新打包 |
| 首次启动绑定 | 生成 HMAC 绑定记录；模拟换机被拒 |
| 固定机器绑定 | 非白名单机器被拒 |
| 绑定记录篡改 | `binding record was modified` |
| AES-256-GCM / ChaCha20-Poly1305 / 纯 ChaCha20 | 全部端到端通过 |
| 自动化测试 | 91 个通过（core 48 + builder 9 + tool 34） |
| 工具授权 P0 | 试用 3 次后拒绝；Pro 许可证解锁 in-place / 客户水印；月度配额耗尽拒绝；Maven 插件闸门与清单水印实测通过 |
| Spring Boot 3.2.12 fat jar（JDK 17） | 正常启动；bean 扫描 255 个；`/api/hello`、`/actuator/health`、`verify` 全部通过 |
| Spring Boot 不挂 agent | `LinkageError`，启动失败 |
| Spring Boot + in-place | Spring ASM 扫描失败（预期，stub 模式强制） |
| Maven 插件 `mvn -Pjavashield package` | 自动保护 4 个类，产物可运行，接口与 bean 扫描正常 |
| Maven 插件重复执行 | 检测到已保护并跳过，`mvn clean package` 强制重建 |
