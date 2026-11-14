# JavaShield

面向 JVM 服务端的字节码保护与授权交付工具。构建期把业务 class 加密成密文，运行期由 Java Agent 在类加载前解密；授权用 Ed25519 签名的离线许可证，**续期只替换一个 `jshield.lic`，不重新打包**。

它不是 PyShield 的 Java 移植，而是同一套「密钥体系 + 许可体系 + 商业流程」在 JVM 上的重新实现：信封格式、许可证字段、机器指纹算法与 PyShield 保持一致，构建器和运行时按 JVM 的类加载机制重写。

## 当前状态

- 版本：`0.1.0-SNAPSHOT`
- 构建：Maven 3.6+，JDK 11 编译（产物为 Java 8 字节码）
- 已验证：JDK 11 上普通可执行 jar、三种密码套件、stub / in-place 两种模式
- 未验证：Spring Boot fat jar（结构已适配，待真实项目回归）、JDK 8/17/21 实机
- 暂不支持：WAR（0.2 计划，需要 webapp 类加载器懒初始化）
- 测试：54 个单元与集成测试通过

## 快速开始

### 1. 构建工具

```bash
mvn -q -DskipTests package
```

产物：

- `javashield-cli/target/javashield.jar`：命令行工具
- `javashield-agent/target/javashield-agent-0.1.0-SNAPSHOT-agent.jar`：运行时 agent 模板

发布时把两者放在同一目录，并把 agent 重命名为 `jshield-agent.jar`（或构建时用 `-Djavashield.agent.jar=<path>` 指定）。

### 2. 保护一个可执行 jar

```bash
java -jar javashield.jar build \
  -i myapp.jar \
  -o dist/myapp.jar \
  --customer "ACME" \
  -e 2027-12-31
```

输出：

```
dist/myapp.jar                     受保护的应用（已内嵌 agent）
dist/jshield-agent.jar             独立 agent，供 -javaagent 或 WAR 使用
dist/jshield.lic                   许可证
dist/myapp.jar.jshield-secret.json 构建密钥（绝不能随包发布）
```

### 3. 运行

```bash
java -jar dist/myapp.jar
```

jar 的 `MANIFEST.MF` 里有 `Launcher-Agent-Class: com.javashield.agent.Agent`，JVM 会在 `main` 之前自动加载 agent，用户不需要加 `-javaagent`。

### 4. 续期

```bash
java -jar javashield.jar issue --secret dist/myapp.jar.jshield-secret.json -e 2028-12-31
```

只重写 `jshield.lic`，业务包、绑定记录、机器指纹都不变。

### 5. 交付前自检

```bash
java -jar javashield.jar verify --jar dist/myapp.jar --secret dist/myapp.jar.jshield-secret.json
java -jar javashield.jar inspect --secret dist/myapp.jar.jshield-secret.json
```

## 两种加密模式

| 模式 | 参数 | class 条目内容 | 适用 |
| --- | --- | --- | --- |
| **stub**（默认） | 无 | 保留字段、方法签名、注解的元数据 stub，方法体是 `throw new LinkageError` | Spring / MyBatis / Swagger 等会扫描类元数据的框架 |
| **in-place** | `--in-place` | 直接是 `JSX1` 密文 | 普通 jar、非框架应用，体积更小、类结构不外泄 |

stub 模式是相对同类工具的关键改进：ClassFinal 通过清空方法体来兼容 Spring，会破坏调试信息和堆栈；JavaShield 把真实字节码放进加密 sidecar，stub 只在 JVM 定义类之前存在，扫描器读到的是完整元数据，运行期执行的是原始字节码（连行号都在）。

## 命令

| 命令 | 作用 |
| --- | --- |
| `build -i <jar> -o <out>` | 构建受保护产物 |
| `issue --secret <json>` | 重新签发 / 续期许可证 |
| `verify --jar <jar> --secret <json>` | 校验清单签名与每个受保护条目的哈希 |
| `inspect --jar <jar>` / `--secret <json>` | 查看构建与许可信息 |
| `fingerprint` | 打印本机机器码 |
| `selftest` | 跑密码、签名、JSON、许可证自检 |

### build 选项

| 选项 | 说明 |
| --- | --- |
| `--cipher auto\|aesgcm\|chacha\|chacha-pure` | 密码套件，默认 `auto`（AES-256-GCM） |
| `--integrity protected\|full\|off` | 清单校验范围，`off` 跳过条目哈希但仍验签 |
| `-e, --expire <yyyy-MM-dd>` | 到期日，省略为永久 |
| `--grace-days <n>` | 到期后的宽限天数，最大 3650 |
| `--bind <machine-id>` | 允许的机器，可重复 |
| `--bind-first-run` | 首次启动绑定到客户机 |
| `--customer <name>` | 客户标识，写进许可证 |
| `--edition <name>` | 版本标识，写进许可证 |
| `--jvm <range>` | 仅作记录，默认 `8-21` |
| `--exclude <package>` | 保持明文的包，可重复 |
| `--in-place` | 使用 in-place 模式 |
| `--no-embed` | 不把 agent 嵌入 jar，只产出独立 agent |
| `--agent <path>` | 指定 agent 模板 |
| `--force` | 覆盖已有输出 |

## 工作原理

### 构建期

```
jar
 ├─ 枚举条目，识别 BOOT-INF/classes、WEB-INF/classes 或根目录
 ├─ 每个业务 class：
 │    ├─ deflate(level 9) → AES-256-GCM 加密（每类独立密钥）
 │    ├─ 密文写入 META-INF/jshield/p/<hash>.bin
 │    └─ 原条目替换为元数据 stub
 ├─ 生成 Ed25519 签名清单 META-INF/jshield-manifest.json
 ├─ 生成 master/build/signing 密钥与 jshield.lic
 └─ 可选：内嵌 agent + Launcher-Agent-Class
```

### 运行期

```
java -jar app.jar
 └─ JVM 读取 Launcher-Agent-Class
      └─ agentmain
           ├─ 验签清单 + 校验每个 stub / payload 的 SHA-256
           ├─ 解封 jshield.lic → 验签 → 取 build_key
           ├─ 校验到期 / 宽限 / 机器指纹 / 首次绑定 / 时钟回拨
           └─ 注册 ClassFileTransformer
 └─ main
      └─ 加载业务类 → transformer 解密 → 返回原始字节码 → JVM 校验并定义
```

密钥分层：

```
master_key（agent 内置，混淆存储）
  └─ HKDF(build_id) → license_key → 解开 jshield.lic → build_key
                                                          └─ HKDF(类名) → class_key
signing_key（只在构建密钥里）──签名──> 许可证 + 清单
public_key（agent 内置）─────验签──> 拒绝伪造
```

## 安全边界

**能做到**

- 解压 + 反编译只能看到 stub，方法体是 `throw LinkageError`；
- 不挂 agent 直接运行必然失败（`ClassFormatError` 或 `LinkageError`），不会静默降级；
- 篡改任意受保护条目会被清单校验拒绝；
- 换机、过期、超宽限期会被许可证拒绝；
- 换构建、换类名移植密文会因 AAD 绑定解密失败。

**做不到**

- 阻止有动机的攻击者挂载自己的 agent、用 JVMTI 或 heap dump 取明文；
- 阻止补丁 agent 或绕过校验逻辑；
- 隐藏类名、方法签名与注解（stub 模式为兼容框架必须保留）。

定位是「把顺手反编译提高到需要写 agent」，不是绝对 DRM。与 PyShield 的表述保持一致。

## 项目结构

```
javashield-core/     信封、HKDF、ChaCha20、Ed25519、JSON、许可证、清单、指纹
javashield-agent/    premain/agentmain、许可闸门、完整性校验、transformer
javashield-cli/      CLI、ASM stub、jar 重写、签发与校验
docs/                执行计划、格式规范、运维手册
samples/hello/       端到端示例
```

## 文档

- [执行计划](docs/execution-plan.md)：竞品取舍、架构、里程碑、风险
- [格式规范](docs/format.md)：信封、许可证、清单、构建密钥的字节级定义
- [运维手册](docs/runbook.md)：构建、部署、续期、排障

## 授权

内部商业项目，版权归作者所有。第三方依赖仅 ASM（构建器，BSD）与 JUnit（测试，EPL）。
