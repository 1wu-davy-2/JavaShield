# JavaShield

[![ci](https://github.com/1wu-davy-2/JavaShield/actions/workflows/ci.yml/badge.svg)](https://github.com/1wu-davy-2/JavaShield/actions/workflows/ci.yml)

面向 JVM 服务端的字节码保护与授权交付工具。构建期把业务 class 加密成密文，运行期由 Java Agent 在类加载前解密；授权用 Ed25519 签名的离线许可证，**续期只替换一个 `jshield.lic`，不重新打包**。

它不是 PyShield 的 Java 移植，而是同一套「密钥体系 + 许可体系 + 商业流程」在 JVM 上的重新实现：信封格式、许可证字段、机器指纹算法与 PyShield 保持一致，构建器和运行时按 JVM 的类加载机制重写。

## 当前状态

- 版本：`0.1.0-SNAPSHOT`
- 构建：Maven 3.6+，JDK 11 编译（产物为 Java 8 字节码）
- 已验证：JDK 11 上的普通可执行 jar、JDK 17 上的 Spring Boot 3.2.12 fat jar（组件扫描、依赖注入、配置绑定、Actuator）、三种密码套件、stub / in-place 两种模式
- 未验证：JDK 8/21 实机、Spring Boot 2.7
- 接入方式：CLI 与 Maven 插件（`package` 阶段自动保护，客户项目零改造）
- 构建器授权：本地试用（14 天 / 3 次构建）与离线工具许可证已接入 CLI 和 Maven 插件
- 状态加固：试用/配额跨进程锁与重试；运行时时钟双副本自愈、临时目录拒绝首次绑定
- 暂不支持：WAR（0.2 计划，需要 webapp 类加载器懒初始化）
- 测试：116 个单元与集成测试通过

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
  -e 2027-12-31
```

> 首次使用默认进入试用模式（14 天 / 3 次构建），所以示例没有使用客户水印、`--in-place`、`--integrity full` 和机器绑定。安装 Pro / Enterprise 工具授权后这些选项才可用，见[工具授权](#工具授权构建器自身)。

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

## Maven 插件（推荐）

客户项目不改代码，加一个 profile 即可：

```xml
<profile>
  <id>javashield</id>
  <build><plugins><plugin>
    <groupId>com.javashield</groupId>
    <artifactId>javashield-maven-plugin</artifactId>
    <version>0.1.0-SNAPSHOT</version>
    <executions><execution>
      <id>protect</id><phase>package</phase><goals><goal>protect</goal></goals>
    </execution></executions>
    <configuration><customer>ACME</customer><expire>2027-12-31</expire></configuration>
  </plugin></plugins></build>
</profile>
```

```bash
mvn -Pjavashield clean package
```

> 上面的 `<customer>` 需要 Pro / Enterprise 工具授权；试用模式请先移除该参数。完整授权流程见下一节。

插件必须声明在 `spring-boot-maven-plugin` 之后，输入才是 fat jar。构建密钥归档到 `${basedir}/.javashield/`，不会因 `mvn clean` 丢失。详见 [Maven 插件文档](docs/maven-plugin.md)。

## 工具授权（构建器自身）

JavaShield 有两层许可证，不要混淆：

| | 工具许可证 | 产品许可证 |
| --- | --- | --- |
| 文件 | `tool-license.json`（本机状态目录） | `jshield.lic`（随产物部署） |
| 管什么 | **谁能使用构建器**、能用哪些功能、每月几次构建 | **受保护应用在哪台机器、什么时间**可以运行 |
| 谁签 | 你的 Ed25519 根密钥 | 每次构建生成的签名密钥 |

不安装工具许可证时进入本地试用：14 天、3 次构建，支持 stub 模式与全部密码套件，但不允许 `--in-place`、`--integrity full`、`--customer` 和机器绑定。状态目录默认是 `%APPDATA%\JavaShield`（Windows）或 `~/.javashield`，可用 `JAVASHIELD_HOME` 覆盖。

签发并安装一枚 Pro 工具许可证：

```bash
# 1. 生成根密钥。root.key 必须离线保管，绝不提交或随工具发布。
java -jar javashield.jar license-admin init-root --out root-keys

# 2. 签发工具许可证（features 默认按 edition 展开）
java -jar javashield.jar license-admin issue \
  --key root-keys/root.key \
  --out pro.json \
  --customer "Your Company" \
  --edition pro \
  --max-builds 100 \
  --expires 2027-12-31

# 3. 让源码构建信任 root.pub，然后安装
export JAVASHIELD_TOOL_PUBLIC_KEY="$(cat root-keys/root.pub)"
java -jar javashield.jar license install --license pro.json
java -jar javashield.jar license status
```

- **正式发布**必须把 `root.pub` 嵌入工具，否则任何人都能替换信任根：
  把 `root.pub` 放到仓库根目录的 `root-keys/`，执行 `mvn -Pembedded-tool-key package`。
  嵌入后环境变量不能再覆盖公钥，`JAVASHIELD_DEV=1` 也会失效。
- 源码开发可显式设置 `JAVASHIELD_DEV=1` 跳过工具授权（仅在没有嵌入公钥的构建中生效）。
- 续期工具许可证就是重新 `issue` + `license install`，不需要重装工具。
- 详细格式、状态码、配额与撤销列表见 [工具授权文档](docs/tool-license.md)。

## 两种加密模式

| 模式 | 参数 | class 条目内容 | 适用 |
| --- | --- | --- | --- |
| **stub**（默认） | 无 | 保留字段、方法签名、注解的元数据 stub，方法体是 `throw new LinkageError` | Spring / MyBatis / Swagger 等会扫描类元数据的框架 |
| **in-place** | `--in-place` | 直接是 `JSX1` 密文 | 仅限不扫描类元数据的普通 jar；Spring / MyBatis / Swagger 项目**禁用** |

stub 模式是相对同类工具的关键改进：ClassFinal 通过清空方法体来兼容 Spring，会破坏调试信息和堆栈；JavaShield 把真实字节码放进加密 sidecar，stub 只在 JVM 定义类之前存在，扫描器读到的是完整元数据，运行期执行的是原始字节码（连行号都在）。

## 命令

| 命令 | 作用 |
| --- | --- |
| `build -i <jar> -o <out>` | 构建受保护产物 |
| `issue --secret <json>` | 重新签发 / 续期许可证 |
| `verify --jar <jar> --secret <json>` | 校验清单签名与每个受保护条目的哈希 |
| `inspect --jar <jar>` / `--secret <json>` | 查看构建与许可信息 |
| `license status\|install\|deactivate\|revocations` | 查看 / 安装 / 移除构建器授权与撤销列表 |
| `license-admin init-root\|issue\|show\|revoke` | 离线根密钥与工具许可证签发 |
| `fingerprint` | 打印本机机器码 |
| `selftest` | 跑密码、签名、JSON、许可证自检 |

### build 选项

| 选项 | 说明 |
| --- | --- |
| `--cipher auto\|aesgcm\|chacha\|chacha-pure` | 密码套件，默认 `auto`（AES-256-GCM） |
| `--integrity protected\|full\|off` | `protected` 校验类与 payload；`full` 额外校验数据文件；`off` 跳过哈希但仍验签 |
| `-e, --expire <yyyy-MM-dd>` | 到期日，省略为永久 |
| `--grace-days <n>` | 到期后的宽限天数，最大 3650 |
| `--bind <machine-id>` | 允许的机器，可重复 |
| `--bind-first-run` | 首次启动绑定到客户机 |
| `--customer <name>` | 客户标识，写进许可证 |
| `--edition <name>` | 版本标识，写进许可证 |
| `--jvm <range>` | 仅作记录，默认 `8-21` |
| `--exclude <package>` | 保持明文的包，可重复 |
| `--in-place` | 直接加密 class 条目；Spring 等扫描框架不可用 |
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
javashield-core/          信封、HKDF、ChaCha20、Ed25519、JSON、许可证、清单、指纹
javashield-tool/          构建器授权：工具许可证、试用/配额、状态存储、水印
javashield-builder/       ASM stub、jar 重写、加密与清单（CLI 与 Maven 插件共用）
javashield-agent/         premain/agentmain、许可闸门、完整性校验、transformer
javashield-cli/           CLI：build / issue / verify / inspect / fingerprint / selftest
javashield-maven-plugin/  package 阶段的 protect goal
docs/                     执行计划、格式规范、运维手册、回归报告
samples/hello/            最小端到端示例
samples/spring-boot-demo/ Spring Boot 3.2 回归工程
```

## 文档

- [执行计划](docs/execution-plan.md)：竞品取舍、架构、里程碑、风险
- [格式规范](docs/format.md)：信封、许可证、清单、构建密钥的字节级定义
- [工具授权](docs/tool-license.md)：试用、许可证签发、配额、状态码与信任根
- [运维手册](docs/runbook.md)：构建、部署、续期、排障
- [Spring Boot 3.2 回归报告](docs/spring-boot-regression.md)：真实 fat jar 的验证结果与两个兼容性修复
- [Maven 插件](docs/maven-plugin.md)：零改造接入、参数、幂等构建与排障

## 授权

本项目采用 JavaShield 商业软件许可协议，详见 [LICENSE](LICENSE)。提交代码或补丁前请阅读 [CLA.md](CLA.md)。

第三方依赖：ASM（BSD-3-Clause，仅构建器使用）、JUnit 5（EPL-2.0，仅测试使用）。运行时 agent 与 core 零第三方依赖。
