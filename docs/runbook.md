# JavaShield 运维手册

面向两类使用者：构建方（打包交付的人）与部署方（在客户机房启动程序的人）。

---

## 1. 构建环境

- Maven 3.6+，JDK 11 编译；
- 产物是 Java 8 字节码，可运行在 JDK 8/11/17/21；
- 构建器除 ASM 外无第三方依赖，agent 零依赖。

```bash
mvn -q -DskipTests package
```

发布目录建议：

```
release/
  javashield.jar           # CLI（shaded）
  jshield-agent.jar        # agent 模板（由 javashield-agent-*-agent.jar 改名）
```

`javashield.jar` 找不到 agent 时，可以用 `--agent <path>` 或 `-Djavashield.agent.jar=<path>` 指定。

---

## 2. 构建受保护产物

### 2.1 普通可执行 jar

```bash
java -jar javashield.jar build \
  -i myapp.jar \
  -o dist/myapp.jar \
  --customer "ACME" \
  -e 2027-12-31
```

### 2.2 Spring Boot fat jar

构建器读取 `META-INF/MANIFEST.MF` 的 `Spring-Boot-Classes`，只加密 `BOOT-INF/classes/**`，`BOOT-INF/lib` 下的第三方依赖保持原样。

```bash
java -jar javashield.jar build -i app.jar -o dist/app.jar --customer "ACME" -e 2027-12-31
java -jar dist/app.jar
```

注意：

- 必须用默认的 stub 模式。Spring 的组件扫描、条件装配、`@Configuration` 解析都依赖 ASM 读取 `.class` 元数据；
- 如果启动时报 `NoSuchBeanDefinition` 或扫描结果为空，先用 `--exclude` 把可疑包排除，确认是保护导致后再排查；
- Spring Boot 3.2 起 loader 改为 `LaunchedClassLoader`，JavaShield 只做 transformer，不继承任何 loader，理论上不受影响，但 0.1 尚未在真实 Boot 3.2 项目上回归。

### 2.3 不需要内嵌 agent

```bash
java -jar javashield.jar build -i app.jar -o dist/app.jar --no-embed
java -javaagent:dist/jshield-agent.jar -jar dist/app.jar
```

适合客户已有统一启动脚本、或需要把 agent 放到固定路径的场景。

### 2.4 只保护部分包

```bash
java -jar javashield.jar build -i app.jar -o dist/app.jar \
  --exclude com.acme.plugin \
  --exclude com.acme.generated
```

排除规则按包前缀匹配，`com.acme.plugin` 会同时排除 `com.acme.plugin.*`。

---

## 3. 部署

### 3.1 交付物

```
dist/
  myapp.jar                     受保护应用
  jshield.lic                   许可证（必须可写，续期时替换）
  jshield-agent.jar             独立 agent（可选）
  .jshield-binding.json         首次启动绑定后生成（如启用）
```

**不要交付** `myapp.jar.jshield-secret.json`。它是构建方最高权限密钥。

### 3.2 目录权限

运行用户需要：

- 读 `myapp.jar`、`jshield.lic`；
- 写 `jshield.lic` 所在目录（续期替换）；
- 写 `.jshield-binding.json`（首次绑定）；
- 写 `~/.jshield/`（时钟状态）。

只读部署：

```bash
java -Djshield.binding=/var/lib/myapp/binding.json \
     -Djshield.state.dir=/var/lib/myapp/state \
     -jar myapp.jar
```

### 3.3 验证

```bash
java -jar javashield.jar verify --jar dist/myapp.jar --secret myapp.jar.jshield-secret.json
java -jar javashield.jar inspect --secret myapp.jar.jshield-secret.json
```

---

## 4. 续期

```bash
java -jar javashield.jar issue --secret dist/myapp.jar.jshield-secret.json -e 2028-12-31
```

- 只重写 `jshield.lic`，业务包与绑定记录不变；
- 未显式传入的字段（宽限期、客户、绑定机器）沿用原许可证；
- 换机：`issue --secret ... --bind <新机器码>`，或清空 `fingerprints` 改为任意机器；
- 首次绑定模式续期后，客户机不需要重新绑定。

客户机机器码（不需要许可证，客户可自行运行）：

```bash
java -cp jshield-agent.jar com.javashield.core.Fingerprint
```

输出中的 `machineId=` 即 32 位机器码。也可以在构建方运行 `java -jar javashield.jar fingerprint` 取本机机器码。

---

## 5. 排障

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `ClassFormatError: Incompatible magic value 1347639345` | in-place 模式没挂 agent | 用 `java -jar`（内嵌 agent）或加 `-javaagent` |
| `LinkageError: class loaded without the protection agent` | stub 模式没挂 agent | 同上 |
| `licence not found` | 许可证不在 jar 同级 | 放 `jshield.lic` 到 jar 同级，或 `-Djshield.license=<path>` |
| `licence cannot be decrypted for this build` | 许可证属于别的构建 | 用对应构建的 secret 重新 `issue` |
| `licence expired on ...` | 已过到期日 + 宽限期 | `issue -e <新日期>` |
| `this machine is not licensed` | 机器码不在白名单 | 取客户机器码后重新签发 |
| `this package is bound to another machine` | 整包被复制到别的机器 | 重新签发，或由构建方删除绑定记录后重绑 |
| `binding record was modified` | 绑定文件被改 | 删除并由构建方重新签发 |
| `system clock moved backwards` | 系统时间回拨 | 校正 NTP；确认后删除 `~/.jshield/<build_id>.state` |
| `class integrity check failed: X` | jar 被改包或重新压缩 | 从原始包重新构建 |
| `manifest signature is invalid` | 清单被替换 | 重新构建 |
| `cannot locate the agent jar` | 发布目录缺少 agent | `--agent <path>` 或把 `jshield-agent.jar` 放到 CLI 同级 |
| `reg.exe` 被安全软件拦截 | 机器码首次探测失败 | 会回退到卷序列号/主机名+MAC；也可 `-Djshield.machine.id=<id>` 显式指定 |
| `trial period has expired` / `trial build quota is exhausted` | 试用天数或次数用尽 | 安装 Pro/Enterprise 工具许可证；源码构建可 `JAVASHIELD_DEV=1` |
| `trial builds do not allow ... [trial_limit]` | 试用使用了付费构建选项 | 去掉 `--in-place` / `--integrity full` / `--customer` / 绑定，或安装付费许可证 |
| `tool licence does not include the 'x' feature [feature_missing]` | 许可证功能列表不含当前入口 | 重新签发并加入对应 `--feature` / 提高 edition |
| `monthly build quota exhausted [quota_exhausted]` | 当月构建额度用尽 | 等下一个自然月，或签发更高 `--max-builds` 的许可证 |
| `tool licence is bound to another machine [machine_mismatch]` | 工具许可证绑定了别的机器 | 用 `javashield fingerprint` 取本机码后重新签发 |
| `tool state signature is invalid [state_invalid]` | 试用/配额/激活状态被修改或损坏 | 删除状态目录下对应的 `trial.json` / `quota.json` / `install.json` 后重试（会重置本地计数） |
| `tool licence is invalid [license_invalid]` | 文件损坏、格式不对或签名不匹配 | 确认 `JAVASHIELD_TOOL_PUBLIC_KEY` / 嵌入的 `root.pub` 与签发根一致 |
| `no tool public key is configured` | 源码构建没有信任根 | 设置 `JAVASHIELD_TOOL_PUBLIC_KEY`，或正式发布时嵌入 `root.pub` |

### 工具授权排障

```bash
javashield license status                 # 不可用时退出码为 1
javashield license status --license /path/to/license.json
javashield license install --license /path/to/license.json
javashield license deactivate
```

状态目录优先级：`-Djavashield.home` → `JAVASHIELD_HOME` → `%APPDATA%\JavaShield` / `~/.javashield`。CI 中建议显式设置 `JAVASHIELD_HOME` 与 `JAVASHIELD_TOOL_PUBLIC_KEY`，避免依赖用户目录。完整状态码见 [工具授权](tool-license.md)。

### 调试受保护程序

0.1 尚未提供 `-Djshield.debug` 关闭保护。排查业务问题时，用原始 jar 复现，或临时用 `--exclude` 排除相关包重新构建。

### 解不开的类

transformer 失败会抛 `IllegalStateException: javashield: cannot decrypt protected class X`，常见原因：

- 用旧 agent 配新 jar（build_id 不匹配）；
- 手工替换过 payload；
- 把两个构建的文件混在一起。

从原始 jar 重新构建即可。

---

## 6. 密钥与构建产物管理

| 文件 | 敏感度 | 保存要求 |
| --- | --- | --- |
| `*.jshield-secret.json` | 最高 | 离线/加密存储，按构建归档，绝不进版本库 |
| `root.key`（工具授权根私钥） | 最高 | 离线介质 / HSM 保管，绝不进构建机、仓库或发布包 |
| `root.pub` | 公开 | 嵌入发布版工具；可进仓库或随许可证签发流程分发 |
| `tool-license.json` | 中 | 本机构建器授权，按机器安装，不随产品交付 |
| `jshield.lic` | 中 | 可随包交付，可被客户读取（内容加密） |
| `jshield-agent.jar` | 低 | 每次构建重新生成，内含混淆的 master key |
| 原始 jar | 中 | 保留，用于重新构建与回归 |

构建密钥泄漏的处置：

1. 立即用原始 jar 重新构建，生成新的 `master_key` / `build_key` / `signing_key`；
2. 旧包无法离线吊销，只能通过合同与后续版本替换；
3. 若启用了在线撤销（M6），把旧 `build_id` 加入撤销列表。

---

## 7. 发布检查清单

- [ ] 用原始 jar 构建，输出目录干净
- [ ] `verify` 通过
- [ ] 在干净机器上 `java -jar` 启动成功
- [ ] 许可证的客户名、到期日、绑定方式正确
- [ ] `*.jshield-secret.json` 已归档到安全位置，未进入交付包
- [ ] 交付包里没有原始 class（`unzip -l` 抽查）
- [ ] 记录 build_id 与对应的客户
- [ ] 发布版工具已嵌入 `com/javashield/tool/root.pub`（`-Pembedded-tool-key`）
- [ ] 发布版上 `JAVASHIELD_DEV=1` 无法跳过工具授权
- [ ] `javashield license status` 在发布机与 CI 上返回预期状态

---

## 8. 已知限制

- 0.1 只支持 `.jar`，不支持 WAR；
- 不支持 multi-release jar（`META-INF/versions/**` 保持明文）；
- `module-info.class` 保持明文，模块化 jar 未回归；
- 加密后不能用 `jarsigner` 签名（会与条目哈希冲突）；
- agent 只能启动期加载，不支持运行期 attach（顺应 JEP 451）；
- 同类工具都无法阻止同进程 dump，JavaShield 不承诺绝对安全；
- 工具授权的本地试用/配额状态可以删除重置，P0 没有服务端登记；在线激活、心跳与撤销同步在 P2；
- `activation_required` 目前只生成本机激活记录，离线可用，但没有服务端次数控制；
- Gradle 插件、WAR、GUI、native 密钥模块尚未实现，功能位已预留在工具许可证中。
