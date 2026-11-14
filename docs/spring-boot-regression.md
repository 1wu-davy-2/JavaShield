# Spring Boot 3.2 回归报告

日期：2026-11-14
对象：JavaShield 0.1.0
结论：**Spring Boot 3.2.12 fat jar 在 stub 模式下通过回归，包括组件扫描、依赖注入、`@ConfigurationProperties`、Jackson、Actuator。** 过程中发现并修复了两个 Boot 兼容缺陷。

---

## 1. 环境

| 项 | 值 |
| --- | --- |
| JDK | JetBrains Runtime 17.0.10（`javac` 可用） |
| Maven | 3.9.9 |
| Spring Boot | 3.2.12 |
| 被测应用 | `samples/spring-boot-demo` |
| JavaShield 构建器 | JDK 11 运行，产物 Java 8 字节码 |
| 端口 | 18080 |

## 2. 被测应用

一个最小的 Spring Boot Web 应用，刻意覆盖容易受字节码保护影响的机制：

| 机制 | 实现 |
| --- | --- |
| 组件扫描 | `@RestController`、`@Service`、`@SpringBootApplication` 同包 |
| 构造器注入 | `HelloController(GreetingService)` |
| 配置绑定 | `@ConfigurationProperties(prefix="demo")` + `application.yml` |
| Jackson 序列化 | `Map<String,Object>` 返回值 |
| Actuator | `/actuator/health`、`/actuator/beans` |
| 业务字符串常量 | `GreetingService.INTERNAL_SALT = "internal-salt-9f3a"`，用于检查 stub 泄漏 |

接口：

```bash
GET /api/hello?name=x   -> {"message":"hello, x from acme-2026","retries":5,"salt":"internal-bff9b6a2"}
GET /api/ping           -> pong
GET /actuator/health    -> {"status":"UP",...}
```

## 3. 结果

### 3.1 明文 vs 受保护

| 检查 | 明文 | 受保护 |
| --- | --- | --- |
| 启动 | 成功 | 成功，agent 输出 `ready build=... classes=4` |
| `/api/hello?name=plain` | `hello, plain from acme-2026` | 换成 `name=protected` 后输出一致，`salt` 完全相同 |
| `/api/ping` | `pong` | `pong` |
| `/actuator/health` | `UP` | `UP` |
| bean 扫描 | 255 个 | 255 个，`helloController`、`greetingService`、`demo-com.example.demo.DemoProperties` 均在 |
| `verify` | — | `verify OK`，4 个类 |

`@ConfigurationProperties` 的 bean 名是 `demo-com.example.demo.DemoProperties`，说明 `@ConfigurationPropertiesScan` 与绑定都正常。

### 3.2 结构检查

- `BOOT-INF/classes/**` 的 4 个类全部变为 stub；
- `BOOT-INF/lib/**` 的 200+ 个依赖 jar 原样保留；
- 反汇编 `GreetingService.class`：字段与签名保留，方法体只剩 `throw new LinkageError`；
- 在 stub 中搜索 `internal-salt-9f3a`：**不存在**；
- jar 条目数、目录条目数与原始包一致（28 个目录条目）。

### 3.3 反例

| 场景 | 结果 |
| --- | --- |
| `--no-embed` 且不加 `-javaagent` | `Caused by: java.lang.LinkageError: JavaShield: class loaded without the protection agent`，启动失败 |
| `--in-place` 模式 | Spring 扫描失败：`ClassFormatException: ... Unsupported class file major version 3088` |
| 许可证过期 | `refusing to start: licence expired on 2020-01-01` |

`--in-place` 的失败是**预期行为**，也是默认使用 stub 模式的原因：Spring 的 `SimpleMetadataReader` 在类加载之前用 ASM 读取 `.class`，密文的头 4 字节 `JSX1` 会被当成 class 版本号。错误信息里 Spring 提示设置 `spring.classformat.ignore=true`，但那会让扫描静默跳过这些类，不能作为解决方案。

## 4. 本次发现并修复的缺陷

### 4.1 嵌套 jar 被重新压缩

Spring Boot 要求 `BOOT-INF/lib/*.jar` 以 **STORED**（不压缩）存储，启动器才能随机访问嵌套 jar。首版构建器用 `JarOutputStream` 复制条目时统一按 DEFLATE 写入，导致受保护包启动失败。

修复：`JarBuilder.copy()` 保留原始条目的压缩方法；STORED 条目先读全量、计算 CRC 与 size，再以 STORED 写入。

### 4.2 目录条目被丢弃

首版跳过了所有目录条目。Boot 3.2 的 `NestedJarFile` 通过 `BOOT-INF/classes/` 这类目录条目解析嵌套根，缺失时 `LaunchedClassLoader` 找不到 `Start-Class`：

```
java.lang.ClassNotFoundException: com.example.demo.DemoApplication
  at java.net.URLClassLoader.findClass
  at org.springframework.boot.loader.launch.LaunchedClassLoader.loadClass
```

修复：`JarBuilder.writeDirectory()` 保留原始目录条目。修复后目录条目数与原始包一致（28）。

两个缺陷都补了集成测试：`springBootJarKeepsDirectoriesAndStoredNestedJars`，断言 STORED 方法与目录条目在产物中保留。

## 5. 复现步骤

```bash
# 1. 构建应用（JDK 17）
cd samples/spring-boot-demo
JAVA_HOME=/path/to/jdk17 mvn -q -DskipTests package

# 2. 明文基线
java -jar target/demo-1.0.0.jar
curl "http://localhost:18080/api/hello?name=plain"

# 3. 保护
java -jar ../../javashield-cli/target/javashield.jar build \
  -i target/demo-1.0.0.jar -o dist/demo-1.0.0.jar \
  --customer "Spring Regression" -e 2028-12-31

# 4. 运行受保护包
java -jar dist/demo-1.0.0.jar
curl "http://localhost:18080/api/hello?name=protected"
curl http://localhost:18080/actuator/health

# 5. 校验
java -jar ../../javashield-cli/target/javashield.jar verify \
  --jar dist/demo-1.0.0.jar --secret dist/demo-1.0.0.jar.jshield-secret.json
```

## 6. 结论与后续

- stub 模式可以用于 Spring Boot 3.2 fat jar，默认配置即可，无需改启动参数；
- 构建器需要保留目录条目与嵌套 jar 的 STORED 属性，这两点已固化为回归测试；
- in-place 模式不适用于任何依赖 ASM 扫描的框架，文档与 CLI 帮助需明确提示；
- 尚未覆盖：Spring Boot 2.7、Boot 3.3/3.4、WAR、`spring-boot:layertools` 分层 jar、DevTools；
- 性能：4 个类的应用启动增量不明显；大包（数千类）的冷启动与内存占用待压测。
