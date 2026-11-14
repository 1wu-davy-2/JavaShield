# Maven 插件

`javashield-maven-plugin` 把保护动作接进 `package` 阶段，客户项目只需要加一段插件配置，不用改代码、不用改启动脚本。

## 1. 安装

本地开发：

```bash
mvn -q clean install
```

发布到私服后，客户项目直接引用即可。

## 2. 接入

推荐用 profile，默认构建保持明文，需要交付时加 `-Pjavashield`：

```xml
<profiles>
  <profile>
    <id>javashield</id>
    <build>
      <plugins>
        <plugin>
          <groupId>com.javashield</groupId>
          <artifactId>javashield-maven-plugin</artifactId>
          <version>0.1.0-SNAPSHOT</version>
          <executions>
            <execution>
              <id>protect</id>
              <phase>package</phase>
              <goals><goal>protect</goal></goals>
            </execution>
          </executions>
          <configuration>
            <!-- customer 等选项需要 Pro / Enterprise 工具授权；试用时请移除 -->
            <customer>ACME</customer>
            <expire>2027-12-31</expire>
          </configuration>
        </plugin>
      </plugins>
    </build>
  </profile>
</profiles>
```

```bash
mvn -Pjavashield clean package
java -jar target/app.jar
```

### 与 spring-boot-maven-plugin 的顺序

本插件必须**在 repackage 之后**执行，输入才是可执行的 fat jar。把插件声明在 `spring-boot-maven-plugin` 之后（profile 注入默认就在后面），或者显式绑定到 `verify`：

```xml
<execution>
  <id>protect</id>
  <phase>verify</phase>
  <goals><goal>protect</goal></goals>
</execution>
```

如果顺序反了，产物会是「先保护、再被 repackage 覆盖」的明文包。构建日志里出现 `javashield:...:protect` 之后仍然能用 `unzip -l` 看到明文 class，就是顺序问题。

### 工具授权与试用

插件在 `protect` 执行前检查构建器许可证的 `maven` 功能。没有安装许可证时进入 14 天 / 3 次构建的本地试用：

- 试用允许 stub 模式、全部密码套件、`embedAgent`、`excludes`、产品 `expire` / `edition`；
- 试用**不允许** `customer`、`inPlace`、`integrity=full`、`bind` / `bindFirstRun`，否则构建在开始前失败，不消耗额度；
- 输入 jar 已受保护时插件直接跳过，也不会消耗额度；
- 许可证、激活与撤销的完整说明见 [工具授权](tool-license.md)。

安装许可证的两种方式：

```bash
# 方式一：装到用户状态目录，CLI 与插件共用
javashield license install --license pro.json

# 方式二：CI 中显式指定文件
mvn -Pjavashield package -Djavashield.toolLicense=/secure/pro.json
```

CI 还需要让插件信任签发根公钥：

```bash
export JAVASHIELD_TOOL_PUBLIC_KEY="$(cat root.pub)"
# 或者把 root.pub 嵌入发布版工具
```

失败时日志会带稳定错误码，例如：

```
JavaShield tool licence: trial builds do not allow customer watermark [trial_limit]
JavaShield tool licence: monthly build quota exhausted (100/100) [quota_exhausted]
JavaShield tool licence: tool licence does not include the 'maven' feature [feature_missing]
```

源码开发可设置 `JAVASHIELD_DEV=1` 跳过工具授权；发布版嵌入公钥后该变量失效。

## 3. 参数

| 参数 | 属性 | 默认 | 说明 |
| --- | --- | --- | --- |
| `input` | `javashield.input` | `target/${finalName}.jar` | 输入 jar |
| `output` | `javashield.output` | 与 input 相同 | 输出路径，默认原地替换 |
| `agentJar` | `javashield.agentJar` | 插件内置 | agent 模板 |
| `cipher` | `javashield.cipher` | `auto` | `auto/aesgcm/chacha/chacha-pure` |
| `integrity` | `javashield.integrity` | `protected` | `protected/full/off` |
| `expire` | `javashield.expire` | 永久 | `yyyy-MM-dd` |
| `graceDays` | `javashield.graceDays` | `0` | 宽限天数 |
| `customer` | `javashield.customer` | 空 | 写进许可证 |
| `edition` | `javashield.edition` | `standard` | 写进许可证 |
| `jvm` | `javashield.jvm` | `8-21` | 仅记录 |
| `bind` | `javashield.bind` | 空 | 机器码列表 |
| `bindFirstRun` | `javashield.bindFirstRun` | `false` | 首次启动绑定 |
| `excludes` | `javashield.excludes` | 空 | 保持明文的包 |
| `inPlace` | `javashield.inPlace` | `false` | Spring 项目禁用 |
| `embedAgent` | `javashield.embedAgent` | `true` | 内嵌 agent + `Launcher-Agent-Class` |
| `secretDirectory` | `javashield.secretDirectory` | `${basedir}/.javashield` | 构建密钥归档目录 |
| `toolLicense` | `javashield.toolLicense` | 用户状态目录 | 显式指定工具许可证文件（CI 常用） |
| `skip` | `javashield.skip` | `false` | 跳过保护 |

配置示例：

```xml
<configuration>
  <customer>ACME</customer>
  <expire>2027-12-31</expire>
  <graceDays>14</graceDays>
  <excludes>
    <exclude>com.acme.generated</exclude>
  </excludes>
</configuration>
```

命令行覆盖：

```bash
mvn -Pjavashield package -Djavashield.expire=2028-06-30 -Djavashield.customer=ACME
mvn -Pjavashield package -Djavashield.skip=true
```

## 4. 构建密钥

默认写到 `${basedir}/.javashield/<jar 名>.jshield-secret.json`，**不放在 `target/`**，避免 `mvn clean` 把唯一的签名密钥删掉。

- 该文件是续期与复核的唯一凭据，泄漏等同于该构建的最高权限；
- 不要提交到版本库（`.javashield/` 已在 `.gitignore`）；
- CI 上应把它收集为构建产物并转存到密钥管理服务；
- 通过工具授权构建时，密钥里还会多一个 `tool_license` 对象，记录工具许可证编号、客户、机器与本次构建后的配额计数；公开清单只含编号、版本与 `trial` 标记。

许可证 `jshield.lic` 写在 jar 同级（默认 `target/`），因为它必须随包部署。

## 5. 重复构建

`mvn package` 在内容未变时，maven-jar-plugin 不会重写 jar，因此插件会检测到输入已受保护并跳过：

```
[WARNING] input is already protected: target/app.jar; skipping (run 'mvn clean package' to rebuild it)
```

行为约定：

| 场景 | 结果 |
| --- | --- |
| 改了代码/资源再 `package` | jar 重建，重新保护，build id 变化 |
| 什么都没改再 `package` | 跳过，保留原产物 |
| 只改许可证参数（customer/expire） | **需要 `mvn clean package`**，否则会沿用旧许可证 |
| `mvn clean package` | 总是重新保护 |

## 6. 安装与部署

受保护 jar 会原地替换 `target/${finalName}.jar` 并作为项目产物，因此：

```bash
mvn -Pjavashield clean install   # 安装的是受保护版本
mvn -Pjavashield clean deploy    # 部署的也是受保护版本
```

如果只想本地跑明文、交付时再保护，保持 profile 默认不激活即可。

## 7. 排障

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 构建报 `input is already protected` | maven-jar-plugin 未重写 jar | 用 `mvn clean package`，或接受跳过 |
| 产物里还能看到明文 class | 插件在 repackage 之前执行 | 调整声明顺序或绑定到 `verify` |
| `input jar not found` | 在 `package` 之前调用了 `protect` | 绑定到 `package` 或 `verify` |
| `automatically bound to the plugin` 警告 | 没写 `<executions>` | 显式声明 execution |
| Spring 启动报 bean 找不到 | 用了 `inPlace` | 去掉 `<inPlace>true</inPlace>` |

## 8. 示例

`samples/spring-boot-demo/pom.xml` 中的 `javashield` profile 是可直接运行的完整例子，回归结果见 [Spring Boot 3.2 回归报告](spring-boot-regression.md)。
