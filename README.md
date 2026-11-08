# rootkey-toolkit — 根密钥管理工具

根密钥的 **4-of-4 分片派生、还原与 AES-256-GCM 加解密** 的 Java SDK（含本地 CLI 管理工具）。

- 纯 JDK 实现，**运行时零第三方依赖**（无版本漂移，天然稳定）
- 组件位置由**配置项承载**，支持 JVM 系统属性 / 环境变量覆盖
- 派生与还原为**字节级确定性**操作，附带多重完整性校验

## 一、快速开始

```bash
mvn -q package          # 构建，产物 target/rootkey-toolkit.jar（SDK + CLI 二合一）
./bin/rootkey help      # 查看管理工具用法
```

## 二、本地管理工具（CLI）

### 1. 生成根密钥四组件（在本地/运维机执行）

```bash
./bin/rootkey generate --out ./secrets --key-id order-service
```

产出（根密钥本身**不落盘**）：

```
secrets/
├── a.comp   # 组件 a（32 字节随机材料）
├── b.comp   # 组件 b（32 字节随机材料）
├── c.comp   # 组件 c（32 字节随机材料）
├── d.comp   # 组件 d（= root ⊕ a ⊕ b ⊕ c）
└── manifest.properties   # keyId / KCV 等信息文件（不参与还原）
```

生成命令会打印 **KCV（根密钥指纹）**，请记录下来，用于日后与服务器还原结果核对。

### 2. 校验与试还原

```bash
./bin/rootkey verify ./secrets      # 逐文件校验 checksum、一致性、KCV，并对照 manifest
./bin/rootkey restore ./secrets     # 还原（仅显示 KCV，绝不输出密钥本体）
```

### 3. 加解密（演示/排查用）

```bash
echo -n '机密数据' | ./bin/rootkey encrypt ./secrets --base64 > msg.b64
./bin/rootkey decrypt ./secrets --in msg.b64 --base64
# 也支持二进制文件：./bin/rootkey encrypt ./secrets --in photo.jpg --out photo.jpg.enc
```

### 4. 分发到服务器

将 `a/b/c/d.comp` 四个文件**分别**通过安全渠道放到服务器的不同位置（建议不同目录、不同权限，甚至不同挂载点/密管系统），例如：

```
/etc/rootkey/a.comp
/var/lib/app/keys/b.comp
/srv/secrets/c.comp
/opt/share/d.comp
```

## 三、服务器 SDK 集成

### 1. 引入依赖

Maven 本地安装后依赖，或直接把 `target/rootkey-toolkit.jar` 放入 classpath：

```bash
mvn install:install-file -Dfile=target/rootkey-toolkit.jar -DgroupId=com.metrace \
    -DartifactId=rootkey-toolkit -Dversion=1.0.0 -Dpackaging=jar
```

```xml
<dependency>
    <groupId>com.metrace</groupId>
    <artifactId>rootkey-toolkit</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 2. 配置项（abcd 位置）

`/etc/app/rootkey.properties`：

```properties
rootkey.component.a.path=/etc/rootkey/a.comp
rootkey.component.b.path=/var/lib/app/keys/b.comp
rootkey.component.c.path=/srv/secrets/c.comp
rootkey.component.d.path=/opt/share/d.comp
```

优先级：**系统属性 > 环境变量 > 配置文件**。环境变量命名：点号转下划线并大写，如
`ROOTKEY_COMPONENT_A_PATH`、`ROOTKEY_COMPONENT_B_PATH` …（容器部署友好）。

### 3. Java API

```java
try (RootKeyManager km = RootKeyManager.fromConfigFile(Paths.get("/etc/app/rootkey.properties"))) {
    String cipherB64 = km.encryptToBase64("机密数据");   // AES-256-GCM，输出 Base64
    String plain     = km.decryptFromBase64(cipherB64); // 还原明文
    km.kcv();                                           // 与生成端核对的指纹
}
```

Spring 场景注册为单例 Bean 即可（`RootKeyManager` 线程安全，首次加解密时惰性还原并缓存，`close()` 销毁内存密钥）：

```java
@Bean(destroyMethod = "close")
public RootKeyManager rootKeyManager() throws Exception {
    return RootKeyManager.fromConfigFile(Paths.get("/etc/app/rootkey.properties"));
}
```

## 四、设计说明

### 分片方案（4-of-4 XOR）

- `root`：SecureRandom 生成的 32 字节（AES-256）
- `a`、`b`、`c`：各自独立的 32 字节随机材料
- `d = root ⊕ a ⊕ b ⊕ c`
- 还原：`root = a ⊕ b ⊕ c ⊕ d`（顺序无关、纯函数、跨平台字节级一致）

信息论安全性：任意丢失/泄露 **少于 4 个** 组件时，攻击者对根密钥 **零信息**（与重新随机生成无异）。代价是 4 个组件**缺一不可**，请务必各自备份。

### 稳定性保障（对应需求 5）

| 措施 | 作用 |
|---|---|
| 还原 = 纯 XOR，无任何随机/环境因素 | 同一组组件，任意时间/次数/JVM/操作系统还原结果完全一致（已用 200 次循环测试验证） |
| 组件文件自带 SHA-256 checksum | 文件损坏、误编辑在加载时即报错，绝不静默还原出错误密钥 |
| KCV（SHA-256(root) 前 8 字节）四份一致 + 还原后自证 | 混入其他批次的组件会立刻被发现 |
| 密文格式 `RK 0x01 \| IV(12B) \| 密文+Tag(16B)` | 带魔数与版本，跨版本可识别、可演进 |
| 纯 JDK 加密原语（AES-256-GCM，JCE 标准） | 不依赖任何第三方库，无供应链漂移 |

说明：加密使用随机 IV（同一明文每次密文不同，这是认证加密的正确语义）；**稳定性要求落在"派生/还原确定性"与"解密可重现"上**，两者均有测试覆盖。

### 错误场景一览

| 场景 | 结果 |
|---|---|
| 组件文件被篡改/损坏 | 加载时报 `校验和不匹配` |
| 传入重复组件（如 a 传两次） | 报 `标签校验失败: 重复/缺失` |
| 混入其他根密钥的组件 | 报 `KCV 校验失败` |
| 用错误密钥解密/密文被改 | GCM 认证失败，报 `解密失败：密文被篡改或密钥不匹配` |

## 五、安全与运维建议

1. **四组件分开存放**：不同目录 + 最小权限（文件已尽力设为 `600`）。更严格时可分别存入不同密管/配置中心，只要四个配置项能指到即可。
2. **传输安全**：组件可分批、分人传输；四者**同时**到达同一位置前不构成风险。
3. **备份**：丢任何一个组件 = 根密钥永久丢失（无法穷举恢复），请对四个组件分别离线备份。
4. **轮换**：重新 `generate` 一批组件（新 keyId/KCV），旧数据需先解密再用新密钥加密。
5. **绝不**把组件提交到代码仓库（`.gitignore` 已包含 `*.comp`）；KCV 可以记日志，密钥本体与组件材料不可。

## 六、项目结构

```
rootkey-toolkit/
├── bin/rootkey(.cmd)              # CLI 启动脚本
├── pom.xml
└── src
    ├── main/java/com/metrace/rootkey
    │   ├── RootKeyManager          # SDK 门面：生成/还原/加解密 API
    │   ├── RootKeyConstants / RootKeyException
    │   ├── core/                   # ComponentFile / Generator / Restorer / RootKeySecret
    │   ├── crypto/                 # AesGcmCipher（AES-256-GCM）
    │   ├── config/                 # RootKeyConfig（abcd 配置项 + 环境变量覆盖）
    │   └── cli/                    # RootKeyCli（本地管理工具）
    └── test/java/...               # 13 个测试：往返/确定性/防篡改/混用/配置覆盖
```
