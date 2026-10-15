# quic-reality

QUIC 代理，认证与伪装做在 **QUIC Initial 包的 TLS ClientHello 里**（REALITY 思路）：
合法客户端才会被 quinn 看到；其余一切（扫描、主动探测、重放）被**透明转发到真实站点**，
探测者看到的是该站点自己的证书和行为。

## 工作方式

1. 客户端的临时 X25519 公钥放进 ClientHello `key_share`；`K = X25519(e, S)`。
2. ClientHello `random` 是用 `K` 派生密钥 AES-256-GCM 加密的 `版本|时间戳|short_id`（AAD 绑定 key_share 与 SNI），看起来就是随机数。
3. 服务端在 UDP 层解开 Initial（其密钥由公开的 DCID 导出），验证：私钥 ECDH、short_id、±60s 时间窗、SNI、重放缓存。
4. 通过 → 交给 quinn；服务端为这条连接现场签发 Ed25519 临时证书，签名位被替换为 `HMAC-SHA512(auth_key, 公钥)`，**客户端据此验证服务端**（只有持有私钥者能产生）。
5. 不通过 → 整包转发到 `reality.dest`（真实 QUIC 站点），回包原样转回。
6. 之后的包用只有服务端能生成的 HMAC 连接 ID 做无状态识别（也支持客户端换 IP）。

## 用法

```bash
cargo build --release
./target/release/quic-reality keygen            # 生成密钥
./target/release/quic-reality example           # 服务端示例配置
./target/release/quic-reality example --client  # 客户端示例配置
./target/release/quic-reality run -c config.toml
```

`reality.server_name` 必须是 `dest` 真正通过 HTTP/3 提供服务的域名；`dest` 请选择在服务器出口方向可达的、支持 QUIC 的站点。
服务端默认禁止客户端访问内网/回环/链路本地（含云元数据）地址，可用 `security.allow_private_targets` 放开。

## 相对上一版修复的问题

| 问题 | 现在 |
|---|---|
| 服务端出示 `localhost` 自签证书，探测一眼识破 | 未认证流量根本到不了 quinn，探测者拿到的是 `dest` 的真证书 |
| 认证放在握手之后，且只用公钥派生，等于没有私钥 | 认证在首个 Initial，必须 ECDH（需要私钥）+ short_id |
| 客户端 `SkipServerVerification`，可被中间人 | 客户端校验临时证书里的 HMAC 与 CertificateVerify 签名 |
| 无重放保护 | 时间窗 + 重放缓存（同流重传放行，异地重放转诱饵） |
| Salamander 无完整性校验，回落分支基本不会触发 | 判定基于 QUIC 解析 + REALITY 认证，不依赖 Salamander；Salamander 默认关闭 |
| ALPN 带自定义 `quic-reality` | 仅 `h3` |
| 一次 `read` 读认证/请求头，可能截断或吞数据 | 全部 `read_exact` 精确解析，不过读 |
| `select!` 转发，半关闭时截断响应 | 双向独立半关闭 |
| 无重连 | 连接断开后自动重连一次并重试 |
| 拥塞控制 Cubic、关闭 MTU 探测，却宣称 hy2 速度 | 默认 BBR，开启 MTU 探测；不再宣称 hy2 同等速度 |
| UDP 每包开一个流，且代码自相矛盾 | 每个 SOCKS5 UDP 关联一条长流，双向帧 |
| HTTP 代理转发只带 Host，丢头和 body | 保留头与 body，去掉 Proxy-* 与 Connection |
| 认证后可访问任意内网地址 | 默认拒绝非公网目标 |
| CID 无校验 | HMAC 连接 ID（quinn 自带的哈希 CID 只有 40 位非密码学校验，故自实现） |

## 测试

`cargo test`：30 项，含真实 quinn 的端到端测试——合法客户端代理 TCP/UDP、2MB 双向传输、重连、
**探测者只信任诱饵证书也能与诱饵完成握手**、错误 short_id/错误服务端公钥被拒、重放被转发、Salamander 模式、内网目标被拒。

## 已知局限（请务必了解）

- **ClientHello 不是 Chrome 的**：用的是 rustls 的指纹（密码套件/扩展顺序/无 GREASE/无 ML-KEM 等），只有一个 X25519 key share。能做到“被动看不出是代理协议”，但**挡不住针对 rustls/quinn 指纹的识别**。要拟态 Chrome 需要改 rustls 的 ClientHello 构造。
- 首个 Initial 的 ClientHello 必须在单个包内（我们的客户端满足）；分片的 ClientHello 一律视为非本客户端而转发。
- 服务端对每个陌生 Initial 要做一次 X25519 + AES-GCM，高速洪泛可造成 CPU 消耗，未做限速。
- 服务端重启后 HMAC 密钥更换，已有连接需重连（客户端会自动重连）。
- 只支持 QUIC v1；其他版本的包一律转诱饵。
- Salamander 打开后所有包是随机噪声，与“看起来像普通 QUIC”目标相反，仅为兼容保留。
- 回落是 UDP 层转发：源地址对诱饵站而言是本服务器；`dest` 站点若按客户端 IP 做行为差异，需自行评估。
- 未经过第三方安全审计，不要把它当作经过验证的抗审查方案。
