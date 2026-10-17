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
| 拥塞控制 Cubic、关闭 MTU 探测，却宣称 hy2 速度 | 默认 BBR，开启 MTU 探测；提供移植自 hy2 的 brutal（按配置带宽定速），不再空宣称同等速度 |
| UDP 每包开一个流，且代码自相矛盾 | 每个 SOCKS5 UDP 关联一条长流，双向帧 |
| HTTP 代理转发只带 Host，丢头和 body | 保留头与 body，去掉 Proxy-* 与 Connection |
| 认证后可访问任意内网地址 | 默认拒绝非公网目标 |
| CID 无校验 | HMAC 连接 ID（quinn 自带的哈希 CID 只有 40 位非密码学校验，故自实现） |

## 0.5.0 的改动

**ClientHello（`src/chrome_tls.rs`，手写 TLS 1.3 客户端）**
- 只提供 TLS 1.3：版本列表和密码套件（`1301/1302/1303`）都去掉了 TLS 1.2。RFC 9001 §4.2 要求 QUIC 客户端不得提供更低版本，此前的 15 个套件加 TLS 1.2 版本是浏览器走 TCP 时的特征，QUIC 里不存在。
- 去掉只属于 TLS 1.2 的扩展（extended_master_secret、renegotiation_info、ec_point_formats、session_ticket）。
- 扩展顺序每个连接随机打乱（首尾 GREASE 位置固定），与 Chrome 110 以后的行为一致。
- 剔除 quinn 无条件携带的 `min_ack_delay` 参数，关闭 `grease_quic_bit` 参数；流量窗口和流数量改为浏览器常见的整数值（6 MiB / 15 MiB，100 / 103）。
- 拒绝 TLS KeyUpdate（QUIC 禁止），ChaCha20 的完整性限额改为 RFC 9001 §6.6 的 2^36。

**拥塞控制（`congestion = "brutal"`，移植自 hysteria 2）**
- 按配置带宽固定速率发送，不做 BBR 式探测：窗口 = `bps × rtt / ackRate`（一个 BDP），
  丢包只通过 ACK 速率补偿（5 个 1 秒时隙内 `ack/(ack+loss)`，下限 0.8），**从不缩小窗口**。
- 带宽填 `brutal_bandwidth`（如 `"100 Mbps"`、`"512 kbps"`，或字节/秒整数）；
  `brutal_disable_loss_compensation = true` 可关闭丢包补偿（ackRate 恒为 1）。
  带宽必填，缺省会直接报错退出（fail-fast）。
- brutal 模式会通过 QUIC ACK Frequency 扩展请求对端每包立即回 ACK：brutal 的窗口只有
  一个 BDP，低延迟链路上也就几个包，quinn 默认的"每两包一回"策略在这种窗口下会退化成
  25 ms 的 MaxAckDelay 定时器，把有效 RTT 拉长、速率塌到配置值的零头。对端是 quinn 时
  自动生效，非 quinn 对端不支持该扩展，保持默认策略。
- 与 hysteria 的差异（quinn 的 `Controller` 接口没有 pacing 钩子，发送速率由窗口派生，
  长期速率 = 1.25 × 窗口 / RTT）：
  - 窗口取一个 BDP 而非 hysteria 的两个 BDP——两个 BDP 会让 quinn 的派生速率翻倍；
  - 因此速率在 **BDP ≥ 2×MTU 的真实链路上精确等于 `bps/ackRate`**（30 ms RTT 下实测
    100 Mbps 配置跑 96.7 Mbps、20 Mbps 跑 19.5 Mbps、1% 丢包不降速）；
  - 但 RTT 极小（BDP < 2×MTU，如本机回环）时窗口被 2×MTU 下限兜住，速率 = 2×MTU/RTT
    会**超过**配置带宽。hysteria 在同样场景靠独立 pacer 限速，quinn 无此接口，无法移植；
  - 双向共用同一个带宽值（hysteria 会协商 `min(serverRx, clientTx)`，QUIC Initial 认证
    没有握完后的带宽交换环节）。

**服务端重启后的恢复**
- CID 的 HMAC 密钥与 stateless-reset 密钥由服务端私钥派生（HKDF），重启后不变。重启后的服务端仍能认出旧连接的 CID，回应 stateless reset，客户端立即重连。
- 实测（真实进程，`kill -9` 后重启）：修改前首个请求失败，下一个请求 8 秒后才通，合计约 28 秒不可用；现在首个请求 0.05 秒内成功。
- 客户端任何“连接已死”的迹象（已关闭、被 reset、15 秒无应答）都会立刻丢弃连接并重试一次；服务端明确拒绝（策略、目标不可达）则不重连。默认 `idle_timeout_secs=20`，`keep_alive_secs=6`。

**稳健性**
- 去掉 release 的 `panic = "abort"`；网关判定外包一层 `catch_unwind`（它运行在 quinn 的收包任务里，panic 会让服务端什么都收不到）。
- 删除仓库根目录下与 `src/` 重复的源文件。

## 测试

`cargo test`：47 项，含真实 quinn 的端到端测试。0.5.0 新增：
- RFC 9001 附录 A 的 Initial 密钥向量；
- ClientHello 结构测试（仅 TLS 1.3、无 TLS 1.2 扩展、顺序确实在变、服务端解析器能取出全部字段）；
- 三种 TLS 1.3 套件（SHA-256 / SHA-384 / ChaCha20）各完成一次握手并传输数据，断言协商结果等于被强制的套件；
- 服务端被强杀后重启，客户端在 5 秒内恢复（实测 10 毫秒量级）；
- 传输参数清洗、派生密钥稳定性。

## 已知局限（请务必了解）

- **指纹仍不是 Chrome 的逐字节复刻。** 本版去掉了最明显的、QUIC 里不可能出现的特征，但以下尚未处理，且我没有真实 Chrome 的 QUIC 抓包可供对照，不应认为已经“与 Chrome 一致”：
  - 没有 X25519MLKEM768 混合密钥交换（新版 Chrome 默认带，使 ClientHello 超过一个包）。要加需要网关支持跨多个 Initial 包重组 ClientHello。
  - 扩展集合、扩展内部取值、QUIC 传输参数的集合与顺序是按记忆与常见值做的近似，未经实测验证。传输参数的顺序仍由 quinn 决定。
  - 浏览器在 QUIC Initial 里的 PADDING/ACK 行为、包长度分布等未做拟态。
- 手写的 TLS 1.3 客户端没有经过第三方审计。它与 rustls 服务端互通，并有 RFC 向量与三套件测试，但这不等于安全证明。
- 首个 Initial 的 ClientHello 必须在单个包内（当前客户端满足）。
- 服务端对每个陌生 Initial 要做一次 X25519 + AES-GCM，高速洪泛会消耗 CPU，未做限速。
- 只支持 QUIC v1；其他版本一律转诱饵。
- Salamander 打开后所有包是随机噪声，与“看起来像普通 QUIC”相反，仅为兼容保留。
- 回落是 UDP 层转发：诱饵站看到的源地址是本服务器。
- 本版本只在本机回环上测试过，未在真实网络和真实 HTTP/3 站点上联调。
