# quic-reality v0.4

QUIC 隐蔽代理：Xray 级 REALITY 认证 + 真实站点回落 + datagram UDP + BBR/Brutal。

v0.4 是对 v0.3 的重写，修复了原实现全部核心缺陷。

## 与 v0.3 的差异

| 问题（v0.3） | 修复（v0.4） |
|---|---|
| 服务端自签证书直接暴露给探测者 | UDP 网关前置认证：解密 QUIC Initial → 校验 REALITY session id，失败者被 NAT 透传到真实站点，探测者只能看到 dest 的真证书 |
| 认证在 QUIC 握手之后（顺序反了） | 认证移到 TLS 握手之前（网关层），未认证连接永远到不了 quinn |
| 认证形同虚设（无 ECDH、nonce 可重放、SkipServerVerification） | Xray REALITY 协议：X25519 ECDH + HKDF-SHA256 + AES-128-GCM（AAD=零化 sid 的 ClientHello）+ 时间戳窗口防重放 + short_id 集合；客户端证书指纹锁定（支持 TOFU） |
| "Chrome 指纹"为空、自定义 ALPN 泄露 | 移除自定义 ALPN，默认 `h3`；无任何项目特征字符串 |
| Salamander 与伪装目标冲突、XOR 无完整性致回落失效 | 回落判据改为 REALITY 认证 + QUIC AEAD 解密，不再依赖 XOR 校验；README 明确 Salamander 开启时回落仅对同密码目标有效 |
| "hy2 速度"不成立（Cubic、UDP 走可靠 stream） | BBR/Brutal（从 hysteria 移植）可选；UDP 改走 RFC 9221 unreliable datagram + 分片重组，消除队头阻塞 |
| 无重连、单次 read、无内网限制、examples 缺失、版本混乱 | 客户端自动重连（退避）；TCP 全双工 `copy` 循环；默认封锁 loopback/RFC1918/链路本地等目标（可关）；本目录即完整工程；统一 v0.4 |

## 目录结构

```
Cargo.toml           # rustls 指向 vendor/rustls（patch）
src/
  main.rs            # CLI: run / keygen / example / fingerprint
  config.rs          # TOML 配置
  reality.rs         # REALITY 认证协议（seal/open/重放缓存）
  quic_initial.rs    # QUIC v1 Initial 解密 + ClientHello 提取（RFC 9001 密钥调度）
  gate.rs            # REALITY 网关 socket（AsyncUdpSocket）+ dest NAT 回落
  server.rs          # 服务端：证书持久化、TCP 中继、UDP datagram 分片、私有地址封锁
  client.rs          # 客户端：rustls fork 钩子、指纹锁定、SOCKS5/HTTP CONNECT、自动重连
  congestion.rs      # BBR / Cubic / Brutal（hysteria 移植）
  protocol.rs        # cmd + TargetAddr 编码
  salamander.rs      # 可选 UDP 混淆层
vendor/rustls/       # rustls 0.23.45 fork（ClientHello session_id 注入钩子）
e2e/                 # 端到端测试配置与脚本
```

## 构建

```bash
cargo build --release
```

依赖 vendored rustls fork，通过 `[patch.crates-io]` 自动生效，无需手动操作。

## 使用

```bash
# 1. 生成密钥对
cargo run --release -- keygen

# 2. 生成示例配置
cargo run --release -- example          # server
cargo run --release -- example --client # client

# 3. 运行
cargo run --release -- run -c server.toml
cargo run --release -- run -c client.toml

# 4. 使用
curl --socks5-hostname 127.0.0.1:1080 https://example.com/

# 5. 查看证书指纹（配置 server_fingerprint 用）
cargo run --release -- fingerprint --cert cert.pem
```

## REALITY 认证协议

```
reality_key  = X25519(client_ephemeral_priv, server_static_pub)
sealing_key  = HKDF-SHA256(salt=client_random[0..20], ikm=reality_key, info="REALITY")
nonce        = client_random[20..32]
header       = version(3) || rsv(1) || ts_be32(4) || short_id(8)        # 16B
session_id   = AES-128-GCM(sealing_key[..16], nonce,
                           aad=ClientHello(零化 sid), header) || tag     # 32B
```

客户端通过 vendored rustls 的 `ClientHelloCallback` 钩子，用握手中已生成的
X25519 临时私钥（`ActiveKeyExchange::extract_reality_key`）计算 reality_key 并
把密文写进 ClientHello 的 32 字节 legacy session_id。服务端网关自实现 QUIC v1
Initial 密钥派生（RFC 9001 §5.2，与 RFC 附录 A.2 测试向量逐字节对齐）、header
protection 移除与 payload 解密，取出 ClientHello 后做同样运算校验。

## 配置要点

| 配置 | 说明 |
|---|---|
| `reality.dest` | 回落目标。**必配**，空则探测包直接丢弃（无伪装） |
| `quic.congestion` | `bbr`（默认）/ `cubic` / `brutal:<bytes-per-second>` |
| `quic.block_private` | 服务端拒绝中继到 loopback/RFC1918 等地址，默认开 |
| `quic.server_fingerprint` | 客户端锁定服务端证书 SHA-256；空则 TOFU 并写入 `known_server.fingerprint` |
| `obfuscation.type = "salamander"` | 可选混淆。**注意**：开启后回落流量也带混淆，真实站点会丢弃；仅当 dest 同密码时回落才有意义。伪装普通网站请关闭 |

## 端到端验证结果

- 单元测试 16/16 通过（含 RFC 9001 A.2 官方测试向量）
- REALITY 认证通过 → QUIC 握手 → SOCKS5 → 真实公网站点（example.com）取回页面
- 伪造探测包被网关拒绝并原样 NAT 转发到 dest（UDP echo 收到完整 1200B）
- `block_private` 拦截回环目标行为符合预期
- PSK 会话恢复（重连 0-RTT）正常
