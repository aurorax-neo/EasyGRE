# EasyGRE

零外部依赖（`Cargo.toml` 无第三方 crate）的 Rust 用户态三层 GRE 隧道守护进程，完整支持标准 GRE 封装、双向 Keepalive 探测与载波联动、多隧道并发、IPv4/IPv6 内层双栈、TCP MSS 钳制、1:1 NAT 公网 IP 自学习，以及基于 `FROM scratch` 镜像的一键 Docker 部署。

## 特性

- **零外部依赖**：仅依赖 Rust 标准库（`std`）与内联 Linux 系统调用（`ioctl`、`AF_NETLINK`、`io_uring`、`epoll`、`SOCK_RAW`），`x86_64` musl 静态编译后为单个约 730 KB ELF 二进制，容器内无需 `ip_gre` 内核模块、`iproute2`、`iptables` 或 `nftables`。
- **纯用户态高性能转发**：支持内联 `io_uring`（`IORING_OP_READV + RWF_NOWAIT`）批量零拷贝将 `TUN` 报文直读入 `AF_PACKET` `PACKET_TX_RING` (`TPACKET_V2`) 2048 帧共享内存环（容器禁用 `io_uring` 时自动降级为零拷贝 `readv`）、`IPPROTO_RAW` 出站套接字隔离（消除入站 `raw_v4_input` 多余 `skb_clone`）、`IFF_VNET_HDR` TCP TSO 与 Linux 6.2+ UDP GSO（`TUN_F_USO4 | TUN_F_USO6`）零拷贝切片、16 槽位双协议（TCP + UDP）RX GRO 合并、`IFF_MULTI_QUEUE` 多核 TX 队列池以及 L2 友好的 128 槽奇步长 `recvmmsg` 批量收包。
- **完整三层 GRE 协议能力**：
  - **Keepalive**：实现带 32-bit 随机探测令牌关联校验的双向 GRE-in-GRE (`PT=0x0000`) 探测与应答，防伪造保活回包；连续未响应达到重试次数后摘除载波并切换为 `down`，对端恢复后自动拉起；兼容 `10s,10`、`00:00:10,10`、`off`。
  - **MTU / Actual MTU**：`auto` 模式自动探测到对端物理出接口 MTU 并减去 24 字节（标准 1500 接口下得出 `1476`）。
  - **Clamp TCP MSS**：用户态双向拦截 IPv4/IPv6 TCP `SYN`/`SYN+ACK`，将 MSS 钳制到 `MTU - 40`（IPv4）或 `MTU - 60`（IPv6）并按 RFC 1624 增量更新 TCP 校验和。
  - **DSCP / Dont Fragment**：`dscp` 支持 `inherit` 或 `0..63`；`dont-fragment` 支持 `no`（允许外层分片）与 `inherit`（跟随内层 IPv4 DF，超路径 MTU 时自动向 TUN 内层源回送 ICMPv4 Frag Needed / ICMPv6 Packet Too Big）。
  - **DDNS 与 1:1 NAT 自适应**：支持后台非阻塞域名重解析与无损物理路由切换；在云主机 VPC 1:1 NAT 后无需修改 `accept_local=1`，支持 `--public-ip` 指定或经连续两次一致校验后从对端 Keepalive 自动学习公网 IP。
- **安全多隧道与非破坏式双栈路由**：单进程复用管理多条隧道，使用专用路由协议号（`198`）与 `NLM_F_EXCL` 拒绝覆盖宿主机已有路由；配置 `0.0.0.0/0` 或 `::/0` 时自动拆分为 `/1` 路由对保留宿主机原默认路由，并对对端公网 IP 自动维护 `/32` 旁路路由防回环。

## 运行前置条件

- 运行宿主机：Linux 内核（推荐 5.0+ 以完整支持 `TUNSETCARRIER` 载波联动；老版本内核会自动降级仅保持接口运行）。
- 容器权限：`network_mode: host`、`--cap-add NET_ADMIN`、`--cap-add NET_RAW` 以及映射 `/dev/net/tun`。
- 协议放行与源地址限制：由于标准 GRE 协议本身无密码学认证，建议在防火墙/云安全组上仅放行对端可信源 IP 的 IP 协议号 47（GRE）。

## 一键 Docker 启动

### 方式一：Docker Compose（推荐）

```bash
cp .env.example .env
# 修改 .env 中的 GRE_REMOTE、GRE_ADDR、GRE_ROUTE
docker compose up -d --build
```

不创建 `.env` 直接传参启动：

```bash
GRE_REMOTE=203.0.113.1 \
GRE_ADDR=172.16.1.2/30 \
GRE_ROUTE=10.1.101.0/24 \
docker compose up -d --build
```

Compose 多隧道配置建议使用 `GRE_TUNNELS`（若想使用 `GRE_1_*` 编号变量，可在 `docker-compose.yml` 中增加 `env_file: [.env]` 透传）：

```bash
GRE_TUNNELS="name=gre-bj;remote=203.0.113.1;addr=172.16.1.2/30;route=10.1.101.0/24 | name=gre-hk;remote=hk.example.com;addr=172.16.2.2/30;mtu=1400;keepalive=00:00:05,5" \
docker compose up -d --build
```

### 方式二：直接 `docker run`

```bash
# 直接拉取预构建多架构镜像（linux/amd64、linux/arm64）：
docker run -d --name easygre --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -e GRE_REMOTE=203.0.113.1 \
  -e GRE_ADDR=172.16.1.2/30 \
  -e GRE_ROUTE=10.1.101.0/24 \
  ghcr.io/aurorax-neo/easygre:latest

# 或在本地从源码构建镜像（如需使用镜像加速可传 --build-arg）：
docker build -t easygre:latest .
# docker build --build-arg RUST_IMAGE=dx.aorz.kdns.fr/library/rust:1-alpine -t easygre:latest .
```

### 容器状态与健康检查

容器内置基于二进制自身的 `HEALTHCHECK`（每 15 秒执行 `/easygre healthcheck`），也可手动执行：

```bash
docker exec easygre /easygre status
docker exec easygre /easygre healthcheck
ip -d link show gre-tunnel1
```

## 命令行与多隧道用法

### 单隧道启动

```bash
easygre --name gre-tunnel1 \
  --remote 203.0.113.1 \
  --addr 172.16.1.2/30 \
  --route 10.1.101.0/24 \
  --keepalive 10s,10
```

### 多隧道启动

支持以下三种等价写法（字段间用分号 `;` 分隔，避免与 `addr`/`route`/`keepalive` 中的逗号冲突）：

1. 重复 `--tunnel` 参数：

```bash
easygre \
  --tunnel "name=gre-bj;remote=203.0.113.1;addr=172.16.1.2/30;route=10.1.101.0/24" \
  --tunnel "name=gre-hk;remote=hk.example.com;addr=172.16.2.2/30;mtu=1400;keepalive=00:00:05,5"
```

2. 环境变量 `GRE_TUNNELS`（使用 `|` 或换行分隔多条隧道）：

```bash
export GRE_TUNNELS="name=gre-bj;remote=203.0.113.1;addr=172.16.1.2/30 | name=gre-hk;remote=hk.example.com;addr=172.16.2.2/30"
easygre
```

3. 编号环境变量 `GRE_<N>_*`：

```bash
export GRE_1_NAME=gre-bj GRE_1_REMOTE=203.0.113.1 GRE_1_ADDR=172.16.1.2/30
export GRE_2_NAME=gre-hk GRE_2_REMOTE=hk.example.com GRE_2_ADDR=172.16.2.2/30
easygre
```

> 配置优先级：命令行 `--tunnel` > 命令行单隧道参数（覆盖单隧道环境变量）> `GRE_TUNNELS` > `GRE_<N>_*` > 单隧道 `GRE_*`。同组内所有启用隧道接口 `name` 必须唯一。

## 参数总表

| CLI 参数 | 环境变量 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--name <ifname>` | `GRE_NAME` | `gre-tunnel1` | 虚拟网卡名，最长 15 字节（Linux `IFNAMSIZ` 限制） |
| `--remote <ip\|host>` | `GRE_REMOTE` | 必填 | 对端 IPv4 或域名（DDNS） |
| `--local <ip\|auto>` | `GRE_LOCAL` | `auto` | 本端绑定 IPv4；`auto` 或 `0.0.0.0` 自动探测出接口源 IP |
| `--public-ip <ip>` | `GRE_PUBLIC_IP` | 空 | 可选 1:1 NAT 公网 IPv4（不填亦可由 Keepalive 自动学习） |
| `--addr <cidr[,...]>` | `GRE_ADDR` | 空 | 隧道接口 IPv4/IPv6 CIDR，逗号分隔 |
| `--route <spec[,...]>` | `GRE_ROUTE` | 空 | 静态路由，支持 `10.1.0.0/16` 或 `10.1.0.0/16 via 172.16.1.1` |
| `--mtu <auto\|num>` | `GRE_MTU` | `auto` | 范围 `68..65500`，`auto` 为物理出接口 MTU 减 24 |
| `--keepalive <spec>` | `GRE_KEEPALIVE` | `10s,10` | 支持 `10s,10`、`00:00:10,10`、`1m,5`、`off`（间隔 `1s..3600s`，重试 `1..1000`） |
| `--dscp <inherit\|0..63>` | `GRE_DSCP` | `inherit` | 外层 IPv4 TOS 的 DSCP 字段策略 |
| `--dont-fragment <no\|inherit>` | `GRE_DONT_FRAGMENT` | `no` | 外层 DF 位策略；仅支持 `no` 或 `inherit`（显式拒收 `yes`） |
| `--clamp-tcp-mss <bool>` | `GRE_CLAMP_TCP_MSS` | `true` | 亦可用 `--no-clamp-tcp-mss` 关闭 |
| `--allow-fast-path <bool>` | `GRE_ALLOW_FAST_PATH` | `true` | 控制是否允许该隧道启用 `AF_PACKET PACKET_TX_RING` 二层直发（`--no-allow-fast-path` 强制走内核三层栈） |
| `--enabled <bool>` | `GRE_ENABLED` | `true` | 为 `false`（或 `--disabled`）时跳过该隧道 |
| `--dns-refresh <dur>` | `GRE_DNS_REFRESH` | `60s` | 域名型对端重解析周期（范围 `5s..86400s`，支持 `s`/`m`/`h` 或纯秒数） |
| `--tx-mode <auto\|mmap\|raw>` | `GRE_TX_MODE` | `auto` | 出站发包引擎：`auto` 优先 `PACKET_TX_RING` 并自动回退 `raw`；`mmap` 强制优先；`raw` 强制 `SOCK_RAW sendmmsg` |
| `--queues <auto\|1..16>` | `GRE_QUEUES` | `auto` | TUN 多队列与 TX 工作线程数（`auto` 取 `clamp(CPU, 1, 8)`） |
| `--comment <text>` | `GRE_COMMENT` | 空 | 备注信息，记录于状态文件 |
| `--status-file <path>` | `GRE_STATUS_FILE` | `/run/easygre/status` | 运行时状态文件路径（无 `/run` 环境自动回退 `/tmp/easygre.status`，权限 `0600`） |

> 安全说明：若显式传入非空 `ipsec-secret`（或 `GRE_IPSEC_SECRET`），程序会直接报错拒绝启动，避免在误以为启用加密的情况下以明文 GRE 运行。

## 双端 GRE 对接示例

假设节点 A 公网 IP 为 `198.51.100.10`（内网 `10.2.202.0/24`），节点 B 公网 IP 为 `203.0.113.1`（内网 `10.1.101.0/24`），节点 A 上的配置如下：

```env
GRE_NAME=gre-tunnel1
GRE_REMOTE=203.0.113.1
GRE_ADDR=172.16.1.2/30
GRE_ROUTE=10.1.101.0/24
GRE_KEEPALIVE=10s,10
```

节点 B 若同样运行 EasyGRE，只需将 `GRE_REMOTE` 设为 `198.51.100.10`、`GRE_ADDR` 设为 `172.16.1.1/30`、`GRE_ROUTE` 设为 `10.2.202.0/24`；若节点 B 为硬件路由器或标准三层 GRE 设备，按标准 GRE 协议放行 IP 协议号 47 并配置匹配的 `remote-address`、`keepalive=10s,10`、`mtu=auto` 与隧道地址即可互通。

更多配置示例（IPv6 双栈、云主机 1:1 NAT、全局默认路由防环回、Linux `ip_gre` 互通与排错）请参阅 [GRE 协议适配与运维排错指南](docs/gre-guide.md)。

## 状态输出与健康检查

`easygre status` 输出格式如下：

```text
updated_at=1794535200
pid=1
workers_ok=1
tunnel_count=1
tunnel	name=gre-tunnel1	state=running	carrier=1	local=10.0.0.2	public=198.51.100.10	remote_cfg=203.0.113.1	remote_ip=203.0.113.1	mtu=1476	misses=0	tx=120	rx=118	tx_drop=0	rx_drop=0	rx_trunc=0	ka_tx=6	ka_rx=6	ka_ans=6	ka_drop=0	comment=site-a
```

- `state` 取值：`probing`（初始握手中）、`running`（Keepalive 正常）、`running(keepalive-off)`（禁用 Keepalive 常通）、`down`（连续未响应超限，载波已摘除）。
- 丢包与安全指标：`tx_drop`（出站丢包/超 PMTU）、`rx_drop`（入站校验失败或 TUN 队列满丢包）、`rx_trunc`（超长截断包，触发后自动扩容至 64KB 槽位）、`ka_drop`（令牌不匹配的伪造或过期 Keepalive 应答）。
- `easygre healthcheck` 检查状态文件更新时间在 30 秒内、`workers_ok=1`（所有收发工作线程心跳正常）且至少一条隧道处于活跃状态时返回退出码 `0`，否则返回 `1`。

## 编译与测试

- 本机单元测试：`cargo test`
- Linux x86_64 musl 静态编译：

```bash
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc \
RUSTFLAGS="-C target-feature=+crt-static" \
cargo build --release --target x86_64-unknown-linux-musl
```

- Linux Network Namespace 双节点实网测试（Keepalive 上下线、IPv4/IPv6 互通）：

```bash
sudo ./scripts/e2e_netns_test.sh
```

- 长时间稳定性与 DDNS 热切换压测（默认 24 小时，可通过 `SOAK_DURATION_SECS` 自定义时长）：

```bash
sudo SOAK_DURATION_SECS=86400 ./scripts/soak_test.sh
```

## 延伸文档

- [GRE 协议适配与运维排错指南](docs/gre-guide.md)
- [架构设计与实现细节](docs/architecture.md)
