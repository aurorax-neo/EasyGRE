# GRE 协议适配与运维排错指南

本文档说明 EasyGRE 的三层 GRE 封装规范、双向 Keepalive 报文机制、云主机 1:1 NAT 自适应逻辑、常见拓扑示例及故障定位方法。

## 1. 参数规范与行为说明

EasyGRE 实现标准无加密 Layer-3 GRE over IPv4（RFC 2784，IP 协议号 47），虚拟网卡仅承载三层 IPv4（EtherType `0x0800`）与 IPv6（EtherType `0x86DD`）报文：

| 参数 | 环境变量 | 默认值 | 行为细节 |
| --- | --- | --- | --- |
| `--enabled` | `GRE_ENABLED` | `true` | 设为 `false`（或 `--disabled`）时启动阶段跳过该隧道 |
| `--comment` | `GRE_COMMENT` | 空 | 写入运行时状态文件，便于区分多条隧道 |
| `--name` | `GRE_NAME` | `gre-tunnel1` | Linux TUN 接口名，受内核 `IFNAMSIZ` 限制最长 15 字节 |
| `--mtu` | `GRE_MTU` | `auto` | `auto` 时按出接口物理 MTU 减 24 字节计算（例如 `1500 -> 1476`） |
| `--local` | `GRE_LOCAL` | `auto` | `auto` 或 `0.0.0.0` 时通过 Netlink 向内核查询到达对端的首选源 IP |
| `--remote` | `GRE_REMOTE` | 必填 | 对端公网 IPv4 地址或域名（DDNS） |
| `--public-ip` | `GRE_PUBLIC_IP` | 空 | 可选 1:1 NAT 映射公网 IPv4，留空亦可从对端 Keepalive 自动学习 |
| `--keepalive` | `GRE_KEEPALIVE` | `10s,10` | 默认开启；支持 `00:00:10,10`、`10s,10`、`10,10`、`1m,5`、`off`（间隔 `1s..3600s`，重试 `1..1000`） |
| `--nat` | `GRE_NAT` | `off` | 纯用户态 NAT44/NAT66：`out`（隧道出向 SNAT）、`exit`（出口 WAN 落地伪装）、`both`（双向同时开启） |
| `--dnat` | `GRE_DNAT` | 空 | 纯用户态端口映射，支持 `[tcp\|udp\|both/][listen_ip:]port->target_ip:port`（可重复传参或逗号分隔） |
| `--dscp` | `GRE_DSCP` | `inherit` | `inherit` 继承内层 IPv4 TOS / IPv6 Traffic Class 高 6 位；或指定 `0..63` |
| `--dont-fragment` | `GRE_DONT_FRAGMENT` | `no` | `no` 允许外层分片；`inherit` 跟随内层 DF，超 PMTU 时向内层源回送 ICMPv4 Frag Needed / ICMPv6 Packet Too Big |
| `--clamp-tcp-mss` | `GRE_CLAMP_TCP_MSS` | `true` | 对进出 TUN 的 TCP `SYN`/`SYN+ACK` 双向执行 MSS 钳制（IPv4: `MTU-40`，IPv6: `MTU-60`） |
| `--allow-fast-path` | `GRE_ALLOW_FAST_PATH` | `true` | 为 `true` 时允许使用 `AF_PACKET PACKET_TX_RING` 二层直发；设为 `false`（`--no-allow-fast-path`）时该隧道走内核三层栈（保留宿主机出站防火墙/SNAT/`tc` 规则） |
| `--dns-refresh` | `GRE_DNS_REFRESH` | `60s` | 域名型对端后台非阻塞重解析周期（`5s..86400s`），IP 变更时无环回热更新隧道与旁路路由 |
| `--tx-mode` | `GRE_TX_MODE` | `auto` | 出站发包引擎（`auto`、`mmap`、`raw`），`auto` 优先使用 `AF_PACKET PACKET_TX_RING` |
| `--queues` | `GRE_QUEUES` | `auto` | TUN 多队列（`IFF_MULTI_QUEUE`）与并行 TX 工作线程数（`auto` 或 `1..16`） |

> 安全与宿主机规则提示：
> 1. 标准三层 GRE 无密码学认证，生产环境应在宿主机防火墙或云安全组上将入站 IP 协议 47（GRE）限制为对端公网 IP。
> 2. `AF_PACKET` 快速路径开启了 `PACKET_QDISC_BYPASS` 直接向网卡驱动发送二层帧，外层 GRE 报文不会经过宿主机 `iptables`/`nftables` 出站链（如本机 SNAT）与 `tc` 限速队列；若外层报文依赖宿主机防火墙或 `tc` 整形，请设置 `GRE_TX_MODE=raw` 或 `--no-allow-fast-path`。

## 2. 双向 GRE Keepalive 工作机制

标准三层 GRE 本身无连接状态。为及时感知对端故障，EasyGRE 在用户态实现标准的 **GRE-in-GRE (`PT=0x0000`)** 双向保活协议，不依赖内核 `ip_gre` 模块，也无需修改高风险内核参数 `net.ipv4.conf.*.accept_local=1`：

1. **响应对端探测（Peer -> EasyGRE）**：
   对端路由设备周期发送双重封装探测报文：
   `[Outer IPv4: Peer -> Local, proto=47] + [Outer GRE: PT=0x0800] + [Inner IPv4: LocalPublic -> Peer, proto=47] + [Inner GRE: PT=0x0000]`
   EasyGRE 解封装后识别到内层协议为 `47` 且内层 GRE `PT=0x0000`，**不注入 TUN 设备**，而是立即通过 TX Raw Socket 向对端外层源地址回送 8 字节 GRE Keepalive 应答（`[0x00; 8]`，包含 4 字节 `PT=0x0000` 头及 4 字节零填充）。
2. **主动探测对端与自适应多层穿透（EasyGRE -> Peer）**：
   EasyGRE 默认开启 `GRE_KEEPALIVE=10s,10`，启动后优先按当前最优路径发起带 32-bit 密码学无关随机令牌与实例标签的探测报文：
   - **第一层（标准 `GRE-in-GRE PT=0x0000`）**：完全兼容 RouterOS、Cisco 与对端 EasyGRE。
   - **自动无感降级穿透 1:1 NAT + `masquerade` 元组冲突**：当对端位于云厂商 1:1 NAT 后且出接口配置了 `srcnat masquerade`（例如联通云等云环境下的 RouterOS / Linux 网关）时，对端解封装回弹的 `GRE-in-GRE` 报文在出网执行 `masquerade` 时因 GREv0 `srckey=0, dstkey=0` 与外层 GRE 隧道已占用的 `nf_conntrack` 表项 `(local_priv_ip, peer_pub_ip, proto=47)` 发生元组冲突而被内核直接丢弃。若首帧 `GRE-in-GRE` 在子窗口（150ms~400ms）内未获响应，EasyGRE 会使用同一周期令牌自动并发探测无冲突备用通道并记忆成功模式：
     1. **隧道内 `ICMPv4 / ICMPv6 Echo`（`in-tunnel-icmp-echo`）**：对 `/30`、`/31`、`/126`、`/127`、`via <gw>` 或数据面自动学习到的对端隧道 IP 发送带 `EGRK` 签名的隧道内 Echo Request，应答封装在正常 GRE 数据帧内原路返回，完全不触发对端物理出口 `masquerade`。
     2. **隧道内 `TTL=1 / HopLimit=1` 探测（`in-tunnel-ttl1`）**：在未知对端隧道 IP 的子网场景下触发对端三层接口回送 `ICMP Time Exceeded`（完整兼容 RFC 792 仅引用内层前 8 字节的截断报文），并自动学习对端隧道内 IP。
     3. **外层 `UDP-in-GRE` 端口回弹（`udp-in-gre`）**：当本端未配置 `--addr` 或对端隧道内 IP 未知且不响应隧道内 ICMP 时，内层高端口 UDP 探测包由对端物理口转发回本端临时监听 UDP 套接字（`proto=17`），彻底避开 `proto=47` 的 GRE `conntrack` 元组冲突。
   - 收到任一通道携带匹配令牌的合法应答即清零 `misses` 并将 TUN 载波置为 `LOWER_UP`（同周期多通道重复回包自动幂等去重，不计入 `ka_drop`）；连续 `retries` 个周期无响应则摘除载波（`NO-CARRIER`）停止黑洞转发，对端恢复后自动拉起。

> 关于 Keepalive 载荷采用 8 字节（IP 总长 28 字节）：Linux 内核 `net/netfilter/nf_nat_proto.c` 的 `gre_manip_pkt()` 在执行 SNAT/DNAT 时强制检查 `skb_ensure_writable(skb, hdroff + 8)`。若 Keepalive 应答仅 4 字节（IP 总长 24 字节），经过任何 Linux `iptables`/`nftables` NAT 网关时会被内核静默丢弃。填充至 8 字节后既符合标准 GRE `PT=0x0000` 解析规范，也能 100% 穿透各类 NAT 网关。

## 3. 云主机 1:1 NAT 场景适配

当 EasyGRE 部署在公有云 VPC 内网网卡（例如 `eth0 = 10.0.0.5`，对外绑定弹性公网 EIP = `198.51.100.10`）之后时：

- **保持 `GRE_LOCAL=auto`**：不要将 `GRE_LOCAL` 填为弹性公网 EIP，否则本地内核无此网卡地址会报 `EADDRNOTAVAIL`。
- **自动学习公网映射 IP**：若未指定 `--public-ip`，EasyGRE 收到对端发来的 GRE-in-GRE Keepalive 请求时，会校验内层 IPv4 头的 `src` 地址（即对端配置中的本端公网地址 `198.51.100.10`）为合法可路由单播地址，并在**连续两次收到相同地址**确认后将其保存为 `learned_public_ip`、立刻触发一轮探测，既防止单包伪造污染，又能在不手动传入公网 IP 的情况下完成穿越 1:1 NAT 的双向握手。
- 若预先确定公网 EIP，亦可显式传入 `--public-ip 198.51.100.10`，首帧即可完成握手。

## 4. 典型配置示例

### 场景 A：内层 IPv4 + IPv6 双栈互联

```bash
# 节点 A（公网 198.51.100.10）
easygre --name gre-dual \
  --remote 203.0.113.1 \
  --addr 172.16.1.2/30,fd00:1::2/64 \
  --route 10.1.101.0/24,fd00:101::/64
```

### 场景 B：全局默认路由（`0.0.0.0/0`）走 GRE 隧道

当配置 `--route 0.0.0.0/0`（或 `::/0`）时，EasyGRE 会自动将其拆分为 `0.0.0.0/1` 与 `128.0.0.0/1`（IPv6 为 `::/1` 与 `8000::/1`）两条更具体的路由挂在 TUN 接口上，**从不覆盖宿主机原有的默认路由**；同时预先通过 Netlink 插入 `remote_ip/32 via <orig_gw> dev <orig_dev>`（`proto 198`）防环回旁路路由，并在进程退出、异常重启或 DDNS 对端 IP 更新时无损切换与回收。

### 场景 C：与 Linux 原生内核 `ip_gre` 对端互联

若对端为普通 Linux 服务器使用内核 `ip_gre`：

```bash
# 对端 Linux 主机（公网 203.0.113.1）
ip tunnel add gre1 mode gre remote 198.51.100.10 local 203.0.113.1 ttl 255
ip link set gre1 mtu 1476 up
ip addr add 172.16.1.1/30 dev gre1
ip route add 10.2.202.0/24 dev gre1
```

注意：即使 Linux 原生 `ip_gre` 默认不主动发起 Keepalive，只要对端 `gre` 接口已配置三层地址，EasyGRE 的自适应多层 Keepalive 也会自动切换至 `in-tunnel-icmp-echo`、`in-tunnel-ttl1` 或 `udp-in-gre` 完成双向死链检测，因此可直接保持默认的 `GRE_KEEPALIVE=10s,10`，无需手动关闭保活。仅当对端隧道完全无三层地址或防火墙同时阻断隧道内 ICMP 与外层 UDP 回弹时才需设置 `--keepalive off`。

### 场景 D：纯用户态内置 NAT 与端口映射（零 `iptables`/`nftables` 依赖）

EasyGRE 在进程收发路径内直接实现了纯用户态 NAT44/NAT66 与端口转发引擎，适用于 `FROM scratch` 极简容器、禁用 `nf_tables` 的裁剪内核或不希望污染宿主机防火墙规则的场景：

- **隧道出向伪装（`--nat out` / `GRE_NAT=out`）**：将本机或下挂内网子网进入该 GRE 隧道的 IPv4/IPv6 流量（TCP/UDP/ICMP 及关联 ICMP Error 引用头）源地址伪装为本端 `--addr` 隧道地址，对端无需配置回程静态路由。仅对主动发起的 `SYN` 新建 TCP 映射，不影响对端主动访问本端或内网服务的回包。
- **出口落地伪装（`--nat exit` / `GRE_NAT=exit`）**：当对端通过 GRE 隧道将公网流量（如 `0.0.0.0/0` 或 `::/0`）路由至本节点时，自动开启 `ip_forward`，并将非本机目的地址的 TCP（通过每实例隔离的 `198.19.<slot>.<idx>/30` 与 `fd45:4752:4500::/48` 用户态门户桥接内核协议栈，完整保留 TSO/GRO 与拥塞控制）、UDP 与 ICMPv4/v6 Echo 流量从宿主机物理网卡伪装出网。
- **双向模式（`--nat both`）**：同时启用 `out` 与 `exit`。
- **宿主机端口映射（`--dnat` / `GRE_DNAT`）**：将宿主机指定 TCP/UDP 端口转发至隧道对端或远端内网地址（命令行含 `->` 时请加引号，亦可使用等价冒号语法 `tcp/8080:172.16.1.2:80`），例如：
  - `--dnat "tcp/8080->172.16.1.2:80"`（仅转发 TCP）
  - `--dnat "udp/5353->172.16.1.2:53"`（仅转发 UDP）
  - `--dnat "both/0.0.0.0:10080->172.16.1.2:8080"`（同时转发 TCP 与 UDP，默认省略协议前缀时仅转发 TCP）

## 5. 常见故障排查

| 现象 | 可能原因与定位方法 | 解决方案 |
| --- | --- | --- |
| 隧道长期处于 `probing`（`carrier=0`） | 防火墙/安全组拦截了 IP 协议 47（GRE），或对端未配置 GRE Keepalive 响应 | 放行双方公网之间的协议 47；用 `tcpdump -ni any proto 47` 检查双向报文；若对端不支持 Keepalive 请配 `--keepalive off` |
| 启动告警 `[warn] kernel module ip_gre/gre is loaded` | 宿主机加载了 `ip_gre` 模块时，内核 `gre_rcv` 会对未匹配内核隧道的每个入站 GRE 包执行 `icmp_route_lookup` 回送 ICMP Port Unreachable，额外损耗约 20% 内核 CPU | 若无内核 GRE 隧道需求建议执行 `modprobe -r ip_gre gre` 卸载，或在防火墙屏蔽出站 ICMP port-unreachable |
| 本机互通但内网子网无法转发，日志提示 `ip_forward is 0` | 宿主机未开启三层包转发 | 在宿主机执行 `sysctl -w net.ipv4.ip_forward=1`（IPv6 需开启 `net.ipv6.conf.all.forwarding=1`） |
| 小包 ICMP 可通但 HTTPS/SSH 传输卡死 | 路径 MTU 低于默认值导致 TCP 大包被丢弃 | 保持 `--clamp-tcp-mss=true`；若底层网络存在 PPPoE 或多层封装，可调小 `--mtu`（如 `1400`） |
| 日志告警 `outer packet exceeded path MTU with dont-fragment=inherit` | 启用了 `--dont-fragment inherit`，且内层携带 `DF=1` 的大包超出外层路径 PMTU | 保持默认 `--dont-fragment no`（允许外层分片）或调小隧道 `--mtu` |
