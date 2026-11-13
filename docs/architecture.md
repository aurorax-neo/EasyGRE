# 架构设计与实现细节

EasyGRE 的核心设计目标是在**零第三方 Crate 依赖**与**零外部命令依赖**的约束下，提供完整兼容标准三层 GRE 与双向 Keepalive 协议的用户态转发引擎及极简静态容器交付物。

## 1. 模块布局

| 模块 | 职责 |
| --- | --- |
| [main.rs](../src/main.rs) | CLI 子命令路由（`run`、`status`、`healthcheck`、`version`、`help`）与退出码映射 |
| [config.rs](../src/config.rs) | 命令行与环境变量解析（单隧道、多隧道 `--tunnel`/`GRE_TUNNELS`/`GRE_<N>_*`、时间格式与布尔参数兼容校验） |
| [engine.rs](../src/engine.rs) | 控制面主循环、专职 `gre-rx` 收包线程、每队列 `tx-<name>-q<i>` 并行转发线程、ARP 邻居 MAC 缓存与防环回路由管理 |
| [gre.rs](../src/gre.rs) | RFC 2784/2890 GRE 头部编解码、可选 `C=1` Checksum 验证、GRE-in-GRE Keepalive 探测与应答报文构造及 NAT 公网 IP 提取 |
| [packet.rs](../src/packet.rs) | 内层 IPv4/IPv6 首部识别、4 路原生字节序无 `bswap` 快速校验和、TCP MSS 钳制（RFC 1624）、零拷贝 TCP TSO / UDP GSO (`GSO_UDP_L4`) 切片器、16 槽位双协议 RX GRO 合并器与对称 5 元组队列哈希 |
| [keepalive.rs](../src/keepalive.rs) | 双向 Keepalive 载波状态机（`AlwaysUp` / `Initial` / `Up` / `Down`）与精确 `awaiting_reply` 计数 |
| [status.rs](../src/status.rs) | 基于 `O_CREAT \| O_EXCL \| O_NOFOLLOW`（`0600`）随机临时文件的防符号链接状态写入与线程心跳校验（默认 `/run/easygre/status`） |
| [sys/linux.rs](../src/sys/linux.rs) | Linux 内联 FFI 与结构体布局（`ioctl`、`AF_NETLINK`、`io_uring`、`SOCK_RAW (IPPROTO_GRE/IPPROTO_RAW)`、`AF_PACKET PACKET_TX_RING`、`IFF_MULTI_QUEUE`、`eventfd`、cBPF、`epoll`、信号钩子） |
| [sys/stub.rs](../src/sys/stub.rs) | 非 Linux 平台的编译桩，使 macOS 等本地环境可无障碍执行 `cargo test` |

## 2. 收发数据路径与多隧道隔离

```text
  [RX Path]
  Outer IP Proto 47 -> Single Global RX Socket (recvmmsg x128, odd-64B stride) -> parse_outer_ipv4()
                                                                  |
                                             match (outer_src, outer_dst)
                                               /                      \
                    [Keepalive Request/Reply] <                        > [IPv4 / IPv6 Data]
                                                                              |
                                                                16-slot RxGroMerger (64KB GSO)
                                                                              |
                                                       write_queue_nonblock(sym_5tuple_hash)

  [TX Path (Per-Queue Parallel Workers: tx-<name>-q0 .. qN)]
  TUN Queue fd[i] --(io_uring READV RWF_NOWAIT x64 / zero-copy readv)--> PacketTxRing Frame[28..]
                                             |
                +----------------------------+----------------------------+
                | (GSO_NONE & MTU ok: 0-copy in-place commit)             | (TSO/USO or Fallback)
                v                                                         v
     AF_PACKET PACKET_TX_RING (2048 frames, kick@256)        segment_tso_into / IPPROTO_RAW sendmmsg
     + PACKET_QDISC_BYPASS + Ethernet/IPv4/GRE               (+ lazy IPPROTO_GRE frag_fd if >PMTU)
```

1. **彻底消除 `raw_v4_input` 多套接字 `skb_clone` 风暴**：Linux 内核 `raw_v4_input()` 会在执行 cBPF 过滤器之前，对哈希桶 `raw_v4_hashinfo[47]` 中的每一个 `SOCK_RAW(IPPROTO_GRE)` 套接字执行一次 `skb_clone` 与 `kfree_skb`。EasyGRE 将所有出站与保活套接字改为 `SOCK_RAW(IPPROTO_RAW = 255)`（落入永不被入站线速包匹配的 `ht[255]` 桶，由用户态直接写入 20 字节外层 IPv4 首部；仅当 `dont-fragment=no` 且报文超路径 MTU 需内核自动分片时按需惰性打开分片句柄），使整个命名空间内 `IPPROTO_GRE(47)` 套接字严格收敛为 **唯一的全局接收套接字**，将多队列下的内核克隆开销降低 85% 以上。
2. **抑制内核 ICMP Protocol Unreachable**：当宿主机未加载 `ip_gre` 模块时，Linux `ip_protocol_deliver_rcu` 发现 `raw_local_deliver` 已成功投递给用户态 RX Raw Socket，即直接 `consume_skb`，不会向对端返回 `ICMP_PROT_UNREACH`。
3. **`io_uring` 批量零拷贝直读与 2048 槽 `PACKET_TX_RING` 快速路径**：在全部 `IFF_MULTI_QUEUE` 队列句柄完成挂载并统一配置 `TUNSETOFFLOAD`（TCP TSO + Linux 6.2+ UDP USO）后再拉起接口并设置 `txqlen=16384`，确保所有队列均匀挂载宿主默认 `fq_pie`/`fq_codel` 队列规则。出站线程通过内联 `io_uring`（`IORING_OP_READV + RWF_NOWAIT`）单次系统调用最多将 64 个 `TUN` 数据包直接散列读入 `PACKET_TX_RING`（2048 帧 / 4 MB `TPACKET_V2` mmap 环，开启 `PACKET_QDISC_BYPASS`）的帧偏移 `28` 处：普通 MTU 报文原地补齐以太网/外层 IPv4/GRE 首部并提交（**用户态载荷零拷贝**，每 256 帧才触发一次 `sendto` 唤醒内核发送，将系统调用降低约 98%）；超大 64 KB TSO/USO 报文自动溢出至副 `iovec` 并经 `segment_tso_into` 切片入环；若容器 seccomp 禁用 `io_uring` 则自动无感降级为单包零拷贝 `readv`。
4. **多核队列、L2 紧凑缓存 RX 批收与 16 槽位双协议 GRO 合并**：默认 `queues=auto` 自动按 `clamp(CPU, 1, 8)` 扩展多队列以降低多流哈希生日碰撞概率；专职 `gre-rx` 线程开启 `SO_RCVBUFFORCE` 32 MB 缓冲，采用 128 槽位、奇数个 64B 缓存行步长（标准 MTU 下为 `2112B`，总工作集仅 270 KB 常驻 L2 缓存，彻底避免 64 KB 步长的缓存组别名冲突）的 `RxBatchBuffer` 执行 `recvmmsg` 连续批收，经 16 槽位 `RxGroMerger` 将同流 TCP 与 UDP 报文合并为 64 KB GSO 大包后按对称 5 元组哈希注入 `tun` 队列。
5. **实测架构取舍说明**：
   - **不启用 `AF_PACKET` RX 环**：监听 `ETH_P_IP` 会向内核 `ptype_base` 注册旁路钩子，使所有出站包在 `dev_queue_xmit_nit()` 中额外触发流解析与 cBPF 检查，反而使多流吞吐下降 20%~35%、CPU 倍增。
   - **不在同一原始套接字上做多线程乱序抢包**：多线程并发 `recvmmsg` 虽能分摊收包，但会导致同流 TCP 分片跨线程乱序写入 `tun`，触发大量 DupACK 与拥塞窗口回退；保留单线程高吞吐紧凑缓存 `gre-rx` 可同时兼顾 `Retr=0` 的 TCP 零重传与 2.5 Gbps 级无损 UDP 收包。

## 3. TCP MSS 钳制与校验和准确性

在 `src/packet.rs` 中：

- **IPv4**：检查 `IHL`、非分片或首片（`frag_off & 0x1fff == 0`）且 `proto == 6`，目标最大 MSS 为 `tunnel_mtu - 40`。
- **IPv6**：顺序跳过常见无状态扩展头（`0` Hop-by-Hop、`43` Routing、`60` Destination Options、首片 `44` Fragment）定位 TCP 段，目标最大 MSS 为 `tunnel_mtu - 60`。
- **奇偶对齐的 RFC 1624 增量修正**：当 TCP Options 在 MSS 前包含单字节 `NOP (1)` 导致 MSS 值位于 TCP 段奇偏移时，直接按 2 字节对齐边界（`val_offset & !1`）读取修改前后的完整 16-bit 字对，逐字应用 RFC 1624 增量更新 `tcp[16..18]`，保证与全量伪首部校验和逐比特一致。

## 4. Linux ABI 与 Netlink 自动化

- **跨架构结构体对齐**：`src/sys/linux.rs` 对 `x86_64`（`#[repr(C, packed)]`，12 字节）与非 `x86_64` 架构（如 `aarch64`，`#[repr(C)]`，16 字节）分别定义 `EpollEvent`，并在单测 `test_linux_abi_struct_sizes` 中校验全部 FFI 结构体尺寸。
- **非破坏式路由所有权与实时邻居联动**：
  - 所有由守护进程下发的路由均标记专用 `rtm_protocol = 198` 并采用 `NLM_F_CREATE | NLM_F_EXCL`，拒绝静默覆盖宿主机原有路由；`0.0.0.0/0` 与 `::/0` 自动拆分为 `/1` 路由对，确保宿主机原默认路由始终保留。
  - 每个守护进程通过网络命名空间级抽象 `AF_UNIX` 套接字锁（`\0easygre/slot/v1/<slot>`）获取唯一实例槽位与专属路由 `metric`（`19800 + slot`），同进程多隧道间对 `/32` 旁路路由做引用计数；异常 `SIGKILL` 后新启动实例仅回收已释放槽位的残留旁路路由，绝不误删同一宿主机网络下其他运行容器的路由；若宿主机已存在管理员配置的 `remote_ip/32` 路由则原样保留。
  - DDNS 后台线程解析到新对端 IP 后，通过 `NLM_F_DUMP` 排除所有本进程 TUN 接口索引定位真实物理出接口，先装新 `/32` 旁路路由并热切换 `PacketTxRing` 后再删旧 `/32`，彻底杜绝回环。
  - 控制线程订阅 `AF_NETLINK` `RTMGRP_NEIGH` 组播事件，网关 ARP/VRRP MAC 变化时毫秒级刷新或降级回退。
- **静态编译镜像**：[Dockerfile](../Dockerfile) 基于 `rust:1-alpine` 开启 `+crt-static` 构建静态链接二进制，最终镜像基于 `FROM scratch` 仅保留 `/easygre`、`/run/easygre`(0700)、`/tmp`(1777) 与 `/etc` 挂载目录。
