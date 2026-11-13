# Changelog

本项目所有重要变更均记录于此文件。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.0] - 2026-11-13

### Features
- 实现零外部依赖（仅 `std` 与内联 Linux FFI）的用户态三层 GRE 隧道守护进程，支持 IPv4/IPv6 内层双栈转发与多隧道并发。
- 实现带 32-bit 随机令牌回显校验的双向 GRE-in-GRE (`PT=0x0000`) Keepalive 状态机、载波联动 (`TUNSETCARRIER`) 与 1:1 NAT 公网 IP 自动学习。
- 支持双向 IPv4/IPv6 TCP `SYN`/`SYN+ACK` MSS 钳制（RFC 1624 增量校验和更新）、`dscp` 继承或固定值、`dont-fragment=inherit` 路径 MTU 反馈（合成 ICMPv4 Frag Needed 与 ICMPv6 Packet Too Big）。
- 支持后台非阻塞 DDNS 域名重解析、ECMP `RTA_MULTIPATH` 物理出接口探测、抽象域套接字租约槽位隔离、进程内 `/32` 旁路路由引用计数，以及 `0.0.0.0/0` 与 `::/0` 自动拆分为 `/1` 路由对保护宿主机默认路由。
- 提供基于 `FROM scratch` 的双模容器构建（本地开发 `Dockerfile` 与多架构发布 `Dockerfile.release`）及内置 `status` / `healthcheck` 子命令。

### Performance
- 实现内联 `io_uring` (`IORING_OP_READV + RWF_NOWAIT`) 批量零拷贝直读入 `AF_PACKET` `PACKET_TX_RING` (`TPACKET_V2`) 共享内存环，受限容器环境自动降级至零拷贝 `readv` 与 `IPPROTO_RAW` `sendmmsg`。
- 支持 `IFF_MULTI_QUEUE` 多队列并发 TX 工作池、`IFF_VNET_HDR` TCP TSO 与 UDP GSO (`TUN_F_USO4 | TUN_F_USO6`) 零拷贝切片，以及 16 槽位 TCP/UDP RX GRO 聚包与奇步长 `recvmmsg` 收包。

### Security & Reliability
- 启用非测试代码编译期门禁 `deny(clippy::unwrap_used, clippy::expect_used)`，消除全部生产路径 `unwrap` / `expect`。
- 状态文件采用 `O_EXCL | O_NOFOLLOW` 与 `0600` 权限原子替换，结合 `CLOCK_MONOTONIC` 时间戳与工作线程单调心跳看门狗防止墙钟跳变误判。
- 内置基于 `std` 的 GRE、IPv4/IPv6、TCP MSS、ICMP 防环、TSO/USO、GRO、Netlink/ARP 及 CLI 配置随机变异测试套件与长稳压测脚本。
