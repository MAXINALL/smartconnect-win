# 联想超级互联（联想互联 / Lenovo Smart Connect）第三方轻量 Windows 客户端

> **声明**：本项目为**非官方（Unofficial）**第三方开源客户端，旨在为联想平板（如联想小新平板 Pro GT 等）与 Motorola 设备提供轻量、低内存占用、无后台冗余服务的 **Lenovo Smart Connect（超级互联 / Ready For）** Windows 桌面端互联体验。“联想”、“超级互联”、“Lenovo Smart Connect”、“Ready For”等商标归联想集团及其关联公司所有，本项目中提及上述名称仅用于说明兼容性（指示性合理使用）。

---

## 核心特性

- **100% 纯 Rust 原生单文件架构**：基于 `tokio` + `rustls` + `wry` (WebView2) + `tray-icon` 构建，前端静态资源编译期直接内嵌（`include_str!`），无 Electron/Node.js 运行时开销。
- **蓝牙 BLE `0x5246` + 局域网 mDNS 自动无感重连**：
  - 首次扫码配对后自动持久化设备配对密钥（`paired.json`）。
  - 后续启动或断开时，自动通过 Windows 原生 BLE GATT（服务 UUID `0x5246`，特征值 `0x0722`）及 `_readyformdns._tcp.local` 发送 AES-256-GCM 加密唤醒邀请，平板端无需亮屏或手动扫码即可在数秒内自动回连。
- **O(1) 内存流式大文件与多文件直传（FEX 协议）**：
  - 采用 ZIP Streaming Store（`0x0808` Data Descriptor 流式标志）直接从本地磁盘按 `64 KB` 分块流式推送至 TLS 通道，动态计算 CRC32。
  - 发送数十 GB 大文件仅占用 `64 KB` 内存，零前置打包等待、零临时文件拷贝。
  - 实时同步发送百分比进度，支持平板端取消/中断状态即时反馈。
  - 支持文件资源管理器**右键“发送到”**（单文件/多选文件）、窗口拖拽直传及原生多文件选择器。
- **双向剪贴板同步与原子便签**：
  - 后台静默同步电脑与平板复制的文本，同时提供随身剪贴板便签卡片，支持快捷键 `Ctrl+Enter` 一键推送文本。
- **平板无线存储浏览（NFSv3 协议）**：
  - 内置纯 Rust 用户态 NFSv3 客户端（支持自签名证书指纹校验），免挂载直接浏览平板 `/sdcard`、相册、下载、截图目录并一键保存文件至电脑。
- **竖屏原子工作台 UI**：
  - 采用聚合圆角卡片、零边框线条、卡片内部零嵌套背景盒的极简设计，支持关闭最小化至系统托盘并自动释放 WebView2 内存。

---

## 快速编译与运行

### 环境要求
- Windows 10 / 11（内置 Microsoft Edge WebView2 Runtime）
- Rust 1.85+（2024 Edition）

### 编译发布版
```powershell
cargo build --release
```
编译产物位于 `target/release/smartconnect.exe`，直接双击即可启动图形界面，或通过命令行参数直接发送文件：
```powershell
# 直接唤醒或发送单个/多个文件到已配对平板
smartconnect.exe "D:\path\to\file1.zip" "D:\path\to\file2.pdf"
```

---

## 目录结构

```text
smartconnect-win/
├── src/
│   ├── main.rs        # 程序入口、单实例唤醒、命令行与右键发送处理
│   ├── discovery.rs   # BLE 0x5246 广播/GATT 唤醒与 mDNS 自动发现重连
│   ├── server.rs      # TLS 控制通道、管理 API 与内嵌静态资源服务
│   ├── fex_stream.rs  # O(1) 内存 64KB 分块 ZIP 流式大文件/多文件直传引擎
│   ├── nfs.rs         # 平板无线存储 NFSv3 (TLS 指纹绑定) 浏览与下载
│   ├── clipboard.rs   # 双向剪贴板监听与同步
│   ├── gui.rs         # 原生窗口、系统托盘与图标生成
│   ├── identity.rs    # RSA 证书生成与设备身份标识
│   ├── invite.rs      # 扫码配对二维码生成
│   ├── pairing.rs     # 配对密钥持久化管理
│   ├── proto.rs       # Smart Connect 控制帧协议定义
│   └── settings.rs    # 本地配置与系统右键菜单注册
├── fex/               # FEX 协议客户端接收与基础帧解析库
└── ui/                # 竖屏原子工作台前端界面（编译时自动内嵌至二进制）
```

---

## 参考与致谢（References & Acknowledgements）

本项目的协议逆向对接与实现参考了以下优秀的开源项目，特此致谢：

1. **[`rudrahnpatel/smartconnect-linux`](https://github.com/rudrahnpatel/smartconnect-linux)**
   - 提供了 Lenovo Smart Connect / Motorola Ready For 协议在 Linux 下的详尽逆向文档与 Rust 参考实现（包括 TLS 握手、Service 0/2/9/25/168 报文格式、mDNS 密文帧格式以及 `fex` 协议基础库）。本项目在此基础上针对 Windows 平台实现了原生 WinRT 蓝牙 GATT 自动解绑/唤醒、64 KB 流式大文件 FEX 发送器及原生桌面 GUI。
2. **[`HoratioSlob/cattysend`](https://github.com/HoratioSlob/cattysend) & `mtapy`**
   - 跨设备无线快传与互传工具链的设计思路参考。

---

## 开源许可

本项目基于 [MIT License](LICENSE) 开源。
