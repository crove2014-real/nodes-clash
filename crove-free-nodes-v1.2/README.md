# Crove Free Nodes v1.2 — Pure Pages

Cloudflare Pages 负责发布静态订阅，GitHub Actions 负责定时抓取、解析、去重和 TCP 连通性筛选。

## 1. 生成链路

```text
公开订阅源
   ↓
下载（多源）
   ↓
识别 Clash YAML / Base64 / URI
   ↓
解析 SS / VMess / VLESS / Trojan / Hysteria / Hysteria2 / TUIC / SOCKS5 / HTTP
   ↓
去重
   ↓
TCP connect 筛选
   ↓
生成 Clash/Mihomo + Shadowrocket URI + Base64
```

## 2. v1.2 主要修复

- 多源 fallback，而不是只依赖 3 个来源。
- 支持从普通文本/README 中提取 URI。
- Base64 feed 自动解码。
- Clash `proxies` 自动识别。
- 修复 VMess → URI 输出。
- VLESS WS 的 path/Host 尽量保留。
- 增加 Hysteria/Hysteria2/TUIC/SOCKS5/HTTP 基础解析。
- 增加 `debug.json`，显示每个源的抓取、解析和筛选数量。
- **如果本轮 0 个节点，不覆盖上一轮成功的订阅文件。**
- Actions 超时与并发保护。
- 不把 TCP 成功误称为“代理业务完全可用”。

## 3. Pages

Framework preset: `None`

Build command: 留空

Build output directory: `/`

无需 Functions / KV / Worker。

发布后：

- `/` 首页
- `/clash.yaml` Clash / Mihomo
- `/shadowrocket.txt` Shadowrocket 原始 URI
- `/base64.txt` Base64 订阅
- `/status.json` 状态
- `/debug.json` 抓取诊断

## 4. GitHub Actions

默认每 6 小时执行一次；也可在 Actions → Update nodes → Run workflow 手动执行。

仓库需要允许 Actions 写回 `contents`，workflow 已声明：

```yaml
permissions:
  contents: write
```

## 5. 关于 0 节点

如果所有源都抓取失败，或者所有候选节点 TCP 测试失败，脚本会返回失败状态，并保留上一轮有效订阅，避免 Pages 被空文件覆盖。

## 6. 安全

节点来自公开互联网，服务器端不受本项目控制。TCP connect 只能证明目标地址和端口可建立 TCP 连接，不能证明 TLS、协议握手、转发或长期可用。

不要使用公开免费节点处理银行、支付、密码、私密文件等敏感流量。
