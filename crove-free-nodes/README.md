# Crove Free Nodes v1.1 — Pure Pages

一个以 Cloudflare Pages 为发布端、GitHub Actions 为更新端的公开节点聚合项目。

## 工作方式

GitHub Actions 每 6 小时抓取 `sources.json` → 解析 Clash/Base64/URI → 去重 → TCP 连通性筛选 → 生成订阅文件 → 提交回仓库。Cloudflare Pages 从仓库直接发布静态文件。

> 连通性测试只进行 TCP connect，不会通过候选代理访问测试网站；因此“通过测试”不等于代理业务流量一定可用。

## Cloudflare Pages

- Framework preset: None
- Build command: 留空
- Build output directory: `/`（仓库根目录）
- 不需要 Functions、KV 或 Worker。

部署后：

- `/` 首页
- `/clash.yaml` Clash/Mihomo
- `/shadowrocket.txt` Shadowrocket 原始 URI
- `/base64.txt` Base64 订阅
- `/status.json` 更新状态

## GitHub Actions

默认每 6 小时运行一次，也可以在 Actions → Update nodes → Run workflow 手动运行。

仓库需要允许 Actions 写回 `contents`；workflow 已声明 `permissions: contents: write`。

## 安全提醒

公开免费节点的服务器端并不受本项目控制。不要把免费节点用于银行、支付、密码管理或其他敏感业务。
