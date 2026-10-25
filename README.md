# 节点转订阅地址

单页工具：贴入节点，选个格式，生成可直接订阅的链接。内容写进你自己的 GitHub 仓库，走 jsDelivr 分发，不经过任何第三方服务器。

## 用法

1. 打开 GitHub Pages 地址（见仓库 Settings → Pages）。
2. 贴入节点文本（每行一条完整节点链接），选订阅格式，填 GitHub 仓库（owner/repo）、分支、文件路径和 Token。
3. 点“发布并生成订阅链接”，得到一条 jsDelivr 订阅链接，粘贴到对应客户端当订阅地址用。
4. 不想发布时点“只在本地转格式，不发布”，只在浏览器里出结果。

## 订阅格式

- 通用链接（明文）/ Base64 订阅：V2RayN / NekoBox / Shadowrocket / v2rayNG / Hiddify
- Clash YAML：Clash / Mihomo / Verge / Stash
- sing-box JSON：sing-box / SFI
- Surge 配置：Surge
- Quantumult X 配置：Quantumult X
- Loon 配置：Loon

## Token 要求

细粒度 Personal Access Token，只给目标仓库的 **Contents 写权限**（read + write）。
Token 只存在浏览器 localStorage（可取消“记住”），不会出现在订阅内容或链接里。

## 说明

- 发布 = 调 GitHub Contents API 写文件（已存在则覆盖，需先读 SHA）。
- 链接本身拿到就能拉，这是订阅链接固有的；和公开粘贴服务的区别是文件在你自己仓库里。
- jsDelivr 有缓存，刚发布后几分钟内可能还是旧内容。
- 结构化格式需要完整节点链接，纯 IP:端口行无协议信息会被跳过并计数提示；
  想转纯 IP 行，先用 CFProbe 的节点模式导出完整链接再贴过来。
- 转换器支持的节点协议：vless / vmess / trojan / ss / socks5 / http / hysteria2 / tuic；
  Surge / Quantumult X 不支持 vless / hysteria2 / tuic（按各软件文档协议范围映射），这类节点会被跳过。

## server/（可选，不用也能跑）

`server/` 是一套自适应转换后端（按客户端 User-Agent 实时返回对应格式），之前部署在 InstaBox 上验证过。
GitHub Pages 版不需要它；只有还想用“一条链接自适应所有软件”时才需要另外部署它。
