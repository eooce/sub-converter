# sub-converter

## 项目简介

sub-converter 是一个支持多种客户端格式的**订阅链接转换与短链生成服务**，支持 Singbox、Clash、Surge、Xray 等主流代理配置格式。支持多语言界面、在线转换、短链跳转、订阅配置存储等功能，适合自部署和团队共享。

## 温馨提示
- main主分支为cloudflare worker部署使用，server分支为服务器/docker容器等构建所需的源代码
- 如需部署公共服务使用，请使用docker部署或vps部署，cloudflare worker的KV有请求限制

## 主要功能
- 订阅链接格式互转（Singbox/Clash/Surge/Xray）
- 在线生成和管理短链，支持跳转
- 支持多语言切换（中/英/俄/波斯）
- 支持自定义规则、UA、基础配置
- 支持订阅配置存储与解析
- 支持 Docker部署或vps源代码部署

## server分支目录结构简述
```
├── src/                # 核心业务代码
│   ├── kvSqlite.js     # SQLite 持久化 KV 封装
│   ├── ...             # 其它 builder、工具、i18n
├── database/           # SQLite 数据库存储目录（持久化）
├── server.js           # Node.js 启动入口
├── package.json        # 依赖与脚本
├── Dockerfile          # Docker 构建文件
```
- [API 文档（APIDoc.md）](docs/APIDoc.md)


## 源码构建与运行

1. 安装依赖
   ```bash
   npm install
   ```
2. 启动服务（默认 7788 端口）
   ```bash
   npm start
   # 或指定端口
   PORT=8080 npm start
   ```
3. 访问
   - http://localhost:7788

## Docker 构建与运行

1. 直接拉取并运行镜像
   ```bash
   docker run -d \
     -v /your/host/database:/app/database \
     -p 7788:7788 \
     --name sub-converter \
     eooce/sub-converter:latest
   ```
   > 持久化目录 `/your/host/database` 用于保存 SQLite 数据库文件

## Docker Compose 部署示例

新建 `docker-compose.yml`：
```yaml
version: '3'
services:
  sub-converter:
    image: ghcr.io/eooce/sub-converter:latest
    container_name: sub-converter
    ports:
      - "7788:7788"
    volumes:
      - ./database:/app/database
    restart: unless-stopped
```

启动：
```bash
docker-compose up -d
```

## 数据持久化说明
- 所有短链、配置等数据均存储于 `database/sublink_kv.db`（SQLite）
- 挂载 `database` 目录可实现数据持久化，适合 Docker 部署
- 首次运行自动创建 `database` 目录，无需手动操作

## 主要依赖
- Node.js >=14 <=20
- express
- better-sqlite3
- js-yaml

## 环境变量说明

- `PORT`：服务监听端口，默认 7788。可通过 `PORT=8080 npm start` 或 docker-compose 的 environment 配置自定义。

## Cloudflare Workers 网页端一键部署

1. **Fork 本项目main分支到你的 GitHub 账号。**
2. 打开 [Cloudflare Workers 控制台](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create)。
3. 选择 "Connect to Git" → 选择你的 GitHub 账号和 Fork 后的仓库。
4. 选择 `server` 分支（或你需要的分支）。
5. 保持默认构建设置（Node.js 项目会自动识别）。
6. 在 "Environment Variables" 或 "KV Namespaces" 里添加/绑定所需的 KV 命名空间（如 `SUBLINK_KV`）。
7. 点击 "Deploy" 即可一键部署，无需本地命令行操作。

**注意事项：**
- 首次部署需授权 Cloudflare 访问你的 GitHub 仓库。
- KV 命名空间需在 Cloudflare 控制台提前创建并绑定到 Worker。
- 如需自定义域名，可在 Cloudflare 控制台绑定。

---
如有问题或建议，欢迎 issue 或 PR！

<details>
<summary>原项目readme（点击展开）</summary>

<div align="center">
  <h1><b>Sublink Worker</b></h1>
  <h5><i>Best Practice for Serverless Self-Deployed Subscription Conversion Tool</i></h5>
  
  <a href="https://trendshift.io/repositories/12291" target="_blank">
    <img src="https://trendshift.io/api/badge/repositories/12291" alt="7Sageer%2Fsublink-worker | Trendshift" width="250" height="55"/>
  </a>
  
  <!-- <p>
    <a href="https://sublink-worker.sageer.me">https://sublink-worker.sageer.me</a>
  </p> -->
  <br>

  <p>
    <a href="https://dash.cloudflare.com/?to=/:account/workers-and-pages/create">
      <img src="https://deploy.workers.cloudflare.com/button" alt="Deploy to Cloudflare Workers"/>
    </a>
  </p>
  
  <p><a href="/docs/README_CN.md">中文文档</a></p>
</div>

## 🚀 Quick Start

### Quick Deployment
- Fork this project, click the `Deploy to Cloudflare` button above
- Select your repository in the `Import Repository` section (you need to link your GitHub account)
- Change the `Deploy Command` as follows, then select `Save and Deploy`
``` bash
npm run deploy
```

## ✨ Features

### Supported Protocols
- ShadowSocks
- VMess
- VLESS
- Hysteria2
- Trojan
- TUIC

### Core Features
- Support for importing Base64 http/https subscription links and various protocol sharing URLs
- Pure JavaScript + Cloudflare Worker implementation, one-click deployment, ready to use
- Support for fixed/random short link generation (based on KV)
- Light/Dark theme toggle
- Flexible API, supporting script operations
- Support for Chinese, English, and Persian languages

### Client Support
- Sing-Box
- Clash
- Xray/V2Ray

### Web Interface Features
- User-friendly operation interface
- Various predefined rule sets
- Customizable policy groups for geo-site, geo-ip, ip-cidr, and domain-suffix

## 📖 API Documentation

For detailed API documentation, please refer to [APIDoc.md](/docs/APIDoc.md)

### Main Endpoints
- `/singbox` - Generate Sing-Box configuration
- `/clash` - Generate Clash configuration
- `/xray` - Generate Xray configuration
- `/shorten` - Generate short links

## 📝 Recent Updates

### 2025-11-08

- feat(config): Added support for proxy configuration grouped by country, updated related translations

## 🔧 Project Structure

```
.
├── index.js                 # Main server logic, handles request routing
├── BaseConfigBuilder.js     # Build base configuration
├── SingboxConfigBuilder.js  # Build Sing-Box configuration
├── ClashConfigBuilder.js    # Build Clash configuration
├── ProxyParsers.js          # Parse URLs of various proxy protocols
├── utils.js                 # Provide various utility functions
├── htmlBuilder.js           # Generate Web interface
├── style.js                 # Generate CSS for Web interface
├── config.js                # Store configuration information
└── docs/
    ├── APIDoc.md            # API documentation
    ├── UpdateLogs.md        # Update logs
    ├── FAQ.md               # Frequently asked questions
    └── BaseConfig.md        # Basic configuration feature introduction
```

## 🤝 Contribution

Issues and Pull Requests are welcome to improve this project.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This project is for learning and exchange purposes only. Please do not use it for illegal purposes. All consequences resulting from the use of this project are solely the responsibility of the user and are not related to the developer.

## 💰 Sponsorship

<div align="center">
  <h3>Thanks to the following sponsors for their support of this project</h3>
<table border="0">
  <tr>
    <td>
      <a href="https://yxvm.com/" target="_blank" title="YXVM">
        <img src="https://image.779477.xyz/yxvm.png" alt="YXVM" height="60" hspace="20"/>
      </a>
    </td>
    <td>
      <a href="https://github.com/NodeSeekDev/NodeSupport" target="_blank" title="NodeSupport">
        <img src="https://image.779477.xyz/ns.png" alt="NodeSupport" height="60" hspace="20"/>
      </a>
    </td>
  </tr>
</table>
  <p><b>NodeSupport has sponsored this project, thank you for your support!</b></p>
  <p>If you would like to sponsor this project, please contact the developer <a href="https://github.com/7Sageer" style="text-decoration: none;">@7Sageer</a></p>
</div>

## ⭐ Star History

Thanks to everyone who has starred this project! 🌟

<a href="https://star-history.com/#7Sageer/sublink-worker&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=7Sageer/sublink-worker&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=7Sageer/sublink-worker&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=7Sageer/sublink-worker&type=Date" />
 </picture>
</a>

</details>
