# NodeSeek OAuth2 授权服务

[![](https://img.shields.io/github/license/iidamie/ns_oauth2.svg)](LICENSE)
![](https://img.shields.io/github/stars/iidamie/ns_oauth2.svg)
![](https://img.shields.io/github/forks/iidamie/ns_oauth2.svg)

支持使用 NodeSeek 账号快速登录授权第三方应用，实现标准 OAuth2 接口，支持应用开发者创建客户端并接入。

## 目录

* [免责声明](#免责声明)
* [项目介绍](#项目介绍)
* [功能特点](#功能特点)
* [接入准备](#接入准备)
  * [配置说明](#配置说明)
* [Docker 部署](#docker-部署)
* [Docker-compose 部署](#docker-compose-部署)
* [原生部署](#原生部署)
* [接口列表](#接口列表)
  * [授权端点](#授权端点)
  * [令牌端点](#令牌端点)
  * [用户信息端点](#用户信息端点)
* [注意事项](#注意事项)
  * [Nginx 反代优化](#nginx-反代优化)
  * [应用开发流程](#应用开发流程)
* [项目技术栈](#项目技术栈)
* [鸣谢](#鸣谢)

## 免责声明

**本项目使用的 API 是基于 NodeSeek 网站的逆向工程，不代表 NodeSeek 官方。**

**本组织和个人不接受任何资金捐助和交易，此项目是纯粹研究交流学习性质！**

## 项目介绍

NodeSeek OAuth2 授权服务是一个基于 FastAPI 开发的标准 OAuth2 授权服务，支持使用 NodeSeek 账号授权登录第三方应用。它提供了完整的 OAuth2 授权流程，包括授权码模式和隐式授权模式。此外，它还支持用户（等级≥配置值）创建和管理自己的 OAuth2 客户端应用。
示例网站: [https://ns.idamie.com/](https://ns.idamie.com/)

## 功能特点

* 符合标准 OAuth2 协议规范
* 使用 NodeSeek 账号验证身份（通过发送验证码）
* 支持授权码模式和隐式授权模式
* 支持用户创建和管理 OAuth2 客户端应用
* 简洁美观的用户界面
* 完善的客户端管理功能
* 安全的会话管理和令牌处理

## 接入准备

需要准备一个有效的 NodeSeek 账号，并获取以下信息：

* 有效的 NodeSeek 会话 Cookie
* NodeSeek 管理员 ID (用于接收验证码消息)

### 配置说明

项目使用环境变量进行配置：

* `DB_PATH` - SQLite 数据库路径

## Docker 部署

请准备一台具有公网 IP 的服务器并开放必要的端口。

普通部署

```shell
docker run -d -p 5001:5001 \
  -e DB_PATH="/app/data/oauth_db.sqlite" \
  --name ns_oauth2 ghcr.io/iidamie/ns_oauth2:latest
```

持久化部署

```shell
docker run -d -p 8000:8000 \
  -v /path/to/data:/app/data \
  -e DB_PATH="/app/data/oauth_db.sqlite" \
  --name ns_oauth2 ghcr.io/iidamie/ns_oauth2:latest
```

部署成功后访问网站即可开始进行初始化

查看服务实时日志:

```shell
docker logs -f ns_oauth2
```

重启服务:

```shell
docker restart ns_oauth2
```

停止服务:

```shell
docker stop ns_oauth2
```

## Docker-compose 部署

创建 `docker-compose.yml` 文件:

普通部署

```yaml
version: "3"
services:
  ns_oauth2:
    container_name: ns_oauth2
    image: ghcr.io/iidamie/ns_oauth2:latest
    restart: always
    ports:
      - "5001:5001"
    environment:
      - DB_PATH=/app/data/oauth_db.sqlite
```

持久化部署

```yaml
version: "3"
services:
  ns_oauth2:
    container_name: ns_oauth2
    image: ghcr.io/iidamie/ns_oauth2:latest
    restart: always
    ports:
      - "5001:5001"
    volumes:
      - ./data:/app/data
    environment:
      - DB_PATH=/app/data/oauth_db.sqlite
```

启动服务:

```shell
docker-compose up -d
```

部署成功后访问网站即可开始进行初始化

## 原生部署

请先安装好 Python 环境并且配置好环境变量，确认 python 命令可用。

安装依赖:

```shell
git clone https://github.com/iidamie/ns_oauth2.git
cd ns_oauth2
pip install -r requirements.txt
```

配置环境变量:

```shell
export DB_PATH="./data/oauth_db.sqlite"
```

启动服务:

```shell
uvicorn main:app --host 0.0.0.0 --port 5001
```

使用 nohup 启动:

```shell
nohup uvicorn main:app --host 0.0.0.0 --port 5001 > uvicorn.log 2>&1 &
```

部署成功后访问网站即可开始进行初始化

## 接口列表

本项目实现了标准 OAuth2 规范的主要接口：

### 授权端点

**GET /oauth/authorize**

用于获取用户的授权。

请求参数:
* `client_id` - 客户端标识
* `redirect_uri` - 重定向URI
* `response_type` - 响应类型 (`code` 或 `token`)
* `scope` - 请求的权限范围 (`basic` 或 `profile`)
* `state` - 防CSRF攻击的随机字符串

授权码模式响应:
```
https://example.com/callback?code=auth_XXXXXXXXXXXX&state=XXXX
```

隐式授权模式响应:
```
https://example.com/callback#access_token=access_XXXXXXXXXXXX&token_type=Bearer&expires_in=3600&state=XXXX
```

### 令牌端点

**POST /oauth/token**

用于客户端获取访问令牌。

请求参数 (表单格式):
* `grant_type` - 授权类型 (`authorization_code` 或 `refresh_token`)
* `code` - 授权码 (当 grant_type 为 authorization_code)
* `refresh_token` - 刷新令牌 (当 grant_type 为 refresh_token)
* `redirect_uri` - 重定向URI
* `client_id` - 客户端标识
* `client_secret` - 客户端密钥

响应数据:
```json
{
  "access_token": "access_XXXXXXXXXXXX",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_XXXXXXXXXXXX",
  "scope": "basic"
}
```

### 用户信息端点

**GET /api/user/info**

获取授权用户的信息。

请求头:
```
Authorization: Bearer access_XXXXXXXXXXXX
```

响应数据:
```json
{
  "member_id": 1,
  "member_name": "username",
  "rank": 6
}
```

当 scope 为 `profile` 时:
```json
{
  "member_id": 1,
  "member_name": "username",
  "rank": 6,
  "coin": 6175,
  "bio": "用户简介",
  "created_at": "2023-12-03T10:29:32.000Z"
}
```

### 应用开发流程

1. 在平台创建应用，获取 client_id 和 client_secret
2. 引导用户访问授权端点获取授权
3. 使用授权码换取访问令牌
4. 使用访问令牌请求用户信息

示例代码:

```javascript
// 1. 构建授权URL
const authorizeUrl = "https://your-server.com/oauth/authorize";
const clientId = "your_client_id";
const redirectUri = "https://your-app.com/callback";
const responseType = "code";
const scope = "basic"; // 或 "profile"
const state = "random_string"; // 用于防止CSRF攻击

// 2. 引导用户访问授权页面
const authUrl = `${authorizeUrl}?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=${responseType}&scope=${scope}&state=${state}`;
window.location.href = authUrl;

// 3. 授权成功后，用授权码换取访问令牌
// 在您的回调地址中获取授权码
const code = new URL(window.location.href).searchParams.get("code");

// 服务器端请求访问令牌
const response = await fetch("https://your-server.com/oauth/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: code,
    redirect_uri: redirectUri,
    client_id: clientId,
    client_secret: "your_client_secret"
  })
});

const tokenData = await response.json();
// 使用访问令牌请求用户信息
const userInfoResponse = await fetch("https://your-server.com/api/user/info", {
  headers: { "Authorization": `Bearer ${tokenData.access_token}` }
});
const userInfo = await userInfoResponse.json();
console.log("用户信息:", userInfo);
```

## 项目技术栈

- FastAPI - 现代化、高性能的Python Web框架
- SQLite - 轻量级数据库
- curl-cffi - 网络请求库
- JWT - 用户会话和令牌管理
- Bootstrap 5 - 前端UI框架

---

**请注意**: 本项目仅供学习和研究使用，不代表 NodeSeek 官方。在使用过程中请遵守相关法律法规和 NodeSeek 平台的使用条款。