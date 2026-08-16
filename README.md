# dsh-auth-tailscale

为
[dsh-client-connection-authz](https://github.com/sperictao/dsh-client-connection-authz)
提供 `connectionRequestAuthorizer` 的 Tailscale Serve 认证插件。

它使用 Serve 注入并防伪处理的 `Tailscale-User-Login`、
`Tailscale-User-Name` 和 `Tailscale-App-Capabilities`，实现精确用户 allowlist、
普通使用 capability 和独立的管理 capability。缺 identity、非法 RFC 2047、非法
capability JSON 或权限不足都会 fail closed。

## 安装

```bash
gh auth setup-git
dsh plugin --profile web add \
  git+https://github.com/sperictao/dsh-client-connection-authz.git \
  git+https://github.com/sperictao/dsh-auth-tailscale.git
```

两个仓库目前是 private；上面的已验证路径使用当前 `gh` 登录为 Git 配置 HTTPS
凭据。也可以改用已配置公钥的 SSH URL。

## 配置

bundle patch 从环境变量读取策略：

| 变量 | 是否必需 | 含义 |
| --- | --- | --- |
| `DSH_TAILSCALE_ALLOWED_LOGINS` | 是 | 逗号分隔、大小写敏感的 Tailscale login allowlist |
| `DSH_TAILSCALE_USE_CAPABILITY` | 否 | 普通远程 API/WS 必须具备的 App Capability |
| `DSH_TAILSCALE_ADMIN_CAPABILITY` | 否 | 远程访问 `loopback` 特权接口必须具备；不配置时远程特权调用恒为 403 |

推荐同时使用 allowlist 和 capabilities：前者限制具体身份，后者把普通使用与管理权限
放进 tailnet policy。

```bash
export DSH_TAILSCALE_ALLOWED_LOGINS='alice@example.com,bob@example.com'
export DSH_TAILSCALE_USE_CAPABILITY='example.com/cap/dsh'
export DSH_TAILSCALE_ADMIN_CAPABILITY='example.com/cap/dsh-admin'
```

未设置或解析为空的 allowlist 会让整个 dsh plugin tree 启动失败，不会退回匿名访问。

## 推荐部署

让 dsh 只监听回环地址，并把 Serve DNS 名加入现有 Host fence：

```bash
dsh --profile web \
  --host 127.0.0.1 \
  --port 3080 \
  --trusted-host your-node.your-tailnet.ts.net
```

再由 Tailscale Serve 终止 HTTPS、注入身份并转发所需 capabilities：

```bash
tailscale serve --bg \
  --accept-app-caps=example.com/cap/dsh,example.com/cap/dsh-admin \
  3080
```

Tailscale 官方说明 Serve 会删除客户端伪造的同名身份/capability headers；但这些头
只有在后端无法被绕过 Serve 直连时才可信。因此 dsh 必须绑定 `127.0.0.1`，不要绑定
`0.0.0.0`，也不要用公开的 Funnel 代替私有 Serve。参见
[Serve identity headers](https://tailscale.com/docs/features/tailscale-serve)、
[Serve App Capability 示例](https://tailscale.com/docs/reference/examples/serve#forward-app-capabilities-to-a-local-service)
和
[App Capability grants](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities)。

App Capability 需要 Tailscale `1.92+`。自定义 capability 名应使用你控制的域名并遵循
`{domain}/{path}` 格式。

一个最小 tailnet grants 结构如下；管理员同时获得普通与管理 capability：

```json
{
  "grants": [
    {
      "src": ["group:dsh-users"],
      "dst": ["tag:dsh-host"],
      "app": {
        "example.com/cap/dsh": [{}]
      }
    },
    {
      "src": ["group:dsh-admins"],
      "dst": ["tag:dsh-host"],
      "app": {
        "example.com/cap/dsh": [{}],
        "example.com/cap/dsh-admin": [{}]
      }
    }
  ]
}
```

## 边界

- Tailscale identity headers 不会为 tagged devices 填充；本插件要求
  `Tailscale-User-Login`，所以 tagged-device-only 调用会被拒绝。
- login 精确匹配，不自动转小写。
- 非 ASCII identity/capability header 只接受 Tailscale 文档规定的 UTF-8 RFC 2047
  Q 编码；格式异常不回退原文。
- capability 顶层必须是 object，每个值必须是非空 object 数组；危险原型键会被拒绝。
- 同机其它进程仍可能伪造 localhost 请求头；这是本机进程信任边界，不是 Tailscale
  能解决的远程边界。

## 开发

先确保当前 GitHub 凭据有权读取私有 connection 仓库，再运行：

```bash
gh auth setup-git
pnpm install
pnpm check
```

开发依赖固定到 connection 的完整 commit SHA，避免认证包随对方 `main` 分支静默漂移。
