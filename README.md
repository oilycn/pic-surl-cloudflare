# pic-surl-cloudflare
cloudflare 图床及短链接一站式 基于 workers，d1，r2

### 预览如下
![预览](https://ju.mk/1758186983904.png)

### 变量如下
![预览](https://ju.mk/1758187178302.png)


#### 1. `ADMIN_PATH`（弃用）
*   **类型**：纯文本
*   **解释**：这很可能是一个自定义的管理员路径或路由前缀。例如，如果您的 Worker 部署在一个网站上，这个变量可能定义了只有管理员才能访问的 URL 路径，如 `/p` 或 `/admin`。这用于区分普通的公共访问和需要特定权限的后台操作。
#### 2. `CLOUDFLARE_ACCOUNT_ID`
*   **类型**：纯文本
*   **解释**：这是您的 **Cloudflare 账户的唯一标识符**。许多 Cloudflare API 调用都需要这个 ID 来指定操作是针对哪个账户执行的。例如，在获取 R2 存储数据、与 Worker KV 存储交互等场景中，都会用到它。
#### 3. `CLOUDFLARE_API_KEY`
*   **类型**：纯文本
*   **解释**：这是您的 **Cloudflare 全局 API Key**。它拥有您整个 Cloudflare 账户的所有权限（包括但不限于 DNS、SSL、防火墙等），功能强大。
    *   **安全性警告**：由于其极高的权限，**将全局 API Key 直接作为环境变量存储并用于 Worker 业务逻辑是高度不安全的做法**。如果这个密钥泄露，攻击者可以完全控制您的 Cloudflare 账户。
    *   **推荐替代方案**：通常，更安全的做法是创建一个**具有最小所需权限的 API 令牌（API Token）**，而不是使用全局 API Key。例如，如果只需要读取 R2 存储使用量，就创建一个只拥有 `Account -> R2 Storage -> Analytics:Read` 权限的 API 令牌，并将其作为 `CLOUDFLARE_API_TOKEN` 或类似的变量名存储。
#### 4. `CLOUDFLARE_EMAIL`
*   **类型**：纯文本
*   **解释**：这是您用来注册 **Cloudflare 账户的邮箱地址**。在某些传统的 Cloudflare API 认证方式中（尤其是在使用全局 API Key 时），除了 API Key，还需要提供账户邮箱进行身份验证。
#### 5. `DOMAIN`
*   **类型**：纯文本
*   **解释**：这可能指的是您的 Worker 正在服务或与之交互的**主域名**。例如，如果您的 Worker 部署在 `ju.mk` 这个域名下，那么这个变量就存储了这个值。它有助于 Worker 在代码中动态构建 URL 或进行域名相关的逻辑判断。
#### 6. `ENABLE_AUTH`
*   **类型**：纯文本 (通常表示布尔值：`"true"` 或 `"false"`)
*   **解释**：这是一个**布尔开关**，用于控制 Worker 中的某些认证逻辑是否启用。例如，如果其值为 `"true"`，Worker 可能会检查请求是否包含有效的用户名和密码；如果为 `"false"`，则可能跳过认证步骤。
#### 7. `PASSWORD`
*   **类型**：纯文本
*   **解释**：这很可能是用于 Worker 内部某个**认证机制的密码**。例如，结合 `USERNAME` 和 `ENABLE_AUTH`，它可能用于实现一个简单的 Basic Auth 或者其他形式的身份验证。
    *   **安全性警告**：虽然作为环境变量存储比硬编码好，但对于生产环境，应考虑使用像 Cloudflare Workers KV 存储、Durable Objects 或其他身份提供商（如 OAuth）来更安全地处理用户凭据。
#### 8. `USERNAME`
*   **类型**：纯文本
*   **解释**：这很可能与 `PASSWORD` 结合使用，作为一个**预设的用户名**，用于 Worker 内部的认证。例如，在实施基本身份验证时，它会与传入请求中的用户名进行比对。

> 路径 》 存储和数据库 〉 D1 sql数据库 》 创建数据库 〉完成后在控制台输入下列代码执行

### 绑定D1和R2
![预览](https://ju.mk/1758187521921.png)


* 创建图床链接表
``` sql
CREATE TABLE media ( url TEXT PRIMARY KEY )
```

* 创建短链接表
``` sql
CREATE TABLE short_urls ( id INTEGER PRIMARY KEY AUTOINCREMENT,   short_id TEXT UNIQUE NOT NULL,   url TEXT NOT NULL,   created_at TEXT NOT NULL,   clicks INTEGER DEFAULT 0 )
```
