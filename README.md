# pic-surl-cloudflare
cloudflare 图床及短链接一站式 基于 workers，d1，r2

展示包括数据统计，列表查看，储存使用量等。

### 预览如下
![预览](https://ju.mk/1758347828383.png)

### 变量如下
![预览](https://ju.mk/1758511347828.png)


#### 1. `CLOUDFLARE_ACCOUNT_ID`
*   **类型**：纯文本
*   **解释**：这是您的 **Cloudflare 账户的唯一标识符**。许多 Cloudflare API 调用都需要这个 ID 来指定操作是针对哪个账户执行的。例如，在获取 R2 存储数据、与 Worker KV 存储交互等场景中，都会用到它。
#### 2. `CLOUDFLARE_API_KEY`
*   **类型**：纯文本
*   **解释**：这是您的**具有最小所需权限的 API 令牌（API Token）**，例如，如果只需要读取 R2 存储使用量，就创建拥有 `Account -> R2 Storage -> Analytics:Read` 权限的 API 令牌，加R2 list权限
#### 3. `DOMAIN`
*   **类型**：纯文本
*   **解释**：这可能指的是您的 Worker 正在服务或与之交互的**主域名**。例如，如果您的 Worker 部署在 `ju.mk` 这个域名下，那么这个变量就存储了这个值。它有助于 Worker 在代码中动态构建 URL 或进行域名相关的逻辑判断。
#### 4. `ENABLE_AUTH`
*   **类型**：纯文本 (通常表示布尔值：`"true"` 或 `"false"`)
*   **解释**：这是一个**布尔开关**，用于控制 Worker 中的某些认证逻辑是否启用。例如，如果其值为 `"true"`，Worker 可能会检查请求是否包含有效的用户名和密码；如果为 `"false"`，则可能跳过认证步骤。
#### 5. `PASSWORD`
*   **类型**：纯文本
*   **解释**：这很可能是用于 Worker 内部某个**认证机制的密码**。例如，和 `ENABLE_AUTH`，它可能用于实现一个简单的身份验证。

下面为企业微信配置，由于企业微信需要设置可信IP，这里需要再固定ip的服务器创建一个代理服务，这里暂时不写。

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

### 进入已上传的图片和短链接列表
![预览](https://ju.mk/1758203674942.png)
* 图床
![预览](https://ju.mk/1758203790133.png)
* 短链接
![预览](https://ju.mk/1758203887562.png)

> **变量及绑定都完成以后，就可以直接粘贴代码到worker里面部署了，绑定自定义域名**
