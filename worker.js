export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const domain = env.DOMAIN;
    const DATABASE = env.DATABASE;
    const enableAuth = env.ENABLE_AUTH === 'true';
    const R2_BUCKET = env.R2_BUCKET;
    const maxSizeMB = env.MAX_SIZE_MB ? parseInt(env.MAX_SIZE_MB, 10) : 10;
    const maxSize = maxSizeMB * 1024 * 1024;
    // 新增：登录页路由
    if (pathname === '/login') {
      return handleLoginRequest(request, env);
    }
    
    // 新增：登出路由
    if (pathname === '/logout') {
      return handleLogoutRequest(request);
    }
    // 为需要认证的路由创建一个检查器
    const requireAuth = async (handler, ...args) => {
      if (enableAuth && !(await isAuthenticated(request, env))) {
        // 如果未认证，重定向到登录页面
        const loginUrl = new URL('/login', request.url);
        // 记录用户想访问的页面，以便登录后跳回
        loginUrl.searchParams.set('redirect', pathname); 
        return Response.redirect(loginUrl.toString(), 302);
      }
      return handler(request, ...args);
    };
    switch (pathname) {
      case '/':
        return requireAuth(handleRootRequest);
      case '/upload':
        // 上传请求比较特殊，不能直接重定向，返回 JSON 错误
        if (enableAuth && !(await isAuthenticated(request, env))) {
          return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }
        return handleUploadRequest(request, DATABASE, domain, R2_BUCKET, maxSize, env);
      case '/r2-usage':
        return handleR2UsageRequest(env);
      case '/delete-images':
        // 删除请求也返回 JSON 错误
        if (enableAuth && !(await isAuthenticated(request, env))) {
          return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }
        return handleDeleteImagesRequest(request, DATABASE, R2_BUCKET);
      case '/shorten':
         // 缩短链接请求也返回 JSON 错误
        if (enableAuth && !(await isAuthenticated(request, env))) {
          return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }
        return handleShortenRequest(request, DATABASE, domain);
      case '/stats':
        return handleStatsRequest(DATABASE);
      case '/images':
        return requireAuth(handleImagesListRequest, DATABASE);
      case '/urls':
        return requireAuth(handleUrlsListRequest, DATABASE);
      default:
        if (pathname.startsWith('/img/')) {
          return handleImageRequest(request, DATABASE, R2_BUCKET);
        }
        // 检查是否是短链接
        const shortId = pathname.substring(1);
        if (shortId && shortId.length <= 10) {
          return await handleShortUrlRedirect(request, DATABASE, shortId);
        }
        return await handleImageRequest(request, DATABASE, R2_BUCKET);
    }
  }
};
// --- 新增和修改的认证函数 ---
const COOKIE_NAME = 'auth_session';
/**
 * 将字符串进行 SHA-256 哈希
 * @param {string} message - 要哈希的字符串
 * @returns {Promise<string>} - 哈希后的十六进制字符串
 */
async function sha256(message) {
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}
/**
 * 检查请求中的 Cookie 是否有效
 * @param {Request} request
 * @param {object} env
 * @returns {Promise<boolean>}
 */
async function isAuthenticated(request, env) {
  if (!env.PASSWORD) return true; // 如果没设置密码，则认为总是认证成功
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;
  const cookies = cookieHeader.split(';');
  const authCookie = cookies.find(c => c.trim().startsWith(`${COOKIE_NAME}=`));
  if (!authCookie) return false;
  const cookieValue = authCookie.split('=')[1].trim();
  const expectedValue = await sha256(env.PASSWORD + '_secret_salt'); // 加盐以增加安全性
  
  return cookieValue === expectedValue;
}
/**
 * 处理登录请求 (GET 和 POST)
 * @param {Request} request
 * @param {object} env
 */
async function handleLoginRequest(request, env) {
  const url = new URL(request.url);
  if (request.method === 'POST') {
    const formData = await request.formData();
    const password = formData.get('password');
    if (password === env.PASSWORD) {
      const sessionValue = await sha256(env.PASSWORD + '_secret_salt');
      const cookie = `${COOKIE_NAME}=${sessionValue}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`; // 30天有效期
      
      const redirectPath = url.searchParams.get('redirect') || '/';
      
      return new Response(null, {
        status: 302,
        headers: {
          'Location': redirectPath,
          'Set-Cookie': cookie
        }
      });
    } else {
      // 密码错误，重新显示登录页并带上错误提示
      const html = getLoginPageHtml(true);
      return new Response(html, { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
  }
  // GET 请求，显示登录页面
  const html = getLoginPageHtml(false);
  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
/**
 * 处理登出请求
 * @param {Request} request
 */
function handleLogoutRequest(request) {
  // 设置一个过期的 Cookie 来删除它
  const cookie = `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
  const loginUrl = new URL('/login', request.url);
  
  return new Response(null, {
    status: 302,
    headers: {
      'Location': loginUrl.toString(),
      'Set-Cookie': cookie
    }
  });
}
/**
 * 生成登录页面的 HTML
 * @param {boolean} hasError - 是否显示错误信息
 * @returns {string}
 */
function getLoginPageHtml(hasError) {
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: #f6f8fb;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            color: #0f172a;
        }
        .login-card {
            background: #ffffff;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
            width: 100%;
            max-width: 380px;
            text-align: center;
            margin: 0 20px;
        }
        
        @media (max-width: 480px) {
            .login-card {
                padding: 24px;
                margin: 0 16px;
                border-radius: 12px;
            }
            
            .login-card h1 {
                font-size: 1.6rem;
            }
            
            .login-card p {
                font-size: 0.9rem;
                margin-bottom: 24px;
            }
            
            .input-field {
                padding: 12px;
                font-size: 0.9rem;
            }
            
            .btn {
                padding: 12px;
                font-size: 0.9rem;
            }
        }
        .login-card h1 {
            font-size: 2rem;
            margin-bottom: 10px;
            font-weight: 700;
        }
        .login-card p {
            color: #475569;
            margin-bottom: 30px;
        }
        .input-field {
            width: 100%;
            padding: 14px;
            border: 1px solid #cbd5e1;
            border-radius: 10px;
            font-size: 1rem;
            margin-bottom: 20px;
            box-sizing: border-box;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .input-field:focus {
            outline: none;
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
        }
        .btn {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(90deg, #2563eb, #7c3aed);
            color: white;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(37, 99, 235, 0.2);
        }
        .error-message {
            background-color: #fef2f2;
            color: #dc2626;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.9rem;
            display: ${hasError ? 'block' : 'none'};
            animation: shake 0.5s;
        }
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h1>访问授权验证</h1>
        <p>请输入密码</p>
        <div class="error-message">密码不正确，请重试。</div>
        <form method="POST">
            <input type="password" name="password" class="input-field" placeholder="请输入密码..." required autofocus>
            <button type="submit" class="btn">登 录</button>
        </form>
    </div>
</body>
</html>
  `;
}

async function handleRootRequest(request) {
  const cache = caches.default;
  const cacheKey = new Request(request.url);
  const cachedResponse = await cache.match(cacheKey);
  if (cachedResponse) {
      return cachedResponse;
  }
  const response = new Response(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JUMK聚合云服务平台</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #f6f8fb; /* 统一浅色背景 */
      color: #0f172a; /* 深色文字便于阅读 */
      min-height: 100vh;
      padding: 20px;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
    .header {
      text-align: center;
      margin-bottom: 40px;
      color: #0f172a;
    }

    .header h1 {
      font-size: 2.6rem;
      margin-bottom: 8px;
      font-weight: 700;
      color: #0f172a;
    }

    .header h1 img {
      max-width: 500px; /* **这里缩小了图片的最大宽度** */
      height: auto; /* 保持图片比例 */
      border-radius: 8px;
    }

    .header p {
      font-size: 1.05rem;
      color: #475569;
    }
        
        .services {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
    .service-card {
      background: #ffffff;
      border-radius: 14px;
      padding: 24px;
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
      transition: transform 0.22s ease, box-shadow 0.22s ease;
      border: 1px solid rgba(15,23,42,0.04);
    }

    .service-card:hover {
      transform: translateY(-4px);
      box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
    }
        
        .service-header {
            display: flex;
            align-items: center;
            margin-bottom: 25px;
        }
        
    .service-icon {
      font-size: 2rem;
      margin-right: 12px;
      color: #2563eb; /* 主要图标色 */
    }
        
        .service-title {
            font-size: 1.8rem;
            color: #333;
            font-weight: 600;
        }
        
        .upload-area {
            border: 3px dashed #ddd;
            border-radius: 15px;
            padding: 40px;
            text-align: center;
            margin-bottom: 20px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .upload-area:hover, .upload-area.dragover {
            border-color: #667eea;
            background: linear-gradient(45deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
            transform: scale(1.02);
        }
        
        .upload-icon {
            font-size: 3rem;
            color: #667eea;
            margin-bottom: 15px;
        }
        
        .upload-text {
            font-size: 1.1rem;
            color: #666;
            margin-bottom: 20px;
        }
        
    .btn {
      background: linear-gradient(90deg, #2563eb, #7c3aed);
      color: white;
      border: none;
      padding: 10px 22px;
      border-radius: 12px;
      font-size: 0.98rem;
      cursor: pointer;
      transition: transform 0.18s ease, box-shadow 0.18s ease;
      box-shadow: 0 6px 18px rgba(37,99,235,0.12);
    }

    .btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 24px rgba(37,99,235,0.14);
    }
        
        .btn-secondary {
            background: linear-gradient(45deg, #28a745, #20c997);
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
        }
        
        .btn-secondary:hover {
            box-shadow: 0 6px 20px rgba(40, 167, 69, 0.4);
        }
        
        .input-group {
            display: flex;
            margin-bottom: 15px;
            gap: 10px;
        }
        
        .input-field {
            flex: 1;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }
        
        .input-field:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .progress {
            width: 100%;
            height: 8px;
            background: #f0f0f0;
            border-radius: 10px;
            overflow: hidden;
            margin: 15px 0;
            display: none;
        }
        
        .progress-bar {
            height: 100%;
            background: linear-gradient(45deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.3s ease;
        }
        
        .result {
            margin-top: 20px;
            padding: 20px;
            border-radius: 15px;
            display: none;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .success {
            background: linear-gradient(45deg, rgba(40, 167, 69, 0.1), rgba(32, 201, 151, 0.1));
            border: 2px solid #28a745;
            color: #155724;
        }
        
        .error {
            background: linear-gradient(45deg, rgba(220, 53, 69, 0.1), rgba(255, 107, 107, 0.1));
            border: 2px solid #dc3545;
            color: #721c24;
        }
        
        .url-display {
            background: rgba(0,0,0,0.05);
            padding: 15px;
            border-radius: 10px;
            margin-top: 10px;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
        }
        
        .copy-btn {
            background: #28a745;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            white-space: nowrap;
        }
        
        .copy-btn:hover {
            background: #218838;
            transform: scale(1.05);
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 40px;
        }
        
    .stat-card {
      background: #ffffff;
      padding: 12px 14px;
      border-radius: 12px;
      text-align: center;
      cursor: pointer;
      transition: transform 0.16s ease, box-shadow 0.16s ease;
      min-height: 78px;
      border: 1px solid rgba(15,23,42,0.04);
      box-shadow: 0 8px 20px rgba(15,23,42,0.04);
    }
        
    .stat-card:hover {
      transform: translateY(-3px);
      box-shadow: 0 8px 20px rgba(0,0,0,0.12);
      background: rgba(255, 255, 255, 1);
    }
        
        .stat-card.clickable:hover .stat-number {
            color: #5a67d8;
        }

        /* R2 行紧凑样式 */
        .r2-row { max-width:1200px; margin:12px auto 0; }
  .r2-row .r2-box { background: #ffffff; padding:10px 14px; border-radius:10px; display:flex; align-items:center; gap:14px; box-shadow:0 8px 24px rgba(15,23,42,0.04); min-height:72px; border:1px solid rgba(15,23,42,0.04); }
  .r2-row .r2-label { font-weight:600; color:#0f172a; min-width:100px; font-size:1rem; }
  .r2-row .r2-text { font-size:0.85rem; color:#475569; margin-top:4px; }
        .r2-row .r2-percent { font-weight:700; color:#667eea; min-width:64px; text-align:right; }
        .r2-row .r2-text { font-size:0.85rem; color:#666; white-space:nowrap; }

        @media (max-width: 768px) {
          .stat-card { padding: 10px; min-height:56px; }
          .stats { gap: 12px; }
          .r2-row .r2-box { padding:6px; }
          .r2-row .r2-label { display:none; }
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        
        input[type="file"] {
            display: none;
        }
        
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .services {
                grid-template-columns: 1fr;
                gap: 15px;
            }
            
            .header h1 {
                font-size: 1.8rem;
            }
            
            .header h1 img {
                max-width: 280px;
            }
            
            .header p {
                font-size: 0.95rem;
                margin-bottom: 20px;
            }
            
            .service-card {
                padding: 16px;
                margin-bottom: 10px;
            }
            
            .service-title {
                font-size: 1.4rem;
            }
            
            .service-header {
                flex-wrap: wrap;
                gap: 10px;
            }
            
            .upload-area {
                padding: 25px 15px;
            }
            
            .upload-text {
                font-size: 0.95rem;
            }
            
            .input-group {
                flex-direction: column;
                gap: 8px;
            }
            
            .btn {
                padding: 12px 18px;
                font-size: 0.9rem;
            }
            
            .url-display {
                flex-direction: column;
                align-items: stretch;
                gap: 8px;
                padding: 12px;
            }
            
            .copy-btn {
                width: 100%;
                padding: 10px;
            }
            
            .github-corner {
                width: 60px;
                height: 60px;
            }
            
            .github-corner svg {
                width: 60px;
                height: 60px;
            }
        }
        
        @media (max-width: 480px) {
            body {
                padding: 8px;
            }
            
            .container {
                padding: 0;
            }
            
            .header h1 {
                font-size: 1.5rem;
            }
            
            .header h1 img {
                max-width: 240px;
            }
            
            .service-card {
                padding: 12px;
            }
            
            .service-title {
                font-size: 1.2rem;
            }
            
            .upload-area {
                padding: 20px 10px;
            }
            
            .upload-icon {
                font-size: 2.5rem;
            }
            
            .upload-text {
                font-size: 0.9rem;
                margin-bottom: 15px;
            }
            
            .btn {
                padding: 10px 15px;
                font-size: 0.85rem;
            }
            
            .input-field {
                padding: 10px 12px;
                font-size: 0.9rem;
            }
            
            .stat-card {
                padding: 8px;
                min-height: 50px;
            }
            
            .stat-number {
                font-size: 1.5rem;
            }
            
            .stat-label {
                font-size: 0.8rem;
            }
            
            .github-corner {
                width: 50px;
                height: 50px;
            }
            
            .github-corner svg {
                width: 50px;
                height: 50px;
            }
        }



    /* 样式，确保图标显示在右上角 */
    .github-corner {
      position: fixed;
      top: 0;
      right: 0;
      border: 0;
      overflow: hidden; /* 防止 SVG 超出三角形范围 */
      z-index: 1000;
      width: 80px; /* 调整大小 */
      height: 80px; /* 调整大小 */
    }

    .github-corner svg {
      position: absolute;
      top: 0;
      border: 0;
      right: 0;
      fill: #317ecbff; /* 三角形背景颜色 */
      color: #fff; /* Octocat 颜色 */
      transform: scale(1.1); /* 稍微放大 Octocat */
    }

    .github-corner:hover svg {
      fill: #151513; /* 鼠标悬停时的三角形背景颜色 */
      color: #fff; /* 鼠标悬停时的 Octocat 颜色，可以自定义 */
    }

     /* 隐藏默认的三角形 */
    .github-corner .octo-arm {
        fill: #fff; /* 或者你想要的 Octocat 颜色 */
        transform: translate(120px, 20px);
    }

    </style>
</head>
<body>
    <!-- GitHub 链接和图标 -->
    <a href="https://github.com/oilycn/pic-surl-cloudflare" class="github-corner" aria-label="View source on GitHub">
      <svg width="80" height="80" viewBox="0 0 250 250" aria-hidden="true">
        <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
        <path class="octo-arm" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"></path>
      </svg>
    </a>
    
    <div class="container">
        <div class="header">
            <h1>
            <a href="/"> <!-- 如果图片是logo，通常会链接到首页 -->
                <img src="https://ju.mk/1758200160455.png" alt="JUMK 聚合云服务平台 Logo">
            </a>
            </h1>
            <p>图片托管 & 短链接生成 - 一站式解决方案 
            <a href="/logout" class="btn" style="text-decoration: none; background: transparent; color: #475569; border: 2px solid #cbd5e1; box-shadow: none; font-weight: 600;">注销</a>
            </p>
        </div>
        
        <div class="services">
            <!-- 图片上传服务 -->
            <div class="service-card">
                <div class="service-header">
                    <i class="fas fa-images service-icon"></i>
                    <h2 class="service-title">图片托管服务</h2>
                    <button class="btn" id="compressionToggle" onclick="toggleCompression()" style="margin-left: auto; padding: 8px 15px; font-size: 0.9rem;">
                        <i class="fas fa-compress-alt"></i> 压缩开启
                    </button>
                </div>
                
                <div class="upload-area" id="uploadArea">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <div class="upload-text">拖拽图片到这里、点击选择文件或直接粘贴图片</div>
                    <button class="btn" onclick="document.getElementById('fileInput').click()">
                        <i class="fas fa-plus"></i> 选择图片
                    </button>
                    <input type="file" id="fileInput" accept="image/*" multiple>
                </div>
                
                <div class="progress" id="progress">
                    <div class="progress-bar" id="progressBar"></div>
                </div>
                
                <div class="result" id="uploadResult"></div>
            </div>
            
            <!-- 短链接服务 -->
            <div class="service-card">
                <div class="service-header">
                    <i class="fas fa-link service-icon"></i>
                    <h2 class="service-title">短链接生成</h2>
                </div>
                
                <div class="input-group">
                    <input type="url" id="urlInput" class="input-field" placeholder="请输入要缩短的网址..." required>
                    <button class="btn btn-secondary" onclick="shortenUrl()">
                        <i class="fas fa-compress-alt"></i> 生成短链
                    </button>
                </div>
                
                <div class="input-group">
                    <input type="text" id="customId" class="input-field" placeholder="自定义短链ID (可选)" maxlength="10">
                </div>
                
                <div class="result" id="shortenResult"></div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card clickable" onclick="goToImagesList()" title="点击查看图片列表">
                <div class="stat-number" id="totalImages">-</div>
                <div class="stat-label">📸 图片总数</div>
            </div>
            <div class="stat-card clickable" onclick="goToUrlsList()" title="点击查看短链列表">
                <div class="stat-number" id="totalUrls">-</div>
                <div class="stat-label">🔗 短链总数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="totalClicks">-</div>
                <div class="stat-label">👆 总点击量</div>
            </div>
            <!-- R2 使用率 已移至下面的单行紧凑显示 -->
        </div>
    </div>

    <!-- R2 使用率 单独一行（紧凑显示） -->
    <div class="r2-row">
      <div class="r2-box">
        <div class="r2-label">R2 使用率</div>
        <div style="flex:1; display:flex; flex-direction:column; gap:6px;">
          <div style="display:flex; align-items:center; gap:12px;">
            <div style="flex:1; height:12px; background:#f0f0f0; border-radius:8px; overflow:hidden;">
              <div id="r2UsageBar" style="width:0%; height:100%; background:linear-gradient(45deg,#667eea,#764ba2);"></div>
            </div>
            <div id="r2UsagePercent" class="r2-percent">-</div>
          </div>
          <div id="r2UsageText" class="r2-text">-</div>
        </div>
      </div>
    </div>

    <script>
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const uploadResult = document.getElementById('uploadResult');
        const shortenResult = document.getElementById('shortenResult');
        const progress = document.getElementById('progress');
        const progressBar = document.getElementById('progressBar');
        
        // 压缩功能开关
        let enableCompression = true;

        // 图片上传相关事件
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            handleFiles(files);
        });

        fileInput.addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });

        // 粘贴功能
        document.addEventListener('paste', async (e) => {
            const clipboardData = e.clipboardData;
            if (clipboardData && clipboardData.items) {
                const items = Array.from(clipboardData.items);
                const imageItems = items.filter(item => item.kind === 'file' && item.type.startsWith('image/'));
                
                if (imageItems.length > 0) {
                    const files = imageItems.map(item => item.getAsFile());
                    handleFiles(files);
                    e.preventDefault();
                }
            }
        });

        // 移动端优化：防止双击缩放
        document.addEventListener('touchstart', function(e) {
            if (e.touches.length > 1) {
                e.preventDefault();
            }
        }, { passive: false });

        let lastTouchEnd = 0;
        document.addEventListener('touchend', function(e) {
            const now = (new Date()).getTime();
            if (now - lastTouchEnd <= 300) {
                e.preventDefault();
            }
            lastTouchEnd = now;
        }, false);

        // 移动端优化：改善滚动性能
        if ('ontouchstart' in window) {
            document.body.style.webkitOverflowScrolling = 'touch';
        }

        // 压缩切换函数 - 添加到全局作用域
        window.toggleCompression = function() {
            enableCompression = !enableCompression;
            const btn = document.getElementById('compressionToggle');
            const icon = btn.querySelector('i');
            
            if (enableCompression) {
                icon.className = 'fas fa-compress-alt';
                btn.innerHTML = '<i class="fas fa-compress-alt"></i> 压缩开启';
                btn.style.background = 'linear-gradient(45deg, #667eea, #764ba2)';
            } else {
                icon.className = 'fas fa-expand-alt';
                btn.innerHTML = '<i class="fas fa-expand-alt"></i> 压缩关闭';
                btn.style.background = 'linear-gradient(45deg, #dc3545, #fd7e14)';
            }
        }

        // 图片压缩函数
        async function compressImage(file, quality = 0.75) {
            return new Promise((resolve) => {
                const image = new Image();
                image.onload = () => {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    
                    // 计算压缩后的尺寸
                    let { width, height } = image;
                    const maxWidth = 1920;
                    const maxHeight = 1080;
                    
                    if (width > maxWidth || height > maxHeight) {
                        const ratio = Math.min(maxWidth / width, maxHeight / height);
                        width *= ratio;
                        height *= ratio;
                    }
                    
                    canvas.width = width;
                    canvas.height = height;
                    
                    // 绘制压缩后的图片
                    ctx.drawImage(image, 0, 0, width, height);
                    
                    canvas.toBlob((blob) => {
                        const compressedFile = new File([blob], file.name, { 
                            type: 'image/jpeg',
                            lastModified: Date.now()
                        });
                        resolve(compressedFile);
                    }, 'image/jpeg', quality);
                };
                
                const reader = new FileReader();
                reader.onload = (event) => {
                    image.src = event.target.result;
                };
                reader.readAsDataURL(file);
            });
        }

        // 处理文件上传
        async function handleFiles(files) {
            if (files.length === 0) return;

            progress.style.display = 'block';
            uploadResult.style.display = 'none';

            const results = [];
            
            for (let i = 0; i < files.length; i++) {
                let file = files[i];
                progressBar.style.width = ((i / files.length) * 100) + '%';
                
                // 如果启用压缩且是图片文件（非GIF）
                if (enableCompression && file.type.startsWith('image/') && file.type !== 'image/gif') {
                    try {
                        file = await compressImage(file);
                    } catch (error) {
                        console.log('压缩失败，使用原文件:', error);
                    }
                }
                
                const formData = new FormData();
                formData.append('image', file);

                try {
                    const response = await fetch('/upload', {
                        method: 'POST',
                        body: formData
                    });

                    const data = await response.json();
                    
                    if (response.ok) {
                        results.push({
                            success: true,
                            filename: files[i].name, // 使用原始文件名
                            url: data.url || data.data,
                            compressed: enableCompression && files[i].type.startsWith('image/') && files[i].type !== 'image/gif'
                        });
                    } else {
                        results.push({
                            success: false,
                            filename: files[i].name,
                            error: data.error
                        });
                    }
                } catch (error) {
                    results.push({
                        success: false,
                        filename: files[i].name,
                        error: '上传失败: ' + error.message
                    });
                }
            }

            progressBar.style.width = '100%';
            setTimeout(() => {
                progress.style.display = 'none';
                showUploadResults(results);
                loadStats(); // 更新统计数据
            }, 500);
        }

        // 显示上传结果
        function showUploadResults(results) {
            let html = '';
            let hasSuccess = false;
            let hasError = false;

            results.forEach(result => {
                if (result.success) {
                    hasSuccess = true;
                    const compressedText = result.compressed ? ' <span style="color: #28a745; font-size: 0.9em;">(已压缩)</span>' : '';
                    html += \`
                        <div style="margin-bottom: 15px;">
                            <div style="display: flex; align-items: center; margin-bottom: 8px;">
                                <i class="fas fa-check-circle" style="color: #28a745; margin-right: 8px;"></i>
                                <strong>\${result.filename}</strong> - 上传成功！\${compressedText}
                            </div>
                            <div class="url-display">
                                <span>\${result.url}</span>
                                <button class="copy-btn" onclick="copyToClipboard('\${result.url}')">
                                    <i class="fas fa-copy"></i> 复制
                                </button>
                            </div>
                        </div>
                    \`;
                } else {
                    hasError = true;
                    html += \`
                        <div style="margin-bottom: 15px;">
                            <div style="display: flex; align-items: center;">
                                <i class="fas fa-times-circle" style="color: #dc3545; margin-right: 8px;"></i>
                                <strong>\${result.filename}</strong> - \${result.error}
                            </div>
                        </div>
                    \`;
                }
            });

            uploadResult.innerHTML = html;
            uploadResult.className = 'result ' + (hasError ? 'error' : 'success');
            uploadResult.style.display = 'block';
        }

        // 短链接生成
        async function shortenUrl() {
            const url = document.getElementById('urlInput').value.trim();
            const customId = document.getElementById('customId').value.trim();
            
            if (!url) {
                showShortenResult('请输入有效的网址', false);
                return;
            }

            try {
                const response = await fetch('/shorten', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        url: url,
                        customId: customId || undefined
                    })
                });

                const data = await response.json();
                
                if (response.ok) {
                    showShortenResult(\`短链接生成成功！<div class="url-display"><span>\${data.shortUrl}</span><button class="copy-btn" onclick="copyToClipboard('\${data.shortUrl}')"><i class="fas fa-copy"></i> 复制</button></div>\`, true);
                    document.getElementById('urlInput').value = '';
                    document.getElementById('customId').value = '';
                    loadStats(); // 更新统计数据
                } else {
                    showShortenResult(data.error || '生成失败', false);
                }
            } catch (error) {
                showShortenResult('网络错误: ' + error.message, false);
            }
        }

        // 显示短链接结果
        function showShortenResult(message, isSuccess) {
            shortenResult.innerHTML = message;
            shortenResult.className = 'result ' + (isSuccess ? 'success' : 'error');
            shortenResult.style.display = 'block';
        }

        // 复制到剪贴板
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // 创建临时提示
                const toast = document.createElement('div');
                toast.style.cssText = \`
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: #28a745;
                    color: white;
                    padding: 12px 20px;
                    border-radius: 8px;
                    z-index: 1000;
                    animation: slideInRight 0.3s ease;
                \`;
                toast.innerHTML = '<i class="fas fa-check"></i> 链接已复制到剪贴板！';
                document.body.appendChild(toast);
                
                setTimeout(() => {
                    toast.remove();
                }, 3000);
            }).catch(() => {
        // 复制失败，使用可视化 toast 提示替代 alert
        const toast = document.createElement('div');
        toast.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #dc3545; color: white; padding: 12px 20px; border-radius: 8px; z-index: 1000; animation: slideInRight 0.3s ease;';
        toast.innerHTML = '<i class="fas fa-times"></i> 复制失败，请手动复制';
        document.body.appendChild(toast);
        setTimeout(() => { toast.remove(); }, 3000);
            });
        }

        // 加载统计数据
        async function loadStats() {
            try {
                const response = await fetch('/stats');
                if (response.ok) {
                    const stats = await response.json();
                    document.getElementById('totalImages').textContent = stats.totalImages || '-';
                    document.getElementById('totalUrls').textContent = stats.totalUrls || '-';
                    document.getElementById('totalClicks').textContent = stats.totalClicks || '-';
                }
            } catch (error) {
                console.log('无法加载统计数据');
            }
        }

        // 页面加载时获取统计数据
        loadStats();
        // 前端：加载并显示 R2 使用率（如果可用）
        async function loadR2Usage() {
          function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
            const v = bytes / Math.pow(k, i);
            return (v % 1 === 0 ? v.toFixed(0) : v.toFixed(2)) + ' ' + sizes[i];
          }
          try {
            const resp = await fetch('/r2-usage', { cache: 'no-store' });
            if (!resp.ok) return;
            const j = await resp.json();
            const el = document.getElementById('r2UsagePercent');
            const bar = document.getElementById('r2UsageBar');
            const percent = typeof j.percent === 'number' ? j.percent : 0;
            if (el) el.textContent = percent.toFixed(2) + '%';
            if (bar) bar.style.width = Math.min(100, percent) + '%';
            const txt = document.getElementById('r2UsageText');
            if (txt) {
              const used = typeof j.usedBytes === 'number' ? j.usedBytes : 0;
              const limit = typeof j.limitBytes === 'number' ? j.limitBytes : 0;
              txt.textContent = formatBytes(used) + ' / ' + formatBytes(limit);
            }
            // 禁用上传控件
            const fileInput = document.getElementById('fileInput');
            const selectBtn = document.querySelector('.upload-area button');
            if (percent >= 95) {
              if (fileInput) fileInput.disabled = true;
              if (selectBtn) selectBtn.disabled = true;
              if (typeof showToast === 'function') showToast('R2 使用率到达阈值，上传已被禁用', true);
            } else {
              if (fileInput) fileInput.disabled = false;
              if (selectBtn) selectBtn.disabled = false;
            }
          } catch (e) {
            console.warn('loadR2Usage error', e);
          }
        }
        // 首次加载并定期刷新
        loadR2Usage();
        setInterval(() => { try { loadR2Usage(); } catch (e) {} }, 5 * 60 * 1000);
        
        // 跳转到图片列表
        function goToImagesList() {
            window.location.href = '/images';
        }
        
        // 跳转到短链列表
        function goToUrlsList() {
            window.location.href = '/urls';
        }

        // URL输入框回车事件
        document.getElementById('urlInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                shortenUrl();
            }
        });
    </script>    
</body>
</html>  
`, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  await cache.put(cacheKey, response.clone());
  return response;
}

async function handleUploadRequest(request, DATABASE, domain, R2_BUCKET, maxSize, env) {
  try {
    // 注意：上传前会检查 R2 使用率并在 >=95% 时拒绝上传。
    // 该函数依赖于 getR2Usage(env)，因此确保在文件中有该实现并且 handleUploadRequest 收到 env 参数。
    if (typeof env !== 'undefined') {
      try {
        const usage = await getR2UsageFromMetricsAPI(env);
        if (usage && usage.hasBucket && typeof usage.percent === 'number' && usage.percent >= 95) {
          return new Response(JSON.stringify({ error: 'R2 使用率达到或超过95%，暂时禁止上传', usage }), { status: 503, headers: { 'Content-Type': 'application/json' } });
        }
      } catch (e) {
        // 如果获取使用率失败，不阻止上传，但记录日志
        console.error('检查 R2 使用率失败:', e);
      }
    }
    const formData = await request.formData();
    const file = formData.get('image') || formData.get('file');
    if (!file) throw new Error('缺少文件');
    
    if (file.size > maxSize) {
      return new Response(JSON.stringify({ error: `文件大小超过${maxSize / (1024 * 1024)}MB限制` }), { status: 413, headers: { 'Content-Type': 'application/json' } });
    }

    const r2Key = `${Date.now()}`;
    await R2_BUCKET.put(r2Key, file.stream(), {
      httpMetadata: { contentType: file.type }
    });
    const fileExtension = file.name.split('.').pop();
    const imageURL = `https://${domain}/${r2Key}.${fileExtension}`;
    await DATABASE.prepare('INSERT INTO media (url) VALUES (?) ON CONFLICT(url) DO NOTHING').bind(imageURL).run();
    return new Response(JSON.stringify({ url: imageURL, data: imageURL }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  } catch (error) {
    console.error('R2 上传错误:', error);
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

async function handleImageRequest(request, DATABASE, R2_BUCKET) {
  const requestedUrl = request.url;
  const cache = caches.default;
  const cacheKey = new Request(requestedUrl);
  const cachedResponse = await cache.match(cacheKey);
  if (cachedResponse) return cachedResponse;
  const result = await DATABASE.prepare('SELECT url FROM media WHERE url = ?').bind(requestedUrl).first();
  if (!result) {
    const notFoundResponse = new Response('资源不存在', { status: 404 });
    await cache.put(cacheKey, notFoundResponse.clone());
    return notFoundResponse;
  }
  const urlParts = requestedUrl.split('/');
  const fileName = urlParts[urlParts.length - 1];
  const [r2Key, fileExtension] = fileName.split('.');
  const object = await R2_BUCKET.get(r2Key);
  if (!object) {
    return new Response('获取文件内容失败', { status: 404 });
  }
  let contentType = 'text/plain';
  if (fileExtension === 'jpg' || fileExtension === 'jpeg') contentType = 'image/jpeg';
  if (fileExtension === 'png') contentType = 'image/png';
  if (fileExtension === 'gif') contentType = 'image/gif';
  if (fileExtension === 'webp') contentType = 'image/webp';
  if (fileExtension === 'mp4') contentType = 'video/mp4';
  const headers = new Headers();
  headers.set('Content-Type', contentType);
  headers.set('Content-Disposition', 'inline');
  const responseToCache = new Response(object.body, { status: 200, headers });
  await cache.put(cacheKey, responseToCache.clone());
  return responseToCache;
}


async function handleDeleteImagesRequest(request, DATABASE, R2_BUCKET) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }
  try {
    const keysToDelete = await request.json();
    if (!Array.isArray(keysToDelete) || keysToDelete.length === 0) {
      return new Response(JSON.stringify({ message: '没有要删除的项' }), { status: 400 });
    }
    const placeholders = keysToDelete.map(() => '?').join(',');
    const result = await DATABASE.prepare(`DELETE FROM media WHERE url IN (${placeholders})`).bind(...keysToDelete).run();
    if (result.changes === 0) {
      return new Response(JSON.stringify({ message: '未找到要删除的项' }), { status: 404 });
    }
    const cache = caches.default;
    for (const url of keysToDelete) {
      const cacheKey = new Request(url);
      const cachedResponse = await cache.match(cacheKey);
      if (cachedResponse) {
        await cache.delete(cacheKey);
      }
      const urlParts = url.split('/');
      const fileName = urlParts[urlParts.length - 1];
      const r2Key = fileName.split('.')[0];
      await R2_BUCKET.delete(r2Key);
    }
    return new Response(JSON.stringify({ message: '删除成功' }), { status: 200 });
  } catch (error) {
    return new Response(JSON.stringify({ error: '删除失败', details: error.message }), { status: 500 });
  }
}

// 短链接生成函数
async function handleShortenRequest(request, DATABASE, domain) {
  
  try {
    const { url, customId } = await request.json();
    
    if (!url) {
      return new Response(JSON.stringify({ error: '缺少URL参数' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // 验证URL格式
    try {
      new URL(url);
    } catch {
      return new Response(JSON.stringify({ error: '无效的URL格式' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    let shortId;
    
    if (customId) {
      // 验证自定义ID
      if (!/^[a-zA-Z0-9_-]+$/.test(customId) || customId.length > 10) {
        return new Response(JSON.stringify({ error: '自定义ID只能包含字母、数字、下划线和连字符，且长度不超过10个字符' }), { 
          status: 400, 
          headers: { 'Content-Type': 'application/json' } 
        });
      }
      
      // 检查自定义ID是否已存在
      const existing = await DATABASE.prepare('SELECT short_id FROM short_urls WHERE short_id = ?').bind(customId).first();
      if (existing) {
        return new Response(JSON.stringify({ error: '自定义ID已存在' }), { 
          status: 409, 
          headers: { 'Content-Type': 'application/json' } 
        });
      }
      
      shortId = customId;
    } else {
      // 生成随机短ID
      shortId = generateShortId();
      
      // 确保生成的ID不重复
      let attempts = 0;
      while (attempts < 10) {
        const existing = await DATABASE.prepare('SELECT short_id FROM short_urls WHERE short_id = ?').bind(shortId).first();
        if (!existing) break;
        shortId = generateShortId();
        attempts++;
      }
      
      if (attempts >= 10) {
        return new Response(JSON.stringify({ error: '生成短链接失败，请重试' }), { 
          status: 500, 
          headers: { 'Content-Type': 'application/json' } 
        });
      }
    }

    // 保存到数据库
    await DATABASE.prepare(
      'INSERT INTO short_urls (short_id, url, created_at, clicks) VALUES (?, ?, ?, 0)'
    ).bind(shortId, url, new Date().toISOString()).run();

    const shortUrl = `https://${domain}/${shortId}`;
    
    return new Response(JSON.stringify({ 
      shortUrl,
      shortId,
      originalUrl: url 
    }), { 
      status: 200, 
      headers: { 'Content-Type': 'application/json' } 
    });
    
  } catch (error) {
    console.error('短链接生成错误:', error);
    return new Response(JSON.stringify({ error: '服务器内部错误' }), { 
      status: 500, 
      headers: { 'Content-Type': 'application/json' } 
    });
  }
}

// 短链接重定向函数
async function handleShortUrlRedirect(request, DATABASE, shortId) {
  try {
    const result = await DATABASE.prepare(
      'SELECT url FROM short_urls WHERE short_id = ?'
    ).bind(shortId).first();
    
    if (!result) {
      return new Response('短链接不存在', { status: 404 });
    }
    
    // 增加点击次数
    await DATABASE.prepare(
      'UPDATE short_urls SET clicks = clicks + 1 WHERE short_id = ?'
    ).bind(shortId).run();
    
    // 重定向到原始URL
    return new Response(null, {
      status: 302,
      headers: {
        'Location': result.url
      }
    });
    
  } catch (error) {
    console.error('短链接重定向错误:', error);
    return new Response('服务器内部错误', { status: 500 });
  }
}

// 生成随机短ID
function generateShortId(length = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// 统计数据处理函数
async function handleStatsRequest(DATABASE) {
  try {
    // 获取图片总数
    const imageCount = await DATABASE.prepare('SELECT COUNT(*) as count FROM media').first();
    
    // 获取短链总数
    const urlCount = await DATABASE.prepare('SELECT COUNT(*) as count FROM short_urls').first();
    
    // 获取总点击量
    const clicksResult = await DATABASE.prepare('SELECT SUM(clicks) as total FROM short_urls').first();
    
    const stats = {
      totalImages: imageCount?.count || 0,
      totalUrls: urlCount?.count || 0,
      totalClicks: clicksResult?.total || 0
    };
    
    return new Response(JSON.stringify(stats), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('获取统计数据错误:', error);
    return new Response(JSON.stringify({ 
      totalImages: 0,
      totalUrls: 0,
      totalClicks: 0
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleImagesListRequest(request, DATABASE) {
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get('page')) || 1;
  return await generateImagesListPage(DATABASE, page);
}

async function handleUrlsListRequest(request, DATABASE) {
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get('page')) || 1;
  const currentDomain = url.hostname;
  return await generateUrlsListPage(DATABASE, page, currentDomain);
}

async function generateImagesListPage(DATABASE, page = 1) {
  const itemsPerPage = 24;
  const offset = (page - 1) * itemsPerPage;
  // 获取总数
  let totalCount = { count: 0 };
  try {
    const totalCountResult = await DATABASE.prepare('SELECT COUNT(*) as count FROM media').first();
    if (totalCountResult && typeof totalCountResult.count !== 'undefined') {
      totalCount.count = totalCountResult.count;
    }
  } catch (e) {
    totalCount.count = 0;
  }
  const totalPages = Math.max(1, Math.ceil(totalCount.count / itemsPerPage));
  // 获取分页数据
  let mediaList = [];
  try {
    const mediaData = await DATABASE.prepare('SELECT url FROM media ORDER BY url LIMIT ? OFFSET ?').bind(itemsPerPage, offset).all();
    // some DB adapters return { results: [...] } while others return the array directly
    if (mediaData) {
      if (Array.isArray(mediaData.results)) {
        mediaList = mediaData.results;
      } else if (Array.isArray(mediaData)) {
        mediaList = mediaData;
      }
    }
    // normalize to { url, timestamp }
    mediaList = mediaList.map(item => {
      const url = item && item.url ? item.url : (typeof item === 'string' ? item : '');
      let timestamp = null;
      try {
        const name = url.split('/').pop().split('.')[0];
        const t = parseInt(name);
        if (!isNaN(t)) timestamp = t;
      } catch (e) {
        timestamp = null;
      }
      return { url, timestamp };
    });
    // 按时间降序排列（新的在前），没有时间信息的放后面
    mediaList.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  } catch (e) {
    mediaList = [];
  }
  const mediaHtml = mediaList.map(({ url, timestamp }) => {
    const fileExtension = url.split('.').pop().toLowerCase();
  // timestamp parsed from filename when possible
  const timeText = timestamp ? new Date(timestamp).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '无时间信息';
    const mediaType = fileExtension.toUpperCase();
    const supportedImageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'svg'];
    const supportedVideoExtensions = ['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm'];
    const isImage = supportedImageExtensions.includes(fileExtension);
    const isVideo = supportedVideoExtensions.includes(fileExtension);
    const isSupported = isImage || isVideo;
    return `
    <div class="image-card" data-url="${url}">
      <div class="image-container">
        ${isVideo ? `
          <video class="media-preview" preload="metadata" controls>
            <source src="${url}" type="video/${fileExtension}">
            您的浏览器不支持视频标签。
          </video>
          <div class="media-type-badge video">📹 ${mediaType}</div>
        ` : isImage ? `
          <img class="media-preview" src="${url}" alt="Image" loading="lazy">
          <div class="media-type-badge image">🖼️ ${mediaType}</div>
        ` : `
          <div class="unsupported-file">
            <i class="fas fa-file fa-3x"></i>
            <div class="media-type-badge file">📁 ${mediaType}</div>
          </div>
        `}
      </div>
      <div class="image-info">
        <div class="upload-time">
          <i class="fas fa-clock"></i>
          ${timeText}
        </div>
        <div class="image-actions">
          <button class="action-btn copy-btn" onclick="copyImageUrl('${url}')" title="复制链接">
            <i class="fas fa-copy"></i>
          </button>
          <button class="action-btn preview-btn" onclick="previewImage('${url}')" title="预览">
            <i class="fas fa-eye"></i>
          </button>
          <button class="action-btn download-btn" onclick="downloadImage('${url}')" title="下载">
            <i class="fas fa-download"></i>
          </button>
          <button class="action-btn delete-single-btn" onclick="deleteSingleImage('${url}', this)" title="删除">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </div>
    </div>
    `;
  }).join('');
  
  const html = `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>图片列表 - 多功能云服务平台</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      
      body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #f6f8fb;
        color: #0f172a;
        min-height: 100vh;
        padding: 20px;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
      }
      
      .container {
        max-width: 1200px;
        margin: 0 auto;
      }
      
      .header {
        background: rgba(255, 255, 255, 0.95);
        backdrop-filter: blur(10px);
        border-radius: 20px;
        padding: 30px;
        margin-bottom: 30px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 20px;
      }
      
      .header-left h1 {
        color: #333;
        font-size: 2.5rem;
        margin-bottom: 10px;
        background: linear-gradient(45deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
      }
      
      .header-left p {
        color: #666;
        font-size: 1.1rem;
      }
      
      .header-right {
        display: flex;
        gap: 15px;
        align-items: center;
      }
      
      .btn {
        background: linear-gradient(45deg, #667eea, #764ba2);
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 25px;
        font-size: 1rem;
        cursor: pointer;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        gap: 8px;
      }
      
      .btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
      }
      
      .btn-secondary {
        background: linear-gradient(45deg, #28a745, #20c997);
        box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
      }
      
      .btn-secondary:hover {
        box-shadow: 0 6px 20px rgba(40, 167, 69, 0.4);
      }
      
      .stats-bar {
        background: #ffffff;
        border-radius: 12px;
        padding: 14px;
        margin-bottom: 20px;
        display: flex;
        justify-content: center;
        gap: 20px;
        flex-wrap: wrap;
        border: 1px solid rgba(15,23,42,0.04);
        box-shadow: 0 8px 20px rgba(15,23,42,0.04);
      }
      
      .stat-item {
        text-align: center;
      }
      
      .stat-number {
        font-size: 2rem;
        font-weight: bold;
        color: #667eea;
        margin-bottom: 5px;
      }
      
      .stat-label {
        color: #666;
        font-size: 0.9rem;
      }
      
      .images-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
        gap: 15px;
        margin-bottom: 30px;
      }
      
      .image-card {
        background: #ffffff;
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 8px 22px rgba(15,23,42,0.04);
        transition: transform 0.18s ease, box-shadow 0.18s ease;
        border: 1px solid rgba(15,23,42,0.04);
      }
      
      .image-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
      }
      .image-card.selected {
        border: 3px solid #ff9800; /* 更醒目的橙色边框，和背景区分开 */
        box-shadow: 0 12px 30px rgba(255,152,0,0.12);
      }

      /* 保持卡片内部信息区为纯白，选中时不改变其白色背景 */
      .image-card .image-info {
        background: white;
      }
      
      .image-container {
        position: relative;
        width: 100%;
        height: 150px;
        overflow: hidden;
        background: linear-gradient(180deg, #f8fafc, #f1f5f9);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      
      .media-preview {
        width: 100%;
        height: 100%;
        object-fit: cover;
        transition: transform 0.3s ease;
      }
      
      .image-card:hover .media-preview {
        transform: scale(1.05);
      }
      
      .unsupported-file {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 100%;
        color: #999;
      }
      
      .media-type-badge {
        position: absolute;
        top: 10px;
        left: 10px;
        padding: 6px 10px;
        border-radius: 12px;
        font-size: 0.78rem;
        font-weight: 700;
        color: white;
      }
      
      .media-type-badge.image {
        background: rgba(40, 167, 69, 0.8);
      }
      
      .media-type-badge.video {
        background: rgba(220, 53, 69, 0.8);
      }
      
      .media-type-badge.file {
        background: rgba(108, 117, 125, 0.8);
      }
      
      .image-info {
        padding: 12px 14px;
      }
      
      .upload-time {
        color: #666;
        font-size: 0.75rem;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        gap: 5px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      
      .image-actions {
        display: flex;
        gap: 6px;
        justify-content: center;
      }
      
      .action-btn {
        background: #ffffff;
        border: 1px solid rgba(15,23,42,0.06);
        color: #0f172a;
        padding: 6px;
        border-radius: 8px;
        cursor: pointer;
        transition: transform 0.14s ease, box-shadow 0.14s ease;
        font-size: 0.88rem;
        width: 32px;
        height: 32px;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      
      .action-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      }

      .action-btn {
        position: relative;
        z-index: 10;
      }
      
      .copy-btn:hover {
        background: #28a745;
        border-color: #28a745;
        color: white;
      }
      
      .preview-btn:hover {
        background: #007bff;
        border-color: #007bff;
        color: white;
      }
      
      .download-btn:hover {
        background: #6f42c1;
        border-color: #6f42c1;
        color: white;
      }
      
      .empty-state {
        text-align: center;
        padding: 60px 20px;
        color: white;
      }
      
      .empty-state i {
        font-size: 4rem;
        margin-bottom: 20px;
        opacity: 0.7;
      }
      
      .empty-state h3 {
        font-size: 1.5rem;
        margin-bottom: 10px;
      }
      
      .empty-state p {
        opacity: 0.8;
      }
      
      /* 预览模态框 */
      .modal {
        display: none;
        position: fixed;
        z-index: 1000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(15,23,42,0.6);
        backdrop-filter: blur(4px);
      }
      
      .modal-content {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        max-width: 90%;
        max-height: 90%;
        border-radius: 10px;
        overflow: hidden;
      }
      
      .modal img, .modal video {
        width: 100%;
        height: auto;
        max-height: 80vh;
        object-fit: contain;
      }
      
      .close {
        position: absolute;
        top: 20px;
        right: 30px;
        color: white;
        font-size: 40px;
        font-weight: bold;
        cursor: pointer;
        z-index: 1001;
      }
      
      .close:hover {
        opacity: 0.7;
      }
      
      .toast {
        position: fixed;
        top: 20px;
        right: 20px;
        background: #10b981; /* 更柔和的绿 */
        color: white;
        padding: 12px 18px;
        border-radius: 10px;
        box-shadow: 0 8px 24px rgba(15,23,42,0.08);
        z-index: 1000;
        transform: translateX(400px);
        transition: transform 0.22s ease;
      }
      
      .toast.show {
        transform: translateX(0);
      }
      
      .pagination {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 10px;
        margin: 30px 0;
        flex-wrap: wrap;
      }
      
      .page-numbers {
        display: flex;
        gap: 5px;
      }
      
      .page-btn {
        background: rgba(255, 255, 255, 0.9);
        color: #667eea;
        border: 1px solid #e9ecef;
        padding: 8px 12px;
        border-radius: 8px;
        text-decoration: none;
        font-size: 0.9rem;
        transition: all 0.3s ease;
        min-width: 40px;
        text-align: center;
      }
      
      .page-btn:hover {
        background: #667eea;
        color: white;
        transform: translateY(-1px);
      }
      
      .page-btn.current {
        background: #667eea;
        color: white;
        font-weight: bold;
      }
      
      .page-btn.disabled {
        background: rgba(255, 255, 255, 0.5);
        color: #999;
        cursor: not-allowed;
      }
      
      .page-btn.disabled:hover {
        transform: none;
        background: rgba(255, 255, 255, 0.5);
        color: #999;
      }
      
      @media (max-width: 768px) {
        body {
          padding: 15px;
        }
        
        .header {
          padding: 18px;
        }
        
        .header-top {
          flex-direction: column;
          gap: 15px;
          align-items: stretch;
        }
        
        .title-section {
          text-align: center;
          order: 1;
        }
        
        .title-section h1 {
          font-size: 1.8rem;
          justify-content: center;
        }
        
        .stats-inline {
          order: 2;
          justify-content: center;
          gap: 6px;
        }
        
        .stat-badge {
          font-size: 0.75rem;
          padding: 3px 8px;
        }
        
        .action-buttons {
          order: 3;
          justify-content: center;
          gap: 8px;
        }
        
        .btn-small {
          padding: 6px 12px;
          font-size: 0.8rem;
          min-width: 80px;
        }
        
        .images-grid {
          grid-template-columns: repeat(2, 1fr);
          gap: 12px;
        }
        
        .stats-inline {
          gap: 6px;
        }
        
        .stat-badge {
          font-size: 0.75rem;
          padding: 3px 8px;
        }
        
        .image-card {
          border-radius: 10px;
        }
        
        .image-container {
          height: 120px;
        }
        
        .image-info {
          padding: 10px 12px;
        }
        
        .upload-time {
          font-size: 0.7rem;
        }
        
        .action-btn {
          width: 28px;
          height: 28px;
          font-size: 0.8rem;
        }
        
        .modal-content {
          max-width: 95%;
          max-height: 95%;
        }
        
        .close {
          top: 10px;
          right: 15px;
          font-size: 30px;
        }
        
        .stats-bar {
          padding: 12px;
          gap: 15px;
        }
        
        .stat-number {
          font-size: 1.5rem;
        }
        
        .stat-label {
          font-size: 0.8rem;
        }
      }
      
      @media (max-width: 480px) {
        body {
          padding: 10px;
        }
        
        .header {
          padding: 16px;
          margin-bottom: 20px;
        }
        
        .header-top {
          gap: 12px;
        }
        
        .title-section h1 {
          font-size: 1.5rem;
        }
        
        .stats-inline {
          gap: 4px;
          flex-wrap: wrap;
        }
        
        .stat-badge {
          font-size: 0.7rem;
          padding: 2px 6px;
          flex: 1;
          min-width: 75px;
          text-align: center;
        }
        
        .action-buttons {
          gap: 6px;
        }
        
        .btn-small {
          padding: 5px 10px;
          font-size: 0.75rem;
          flex: 1;
          min-width: 70px;
          justify-content: center;
        }
        
        .images-grid {
          grid-template-columns: repeat(2, 1fr);
          gap: 8px;
        }
        
        .image-container {
          height: 180px;
        }
        
        .image-info {
          padding: 8px 10px;
        }
        
        .upload-time {
          font-size: 0.65rem;
          margin-bottom: 8px;
        }
        
        .image-actions {
          gap: 4px;
        }
        
        .action-btn {
          width: 26px;
          height: 26px;
          font-size: 0.75rem;
        }
        
        .stats-bar {
          padding: 10px;
          gap: 10px;
          flex-direction: column;
        }
        
        .stat-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          width: 100%;
          padding: 8px 0;
        }
        
        .stat-number {
          font-size: 1.3rem;
        }
        
        .stat-label {
          font-size: 0.75rem;
        }
        
        .close {
          top: 5px;
          right: 10px;
          font-size: 25px;
        }
        
        .toast {
          top: 10px;
          right: 10px;
          left: 10px;
          transform: translateY(-100px);
          padding: 10px 15px;
          font-size: 0.9rem;
        }
        
        .toast.show {
          transform: translateY(0);
        }
      }
      
      .btn-small {
        background: linear-gradient(45deg, #667eea, #764ba2);
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 500;
        cursor: pointer;
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        transition: all 0.3s ease;
        white-space: nowrap;
        box-shadow: 0 3px 12px rgba(102, 126, 234, 0.3);
      }
      
      .btn-small:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 16px rgba(102, 126, 234, 0.4);
      }
      
      .btn-small.btn-secondary {
        background: linear-gradient(45deg, #28a745, #20c997);
        color: white;
        box-shadow: 0 3px 12px rgba(40, 167, 69, 0.3);
      }
      
      .btn-small.btn-secondary:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 16px rgba(40, 167, 69, 0.4);
      }
      
      .header-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 20px;
        width: 100%;
      }
      
      .title-section {
        flex-shrink: 0;
      }
      
      .title-section h1 {
        color: #333;
        font-size: 2.2rem;
        margin: 0;
        background: linear-gradient(45deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        display: flex;
        align-items: center;
        gap: 12px;
      }
      
      .stats-inline {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        justify-content: center;
        flex: 1;
      }
      
      .action-buttons {
        display: flex;
        gap: 8px;
        align-items: center;
        flex-shrink: 0;
      }
    </style>
  </head>
  <body>
    <div class="header">
      <div class="header-top">
        <div class="title-section">
          <h1><i class="fas fa-images"></i> 图片列表</h1>
        </div>
        <div class="stats-inline">
          <span class="stat-badge">📸 ${mediaList.length} 张图片</span>
          <span class="stat-badge">💾 ${(mediaList.reduce((sum, item) => sum + (item.size || 0), 0) / 1024 / 1024).toFixed(1)} MB</span>
        </div>
        <div class="action-buttons">
          <a href="/" class="btn-small">
            <i class="fas fa-home"></i> 首页
          </a>
          <button class="btn-small btn-secondary" onclick="refreshList()">
            <i class="fas fa-sync-alt"></i> 刷新
          </button>
        </div>
      </div>
    </div>
    
    <div class="images-grid">
      ${mediaList.length > 0 ? mediaHtml : `
        <div class="empty-state">
          <i class="fas fa-images"></i>
          <h3>暂无图片</h3>
          <p>您还没有上传任何图片，<a href="/" style="color: #2563eb; text-decoration: underline;">点击这里</a> 开始上传吧！</p>
        </div>
      `}
    </div>

    <div style="text-align:center; margin-top: 20px;">
      <button id="selectAllBtn" class="btn" style="margin-right:10px;">全选/取消全选</button>
      <button id="deleteSelectedBtn" class="btn btn-secondary">删除已选图片</button>
    </div>
    
    ${totalPages > 1 ? `
    <div class="pagination">
      ${page > 1 ? `<a href="/images?page=${page - 1}" class="page-btn">« 上一页</a>` : '<span class="page-btn disabled">« 上一页</span>'}
      
      <div class="page-numbers">
        ${Array.from({length: Math.min(5, totalPages)}, (_, i) => {
          let pageNum;
          if (totalPages <= 5) {
            pageNum = i + 1;
          } else if (page <= 3) {
            pageNum = i + 1;
          } else if (page >= totalPages - 2) {
            pageNum = totalPages - 4 + i;
          } else {
            pageNum = page - 2 + i;
          }
          return pageNum === page 
            ? `<span class="page-btn current">${pageNum}</span>`
            : `<a href="/images?page=${pageNum}" class="page-btn">${pageNum}</a>`;
        }).join('')}
      </div>
      
      ${page < totalPages ? `<a href="/images?page=${page + 1}" class="page-btn">下一页 »</a>` : '<span class="page-btn disabled">下一页 »</span>'}
    </div>
    ` : ''}
    
    <script>
      (function(){
        const selectedSet = new Set();

        function updateSelectionUI(card, selected) {
          if (selected) {
            card.classList.add('selected');
          } else {
            card.classList.remove('selected');
          }
        }

        function toggleCardSelection(card) {
          const url = card.getAttribute('data-url');
          if (selectedSet.has(url)) {
            selectedSet.delete(url);
            updateSelectionUI(card, false);
          } else {
            selectedSet.add(url);
            updateSelectionUI(card, true);
          }
        }

        function selectAllToggle() {
          const cards = Array.from(document.querySelectorAll('.image-card'));
          const anyUnselected = cards.some(c => !c.classList.contains('selected'));
          cards.forEach(card => {
            const url = card.getAttribute('data-url');
            if (anyUnselected) {
              selectedSet.add(url);
              updateSelectionUI(card, true);
            } else {
              selectedSet.delete(url);
              updateSelectionUI(card, false);
            }
          });
        }

        async function deleteSelected() {
          const urls = Array.from(selectedSet);
          if (urls.length === 0) {
            showToast('请先选择要删除的图片', true);
            return;
          }
          // 已改为使用带输入确认的模态（实现位于同一脚本中）
          showDeleteConfirmModal(urls.length, async (confirmed) => {
            if (!confirmed) return;
            try {
              const resp = await fetch('/delete-images', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(urls)
              });
              const data = await resp.json();
              if (resp.ok) {
                urls.forEach(u => {
                  const card = document.querySelector('.image-card[data-url="' + u + '"]');
                  if (card) card.remove();
                });
                selectedSet.clear();
                showToast(data.message || '删除成功');
              } else {
                showToast(data.error || data.message || '删除失败', true);
              }
            } catch (err) {
              showToast('删除请求失败: ' + err.message, true);
            }
          });
        }

        // 单图删除
        async function deleteSingleImage(url, btn) {
          // 使用带输入确认的模态
          showDeleteConfirmModal(1, async (confirmed) => {
            if (!confirmed) return;
            try {
              const resp = await fetch('/delete-images', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify([url])
              });
              const data = await resp.json();
              if (resp.ok) {
                const card = btn.closest('.image-card');
                if (card) card.remove();
                selectedSet.delete(url);
                showToast(data.message || '删除成功');
              } else {
                showToast(data.error || data.message || '删除失败', true);
              }
            } catch (err) {
              showToast('删除请求失败: ' + err.message, true);
            }
          });
        }

        // 复制链接
        function copyImageUrl(url) {
          if (!navigator.clipboard) {
            const ta = document.createElement('textarea');
            ta.value = url;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
            showToast('链接已复制到剪贴板');
            return;
          }
          navigator.clipboard.writeText(url).then(() => showToast('链接已复制到剪贴板')).catch(() => showToast('复制失败', true));
        }

        // 预览
        function previewImage(url) {
          // 创建或复用模态框，使用 DOM API 构建以避免字符串嵌套导致的语法问题
          let modal = document.getElementById('imagePreviewModal');
          if (!modal) {
            modal = document.createElement('div');
            modal.id = 'imagePreviewModal';
            modal.className = 'modal';

            const close = document.createElement('div');
            close.className = 'close';
            close.innerHTML = '&times;';
            close.addEventListener('click', () => { modal.style.display = 'none'; });

            const content = document.createElement('div');
            content.className = 'modal-content';
            content.id = 'modalContent';

            modal.appendChild(close);
            modal.appendChild(content);
            document.body.appendChild(modal);
          }
          const content = modal.querySelector('#modalContent');
          // 判断是否视频
          const ext = url.split('.').pop().toLowerCase();
          const videoExts = ['mp4','webm','mkv','mov','avi'];
          if (videoExts.includes(ext)) {
            content.innerHTML = '';
            const video = document.createElement('video');
            video.controls = true;
            video.autoplay = true;
            video.style.width = '100%';
            video.style.height = 'auto';
            video.style.maxHeight = '80vh';
            video.src = url;
            content.appendChild(video);
          } else {
            content.innerHTML = '';
            const img = document.createElement('img');
            img.src = url;
            img.style.width = '100%';
            img.style.height = 'auto';
            img.style.maxHeight = '80vh';
            content.appendChild(img);
          }
          modal.style.display = 'block';
        }

        // 下载
        function downloadImage(url) {
          const a = document.createElement('a');
          a.href = url;
          a.download = '';
          document.body.appendChild(a);
          a.click();
          a.remove();
        }

        function showToast(message, isError) {
          let toast = document.getElementById('globalToast');
          if (!toast) {
            toast = document.createElement('div');
            toast.id = 'globalToast';
            toast.className = 'toast';
            document.body.appendChild(toast);
          }
          toast.textContent = message;
          toast.style.background = isError ? '#dc3545' : '#28a745';
          toast.classList.add('show');
          setTimeout(() => toast.classList.remove('show'), 2500);
        }

        // 带输入确认的删除模态，要求用户输入“删除”两个字
        function showDeleteConfirmModal(count, callback) {
          let modal = document.getElementById('typedDeleteModal');
          if (!modal) {
            modal = document.createElement('div');
            modal.id = 'typedDeleteModal';
            modal.className = 'modal';
            const inner = document.createElement('div');
            inner.className = 'modal-content';
            inner.style.padding = '20px';
            inner.style.maxWidth = '420px';
            inner.style.background = '#fff';
            inner.style.borderRadius = '8px';
            inner.style.color = '#000';
            inner.style.position = 'relative';

            const title = document.createElement('h3');
            title.textContent = '请确认删除';
            title.style.marginBottom = '10px';

            const info = document.createElement('p');
            info.id = 'typedDeleteInfo';
            info.style.marginBottom = '10px';

            const input = document.createElement('input');
            input.type = 'text';
            input.placeholder = '请输入 删除 以确认';
            input.id = 'typedDeleteInput';
            input.style.width = '100%';
            input.style.padding = '10px';
            input.style.marginBottom = '12px';
            input.style.border = '1px solid #ddd';
            input.style.borderRadius = '6px';

            const btnWrap = document.createElement('div');
            btnWrap.style.display = 'flex';
            btnWrap.style.justifyContent = 'flex-end';
            btnWrap.style.gap = '8px';

            const cancelBtn = document.createElement('button');
            cancelBtn.textContent = '取消';
            cancelBtn.className = 'btn';
            cancelBtn.addEventListener('click', () => { modal.style.display = 'none'; callback(false); });

            const okBtn = document.createElement('button');
            okBtn.textContent = '确认删除';
            okBtn.className = 'btn btn-secondary';
            okBtn.addEventListener('click', () => {
              const v = document.getElementById('typedDeleteInput').value.trim();
              if (v === '删除') {
                modal.style.display = 'none';
                callback(true);
              } else {
                showToast('输入不正确，请输入 删除 才能确认', true);
              }
            });

            btnWrap.appendChild(cancelBtn);
            btnWrap.appendChild(okBtn);

            inner.appendChild(title);
            inner.appendChild(info);
            inner.appendChild(input);
            inner.appendChild(btnWrap);

            modal.appendChild(inner);
            document.body.appendChild(modal);
          }
          const infoEl = document.getElementById('typedDeleteInfo');
          const inputEl = document.getElementById('typedDeleteInput');
          if (infoEl) infoEl.textContent = '确认将删除 ' + count + ' 项。请输入 “删除” 并点击 确认删除。此操作无法撤销。';
          if (inputEl) { inputEl.value = ''; inputEl.focus(); }
          modal.style.display = 'block';
        }

        // 初始化（支持脚本在 DOM 已就绪或未就绪时都能绑定事件）
        function initImageListPage() {
          // 卡片点击切换选中
          document.querySelectorAll('.image-card').forEach(card => {
            card.addEventListener('click', (e) => {
              // 如果点击的是按钮（action-btn），不要切换选中状态
              if (e.target.closest('.action-btn') || e.target.closest('button')) return;
              toggleCardSelection(card);
            });
          });

          // 显式绑定按钮事件，防止被卡片点击吞掉
          document.querySelectorAll('.image-card .action-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
              e.stopPropagation();
              const card = btn.closest('.image-card');
              const url = card ? card.getAttribute('data-url') : null;
              if (!url) return;
              if (btn.classList.contains('copy-btn')) {
                copyImageUrl(url);
              } else if (btn.classList.contains('preview-btn')) {
                previewImage(url);
              } else if (btn.classList.contains('download-btn')) {
                downloadImage(url);
              } else if (btn.classList.contains('delete-single-btn')) {
                deleteSingleImage(url, btn);
              }
            });
          });

          const selectAllBtn = document.getElementById('selectAllBtn');
          const deleteBtn = document.getElementById('deleteSelectedBtn');
          if (selectAllBtn) selectAllBtn.addEventListener('click', selectAllToggle);
          if (deleteBtn) deleteBtn.addEventListener('click', deleteSelected);
        }

        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', initImageListPage);
        } else {
          initImageListPage();
        }

        // 刷新列表（确保 header 的刷新按钮可用）
        function refreshList() {
          location.reload();
        }

  // 暴露一些方法供内联 onclick 或外部脚本调用
  window.copyImageUrl = copyImageUrl;
  window.previewImage = previewImage;
  window.downloadImage = downloadImage;
  window.deleteSingleImage = deleteSingleImage;
  window.deleteSelectedImagesOnPage = deleteSelected;
  window.deleteSelected = deleteSelected;
  window.selectAllImagesOnPage = selectAllToggle;
  window.selectAllToggle = selectAllToggle;
  window.refreshList = refreshList;
  window.showDeleteConfirmModal = showDeleteConfirmModal;
      })();
    </script>
  </body>
  </html>
  `;
  
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

async function generateUrlsListPage(DATABASE, page = 1, currentDomain = '') {
  const itemsPerPage = 20;
  const offset = (page - 1) * itemsPerPage;
  
  // 获取总数和分页数据
  let totalCount = { count: 0 };
  try {
    const totalCountResult = await DATABASE.prepare('SELECT COUNT(*) as count FROM short_urls').first();
    if (totalCountResult && typeof totalCountResult.count !== 'undefined') {
      totalCount.count = totalCountResult.count;
    }
  } catch (e) {
    totalCount.count = 0;
  }
  const totalPages = Math.max(1, Math.ceil(totalCount.count / itemsPerPage));
  let urlsList = [];
  try {
    const urlsData = await DATABASE.prepare('SELECT id, short_id, url, clicks, created_at FROM short_urls ORDER BY id DESC LIMIT ? OFFSET ?').bind(itemsPerPage, offset).all();
    if (urlsData) {
      if (Array.isArray(urlsData.results)) {
        urlsList = urlsData.results;
      } else if (Array.isArray(urlsData)) {
        urlsList = urlsData;
      }
    }
  } catch (e) {
    urlsList = [];
  }
  const urlsHtml = urlsList.map(({ short_id, url, clicks, created_at }) => {
    const domain = new URL(url).hostname;
    const shortUrl = currentDomain ? `https://${currentDomain}/${short_id}` : `/${short_id}`;
    const createdDate = new Date(created_at).toLocaleString('zh-CN', { 
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
    return `
    <div class="url-card" data-short-url="${shortUrl}" data-original-url="${url}">
      <div class="url-info">
        <div class="url-header">
          <div class="short-url">
            <i class="fas fa-link"></i>
            <span class="url-text">${shortUrl}</span>
          </div>
          <div class="click-count">
            <i class="fas fa-mouse-pointer"></i>
            <span>${clicks} 次点击</span>
          </div>
        </div>
        <div class="original-url">
          <i class="fas fa-external-link-alt"></i>
          <span class="url-text" title="${url}">${url}</span>
        </div>
        <div class="url-meta">
          <span class="domain"><i class="fas fa-globe"></i> ${domain}</span>
          <span class="created-time"><i class="fas fa-clock"></i> ${createdDate}</span>
        </div>
      </div>
      <div class="url-actions">
        <button class="action-btn copy-short-btn" onclick="copyUrl('${shortUrl}')" title="复制短链">
          <i class="fas fa-copy"></i>
        </button>
        <button class="action-btn copy-original-btn" onclick="copyUrl('${url}')" title="复制原链">
          <i class="fas fa-link"></i>
        </button>
        <button class="action-btn visit-btn" onclick="visitUrl('${shortUrl}')" title="访问链接">
          <i class="fas fa-external-link-alt"></i>
        </button>
      </div>
    </div>
    `;
  }).join('');
  
  const html = `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>短链列表 - 多功能云服务平台</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      
      body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #f6f8fb;
        min-height: 100vh;
        padding: 20px;
      }
      
      .container {
        max-width: 1200px;
        margin: 0 auto;
      }
      
      .header {
        background: rgba(255, 255, 255, 0.95);
        backdrop-filter: blur(10px);
        border-radius: 20px;
        padding: 30px;
        margin-bottom: 30px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 20px;
      }
      
      .header-left h1 {
        color: #333;
        font-size: 2.5rem;
        margin-bottom: 10px;
        background: linear-gradient(45deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
      }
      
      .header-left p {
        color: #666;
        font-size: 1.1rem;
      }
      
      .header-right {
        display: flex;
        gap: 15px;
        align-items: center;
      }
      
      .btn {
        background: linear-gradient(45deg, #667eea, #764ba2);
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 25px;
        font-size: 1rem;
        cursor: pointer;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        gap: 8px;
      }
      
      .btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
      }
      
      .btn-secondary {
        background: linear-gradient(45deg, #28a745, #20c997);
        box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
      }
      
      .btn-secondary:hover {
        box-shadow: 0 6px 20px rgba(40, 167, 69, 0.4);
      }
      
      .stats-bar {
        background: #ffffff;
        border-radius: 12px;
        padding: 14px;
        margin-bottom: 20px;
        display: flex;
        justify-content: center;
        gap: 20px;
        flex-wrap: wrap;
        border: 1px solid rgba(15,23,42,0.04);
        box-shadow: 0 8px 20px rgba(15,23,42,0.04);
      }
      
      .stat-item {
        text-align: center;
      }
      
      .stat-number {
        font-size: 2rem;
        font-weight: bold;
        color: #667eea;
        margin-bottom: 5px;
      }
      
      .stat-label {
        color: #666;
        font-size: 0.9rem;
      }
      
      .urls-list {
        display: flex;
        flex-direction: column;
        gap: 15px;
        margin-bottom: 30px;
      }
      
      .url-card {
        background: #ffffff;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 8px 22px rgba(15,23,42,0.04);
        transition: transform 0.18s ease, box-shadow 0.18s ease;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 20px;
        border: 1px solid rgba(15,23,42,0.04);
      }
      
      .url-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
      }
      
      .url-info {
        flex: 1;
        min-width: 0;
      }
      
      .url-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 10px;
        gap: 15px;
      }
      
      .short-url {
        display: flex;
        align-items: center;
        gap: 8px;
        font-weight: bold;
        color: #667eea;
      }
      
      .click-count {
        display: flex;
        align-items: center;
        gap: 5px;
        color: #28a745;
        font-size: 0.9rem;
        white-space: nowrap;
      }
      
      .original-url {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 10px;
        color: #666;
      }
      
      .url-text {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      
      .url-meta {
        display: flex;
        gap: 20px;
        font-size: 0.8rem;
        color: #999;
      }
      
      .url-meta span {
        display: flex;
        align-items: center;
        gap: 5px;
      }
      
      .url-actions {
        display: flex;
        gap: 8px;
        flex-shrink: 0;
      }
      
      .action-btn {
        background: #ffffff;
        border: 1px solid rgba(15,23,42,0.06);
        color: #0f172a;
        padding: 6px;
        border-radius: 8px;
        cursor: pointer;
        transition: transform 0.14s ease, box-shadow 0.14s ease;
        font-size: 0.88rem;
        width: 32px;
        height: 32px;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      
      .action-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      }
      
      .copy-short-btn:hover {
        background: #28a745;
        border-color: #28a745;
        color: white;
      }
      
      .copy-original-btn:hover {
        background: #007bff;
        border-color: #007bff;
        color: white;
      }
      
      .visit-btn:hover {
        background: #6f42c1;
        border-color: #6f42c1;
        color: white;
      }
      
      .empty-state {
        text-align: center;
        padding: 60px 20px;
        color: white;
      }
      
      .empty-state i {
        font-size: 4rem;
        margin-bottom: 20px;
        opacity: 0.7;
      }
      
      .empty-state h3 {
        font-size: 1.5rem;
        margin-bottom: 10px;
      }
      
      .empty-state p {
        opacity: 0.8;
      }
      
      .toast {
        position: fixed;
        top: 20px;
        right: 20px;
        background: #10b981;
        color: white;
        padding: 12px 18px;
        border-radius: 10px;
        box-shadow: 0 8px 24px rgba(15,23,42,0.08);
        z-index: 1000;
        transform: translateX(400px);
        transition: transform 0.22s ease;
      }
      
      .toast.show {
        transform: translateX(0);
      }
      
      .pagination {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 10px;
        margin: 30px 0;
        flex-wrap: wrap;
      }
      
      .page-numbers {
        display: flex;
        gap: 5px;
      }
      
      .page-btn {
        background: rgba(255, 255, 255, 0.9);
        color: #667eea;
        border: 1px solid #e9ecef;
        padding: 8px 12px;
        border-radius: 8px;
        text-decoration: none;
        font-size: 0.9rem;
        transition: all 0.3s ease;
        min-width: 40px;
        text-align: center;
      }
      
      .page-btn:hover {
        background: #667eea;
        color: white;
        transform: translateY(-1px);
      }
      
      .page-btn.current {
        background: #667eea;
        color: white;
        font-weight: bold;
      }
      
      .page-btn.disabled {
        background: rgba(255, 255, 255, 0.5);
        color: #999;
        cursor: not-allowed;
      }
      
      .page-btn.disabled:hover {
        transform: none;
        background: rgba(255, 255, 255, 0.5);
        color: #999;
      }
      
      @media (max-width: 768px) {
        body {
          padding: 15px;
        }
        
        .header {
          padding: 18px;
        }
        
        .header-top {
          flex-direction: column;
          gap: 15px;
          align-items: stretch;
        }
        
        .title-section {
          text-align: center;
          order: 1;
        }
        
        .title-section h1 {
          font-size: 1.8rem;
          justify-content: center;
        }
        
        .stats-inline {
          order: 2;
          justify-content: center;
          gap: 6px;
        }
        
        .stat-badge {
          font-size: 0.75rem;
          padding: 3px 8px;
        }
        
        .action-buttons {
          order: 3;
          justify-content: center;
          gap: 8px;
        }
        
        .btn-small {
          padding: 6px 12px;
          font-size: 0.8rem;
          min-width: 80px;
        }
        
        .stat-number {
          font-size: 1.5rem;
        }
        
        .stat-label {
          font-size: 0.8rem;
        }
        
        .url-card {
          padding: 16px;
          flex-direction: column;
          align-items: stretch;
          gap: 15px;
        }
        
        .url-header {
          flex-direction: column;
          align-items: stretch;
          gap: 10px;
        }
        
        .short-url, .click-count {
          justify-content: flex-start;
        }
        
        .url-meta {
          flex-direction: column;
          gap: 8px;
        }
        
        .url-actions {
          justify-content: center;
          gap: 12px;
        }
        
        .action-btn {
          width: 36px;
          height: 36px;
        }
      }
      
      @media (max-width: 480px) {
        body {
          padding: 10px;
        }
        
        .header {
          padding: 16px;
          margin-bottom: 20px;
        }
        
        .header-top {
          gap: 12px;
        }
        
        .title-section h1 {
          font-size: 1.5rem;
        }
        
        .stats-inline {
          gap: 4px;
          flex-wrap: wrap;
        }
        
        .stat-badge {
          font-size: 0.7rem;
          padding: 2px 6px;
          flex: 1;
          min-width: 75px;
          text-align: center;
        }
        
        .action-buttons {
          gap: 6px;
        }
        
        .btn-small {
          padding: 5px 10px;
          font-size: 0.75rem;
          flex: 1;
          min-width: 70px;
          justify-content: center;
        }
        
        .stat-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          width: 100%;
          padding: 8px 0;
        }
        
        .stat-number {
          font-size: 1.3rem;
        }
        
        .stat-label {
          font-size: 0.75rem;
        }
        
        .url-card {
          padding: 12px;
          gap: 12px;
        }
        
        .url-header {
          gap: 8px;
        }
        
        .short-url {
          font-size: 0.9rem;
        }
        
        .click-count {
          font-size: 0.8rem;
        }
        
        .original-url {
          font-size: 0.85rem;
        }
        
        .url-meta {
          font-size: 0.7rem;
          gap: 6px;
        }
        
        .url-actions {
          gap: 8px;
        }
        
        .action-btn {
          width: 32px;
          height: 32px;
          font-size: 0.8rem;
        }
        
        .toast {
          top: 10px;
          right: 10px;
          left: 10px;
          transform: translateY(-100px);
          padding: 10px 15px;
          font-size: 0.9rem;
        }
        
        .toast.show {
          transform: translateY(0);
        }
      }
      
      .btn-small {
        background: linear-gradient(45deg, #667eea, #764ba2);
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 500;
        cursor: pointer;
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        transition: all 0.3s ease;
        white-space: nowrap;
        box-shadow: 0 3px 12px rgba(102, 126, 234, 0.3);
      }
      
      .btn-small:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 16px rgba(102, 126, 234, 0.4);
      }
      
      .btn-small.btn-secondary {
        background: linear-gradient(45deg, #28a745, #20c997);
        color: white;
        box-shadow: 0 3px 12px rgba(40, 167, 69, 0.3);
      }
      
      .btn-small.btn-secondary:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 16px rgba(40, 167, 69, 0.4);
      }
      
      .header-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 20px;
        width: 100%;
      }
      
      .title-section {
        flex-shrink: 0;
      }
      
      .title-section h1 {
        color: #333;
        font-size: 2.2rem;
        margin: 0;
        background: linear-gradient(45deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        display: flex;
        align-items: center;
        gap: 12px;
      }
      
      .stats-inline {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        justify-content: center;
        flex: 1;
      }
      
      .action-buttons {
        display: flex;
        gap: 8px;
        align-items: center;
        flex-shrink: 0;
      }
      
      @media (max-width: 768px) {
        .header {
          padding: 18px;
        }
        
        .header-top {
          flex-direction: column;
          gap: 15px;
          align-items: stretch;
        }
        
        .title-section {
          text-align: center;
          order: 1;
        }
        
        .title-section h1 {
          font-size: 1.8rem;
          justify-content: center;
        }
        
        .stats-inline {
          order: 2;
          justify-content: center;
          gap: 6px;
        }
        
        .stat-badge {
          font-size: 0.75rem;
          padding: 3px 8px;
        }
        
        .action-buttons {
          order: 3;
          justify-content: center;
          gap: 8px;
        }
        
        .btn-small {
          padding: 6px 12px;
          font-size: 0.8rem;
          min-width: 80px;
        }
      }
      
      @media (max-width: 480px) {
        .header {
          padding: 16px;
          margin-bottom: 20px;
        }
        
        .header-top {
          gap: 12px;
        }
        
        .title-section h1 {
          font-size: 1.5rem;
        }
        
        .stats-inline {
          gap: 4px;
          flex-wrap: wrap;
        }
        
        .stat-badge {
          font-size: 0.7rem;
          padding: 2px 6px;
          flex: 1;
          min-width: 75px;
          text-align: center;
        }
        
        .action-buttons {
          gap: 6px;
        }
        
        .btn-small {
          padding: 5px 10px;
          font-size: 0.75rem;
          flex: 1;
          min-width: 70px;
          justify-content: center;
        }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="header-top">
          <div class="title-section">
            <h1><i class="fas fa-link"></i> 短链列表</h1>
          </div>
          <div class="stats-inline">
            <span class="stat-badge">🔗 ${totalCount.count} 总链接</span>
            <span class="stat-badge">📄 ${urlsList.length} 当前页</span>
            <span class="stat-badge">👆 ${urlsList.reduce((sum, url) => sum + url.clicks, 0)} 点击</span>
            <span class="stat-badge">📄 ${page}/${totalPages} 页</span>
          </div>
          <div class="action-buttons">
            <a href="/" class="btn-small">
              <i class="fas fa-home"></i> 首页
            </a>
            <button class="btn-small btn-secondary" onclick="refreshList()">
              <i class="fas fa-sync-alt"></i> 刷新
            </button>
          </div>
        </div>
      </div>
      
      <div class="urls-list">
        ${urlsList.length > 0 ? urlsHtml : `
            <div class="empty-state">
              <i class="fas fa-link"></i>
              <h3>暂无短链</h3>
              <p>您还没有创建任何短链接，<a href="/" style="color: #2563eb; text-decoration: underline;">点击这里</a> 开始创建吧！</p>
            </div>
        `}
      </div>
      
      ${totalPages > 1 ? `
      <div class="pagination">
        ${page > 1 ? `<a href="/urls?page=${page - 1}" class="page-btn">« 上一页</a>` : '<span class="page-btn disabled">« 上一页</span>'}
        
        <div class="page-numbers">
          ${Array.from({length: Math.min(5, totalPages)}, (_, i) => {
            let pageNum;
            if (totalPages <= 5) {
              pageNum = i + 1;
            } else if (page <= 3) {
              pageNum = i + 1;
            } else if (page >= totalPages - 2) {
              pageNum = totalPages - 4 + i;
            } else {
              pageNum = page - 2 + i;
            }
            return pageNum === page 
              ? `<span class="page-btn current">${pageNum}</span>`
              : `<a href="/urls?page=${pageNum}" class="page-btn">${pageNum}</a>`;
          }).join('')}
        </div>
        
        ${page < totalPages ? `<a href="/urls?page=${page + 1}" class="page-btn">下一页 »</a>` : '<span class="page-btn disabled">下一页 »</span>'}
      </div>
      ` : ''}
    </div>
    
    <!-- 提示消息 -->
    <div id="toast" class="toast"></div>
    
    <script>
      // 复制URL
      function copyUrl(url) {
        navigator.clipboard.writeText(url).then(() => {
          showToast('链接已复制到剪贴板！', 'success');
        }).catch(() => {
          // 降级方案
          const textArea = document.createElement('textarea');
          textArea.value = url;
          document.body.appendChild(textArea);
          textArea.select();
          document.execCommand('copy');
          document.body.removeChild(textArea);
          showToast('链接已复制到剪贴板！', 'success');
        });
      }
      
      // 访问链接
      function visitUrl(url) {
        window.open(url, '_blank');
      }
      
      // 刷新列表
      function refreshList() {
        location.reload();
      }
      
      // 显示提示消息
      function showToast(message, type = 'success') {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = 'toast show';
        
        if (type === 'success') {
          toast.style.background = '#28a745';
        } else if (type === 'error') {
          toast.style.background = '#dc3545';
        } else if (type === 'info') {
          toast.style.background = '#17a2b8';
        }
        
        setTimeout(() => {
          toast.classList.remove('show');
        }, 3000);
      }
    </script>
  </body>
  </html>
  `;
  
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}


// Modify handleR2UsageRequest to use getR2UsageFromMetricsAPI
async function handleR2UsageRequest(env) {
  try {
      const usage = await getR2UsageFromMetricsAPI(env);
      return new Response(JSON.stringify(usage), { headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
      console.error('handleR2UsageRequest failed:', e);
      return new Response(JSON.stringify({ error: 'failed to get R2 usage', message: String(e) }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}


// ---------------------------------------------------------------------------------------------------------------------
// BEGIN MODIFICATIONS FOR R2 METRICS API USAGE
// ---------------------------------------------------------------------------------------------------------------------

async function getR2UsageFromMetricsAPI(env) {
  const DEFAULT_LIMIT_BYTES = (() => {
      const v = Number(env.R2_FREE_LIMIT_BYTES || env.R2_FREE_LIMIT || 0);
      if (v && !Number.isNaN(v) && v > 0) return v;
      return 10 * 1024 * 1024 * 1024; // 默认 10GB
  })();
  if (!env || !env.CLOUDFLARE_ACCOUNT_ID || !env.CLOUDFLARE_EMAIL || !env.CLOUDFLARE_API_KEY) {
      console.warn('R2 Metrics API: Missing CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_EMAIL, or CLOUDFLARE_API_KEY environment variables. Falling back to listing objects if R2_BUCKET is bound.');
      return { usedBytes: 0, limitBytes: DEFAULT_LIMIT_BYTES, percent: 0, hasBucket: false };
  }
  try {
      const accountId = env.CLOUDFLARE_ACCOUNT_ID;
      const authEmail = env.CLOUDFLARE_EMAIL;
      const authKey = env.CLOUDFLARE_API_KEY;
      const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/r2/metrics`;
      const response = await fetch(apiUrl, {
          method: 'GET',
          headers: {
              'X-Auth-Email': authEmail,
              'X-Auth-Key': authKey,
              'Content-Type': 'application/json',
          },
      });
      if (!response.ok) {
          const errorText = await response.text();
          console.error(`Cloudflare R2 Metrics API error: ${response.status} ${response.statusText} - ${errorText}`);
          // 如果没有 R2_BUCKET 绑定或回退也失败，则抛出错误
          throw new Error(`Failed to fetch R2 metrics: ${response.statusText} - Details: ${errorText}`);
      }
      const metricsData = await response.json();
      console.log(metricsData); // 打印完整的 API 响应
      let used = 0;
      let hasBucketData = false;
      if (metricsData.result && metricsData.result.standard && metricsData.result.standard.published) {
          used = metricsData.result.standard.published.payloadSize || 0;
          if (used > 0 || metricsData.result.standard.published.objects > 0) {
            hasBucketData = true;
          }
      }
      const percent = Math.min(100, (used / DEFAULT_LIMIT_BYTES) * 100);
      return { usedBytes: used, limitBytes: DEFAULT_LIMIT_BYTES, percent, hasBucket: hasBucketData };
  } catch (e) {
      console.error('getR2UsageFromMetricsAPI caught an error:', e);
      throw e;
  }
}
