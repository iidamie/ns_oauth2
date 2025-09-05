# main.py
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional, Dict, Any, List
import secrets
import json
from curl_cffi import requests
import sqlite3
from datetime import datetime, timedelta
import uvicorn
from pydantic import BaseModel
import jwt
from starlette.middleware.sessions import SessionMiddleware
import os

# 配置
DB_PATH = os.environ.get('DB_PATH', 'oauth_db.sqlite')
COOKIE = os.environ.get('COOKIE')
ADMIN_ID = os.environ.get('ADMIN_ID')
JWT_SECRET = os.environ.get('JWT_SECRET')
JWT_ALGORITHM = "HS256"
MIN_CLIENT_CREATION_RANK = os.environ.get('MIN_CLIENT_CREATION_RANK', 1)

# 创建应用实例
app = FastAPI(title="Nodeseek OAuth2 授权服务")

# 添加会话中间件
app.add_middleware(
    SessionMiddleware,
    secret_key=JWT_SECRET,
    max_age=7 * 24 * 60 * 60,  # 7天会话有效期
)

# 配置模板和静态文件
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# 模型定义
class VerifyRequest(BaseModel):
    user_id: str

class ConfirmRequest(BaseModel):
    user_id: str
    verification_code: str

class TokenRequest(BaseModel):
    grant_type: str
    code: str
    redirect_uri: str
    client_id: str
    client_secret: str

class ClientCreateRequest(BaseModel):
    name: str
    website: str
    description: str
    redirect_uris: str

class Client(BaseModel):
    client_id: str
    client_name: str
    website: str
    description: str
    redirect_uris: str
    logo_url: Optional[str] = None
    created_at: str
    created_by: int

# 数据库初始化
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 客户端表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        client_name TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        website TEXT NOT NULL,
        description TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        logo_url TEXT,
        created_at TIMESTAMP NOT NULL,
        created_by INTEGER NOT NULL
    )
    ''')
    
    # 验证码表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS verification_codes (
        user_id INTEGER NOT NULL,
        code TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        PRIMARY KEY (user_id, code)
    )
    ''')
    
    # 授权码表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_codes (
        code TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        scope TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL
    )
    ''')
    
    # 访问令牌表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tokens (
        access_token TEXT PRIMARY KEY,
        refresh_token TEXT UNIQUE,
        client_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        scope TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL
    )
    ''')
    
    # 用户表 - 记录已验证过的用户
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        rank INTEGER NOT NULL,
        coin INTEGER NOT NULL,
        bio TEXT,
        created_at TIMESTAMP NOT NULL,
        last_login TIMESTAMP NOT NULL
    )
    ''')
    
    # 插入测试客户端
    cursor.execute('''
    INSERT OR IGNORE INTO clients 
    (client_id, client_name, client_secret, website, description, redirect_uris, logo_url, created_at, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        'test_client', 
        'NodeApp 演示应用', 
        'test_secret', 
        'https://example.com',
        '这是一个演示应用，用于测试OAuth2授权流程',
        'http://localhost:8000/callback,http://127.0.0.1:8000/callback', 
        '/static/app-icon.svg',
        datetime.now().isoformat(),
        0
    ))
    
    conn.commit()
    conn.close()

# 检查消息是否发送的函数，使用curl_cffi库
def check_message_sent(user_id: str, verification_code: str = None) -> Dict[str, Any]:
    url = f"https://www.nodeseek.com/api/notification/message/with/{user_id}"
    headers = {
        'Cookie': COOKIE
    }
    
    try:
        # 使用curl_cffi库发送请求并指定impersonate参数
        response = requests.get(url, headers=headers, impersonate="safari15_3")
        data = json.loads(response.text)
        
        if data.get("success"):
            # 如果不需要验证码检查，只是获取用户信息
            if verification_code is None:
                return {
                    "success": True,
                    "user_info": {
                        "member_id": data["talkTo"]["member_id"],
                        "member_name": data["talkTo"]["member_name"],
                        "rank": data["talkTo"]["rank"],
                        "coin": data["talkTo"]["coin"],
                        "bio": data["talkTo"].get("bio", ""),
                        "created_at": data["talkTo"].get("created_at", ""),
                        "isAdmin": data["talkTo"].get("isAdmin", 0)
                    }
                }
            
            # 检查是否有包含验证码的消息
            for msg in data.get("msgArray", []):
                if (msg["sender_id"] == int(user_id) and 
                    msg["receiver_id"] == int(ADMIN_ID) and
                    verification_code in msg["content"]):
                    return {
                        "success": True,
                        "user_info": {
                            "member_id": data["talkTo"]["member_id"],
                            "member_name": data["talkTo"]["member_name"],
                            "rank": data["talkTo"]["rank"],
                            "coin": data["talkTo"]["coin"],
                            "bio": data["talkTo"].get("bio", ""),
                            "created_at": data["talkTo"].get("created_at", ""),
                            "isAdmin": data["talkTo"].get("isAdmin", 0)
                        }
                    }
        
        return {"success": False, "message": "验证码未发送或不匹配"}
    
    except Exception as e:
        return {"success": False, "message": f"API请求失败: {str(e)}"}

# 验证客户端
def verify_client(client_id: str, redirect_uri: Optional[str] = None) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if redirect_uri:
        cursor.execute('SELECT redirect_uris FROM clients WHERE client_id = ?', (client_id,))
    else:
        cursor.execute('SELECT 1 FROM clients WHERE client_id = ?', (client_id,))
        
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
        
    if redirect_uri:
        allowed_uris = result[0].split(',')
        return redirect_uri in allowed_uris
        
    return True

# 验证客户端密钥
def verify_client_secret(client_id: str, client_secret: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT client_secret FROM clients WHERE client_id = ?', (client_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
        
    return result[0] == client_secret

# 创建JWT会话令牌
def create_session_token(user_info: Dict[str, Any]) -> str:
    payload = {
        "sub": str(user_info["member_id"]),
        "name": user_info["member_name"],
        "rank": user_info["rank"],
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# 解析JWT会话令牌
def decode_session_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except:
        return None

# 更新或保存用户信息
def save_user_info(user_info: Dict[str, Any]):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute('''
    INSERT OR REPLACE INTO users (user_id, username, rank, coin, bio, created_at, last_login)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_info["member_id"],
        user_info["member_name"],
        user_info["rank"],
        user_info["coin"],
        user_info.get("bio", ""),
        user_info.get("created_at", now),
        now
    ))
    
    conn.commit()
    conn.close()

# 获取用户信息
def get_user_info(user_id: int) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT user_id, username, rank, coin, bio, created_at
    FROM users
    WHERE user_id = ?
    ''', (user_id,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return None
        
    return {
        "member_id": user[0],
        "member_name": user[1],
        "rank": user[2],
        "coin": user[3],
        "bio": user[4],
        "created_at": user[5]
    }

# 获取客户端信息
def get_client_info(client_id: str) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT client_id, client_name, website, description, redirect_uris, logo_url, created_at, created_by
    FROM clients
    WHERE client_id = ?
    ''', (client_id,))
    
    client = cursor.fetchone()
    conn.close()
    
    if not client:
        return None
        
    return {
        "client_id": client[0],
        "client_name": client[1],
        "website": client[2],
        "description": client[3],
        "redirect_uris": client[4],
        "logo_url": client[5],
        "created_at": client[6],
        "created_by": client[7]
    }

# 获取用户创建的客户端列表
def get_user_clients(user_id: int) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT client_id, client_name, website, description, redirect_uris, logo_url, created_at
    FROM clients
    WHERE created_by = ?
    ORDER BY created_at DESC
    ''', (user_id,))
    
    clients = cursor.fetchall()
    conn.close()
    
    return [{
        "client_id": client[0],
        "client_name": client[1],
        "website": client[2],
        "description": client[3],
        "redirect_uris": client[4],
        "logo_url": client[5],
        "created_at": client[6]
    } for client in clients]

# 获取已登录用户
def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    session = request.session
    if "user_token" not in session:
        return None
        
    user_data = decode_session_token(session["user_token"])
    if not user_data:
        return None
        
    return user_data

# 需要登录的依赖项
def require_login(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="需要登录",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

# 路由实现
@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/oauth/authorize", response_class=HTMLResponse)
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str = "basic",
    state: str = None
):
    # 验证客户端和重定向URI
    if not verify_client(client_id, redirect_uri):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "invalid_client", "error_description": "客户端未注册或重定向URI不被允许"}
        )
    
    if response_type not in ["code", "token"]:
        return RedirectResponse(
            f"{redirect_uri}?error=unsupported_response_type&state={state}",
            status_code=status.HTTP_302_FOUND
        )
    
    # 获取当前用户（如果已登录）
    current_user = get_current_user(request)
    
    # 获取应用信息
    client_info = get_client_info(client_id)
    
    # 如果用户已登录，显示授权页面
    if current_user:
        # 渲染授权页面
        return templates.TemplateResponse(
            "authorize.html",
            {
                "request": request,
                "client": client_info,
                "user": current_user,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "scope": scope,
                "state": state
            }
        )
    
    # 如果用户未登录，重定向到登录页面，并将原请求参数保存在会话中
    request.session["oauth_params"] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": scope,
        "state": state
    }
    
    return RedirectResponse(
        url="/login",
        status_code=status.HTTP_302_FOUND
    )

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    # 如果用户已登录，检查是否有待处理的OAuth请求
    current_user = get_current_user(request)
    if current_user and "oauth_params" in request.session:
        oauth_params = request.session["oauth_params"]
        del request.session["oauth_params"]
        
        # 重定向到授权页面
        redirect_url = "/oauth/authorize?" + "&".join([
            f"{k}={v}" for k, v in oauth_params.items() if v is not None
        ])
        return RedirectResponse(redirect_url, status_code=status.HTTP_302_FOUND)
    
    return templates.TemplateResponse(
        "login.html", 
        {"request": request}
    )

@app.post("/oauth/verify")
async def verify_user(request: VerifyRequest):
    user_id = request.user_id
    
    if not user_id or not user_id.isdigit():
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "用户ID必须是数字"}
        )
    
    # 生成验证码
    verification_code = f"NS_AUTH_{secrets.token_hex(4).upper()}"
    
    # 存储验证码
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = datetime.now()
    expires = now + timedelta(minutes=10)
    
    cursor.execute('DELETE FROM verification_codes WHERE user_id = ?', (user_id,))
    cursor.execute('''
    INSERT INTO verification_codes (user_id, code, created_at, expires_at)
    VALUES (?, ?, ?, ?)
    ''', (user_id, verification_code, now.isoformat(), expires.isoformat()))
    
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "verification_code": verification_code,
        "expires_in": 600
    }

@app.post("/oauth/confirm")
async def confirm_verification(request: Request, data: ConfirmRequest):
    user_id = data.user_id
    verification_code = data.verification_code
    
    # 检查验证码是否有效
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    SELECT * FROM verification_codes 
    WHERE user_id = ? AND code = ? AND expires_at > ?
    ''', (user_id, verification_code, datetime.now().isoformat()))
    
    code_record = cursor.fetchone()
    conn.close()
    
    if not code_record:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "验证码无效或已过期"}
        )
    
    # 检查消息是否已发送
    check_result = check_message_sent(user_id, verification_code)
    
    if not check_result["success"]:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=check_result
        )
    
    # 保存用户信息
    save_user_info(check_result["user_info"])
    
    # 创建用户会话
    user_token = create_session_token(check_result["user_info"])
    request.session["user_token"] = user_token
    
    # 检查是否有待处理的OAuth请求
    oauth_params = request.session.get("oauth_params")
    if oauth_params:
        # 清除会话中的OAuth参数
        del request.session["oauth_params"]
        
        # 返回成功并包含重定向信息
        return {
            "success": True,
            "user_info": check_result["user_info"],
            "redirect_to": "/oauth/authorize?" + "&".join([
                f"{k}={v}" for k, v in oauth_params.items() if v is not None
            ])
        }
    
    # 普通登录成功
    return {
        "success": True,
        "user_info": check_result["user_info"]
    }

@app.post("/oauth/approve")
async def approve_authorization(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    response_type: str = Form(...),
    scope: str = Form(...),
    state: str = Form(None)
):
    # 检查用户是否已登录
    current_user = get_current_user(request)
    if not current_user:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "unauthorized", "error_description": "用户未登录"}
        )
    
    user_id = current_user["sub"]
    
    # 如果是授权码模式
    if response_type == "code":
        # 生成授权码
        auth_code = f"auth_{secrets.token_urlsafe(32)}"
        
        # 存储授权码
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now = datetime.now()
        expires = now + timedelta(minutes=10)
        
        cursor.execute('''
        INSERT INTO auth_codes (code, client_id, user_id, scope, redirect_uri, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (auth_code, client_id, user_id, scope, redirect_uri, expires.isoformat()))
        
        conn.commit()
        conn.close()
        
        # 构建重定向URL
        redirect_url = f"{redirect_uri}?code={auth_code}"
        if state:
            redirect_url += f"&state={state}"
        
        return {"success": True, "redirect_uri": redirect_url}
    
    # 如果是隐式授权模式
    elif response_type == "token":
        # 生成访问令牌
        access_token = f"access_{secrets.token_urlsafe(32)}"
        refresh_token = f"refresh_{secrets.token_urlsafe(32)}"
        
        # 存储令牌
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now = datetime.now()
        expires = now + timedelta(hours=1)
        
        cursor.execute('''
        INSERT INTO tokens (access_token, refresh_token, client_id, user_id, scope, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (access_token, refresh_token, client_id, user_id, scope, expires.isoformat()))
        
        conn.commit()
        conn.close()
        
        # 构建重定向URL（注意这里使用片段标识符#而不是查询参数?）
        redirect_url = f"{redirect_uri}#access_token={access_token}&token_type=Bearer&expires_in=3600"
        if state:
            redirect_url += f"&state={state}"
        
        return {"success": True, "redirect_uri": redirect_url}
    
    else:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "unsupported_response_type"}
        )

@app.post("/oauth/deny")
async def deny_authorization(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(None)
):
    # 构建重定向URL
    redirect_url = f"{redirect_uri}?error=access_denied"
    if state:
        redirect_url += f"&state={state}"
    
    return {"success": True, "redirect_uri": redirect_url}

@app.post("/oauth/token")
async def token_endpoint(
    grant_type: str = Form(...),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    refresh_token: str = Form(None)
):
    # 验证客户端凭据
    if not verify_client_secret(client_id, client_secret):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid_client", "error_description": "客户端认证失败"}
        )
    
    # 授权码模式
    if grant_type == "authorization_code":
        if not code or not redirect_uri:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_request", "error_description": "授权码和重定向URI必须提供"}
            )
        
        # 验证授权码
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        SELECT user_id, scope FROM auth_codes 
        WHERE code = ? AND client_id = ? AND redirect_uri = ? AND expires_at > ?
        ''', (code, client_id, redirect_uri, datetime.now().isoformat()))
        
        code_record = cursor.fetchone()
        
        if not code_record:
            conn.close()
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_grant", "error_description": "授权码无效或已过期"}
            )
        
        user_id = code_record[0]
        scope = code_record[1]
        
        # 删除已使用的授权码
        cursor.execute('DELETE FROM auth_codes WHERE code = ?', (code,))
        
        # 生成访问令牌
        access_token = f"access_{secrets.token_urlsafe(32)}"
        refresh_token = f"refresh_{secrets.token_urlsafe(32)}"
        
        # 存储令牌
        now = datetime.now()
        expires = now + timedelta(hours=1)
        
        cursor.execute('''
        INSERT INTO tokens (access_token, refresh_token, client_id, user_id, scope, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (access_token, refresh_token, client_id, user_id, scope, expires.isoformat()))
        
        conn.commit()
        conn.close()
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": scope
        }
    
    # 刷新令牌
    elif grant_type == "refresh_token":
        if not refresh_token:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_request", "error_description": "刷新令牌必须提供"}
            )
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        SELECT user_id, scope FROM tokens 
        WHERE refresh_token = ? AND client_id = ?
        ''', (refresh_token, client_id))
        
        token_record = cursor.fetchone()
        
        if not token_record:
            conn.close()
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "invalid_grant", "error_description": "刷新令牌无效"}
            )
        
        user_id = token_record[0]
        scope = token_record[1]
        
        # 删除旧令牌
        cursor.execute('DELETE FROM tokens WHERE refresh_token = ?', (refresh_token,))
        
        # 生成新令牌
        access_token = f"access_{secrets.token_urlsafe(32)}"
        new_refresh_token = f"refresh_{secrets.token_urlsafe(32)}"
        
        # 存储新令牌
        now = datetime.now()
        expires = now + timedelta(hours=1)
        
        cursor.execute('''
        INSERT INTO tokens (access_token, refresh_token, client_id, user_id, scope, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (access_token, new_refresh_token, client_id, user_id, scope, expires.isoformat()))
        
        conn.commit()
        conn.close()
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": new_refresh_token,
            "scope": scope
        }
    
    else:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "unsupported_grant_type", "error_description": "仅支持授权码和刷新令牌授权类型"}
        )

@app.get("/api/user/info")
async def user_info_endpoint(request: Request):
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid_token", "error_description": "缺少或无效的Authorization头"}
        )
    
    token = auth_header.split(" ")[1]
    
    # 验证令牌
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    SELECT user_id, scope FROM tokens 
    WHERE access_token = ? AND expires_at > ?
    ''', (token, datetime.now().isoformat()))
    
    token_record = cursor.fetchone()
    conn.close()
    
    if not token_record:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid_token", "error_description": "令牌无效或已过期"}
        )
    
    user_id = token_record[0]
    scope = token_record[1]
    
    # 获取用户信息
    user_info = get_user_info(user_id)
    
    if not user_info:
        # 尝试从API获取
        check_result = check_message_sent(str(user_id))
        if check_result["success"]:
            user_info = check_result["user_info"]
            save_user_info(user_info)
        else:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "user_not_found", "error_description": "用户信息不可用"}
            )
    
    # 根据作用域过滤信息
    if scope == "basic":
        return {
            "member_id": user_info["member_id"],
            "member_name": user_info["member_name"],
            "rank": user_info["rank"]
        }
    elif scope == "profile":
        return user_info
    else:
        return {
            "member_id": user_info["member_id"],
            "member_name": user_info["member_name"],
            "rank": user_info["rank"]
        }

@app.get("/clients", response_class=HTMLResponse)
async def clients_page(request: Request, user: Dict = Depends(require_login)):
    # 检查用户等级是否满足创建客户端的要求
    if int(user["rank"]) < MIN_CLIENT_CREATION_RANK:
        return templates.TemplateResponse(
            "clients_denied.html",
            {
                "request": request,
                "user": user,
                "min_rank": MIN_CLIENT_CREATION_RANK
            }
        )
    
    # 获取用户创建的客户端列表
    clients = get_user_clients(int(user["sub"]))
    
    return templates.TemplateResponse(
        "clients.html",
        {
            "request": request,
            "user": user,
            "clients": clients
        }
    )

@app.get("/clients/new", response_class=HTMLResponse)
async def new_client_page(request: Request, user: Dict = Depends(require_login)):
    # 检查用户等级是否满足创建客户端的要求
    if int(user["rank"]) < MIN_CLIENT_CREATION_RANK:
        return RedirectResponse("/clients", status_code=status.HTTP_302_FOUND)
    
    return templates.TemplateResponse(
        "new_client.html",
        {
            "request": request,
            "user": user
        }
    )

@app.post("/api/clients")
async def create_client(request: Request, client_data: ClientCreateRequest, user: Dict = Depends(require_login)):
    # 检查用户等级是否满足创建客户端的要求
    if int(user["rank"]) < MIN_CLIENT_CREATION_RANK:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"success": False, "message": f"创建客户端需要等级 {MIN_CLIENT_CREATION_RANK} 或更高"}
        )
    
    # 验证输入
    if not client_data.name or not client_data.website or not client_data.redirect_uris:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "所有必填字段都需要填写"}
        )
    
    # 生成客户端ID和密钥
    client_id = f"client_{secrets.token_urlsafe(16)}"
    client_secret = f"secret_{secrets.token_urlsafe(32)}"
    
    # 存储客户端信息
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    
    cursor.execute('''
    INSERT INTO clients 
    (client_id, client_name, client_secret, website, description, redirect_uris, created_at, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        client_data.name,
        client_secret,
        client_data.website,
        client_data.description,
        client_data.redirect_uris,
        now,
        int(user["sub"])
    ))
    
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "client": {
            "client_id": client_id,
            "client_name": client_data.name,
            "client_secret": client_secret,
            "website": client_data.website,
            "description": client_data.description,
            "redirect_uris": client_data.redirect_uris,
            "created_at": now
        }
    }

@app.get("/clients/{client_id}", response_class=HTMLResponse)
async def client_details_page(request: Request, client_id: str, user: Dict = Depends(require_login)):
    # 获取客户端信息
    client_info = get_client_info(client_id)
    
    # 检查客户端是否存在
    if not client_info:
        return RedirectResponse("/clients", status_code=status.HTTP_302_FOUND)
    
    # 检查用户是否是客户端的创建者
    if int(user["sub"]) != client_info["created_by"]:
        return RedirectResponse("/clients", status_code=status.HTTP_302_FOUND)
    
    # 获取客户端密钥
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT client_secret FROM clients WHERE client_id = ?', (client_id,))
    client_secret = cursor.fetchone()[0]
    conn.close()
    
    return templates.TemplateResponse(
        "client_details.html",
        {
            "request": request,
            "user": user,
            "client": client_info,
            "client_secret": client_secret
        }
    )

@app.delete("/api/clients/{client_id}")
async def delete_client(client_id: str, user: Dict = Depends(require_login)):
    # 获取客户端信息
    client_info = get_client_info(client_id)
    
    # 检查客户端是否存在
    if not client_info:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"success": False, "message": "客户端不存在"}
        )
    
    # 检查用户是否是客户端的创建者
    if int(user["sub"]) != client_info["created_by"]:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"success": False, "message": "没有权限删除此客户端"}
        )
    
    # 删除客户端
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 首先删除与客户端相关的授权码和令牌
    cursor.execute('DELETE FROM auth_codes WHERE client_id = ?', (client_id,))
    cursor.execute('DELETE FROM tokens WHERE client_id = ?', (client_id,))
    
    # 然后删除客户端
    cursor.execute('DELETE FROM clients WHERE client_id = ?', (client_id,))
    
    conn.commit()
    conn.close()
    
    return {"success": True}
    
@app.put("/api/clients/{client_id}")
async def update_client(client_id: str, data: dict, user: Dict = Depends(require_login)):
    # 验证用户是否有权限修改此客户端
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 查询客户端信息
    cursor.execute('SELECT created_by FROM clients WHERE client_id = ?', (client_id,))
    client = cursor.fetchone()
    
    if not client:
        conn.close()
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"success": False, "message": "客户端不存在"}
        )
    
    if int(user["sub"]) != client[0]:
        conn.close()
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"success": False, "message": "没有权限修改此客户端"}
        )
    
    # 更新客户端信息
    try:
        cursor.execute('''
        UPDATE clients 
        SET client_name = ?, website = ?, description = ?
        WHERE client_id = ?
        ''', (data["name"], data["website"], data["description"], client_id))
        
        conn.commit()
        conn.close()
        
        return {"success": True}
    except Exception as e:
        conn.close()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": f"更新失败: {str(e)}"}
        )

@app.put("/api/clients/{client_id}/redirect")
async def update_redirect_uris(client_id: str, data: dict, user: Dict = Depends(require_login)):
    # 验证用户是否有权限修改此客户端
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 查询客户端信息
    cursor.execute('SELECT created_by FROM clients WHERE client_id = ?', (client_id,))
    client = cursor.fetchone()
    
    if not client:
        conn.close()
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"success": False, "message": "客户端不存在"}
        )
    
    if int(user["sub"]) != client[0]:
        conn.close()
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"success": False, "message": "没有权限修改此客户端"}
        )
    
    # 更新重定向URI
    try:
        cursor.execute('''
        UPDATE clients 
        SET redirect_uris = ?
        WHERE client_id = ?
        ''', (data["redirect_uris"], client_id))
        
        conn.commit()
        conn.close()
        
        return {"success": True}
    except Exception as e:
        conn.close()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": f"更新失败: {str(e)}"}
        )

@app.get("/logout")
async def logout(request: Request):
    if "user_token" in request.session:
        del request.session["user_token"]
    
    return RedirectResponse(
        url="/login",
        status_code=status.HTTP_302_FOUND
    )

@app.get("/")
async def root(request: Request):
    current_user = get_current_user(request)
    
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": current_user}
    )

# 启动服务器
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5001, reload=True)