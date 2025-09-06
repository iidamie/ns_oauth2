# main.py
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional, Dict, Any, List
import secrets
import json
from curl_cffi import requests # 使用指定的请求库
import sqlite3
from datetime import datetime, timedelta
import uvicorn
from pydantic import BaseModel
import jwt
from starlette.middleware.sessions import SessionMiddleware
import os
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import base64
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('oauth_system.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NS_OAuth2")

security = HTTPBasic(auto_error=False)

# 数据库路径
DB_PATH = os.environ.get('DB_PATH', 'oauth_db.sqlite')

# 全局配置变量（将从数据库读取）
SYSTEM_CONFIG = {
    'is_initialized': False,
    'cookie': None,
    'admin_id': None,
    'admin_name': None,
    'jwt_secret': None,
    'min_client_creation_rank': 1,
    'admin_users': []  # 存储管理员用户ID列表
}

JWT_ALGORITHM = "HS256"

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

class SystemConfigRequest(BaseModel):
    cookie: str
    admin_id: str
    admin_name: str
    min_client_creation_rank: int = 1
    admin_users: List[int] = []

class AdminUserRequest(BaseModel):
    user_id: int
    action: str  # 'add' 或 'remove'

# 数据库初始化
def init_db():
    logger.info("开始初始化数据库...")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 系统配置表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )
        ''')
        logger.debug("系统配置表已创建/检查")
        
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
        logger.debug("客户端表已创建/检查")
        
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
        logger.debug("验证码表已创建/检查")
        
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
        logger.debug("授权码表已创建/检查")
        
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
        logger.debug("令牌表已创建/检查")
        
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
        logger.debug("用户表已创建/检查")
        
        conn.commit()
        conn.close()
        logger.info("数据库初始化完成")
    except Exception as e:
        logger.error(f"数据库初始化失败: {str(e)}")
        raise

# 生成JWT密钥
def generate_jwt_secret():
    secret = secrets.token_urlsafe(64)
    logger.info("生成新的JWT密钥")
    return secret

# 确保JWT密钥存在
def ensure_jwt_secret():
    logger.info("检查JWT密钥...")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT value FROM system_config WHERE key = ?', ('jwt_secret',))
        result = cursor.fetchone()
        
        if not result:
            # 生成新的JWT密钥
            jwt_secret = generate_jwt_secret()
            now = datetime.now().isoformat()
            cursor.execute('''
            INSERT INTO system_config (key, value, updated_at)
            VALUES (?, ?, ?)
            ''', ('jwt_secret', jwt_secret, now))
            conn.commit()
            SYSTEM_CONFIG['jwt_secret'] = jwt_secret
            logger.info("JWT密钥已生成并保存")
        else:
            SYSTEM_CONFIG['jwt_secret'] = result[0]
            logger.info("JWT密钥已从数据库加载")
        
        conn.close()
    except Exception as e:
        logger.error(f"JWT密钥处理失败: {str(e)}")
        raise

# 加载系统配置
def load_system_config():
    logger.info("开始加载系统配置...")
    global SYSTEM_CONFIG
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT key, value FROM system_config')
        config_rows = cursor.fetchall()
        conn.close()
        
        if not config_rows:
            SYSTEM_CONFIG['is_initialized'] = False
            logger.info("系统未初始化 - 没有找到配置数据")
            return
        
        config_dict = dict(config_rows)
        SYSTEM_CONFIG.update({
            'is_initialized': config_dict.get('is_initialized', 'false').lower() == 'true',
            'cookie': config_dict.get('cookie'),
            'admin_id': config_dict.get('admin_id'),
            'admin_name': config_dict.get('admin_name'),
            'jwt_secret': config_dict.get('jwt_secret'),
            'min_client_creation_rank': int(config_dict.get('min_client_creation_rank', 1)),
            'admin_users': json.loads(config_dict.get('admin_users', '[]'))
        })
        
        logger.info(f"系统配置加载完成 - 初始化状态: {SYSTEM_CONFIG['is_initialized']}, 管理员数量: {len(SYSTEM_CONFIG['admin_users'])}, 最低等级要求: {SYSTEM_CONFIG['min_client_creation_rank']}")
        if SYSTEM_CONFIG['admin_id']:
            logger.info(f"接收方配置 - ID: {SYSTEM_CONFIG['admin_id']}, 名称: {SYSTEM_CONFIG['admin_name']}")
    except Exception as e:
        logger.error(f"加载系统配置失败: {str(e)}")
        raise

# 保存系统配置
def save_system_config():
    logger.info("开始保存系统配置...")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        config_items = [
            ('is_initialized', str(SYSTEM_CONFIG['is_initialized']).lower()),
            ('cookie', SYSTEM_CONFIG['cookie']),
            ('admin_id', SYSTEM_CONFIG['admin_id']),
            ('admin_name', SYSTEM_CONFIG['admin_name']),
            ('jwt_secret', SYSTEM_CONFIG['jwt_secret']),
            ('min_client_creation_rank', str(SYSTEM_CONFIG['min_client_creation_rank'])),
            ('admin_users', json.dumps(SYSTEM_CONFIG['admin_users']))
        ]
        
        for key, value in config_items:
            cursor.execute('''
            INSERT OR REPLACE INTO system_config (key, value, updated_at)
            VALUES (?, ?, ?)
            ''', (key, value, now))
            logger.debug(f"保存配置项: {key}")
        
        conn.commit()
        conn.close()
        logger.info("系统配置保存完成")
    except Exception as e:
        logger.error(f"保存系统配置失败: {str(e)}")
        raise

# 检查系统是否已初始化
def is_system_initialized():
    return SYSTEM_CONFIG['is_initialized']

# 检查用户是否是系统管理员
def is_system_admin(user_id: int) -> bool:
    is_admin = user_id in SYSTEM_CONFIG['admin_users']
    logger.debug(f"检查用户 {user_id} 是否为管理员: {is_admin}")
    return is_admin

# 检查消息是否发送的函数，使用curl_cffi库
def check_message_sent(user_id: str, verification_code: str = None) -> Dict[str, Any]:
    logger.info(f"检查用户 {user_id} 的消息{f' (验证码: {verification_code})' if verification_code else ' (获取用户信息)'}")
    
    if not SYSTEM_CONFIG['cookie']:
        logger.error("系统配置未完成 - Cookie为空")
        return {"success": False, "message": "系统配置未完成"}
    
    url = f"https://www.nodeseek.com/api/notification/message/with/{user_id}"
    headers = {
        'Cookie': SYSTEM_CONFIG['cookie']
    }
    
    try:
        # 使用curl_cffi库发送请求并指定impersonate参数
        logger.debug(f"向API发送请求: {url}")
        response = requests.get(url, headers=headers, impersonate="safari15_3")
        
        if response.status_code != 200:
            logger.error(f"API请求失败 - HTTP状态码: {response.status_code}")
            return {"success": False, "message": f"API请求失败，状态码: {response.status_code}"}
        
        data = json.loads(response.text)
        logger.debug(f"API响应状态: {data.get('success', False)}")
        
        if data.get("success"):
            talk_to = data.get("talkTo", {})
            if not talk_to:
                logger.error("API响应中没有talkTo数据")
                return {"success": False, "message": "无法获取用户信息"}
            
            # 如果不需要验证码检查，只是获取用户信息
            if verification_code is None:
                user_info = {
                    "member_id": talk_to["member_id"],
                    "member_name": talk_to["member_name"],
                    "rank": talk_to["rank"],
                    "coin": talk_to["coin"],
                    "bio": talk_to.get("bio", ""),
                    "created_at": talk_to.get("created_at", ""),
                    "isAdmin": talk_to.get("isAdmin", 0)
                }
                logger.info(f"获取用户信息成功: 用户名={user_info['member_name']}, 等级={user_info['rank']}, 积分={user_info['coin']}")
                return {
                    "success": True,
                    "user_info": user_info
                }
            
            # 检查是否有包含验证码的消息
            msg_array = data.get("msgArray", [])
            logger.info(f"检查 {len(msg_array)} 条消息中是否包含验证码 {verification_code}")
            
            found_message = False
            for i, msg in enumerate(msg_array):
                sender_id = msg.get("sender_id")
                receiver_id = msg.get("receiver_id")
                content = msg.get("content", "")
                
                logger.debug(f"消息 {i+1}: 发送者={sender_id}, 接收者={receiver_id}, 包含验证码={verification_code in content}")
                
                if (sender_id == int(user_id) and
                    receiver_id == int(SYSTEM_CONFIG['admin_id']) and
                    verification_code in content):
                    
                    found_message = True
                    user_info = {
                        "member_id": talk_to["member_id"],
                        "member_name": talk_to["member_name"],
                        "rank": talk_to["rank"],
                        "coin": talk_to["coin"],
                        "bio": talk_to.get("bio", ""),
                        "created_at": talk_to.get("created_at", ""),
                        "isAdmin": talk_to.get("isAdmin", 0)
                    }
                    logger.info(f"验证码验证成功: 用户={user_info['member_name']}, 验证码={verification_code}")
                    return {
                        "success": True,
                        "user_info": user_info
                    }
            
            if not found_message:
                logger.warning(f"未找到包含验证码 {verification_code} 的有效消息")
                logger.debug(f"期望: 发送者={user_id}, 接收者={SYSTEM_CONFIG['admin_id']}")
        else:
            logger.error(f"API请求失败: {data}")
        
        return {"success": False, "message": "验证码未发送或不匹配"}
    except json.JSONDecodeError as e:
        logger.error(f"API响应JSON解析失败: {str(e)}")
        return {"success": False, "message": "API响应格式错误"}
    except Exception as e:
        logger.error(f"API请求异常: {str(e)}")
        return {"success": False, "message": f"API请求失败: {str(e)}"}

# 使用临时Cookie验证用户ID（仅用于系统配置验证）
def check_user_with_cookie(user_id: str, cookie: str) -> Dict[str, Any]:
    logger.info(f"使用临时Cookie验证用户ID: {user_id}")
    url = f"https://www.nodeseek.com/api/notification/message/with/{user_id}"
    headers = {'Cookie': cookie}
    
    try:
        response = requests.get(url, headers=headers, impersonate="safari15_3")
        
        if response.status_code != 200:
            logger.error(f"用户ID验证失败 - HTTP状态码: {response.status_code}")
            return {"success": False, "message": f"请求失败，状态码: {response.status_code}"}
        
        data = json.loads(response.text)
        
        if data.get("success"):
            talk_to = data.get("talkTo", {})
            if talk_to.get("member_id") == int(user_id):
                logger.info(f"用户ID验证成功: {user_id} - {talk_to.get('member_name')}")
                return {"success": True, "user_info": talk_to}
        
        logger.warning(f"用户ID验证失败: {user_id} - API返回不匹配的用户信息")
        return {"success": False, "message": "无法验证用户ID"}
    except Exception as e:
        logger.error(f"用户ID验证异常: {str(e)}")
        return {"success": False, "message": f"验证失败: {str(e)}"}

# 验证客户端
def verify_client(client_id: str, redirect_uri: Optional[str] = None) -> bool:
    logger.debug(f"验证客户端: {client_id}, 重定向URI: {redirect_uri}")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        if redirect_uri:
            cursor.execute('SELECT redirect_uris FROM clients WHERE client_id = ?', (client_id,))
        else:
            cursor.execute('SELECT 1 FROM clients WHERE client_id = ?', (client_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            logger.warning(f"客户端不存在: {client_id}")
            return False
        
        if redirect_uri:
            allowed_uris = result[0].split(',')
            is_valid = redirect_uri in allowed_uris
            logger.debug(f"重定向URI验证结果: {is_valid}, 允许的URI: {allowed_uris}")
            return is_valid
        
        logger.debug(f"客户端验证成功: {client_id}")
        return True
    except Exception as e:
        logger.error(f"验证客户端时发生错误: {str(e)}")
        return False

# 验证客户端密钥
def verify_client_secret(client_id: str, client_secret: str) -> bool:
    logger.debug(f"验证客户端密钥: {client_id}")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT client_secret FROM clients WHERE client_id = ?', (client_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            logger.warning(f"客户端不存在（密钥验证）: {client_id}")
            return False
        
        is_valid = result[0] == client_secret
        logger.debug(f"客户端密钥验证结果: {is_valid}")
        return is_valid
    except Exception as e:
        logger.error(f"验证客户端密钥时发生错误: {str(e)}")
        return False

# 创建JWT会话令牌
def create_session_token(user_info: Dict[str, Any]) -> str:
    logger.debug(f"为用户 {user_info['member_name']} 创建会话令牌")
    try:
        if not SYSTEM_CONFIG['jwt_secret']:
            raise ValueError("JWT密钥未配置")
        
        payload = {
            "sub": str(user_info["member_id"]),
            "name": user_info["member_name"],
            "rank": user_info["rank"],
            "exp": datetime.utcnow() + timedelta(days=7)
        }
        token = jwt.encode(payload, SYSTEM_CONFIG['jwt_secret'], algorithm=JWT_ALGORITHM)
        logger.info(f"会话令牌创建成功: 用户={user_info['member_name']}")
        return token
    except Exception as e:
        logger.error(f"创建会话令牌失败: {str(e)}")
        raise

# 解析JWT会话令牌
def decode_session_token(token: str) -> Dict[str, Any]:
    try:
        if not SYSTEM_CONFIG['jwt_secret']:
            logger.warning("JWT密钥未配置，无法解析令牌")
            return None
        
        payload = jwt.decode(token, SYSTEM_CONFIG['jwt_secret'], algorithms=[JWT_ALGORITHM])
        logger.debug(f"会话令牌解析成功: 用户={payload.get('name')}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("会话令牌已过期")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"无效的会话令牌: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"解析会话令牌时发生错误: {str(e)}")
        return None

# 更新或保存用户信息
def save_user_info(user_info: Dict[str, Any]):
    logger.debug(f"保存用户信息: {user_info['member_name']} (ID: {user_info['member_id']})")
    try:
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
        logger.info(f"用户信息已保存: {user_info['member_name']}")
    except Exception as e:
        logger.error(f"保存用户信息失败: {str(e)}")
        raise

# 获取用户信息
def get_user_info(user_id: int) -> Optional[Dict[str, Any]]:
    logger.debug(f"获取用户信息: {user_id}")
    try:
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
            logger.debug(f"数据库中未找到用户信息: {user_id}")
            return None
        
        user_info = {
            "member_id": user[0],
            "member_name": user[1],
            "rank": user[2],
            "coin": user[3],
            "bio": user[4],
            "created_at": user[5]
        }
        logger.debug(f"从数据库获取用户信息成功: {user_info['member_name']}")
        return user_info
    except Exception as e:
        logger.error(f"获取用户信息时发生错误: {str(e)}")
        return None

# 获取客户端信息
def get_client_info(client_id: str) -> Optional[Dict[str, Any]]:
    logger.debug(f"获取客户端信息: {client_id}")
    try:
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
            logger.debug(f"客户端不存在: {client_id}")
            return None
        
        client_info = {
            "client_id": client[0],
            "client_name": client[1],
            "website": client[2],
            "description": client[3],
            "redirect_uris": client[4],
            "logo_url": client[5],
            "created_at": client[6],
            "created_by": client[7]
        }
        logger.debug(f"客户端信息获取成功: {client_info['client_name']}")
        return client_info
    except Exception as e:
        logger.error(f"获取客户端信息时发生错误: {str(e)}")
        return None

# 获取用户创建的客户端列表
def get_user_clients(user_id: int) -> List[Dict[str, Any]]:
    logger.debug(f"获取用户创建的客户端列表: {user_id}")
    try:
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
        
        client_list = [{
            "client_id": client[0],
            "client_name": client[1],
            "website": client[2],
            "description": client[3],
            "redirect_uris": client[4],
            "logo_url": client[5],
            "created_at": client[6]
        } for client in clients]
        
        logger.info(f"获取到用户 {user_id} 的 {len(client_list)} 个客户端")
        return client_list
    except Exception as e:
        logger.error(f"获取用户客户端列表时发生错误: {str(e)}")
        return []

# 获取已登录用户
def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    try:
        session = request.session
        if "user_token" not in session:
            return None
        
        user_data = decode_session_token(session["user_token"])
        if not user_data:
            return None
        
        return user_data
    except Exception as e:
        logger.error(f"获取当前用户时发生错误: {str(e)}")
        return None

# 需要登录的依赖项
def require_login(request: Request):
    user = get_current_user(request)
    if not user:
        logger.warning("访问需要登录的资源时用户未登录")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="需要登录",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.debug(f"用户已登录: {user['name']}")
    return user

# 需要系统管理员权限的依赖项
def require_admin(request: Request):
    user = require_login(request)
    if not is_system_admin(int(user["sub"])):
        logger.warning(f"用户 {user['name']} 尝试访问管理员功能但权限不足")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="需要系统管理员权限",
        )
    logger.debug(f"管理员权限验证通过: {user['name']}")
    return user

# 初始化数据库并确保JWT密钥存在
def startup_initialization():
    logger.info("开始系统启动初始化...")
    init_db()
    ensure_jwt_secret()  # 确保JWT密钥在启动时就存在
    load_system_config()
    logger.info("系统启动初始化完成")

# 创建应用实例
app = FastAPI(title="Nodeseek OAuth2 授权服务")

# 在应用启动时就添加会话中间件（使用JWT密钥）
startup_initialization()
app.add_middleware(
    SessionMiddleware,
    secret_key=SYSTEM_CONFIG['jwt_secret'],
    max_age=7 * 24 * 60 * 60,  # 7天会话有效期
)

# 配置模板和静态文件
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# 检查系统初始化状态的中间件
@app.middleware("http")
async def check_initialization(request: Request, call_next):
    # 排除系统配置相关的路径和静态文件
    excluded_paths = ["/setup", "/api/setup", "/static/"]
    
    if any(request.url.path.startswith(path) for path in excluded_paths):
        response = await call_next(request)
        return response
    
    # 如果系统未初始化，重定向到设置页面
    if not is_system_initialized():
        logger.debug(f"系统未初始化，重定向到设置页面: {request.url.path}")
        return RedirectResponse(url="/setup", status_code=status.HTTP_302_FOUND)
    
    response = await call_next(request)
    return response

# 系统配置相关路由
@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    logger.info("访问系统配置页面")
    
    # 如果系统已初始化，检查用户权限
    if is_system_initialized():
        try:
            user = require_admin(request)
            logger.info(f"管理员 {user['name']} 访问系统配置页面")
        except HTTPException:
            logger.warning("非管理员尝试访问已初始化的系统配置页面")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="系统已初始化，仅管理员可以访问配置页面"
            )
    else:
        logger.info("系统未初始化，允许访问配置页面")
    
    return templates.TemplateResponse(
        "setup.html",
        {
            "request": request,
            "is_initialized": is_system_initialized(),
            "config": SYSTEM_CONFIG if is_system_initialized() else {}
        }
    )

@app.post("/api/setup")
async def setup_system(request: Request, config: SystemConfigRequest):
    logger.info(f"收到系统配置请求 - 管理员ID: {config.admin_id}, 管理员名称: {config.admin_name}, 管理员用户数量: {len(config.admin_users)}")
    
    # 如果系统已初始化，检查用户权限
    if is_system_initialized():
        try:
            user = require_admin(request)
            logger.info(f"管理员 {user['name']} 正在修改系统配置")
        except HTTPException as e:
            logger.warning(f"非管理员尝试修改系统配置: {e.detail}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="系统已初始化，仅管理员可以修改配置"
            )
    
    # 使用临时Cookie验证管理员ID
    logger.info("验证管理员ID和Cookie...")
    check_result = check_user_with_cookie(config.admin_id, config.cookie)
    if not check_result["success"]:
        logger.error(f"管理员ID验证失败: {check_result['message']}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "无法验证管理员ID或Cookie无效，请检查Cookie权限和管理员ID是否正确"}
        )
    
    # 更新配置
    logger.info("更新系统配置...")
    old_initialized = SYSTEM_CONFIG['is_initialized']
    SYSTEM_CONFIG.update({
        'is_initialized': True,
        'cookie': config.cookie,
        'admin_id': config.admin_id,
        'admin_name': config.admin_name,
        'min_client_creation_rank': config.min_client_creation_rank,
        'admin_users': config.admin_users
    })
    
    # 确保设置的管理员ID在管理员列表中
    admin_id_int = int(config.admin_id)
    if admin_id_int not in SYSTEM_CONFIG['admin_users']:
        SYSTEM_CONFIG['admin_users'].append(admin_id_int)
        logger.info(f"将管理员ID {admin_id_int} 添加到管理员列表")
    
    # 保存配置到数据库
    save_system_config()
    
    # 如果是首次初始化，插入测试客户端
    if not old_initialized:
        logger.info("首次初始化，插入测试客户端...")
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
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
            logger.info("测试客户端插入完成")
        except Exception as e:
            logger.error(f"插入测试客户端失败: {str(e)}")
    
    logger.info("系统配置完成")
    return {"success": True, "message": "系统配置已保存"}

@app.post("/api/admin/users")
async def manage_admin_users(request: Request, data: AdminUserRequest, user: Dict = Depends(require_admin)):
    logger.info(f"管理员 {user['name']} 请求{data.action}管理员用户: {data.user_id}")
    
    if data.action == "add":
        if data.user_id not in SYSTEM_CONFIG['admin_users']:
            # 验证用户ID是否有效
            check_result = check_message_sent(str(data.user_id))
            if not check_result["success"]:
                logger.warning(f"无法验证新管理员用户ID: {data.user_id}")
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"success": False, "message": "无法验证用户ID，请检查ID是否正确"}
                )
            
            SYSTEM_CONFIG['admin_users'].append(data.user_id)
            save_system_config()
            logger.info(f"用户 {data.user_id} 已添加为管理员")
            return {"success": True, "message": f"用户 {data.user_id} 已添加为管理员"}
        else:
            logger.warning(f"用户 {data.user_id} 已经是管理员")
            return {"success": False, "message": "用户已经是管理员"}
    
    elif data.action == "remove":
        if data.user_id in SYSTEM_CONFIG['admin_users']:
            # 防止删除最后一个管理员
            if len(SYSTEM_CONFIG['admin_users']) <= 1:
                logger.warning(f"尝试删除最后一个管理员: {data.user_id}")
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"success": False, "message": "不能删除最后一个管理员"}
                )
            
            SYSTEM_CONFIG['admin_users'].remove(data.user_id)
            save_system_config()
            logger.info(f"用户 {data.user_id} 已从管理员列表中移除")
            return {"success": True, "message": f"用户 {data.user_id} 已从管理员列表中移除"}
        else:
            logger.warning(f"用户 {data.user_id} 不是管理员")
            return {"success": False, "message": "用户不是管理员"}
    
    else:
        logger.error(f"无效的管理员操作: {data.action}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "无效的操作"}
        )

# 路由实现
@app.on_event("startup")
def startup_event():
    logger.info("FastAPI应用启动事件")

@app.get("/oauth/authorize", response_class=HTMLResponse)
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str = "basic",
    state: str = None
):
    logger.info(f"收到OAuth授权请求 - 客户端: {client_id}, 响应类型: {response_type}, 作用域: {scope}")
    
    # 验证客户端和重定向URI
    if not verify_client(client_id, redirect_uri):
        logger.warning(f"客户端验证失败: {client_id}, 重定向URI: {redirect_uri}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "invalid_client", "error_description": "客户端未注册或重定向URI不被允许"}
        )
    
    if response_type not in ["code", "token"]:
        logger.warning(f"不支持的响应类型: {response_type}")
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
        logger.info(f"用户 {current_user['name']} 已登录，显示授权页面")
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
    logger.info("用户未登录，保存OAuth参数并重定向到登录页面")
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
    logger.info("访问登录页面")
    
    # 如果用户已登录，检查是否有待处理的OAuth请求
    current_user = get_current_user(request)
    if current_user and "oauth_params" in request.session:
        oauth_params = request.session["oauth_params"]
        del request.session["oauth_params"]
        logger.info(f"用户 {current_user['name']} 已登录且有待处理的OAuth请求，重定向到授权页面")
        # 重定向到授权页面
        redirect_url = "/oauth/authorize?" + "&".join([
            f"{k}={v}" for k, v in oauth_params.items() if v is not None
        ])
        return RedirectResponse(redirect_url, status_code=status.HTTP_302_FOUND)
    
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request, 
            "admin_id": SYSTEM_CONFIG['admin_id'],
            "admin_name": SYSTEM_CONFIG['admin_name']
        }
    )

@app.post("/oauth/verify")
async def verify_user(request: VerifyRequest):
    logger.info(f"收到验证码请求 - 用户ID: {request.user_id}")
    
    user_id = request.user_id
    if not user_id or not user_id.isdigit():
        logger.warning(f"无效的用户ID: {user_id}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "用户ID必须是数字"}
        )
    
    # 生成验证码
    verification_code = f"NS_AUTH_{secrets.token_hex(4).upper()}"
    logger.info(f"为用户 {user_id} 生成验证码: {verification_code}")
    
    # 存储验证码
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now = datetime.now()
        expires = now + timedelta(minutes=10)
        
        # 删除该用户的旧验证码
        cursor.execute('DELETE FROM verification_codes WHERE user_id = ?', (user_id,))
        cursor.execute('''
        INSERT INTO verification_codes (user_id, code, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        ''', (user_id, verification_code, now.isoformat(), expires.isoformat()))
        conn.commit()
        conn.close()
        
        logger.info(f"验证码已保存到数据库，有效期至: {expires}")
        
        return {
            "success": True,
            "verification_code": verification_code,
            "expires_in": 600
        }
    except Exception as e:
        logger.error(f"保存验证码时发生错误: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": "服务器内部错误"}
        )

@app.post("/oauth/confirm")
async def confirm_verification(request: Request, data: ConfirmRequest):
    logger.info(f"收到验证确认请求 - 用户ID: {data.user_id}, 验证码: {data.verification_code}")
    
    user_id = data.user_id
    verification_code = data.verification_code
    
    # 检查验证码是否有效
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        SELECT * FROM verification_codes
        WHERE user_id = ? AND code = ? AND expires_at > ?
        ''', (user_id, verification_code, datetime.now().isoformat()))
        code_record = cursor.fetchone()
        conn.close()
        
        if not code_record:
            logger.warning(f"验证码无效或已过期 - 用户ID: {user_id}, 验证码: {verification_code}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"success": False, "message": "验证码无效或已过期"}
            )
        
        # 检查消息是否已发送（保持原来的逻辑）
        check_result = check_message_sent(user_id, verification_code)
        if not check_result["success"]:
            logger.warning(f"验证码校验失败 - 用户ID: {user_id}, 原因: {check_result['message']}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=check_result
            )
        
        # 保存用户信息
        save_user_info(check_result["user_info"])
        
        # 创建用户会话
        user_token = create_session_token(check_result["user_info"])
        request.session["user_token"] = user_token
        logger.info(f"用户会话已创建 - 用户ID: {user_id}")
        
        # 检查是否有待处理的OAuth请求
        oauth_params = request.session.get("oauth_params")
        if oauth_params:
            # 清除会话中的OAuth参数
            del request.session["oauth_params"]
            logger.info(f"检测到待处理的OAuth请求，准备重定向到授权页面")
            # 返回成功并包含重定向信息
            return {
                "success": True,
                "user_info": check_result["user_info"],
                "redirect_to": "/oauth/authorize?" + "&".join([
                    f"{k}={v}" for k, v in oauth_params.items() if v is not None
                ])
            }
        
        # 普通登录成功
        logger.info(f"用户登录成功 - 用户: {check_result['user_info']['member_name']}")
        return {
            "success": True,
            "user_info": check_result["user_info"]
        }
    except Exception as e:
        logger.error(f"验证确认过程中发生错误: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": "服务器内部错误"}
        )

@app.post("/oauth/approve")
async def approve_authorization(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    response_type: str = Form(...),
    scope: str = Form(...),
    state: str = Form(None)
):
    logger.info(f"收到授权批准请求 - 客户端: {client_id}, 响应类型: {response_type}")
    
    # 检查用户是否已登录
    current_user = get_current_user(request)
    if not current_user:
        logger.warning("未登录用户尝试授权")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "unauthorized", "error_description": "用户未登录"}
        )
    
    user_id = current_user["sub"]
    logger.info(f"用户 {current_user['name']} 批准授权")
    
    # 获取客户端信息
    client_info = get_client_info(client_id)
    if not client_info:
        logger.error(f"客户端不存在: {client_id}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "invalid_client", "error_description": "客户端不存在"}
        )
    
    try:
        # 如果是授权码模式
        if response_type == "code":
            # 生成授权码
            auth_code = f"auth_{secrets.token_urlsafe(32)}"
            logger.debug(f"生成授权码: {auth_code}")
            
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
            
            logger.info(f"授权码模式授权成功 - 用户: {current_user['name']}, 客户端: {client_info['client_name']}")
            return {"success": True, "redirect_uri": redirect_url}
        
        # 如果是隐式授权模式
        elif response_type == "token":
            # 生成访问令牌
            access_token = f"access_{secrets.token_urlsafe(32)}"
            refresh_token = f"refresh_{secrets.token_urlsafe(32)}"
            logger.debug(f"生成访问令牌: {access_token}")
            
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
            
            logger.info(f"隐式授权模式授权成功 - 用户: {current_user['name']}, 客户端: {client_info['client_name']}")
            return {"success": True, "redirect_uri": redirect_url}
        
        else:
            logger.error(f"不支持的响应类型: {response_type}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "unsupported_response_type"}
            )
    except Exception as e:
        logger.error(f"授权批准过程中发生错误: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "server_error", "error_description": "服务器内部错误"}
        )

@app.post("/oauth/deny")
async def deny_authorization(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(None)
):
    current_user = get_current_user(request)
    logger.info(f"用户{'(' + current_user['name'] + ')' if current_user else '(未知)'} 拒绝授权 - 客户端: {client_id}")
    
    # 构建重定向URL
    redirect_url = f"{redirect_uri}?error=access_denied"
    if state:
        redirect_url += f"&state={state}"
    
    return {"success": True, "redirect_uri": redirect_url}

@app.post("/oauth/token")
async def token_endpoint(
    request: Request,
    grant_type: str = Form(None),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    refresh_token: str = Form(None),
    authorization: str = Header(None),
    credentials: HTTPBasicCredentials = Depends(security)
):
    logger.info(f"收到令牌请求 - 授权类型: {grant_type}")
    
    # 提取客户端凭据 - 支持多种认证方式
    extracted_client_id = None
    extracted_client_secret = None
    
    # 方式1: 表单参数认证
    if client_id and client_secret:
        extracted_client_id = client_id
        extracted_client_secret = client_secret
        logger.debug("使用表单参数认证")
    # 方式2: HTTP Basic 认证
    elif authorization and authorization.startswith("Basic "):
        try:
            decoded = base64.b64decode(authorization[6:]).decode("utf-8")
            extracted_client_id, extracted_client_secret = decoded.split(":", 1)
            logger.debug("使用HTTP Basic认证")
        except Exception:
            pass
    # 方式3: FastAPI 的 HTTPBasic 依赖项
    elif credentials:
        extracted_client_id = credentials.username
        extracted_client_secret = credentials.password
        logger.debug("使用HTTPBasic依赖项认证")
    # 方式4: JSON 请求体
    elif request.headers.get("content-type", "").lower() == "application/json":
        try:
            body = await request.json()
            # 如果请求体中有必要的字段，则从中提取
            extracted_client_id = body.get("client_id")
            extracted_client_secret = body.get("client_secret")
            # 从JSON请求体中提取其他字段
            grant_type = body.get("grant_type", grant_type)
            code = body.get("code", code)
            redirect_uri = body.get("redirect_uri", redirect_uri)
            refresh_token = body.get("refresh_token", refresh_token)
            logger.debug("使用JSON请求体认证")
        except:
            pass
    
    # 客户端认证验证
    if not extracted_client_id or not extracted_client_secret:
        logger.warning("客户端身份验证失败 - 缺少客户端凭据")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid_client", "error_description": "客户端身份验证失败"}
        )
    
    # 验证客户端凭据
    if not verify_client_secret(extracted_client_id, extracted_client_secret):
        logger.warning(f"客户端认证失败 - 客户端: {extracted_client_id}")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid_client", "error_description": "客户端认证失败"}
        )
    
    try:
        # 授权码模式
        if grant_type == "authorization_code":
            logger.debug("处理授权码模式令牌请求")
            if not code or not redirect_uri:
                logger.warning("授权码模式缺少必要参数")
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
            ''', (code, extracted_client_id, redirect_uri, datetime.now().isoformat()))
            code_record = cursor.fetchone()
            
            if not code_record:
                conn.close()
                logger.warning(f"授权码无效或已过期 - 代码: {code}")
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
            new_refresh_token = f"refresh_{secrets.token_urlsafe(32)}"
            
            # 存储令牌
            now = datetime.now()
            expires = now + timedelta(hours=1)
            cursor.execute('''
            INSERT INTO tokens (access_token, refresh_token, client_id, user_id, scope, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (access_token, new_refresh_token, extracted_client_id, user_id, scope, expires.isoformat()))
            conn.commit()
            conn.close()
            
            logger.info(f"授权码换取令牌成功 - 用户ID: {user_id}, 客户端: {extracted_client_id}")
            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": new_refresh_token,
                "scope": scope
            }
        
        # 刷新令牌
        elif grant_type == "refresh_token":
            logger.debug("处理刷新令牌请求")
            if not refresh_token:
                logger.warning("刷新令牌模式缺少刷新令牌")
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "invalid_request", "error_description": "刷新令牌必须提供"}
                )
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
            SELECT user_id, scope FROM tokens
            WHERE refresh_token = ? AND client_id = ?
            ''', (refresh_token, extracted_client_id))
            token_record = cursor.fetchone()
            
            if not token_record:
                conn.close()
                logger.warning(f"刷新令牌无效 - 客户端: {extracted_client_id}")
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
            ''', (access_token, new_refresh_token, extracted_client_id, user_id, scope, expires.isoformat()))
            conn.commit()
            conn.close()
            
            logger.info(f"刷新令牌成功 - 用户ID: {user_id}, 客户端: {extracted_client_id}")
            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": new_refresh_token,
                "scope": scope
            }
        
        else:
            logger.warning(f"不支持的授权类型: {grant_type}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "unsupported_grant_type", "error_description": "仅支持授权码和刷新令牌授权类型"}
            )
    except Exception as e:
        logger.error(f"令牌端点处理过程中发生错误: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "server_error", "error_description": "服务器内部错误"}
        )

@app.get("/api/user/info")
async def user_info_endpoint(request: Request):
    logger.debug("收到用户信息请求")
    
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.warning("用户信息请求缺少有效的Authorization头")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "invalid_token", "error_description": "缺少或无效的Authorization头"}
        )
    
    token = auth_header.split(" ")[1]
    
    try:
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
            logger.warning("无效或已过期的访问令牌")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "invalid_token", "error_description": "令牌无效或已过期"}
            )
        
        user_id = token_record[0]
        scope = token_record[1]
        logger.debug(f"令牌验证成功 - 用户ID: {user_id}, 作用域: {scope}")
        
        # 获取用户信息
        user_info = get_user_info(user_id)
        if not user_info:
            # 尝试从API获取
            check_result = check_message_sent(str(user_id))
            if check_result["success"]:
                user_info = check_result["user_info"]
                save_user_info(user_info)
                logger.info(f"从API获取并保存用户信息: {user_info['member_name']}")
            else:
                logger.error(f"无法获取用户信息 - 用户ID: {user_id}")
                return JSONResponse(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content={"error": "user_not_found", "error_description": "用户信息不可用"}
                )
        
        # 根据作用域过滤信息
        if scope == "basic":
            result = {
                "member_id": user_info["member_id"],
                "member_name": user_info["member_name"],
                "rank": user_info["rank"]
            }
        elif scope == "profile":
            result = user_info
        else:
            result = {
                "member_id": user_info["member_id"],
                "member_name": user_info["member_name"],
                "rank": user_info["rank"]
            }
        
        logger.info(f"返回用户信息 - 用户: {user_info['member_name']}, 作用域: {scope}")
        return result
    except Exception as e:
        logger.error(f"获取用户信息时发生错误: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "server_error", "error_description": "服务器内部错误"}
        )

@app.get("/clients", response_class=HTMLResponse)
async def clients_page(request: Request, user: Dict = Depends(require_login)):
    logger.info(f"用户 {user['name']} 访问客户端管理页面")
    
    # 检查用户等级是否满足创建客户端的要求
    if int(user["rank"]) < SYSTEM_CONFIG['min_client_creation_rank']:
        logger.info(f"用户 {user['name']} 等级不足 (当前: {user['rank']}, 需要: {SYSTEM_CONFIG['min_client_creation_rank']})")
        return templates.TemplateResponse(
            "clients_denied.html",
            {
                "request": request,
                "user": user,
                "min_rank": SYSTEM_CONFIG['min_client_creation_rank']
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
    logger.info(f"用户 {user['name']} 访问创建客户端页面")
    
    # 检查用户等级是否满足创建客户端的要求
    if int(user["rank"]) < SYSTEM_CONFIG['min_client_creation_rank']:
        logger.warning(f"用户 {user['name']} 等级不足，重定向到客户端列表页面")
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
    logger.info(f"用户 {user['name']} 请求创建客户端: {client_data.name}")
    
    # 检查用户等级是否满足创建客户端的要求
    if int(user["rank"]) < SYSTEM_CONFIG['min_client_creation_rank']:
        logger.warning(f"用户 {user['name']} 等级不足，拒绝创建客户端")
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"success": False, "message": f"创建客户端需要等级 {SYSTEM_CONFIG['min_client_creation_rank']} 或更高"}
        )
    
    # 验证输入
    if not client_data.name or not client_data.website or not client_data.redirect_uris:
        logger.warning(f"用户 {user['name']} 创建客户端时缺少必要字段")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "所有必填字段都需要填写"}
        )
    
    try:
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
        
        logger.info(f"客户端创建成功 - ID: {client_id}, 名称: {client_data.name}, 创建者: {user['name']}")
        
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
    except Exception as e:
        logger.error(f"创建客户端时发生错误: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": "服务器内部错误"}
        )

@app.get("/clients/{client_id}", response_class=HTMLResponse)
async def client_details_page(request: Request, client_id: str, user: Dict = Depends(require_login)):
    logger.info(f"用户 {user['name']} 访问客户端详情: {client_id}")
    
    # 获取客户端信息
    client_info = get_client_info(client_id)
    
    # 检查客户端是否存在
    if not client_info:
        logger.warning(f"客户端不存在: {client_id}")
        return RedirectResponse("/clients", status_code=status.HTTP_302_FOUND)
    
    # 检查用户是否是客户端的创建者
    if int(user["sub"]) != client_info["created_by"]:
        logger.warning(f"用户 {user['name']} 尝试访问非自己创建的客户端: {client_id}")
        return RedirectResponse("/clients", status_code=status.HTTP_302_FOUND)
    
    try:
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
    except Exception as e:
        logger.error(f"获取客户端详情时发生错误: {str(e)}")
        return RedirectResponse("/clients", status_code=status.HTTP_302_FOUND)

@app.delete("/api/clients/{client_id}")
async def delete_client(client_id: str, user: Dict = Depends(require_login)):
    logger.info(f"用户 {user['name']} 请求删除客户端: {client_id}")
    
    # 获取客户端信息
    client_info = get_client_info(client_id)
    
    # 检查客户端是否存在
    if not client_info:
        logger.warning(f"尝试删除不存在的客户端: {client_id}")
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"success": False, "message": "客户端不存在"}
        )
    
    # 检查用户是否是客户端的创建者
    if int(user["sub"]) != client_info["created_by"]:
        logger.warning(f"用户 {user['name']} 尝试删除非自己创建的客户端: {client_id}")
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"success": False, "message": "没有权限删除此客户端"}
        )
    
    try:
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
        
        logger.info(f"客户端删除成功: {client_id} ({client_info['client_name']})")
        return {"success": True}
    except Exception as e:
        logger.error(f"删除客户端时发生错误: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": "服务器内部错误"}
        )

@app.put("/api/clients/{client_id}")
async def update_client(client_id: str, data: dict, user: Dict = Depends(require_login)):
    logger.info(f"用户 {user['name']} 请求更新客户端: {client_id}")
    
    # 验证用户是否有权限修改此客户端
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 查询客户端信息
        cursor.execute('SELECT created_by FROM clients WHERE client_id = ?', (client_id,))
        client = cursor.fetchone()
        
        if not client:
            conn.close()
            logger.warning(f"尝试更新不存在的客户端: {client_id}")
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"success": False, "message": "客户端不存在"}
            )
        
        if int(user["sub"]) != client[0]:
            conn.close()
            logger.warning(f"用户 {user['name']} 尝试更新非自己创建的客户端: {client_id}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"success": False, "message": "没有权限修改此客户端"}
            )
        
        # 更新客户端信息
        cursor.execute('''
        UPDATE clients
        SET client_name = ?, website = ?, description = ?
        WHERE client_id = ?
        ''', (data["name"], data["website"], data["description"], client_id))
        conn.commit()
        conn.close()
        
        logger.info(f"客户端更新成功: {client_id}")
        return {"success": True}
    except Exception as e:
        logger.error(f"更新客户端时发生错误: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": f"更新失败: {str(e)}"}
        )

@app.put("/api/clients/{client_id}/redirect")
async def update_redirect_uris(client_id: str, data: dict, user: Dict = Depends(require_login)):
    logger.info(f"用户 {user['name']} 请求更新客户端重定向URI: {client_id}")
    
    # 验证用户是否有权限修改此客户端
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 查询客户端信息
        cursor.execute('SELECT created_by FROM clients WHERE client_id = ?', (client_id,))
        client = cursor.fetchone()
        
        if not client:
            conn.close()
            logger.warning(f"尝试更新不存在客户端的重定向URI: {client_id}")
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"success": False, "message": "客户端不存在"}
            )
        
        if int(user["sub"]) != client[0]:
            conn.close()
            logger.warning(f"用户 {user['name']} 尝试更新非自己创建的客户端重定向URI: {client_id}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"success": False, "message": "没有权限修改此客户端"}
            )
        
        # 更新重定向URI
        cursor.execute('''
        UPDATE clients
        SET redirect_uris = ?
        WHERE client_id = ?
        ''', (data["redirect_uris"], client_id))
        conn.commit()
        conn.close()
        
        logger.info(f"客户端重定向URI更新成功: {client_id}")
        return {"success": True}
    except Exception as e:
        logger.error(f"更新客户端重定向URI时发生错误: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": f"更新失败: {str(e)}"}
        )

@app.get("/logout")
async def logout(request: Request):
    user = get_current_user(request)
    logger.info(f"用户{'(' + user['name'] + ')' if user else '(未知)'} 退出登录")
    
    if "user_token" in request.session:
        del request.session["user_token"]
    return RedirectResponse(
        url="/login",
        status_code=status.HTTP_302_FOUND
    )

@app.get("/")
async def root(request: Request):
    current_user = get_current_user(request)
    logger.debug(f"访问首页 - 用户: {current_user['name'] if current_user else '未登录'}")
    
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": current_user}
    )

# 启动服务器
if __name__ == "__main__":
    logger.info("启动OAuth2授权服务器...")
    uvicorn.run("main:app", host="0.0.0.0", port=5001, reload=True)