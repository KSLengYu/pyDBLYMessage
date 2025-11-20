from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from supabase import create_client, Client
from typing import Optional, Dict, Any
import hashlib
import smtplib
from email.mime.text import MIMEText
import random
import string
from datetime import datetime, timedelta
import uuid
from user_agents import parse
from dotenv import load_dotenv
import os
import requests  # 已在requirements.txt中，无需额外安装

# 加载环境变量（本地测试用，Vercel部署时在平台配置）
load_dotenv()

# 初始化FastAPI应用（Vercel部署需指定应用名称为app）
app = FastAPI(title="Message Board", version="1.0.1")

# 挂载静态文件（前端HTML放在static目录）
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="static")

# 初始化Supabase客户端（关键：从环境变量读取配置）
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("请配置SUPABASE_URL和SUPABASE_KEY环境变量")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------------- 多邮箱SMTP配置（6个邮箱：5个网易+1个QQ，随机选择发送）----------------------
# 环境变量格式：SMTP_HOST_1~6、SMTP_PORT_1~6、SMTP_USER_1~6、SMTP_PASS_1~6
SMTP_CONFIGS = []
for i in range(1, 7):  # 1-6 对应6个邮箱
    host = os.getenv(f"SMTP_HOST_{i}")
    port = os.getenv(f"SMTP_PORT_{i}")
    user = os.getenv(f"SMTP_USER_{i}")
    password = os.getenv(f"SMTP_PASS_{i}")
    if host and port and user and password:
        SMTP_CONFIGS.append({
            "host": host,
            "port": int(port),
            "user": user,
            "password": password
        })

if not SMTP_CONFIGS:
    raise ValueError("请至少配置一个SMTP邮箱（SMTP_HOST_1~6等环境变量）")

# ---------------------- 工具函数 ----------------------
# 密码加密（SHA256，安全存储）
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# 生成6位数字验证码（邮箱验证用）
def generate_verification_code(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))

# 发送邮箱验证码（随机选择一个配置的邮箱）
def send_verification_email(email: str, code: str):
    # 随机选择一个SMTP配置（从6个中选1个）
    smtp_config = random.choice(SMTP_CONFIGS)
    subject = "【留言板】邮箱验证验证码"
    content = f"""
    <html>
        <body style="background: #f5f5f5; padding: 20px; font-family: Arial, sans-serif;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #333; margin-bottom: 20px; text-align: center;">邮箱验证</h2>
                <p style="color: #666; line-height: 1.6;">您正在注册留言板账号，您的验证码为：</p>
                <div style="font-size: 24px; font-weight: bold; color: #2196F3; text-align: center; margin: 20px 0; padding: 10px; border: 1px solid #eee; border-radius: 4px;">
                    {code}
                </div>
                <p style="color: #999; font-size: 14px; text-align: center;">验证码有效期15分钟，请尽快完成验证</p>
                <p style="color: #999; font-size: 12px; margin-top: 30px;">本邮件由系统自动发送，请勿回复</p>
            </div>
        </body>
    </html>
    """
    msg = MIMEText(content, "html", "utf-8")
    msg["From"] = smtp_config["user"]  # 随机选择的发件人邮箱
    msg["To"] = email
    msg["Subject"] = subject

    # 使用选中的邮箱发送（支持网易/QQ混合配置）
    with smtplib.SMTP(smtp_config["host"], smtp_config["port"]) as server:
        server.starttls()  # 开启TLS加密（兼容所有邮箱）
        server.login(smtp_config["user"], smtp_config["password"])
        server.send_message(msg)

# 获取用户真实IP（适配Vercel反向代理）
def get_client_ip(request: Request) -> str:
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()  # 取第一个IP（避免代理转发多IP）
    return request.client.host  # 本地测试时直接获取IP

# ---------------------- IP定位逻辑（无需密钥，使用ip-api.com免费接口）----------------------
def get_location_from_ip(ip: str) -> str:
    try:
        # 免费无密钥接口：ip-api.com（支持IPv4/IPv6，无需注册）
        response = requests.get(
            f"http://ip-api.com/json/{ip}?lang=zh-CN",  # lang=zh-CN返回中文结果
            timeout=5  # 超时5秒，避免卡顿时长
        )
        data = response.json()
        
        if data["status"] == "success":
            if data["country"] == "中国":
                # 国内：中国 + 省份 + 城市（兼容无省份/城市的情况）
                province = data.get("regionName", "")
                city = data.get("city", "")
                return f"中国 {province} {city}".strip()
            else:
                # 国外：国家 + 城市
                country = data.get("country", "")
                city = data.get("city", "")
                return f"{country} {city}".strip()
        else:
            return "未知位置"
    except Exception as e:
        print(f"IP定位失败：{e}")
        return "未知位置"

# 解析设备型号（例：iPhone16/Android/PC）
def get_device_model(user_agent: str) -> str:
    ua = parse(user_agent)
    if ua.is_mobile:
        # 手机设备（优先显示具体型号）
        if ua.device.brand and ua.device.model:
            return f"{ua.device.brand} {ua.device.model}".strip()
        elif "iPhone" in user_agent:
            return "iPhone16" if "iPhone 16" in user_agent else "iPhone17"  # 适配用户需求
        else:
            return "Android 设备"
    elif ua.is_tablet:
        return "平板设备"
    elif ua.is_pc:
        return "PC 设备"
    else:
        return "未知设备"

# ---------------------- 依赖项（权限控制） ----------------------
# 获取当前登录用户（通过Cookie中的session_id）
def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None  # 未登录
    # 从Supabase查询用户信息（包含角色）
    response = supabase.table("users").select("*, roles(name)").eq("id", session_id).single()
    if response.error or not response.data:
        return None  # 会话失效或用户不存在
    return response.data

# 验证主管理员权限（仅super_admin可访问）
def require_super_admin(current_user: Dict[str, Any] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未登录")
    if current_user["roles"]["name"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="无主管理员权限")

# 验证管理员权限（super_admin/admin可访问）
def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未登录")
    if current_user["roles"]["name"] not in ["super_admin", "admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="无管理员权限")

# ---------------------- 核心接口 ----------------------
# 首页（留言板主体 + 侧边更新日志）
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, current_user: Optional[Dict[str, Any]] = Depends(get_current_user)):
    # 1. 获取所有有效留言（未撤回 + 按时间倒序）
    messages_response = supabase.table("messages").select("*").eq("is_withdrawn", False).order("created_at", desc=True).execute()
    messages = messages_response.data if not messages_response.error else []

    # 2. 为每条留言补充用户信息（昵称、头像、管理员认证勾）
    for msg in messages:
        if msg["user_id"]:
            # 已登录用户留言：查询用户信息
            user_response = supabase.table("users").select("nickname, qq_nickname, qq_avatar, roles(name)").eq("id", msg["user_id"]).single()
            if user_response.data:
                user = user_response.data
                # 优先显示QQ昵称，无则显示注册昵称
                msg["username"] = user.get("qq_nickname") or user["nickname"]
                # 优先显示QQ头像，无则用默认头像
                msg["avatar"] = user.get("qq_avatar") or "https://via.placeholder.com/40/2196F3/ffffff?text=U"
                # 管理员认证勾（super_admin/admin显示蓝色勾）
                msg["is_verified"] = user["roles"]["name"] in ["super_admin", "admin"]
        else:
            # 游客留言：默认信息
            msg["username"] = "游客"
            msg["avatar"] = "https://via.placeholder.com/40/9E9E9E/ffffff?text=G"
            msg["is_verified"] = False

    # 3. 获取更新日志（按时间倒序）
    logs_response = supabase.table("update_logs").select("*").order("created_at", desc=True).execute()
    logs = logs_response.data if not logs_response.error else []

    # 4. 渲染首页HTML
    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": current_user,  # 当前登录用户信息（未登录为None）
        "messages": messages,          # 留言列表
        "logs": logs                   # 更新日志
    })

# 登录页
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# 登录接口（邮箱 + 密码验证）
@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    # 1. 验证用户是否存在 + 密码正确
    password_hash = hash_password(password)
    user_response = supabase.table("users").select("*, roles(name)").eq("email", email).eq("password_hash", password_hash).single()
    
    if not user_response.data:
        return JSONResponse(status_code=400, content={"detail": "邮箱或密码错误"})
    
    user = user_response.data

    # 2. 验证邮箱是否已验证
    if not user["email_verified"]:
        return JSONResponse(status_code=400, content={"detail": "邮箱未验证，请先验证邮箱"})

    # 3. 验证账号是否被封禁
    if user["banned"]:
        return JSONResponse(status_code=403, content={"detail": "账号已被封禁，无法登录"})

    # 4. 登录成功：设置session_id Cookie（有效期7天）
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="session_id", value=user["id"], max_age=3600*24*7, httponly=True)
    return response

# 注册页
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

# 注册接口：发送邮箱验证码
@app.post("/register/send-code")
async def send_register_code(email: str = Form(...)):
    # 1. 检查邮箱是否已注册
    user_response = supabase.table("users").select("id").eq("email", email).single()
    if user_response.data:
        return JSONResponse(status_code=400, content={"detail": "该邮箱已注册"})
    
    # 2. 生成验证码 + 设置过期时间（15分钟）
    code = generate_verification_code()
    code_expires = datetime.now() + timedelta(minutes=15)

    # 3. 存储验证码到用户表（未注册用户先插入临时记录）
    response = supabase.table("users").upsert({
        "email": email,
        "verification_code": code,
        "code_expires_at": code_expires.isoformat(),
        "nickname": f"用户{random.randint(1000, 9999)}"  # 临时昵称（注册时可修改）
    }).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "验证码发送失败，请重试"})

    # 4. 发送验证码到邮箱（随机选择6个邮箱中的一个）
    try:
        send_verification_email(email, code)
        return JSONResponse(content={"detail": "验证码已发送至您的邮箱，请查收"})
    except Exception as e:
        print(f"邮箱发送失败：{e}")
        return JSONResponse(status_code=500, content={"detail": "验证码发送失败，请检查邮箱是否正确"})

# 注册接口：完成注册（验证验证码 + 设置昵称/密码）
@app.post("/register/complete")
async def complete_register(
    email: str = Form(...),
    code: str = Form(...),
    nickname: str = Form(...),
    password: str = Form(...)
):
    # 1. 验证验证码有效性
    user_response = supabase.table("users").select("id, verification_code, code_expires_at").eq("email", email).single()
    if not user_response.data:
        return JSONResponse(status_code=400, content={"detail": "验证码无效"})
    
    user = user_response.data
    # 检查验证码是否匹配 + 是否过期
    if user["verification_code"] != code or datetime.fromisoformat(user["code_expires_at"]) < datetime.now():
        return JSONResponse(status_code=400, content={"detail": "验证码已过期或无效"})

    # 2. 验证密码长度（至少6位）
    if len(password) < 6:
        return JSONResponse(status_code=400, content={"detail": "密码长度至少6位"})

    # 3. 加密密码 + 更新用户信息（完成注册）
    password_hash = hash_password(password)
    response = supabase.table("users").update({
        "password_hash": password_hash,
        "nickname": nickname,
        "email_verified": True,
        "verification_code": None,  # 清空验证码
        "code_expires_at": None
    }).eq("email", email).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "注册失败，请重试"})

    # 4. 注册成功：跳转登录页
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

# 个人主页（改密码 + QQ绑定/解绑）
@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    # 未登录则跳转登录页
    if not current_user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "current_user": current_user  # 传递当前用户信息（QQ绑定状态、昵称等）
    })

# 个人主页：修改密码
@app.post("/profile/change-password")
async def change_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if not current_user:
        return JSONResponse(status_code=401, content={"detail": "未登录"})

    # 1. 验证旧密码是否正确
    old_password_hash = hash_password(old_password)
    user_response = supabase.table("users").select("id").eq("id", current_user["id"]).eq("password_hash", old_password_hash).single()
    if not user_response.data:
        return JSONResponse(status_code=400, content={"detail": "旧密码错误"})

    # 2. 验证新密码长度
    if len(new_password) < 6:
        return JSONResponse(status_code=400, content={"detail": "新密码长度至少6位"})

    # 3. 更新新密码
    new_password_hash = hash_password(new_password)
    response = supabase.table("users").update({"password_hash": new_password_hash}).eq("id", current_user["id"]).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "密码修改失败"})
    return JSONResponse(content={"detail": "密码修改成功"})

# 个人主页：绑定QQ（手动输入QQ信息）
@app.post("/profile/bind-qq")
async def bind_qq(
    qq_number: str = Form(...),
    qq_nickname: str = Form(...),
    qq_avatar: str = Form(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if not current_user:
        return JSONResponse(status_code=401, content={"detail": "未登录"})

    # 1. 检查QQ号是否已被绑定
    user_response = supabase.table("users").select("id").eq("qq_number", qq_number).single()
    if user_response.data and user_response.data["id"] != current_user["id"]:
        return JSONResponse(status_code=400, content={"detail": "该QQ号已被其他账号绑定"})

    # 2. 更新QQ绑定信息
    response = supabase.table("users").update({
        "qq_number": qq_number,
        "qq_nickname": qq_nickname,
        "qq_avatar": qq_avatar
    }).eq("id", current_user["id"]).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "QQ绑定失败"})
    return JSONResponse(content={"detail": "QQ绑定成功"})

# 个人主页：解绑QQ
@app.post("/profile/unbind-qq")
async def unbind_qq(current_user: Dict[str, Any] = Depends(get_current_user)):
    if not current_user:
        return JSONResponse(status_code=401, content={"detail": "未登录"})

    # 清空QQ绑定信息
    response = supabase.table("users").update({
        "qq_number": None,
        "qq_nickname": None,
        "qq_avatar": None
    }).eq("id", current_user["id"]).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "QQ解绑失败"})
    return JSONResponse(content={"detail": "QQ解绑成功"})

# ---------------------- 关键修复：调整send_message函数参数顺序 ----------------------
# 错误原因：有默认值的参数（parent_id、current_user）必须放在无默认值参数（content、request）后面
@app.post("/message/send")
async def send_message(
    content: str = Form(...),  # 无默认值 → 放在前面
    request: Request,          # 无默认值 → 放在前面
    parent_id: Optional[str] = Form(None),  # 有默认值 → 放在后面
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user)  # 有默认值 → 放在后面
):
    # 1. 验证留言内容不为空
    if not content.strip():
        return JSONResponse(status_code=400, content={"detail": "留言内容不能为空"})

    # 2. 游客限制：每日最多5条留言
    user_id = current_user["id"] if current_user else None
    if not user_id:
        ip = get_client_ip(request)
        # 检查该IP今日留言次数
        guest_response = supabase.table("guest_limits").select("*").eq("ip_address", ip).single()
        if guest_response.data:
            # 已超过5条：拒绝发送
            if guest_response.data["message_count"] >= 5:
                return JSONResponse(status_code=403, content={"detail": "游客每日限发5条留言"})
            # 未超过：次数+1
            supabase.table("guest_limits").update({
                "message_count": guest_response.data["message_count"] + 1
            }).eq("ip_address", ip).execute()
        else:
            # 首次留言：创建记录
            supabase.table("guest_limits").insert({
                "ip_address": ip,
                "message_count": 1
            }).execute()

    # 3. 获取IP定位和设备型号
    ip = get_client_ip(request)
    location = get_location_from_ip(ip)  # 调用修改后的定位函数
    device_model = get_device_model(request.headers.get("user-agent", ""))

    # 4. 插入留言到数据库
    response = supabase.table("messages").insert({
        "user_id": user_id,
        "parent_id": parent_id,
        "content": content.strip(),
        "ip_address": ip,
        "location": location,
        "device_model": device_model
    }).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "留言发布失败"})
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

# 留言接口：撤回留言（仅本人可撤回）
@app.post("/message/withdraw/{message_id}")
async def withdraw_message(
    message_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if not current_user:
        return JSONResponse(status_code=401, content={"detail": "未登录"})

    # 1. 验证留言是否存在 + 是否为本人发布
    message_response = supabase.table("messages").select("user_id").eq("id", message_id).single()
    if not message_response.data:
        return JSONResponse(status_code=404, content={"detail": "留言不存在"})
    if message_response.data["user_id"] != current_user["id"]:
        return JSONResponse(status_code=403, content={"detail": "无权限撤回该留言"})

    # 2. 标记留言为撤回
    response = supabase.table("messages").update({"is_withdrawn": True}).eq("id", message_id).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "留言撤回失败"})
    return JSONResponse(content={"detail": "留言已撤回"})

# 留言接口：折叠/展开留言（仅管理员可操作）
@app.post("/message/collapse/{message_id}")
async def collapse_message(
    message_id: str,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    # 1. 验证留言是否存在
    message_response = supabase.table("messages").select("is_collapsed").eq("id", message_id).single()
    if not message_response.data:
        return JSONResponse(status_code=404, content={"detail": "留言不存在"})

    # 2. 切换折叠状态（折叠↔展开）
    new_state = not message_response.data["is_collapsed"]
    response = supabase.table("messages").update({"is_collapsed": new_state}).eq("id", message_id).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": f"留言{ '折叠' if new_state else '展开' }失败"})
    return JSONResponse(content={"detail": f"留言已{ '折叠' if new_state else '展开' }"})

# 留言接口：删除留言（仅管理员可操作）
@app.post("/message/delete/{message_id}")
async def delete_message(
    message_id: str,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    # 1. 验证留言是否存在
    message_response = supabase.table("messages").select("id").eq("id", message_id).single()
    if not message_response.data:
        return JSONResponse(status_code=404, content={"detail": "留言不存在"})

    # 2. 删除留言（级联删除子回复）
    response = supabase.table("messages").delete().eq("id", message_id).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "留言删除失败"})
    return JSONResponse(content={"detail": "留言已删除"})

# 管理员接口：封禁账号（仅管理员可操作）
@app.post("/user/ban/{user_id}")
async def ban_user(
    user_id: str,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    # 1. 不能封禁自己
    if user_id == current_user["id"]:
        return JSONResponse(status_code=400, content={"detail": "不能封禁自己"})

    # 2. 验证用户是否存在
    user_response = supabase.table("users").select("id").eq("id", user_id).single()
    if not user_response.data:
        return JSONResponse(status_code=404, content={"detail": "用户不存在"})

    # 3. 封禁账号（设置banned=True）
    response = supabase.table("users").update({"banned": True}).eq("id", user_id).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "账号封禁失败"})
    return JSONResponse(content={"detail": "账号已封禁"})

# 主管理员接口：设置管理员（仅主管理员可操作）
@app.post("/user/set-admin/{user_id}")
async def set_admin(
    user_id: str,
    current_user: Dict[str, Any] = Depends(require_super_admin)
):
    # 1. 不能设置自己（已是主管理员）
    if user_id == current_user["id"]:
        return JSONResponse(status_code=400, content={"detail": "无需为自己设置管理员权限"})

    # 2. 验证用户是否存在
    user_response = supabase.table("users").select("id").eq("id", user_id).single()
    if not user_response.data:
        return JSONResponse(status_code=404, content={"detail": "用户不存在"})

    # 3. 获取管理员角色ID（roles表中name=admin的id）
    role_response = supabase.table("roles").select("id").eq("name", "admin").single()
    if not role_response.data:
        return JSONResponse(status_code=500, content={"detail": "管理员角色不存在"})
    admin_role_id = role_response.data["id"]

    # 4. 设置用户为管理员
    response = supabase.table("users").update({"role_id": admin_role_id}).eq("id", user_id).execute()

    if response.error:
        return JSONResponse(status_code=500, content={"detail": "设置管理员失败"})
    return JSONResponse(content={"detail": "已成功设置为管理员"})

# 更新日志页（单独访问入口）
@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    logs_response = supabase.table("update_logs").select("*").order("created_at", desc=True).execute()
    logs = logs_response.data if not logs_response.error else []
    return templates.TemplateResponse("logs.html", {"request": request, "logs": logs})

# 退出登录
@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="session_id")  # 清除session_id
    return response

# Vercel部署入口（必须包含，否则部署失败）
if __name__ == "__main__":
    import uvicorn
    # 监听0.0.0.0，端口使用Vercel提供的环境变量PORT
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 3000)))