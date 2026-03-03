from fastapi import FastAPI, Query, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import httpx
import time
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import os
import json
import secrets
import hashlib
import hmac
import re
from collections import defaultdict
import uuid
import csv
import io
import aiofiles
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field, validator
import logging
from logging.handlers import RotatingFileHandler
import redis.asyncio as redis
from cachetools import TTLCache
from tenacity import retry, stop_after_attempt, wait_exponential
import sqlite3
import pytz
import psutil
import platform

# ===== LOGGING SETUP =====
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("global-osint")

# ===== LIFESPAN MANAGEMENT =====
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Global Telegram OSINT Starting...")
    app.state.start_time = datetime.now(pytz.UTC)
    app.state.requests_processed = 0
    
    # Initialize cache
    app.state.cache = TTLCache(maxsize=1000, ttl=300)
    
    # Initialize Redis if available
    try:
        app.state.redis = await redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379"),
            decode_responses=True
        )
        await app.state.redis.ping()
        logger.info("✅ Redis connected")
    except:
        app.state.redis = None
        logger.warning("⚠️ Redis not available")
    
    yield
    
    # Shutdown
    if app.state.redis:
        await app.state.redis.close()
    logger.info("👋 Shutting down...")

app = FastAPI(
    title="🌍 GLOBAL TELEGRAM OSINT - World's Most Advanced",
    description="Kisi bhi country ka Telegram ID se mobile number, location, device, aur bhi bahut kuch | By @Antyrx",
    version="6.0.0",
    lifespan=lifespan
)

# ===== CORS =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== MODELS =====
class LookupRequest(BaseModel):
    query: str = Field(..., description="Telegram ID or Username", min_length=1, max_length=100)
    key: str = Field(..., description="API Key")
    format: str = Field("json", description="Response format (json/csv)")
    webhook: Optional[str] = Field(None, description="Webhook URL for async results")

class BulkLookupRequest(BaseModel):
    queries: List[str] = Field(..., description="List of Telegram IDs", max_items=50)
    key: str = Field(..., description="API Key")

class KeyRequest(BaseModel):
    username: str = Field(..., description="Telegram username", min_length=3)
    tier: str = Field("free", description="free/premium/enterprise")
    purpose: Optional[str] = Field(None, description="Purpose of API usage")

# ===== SECURITY =====
security = HTTPBearer(auto_error=False)

# ===== OWNER CONFIGURATION =====
OWNER_USERNAME = "@Antyrx"
OWNER_IDS = ["antyrx", "Antyrx", "ANTYRX"]
MASTER_KEY = os.getenv("MASTER_KEY", "ANTYRX-OSINT")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))

# ===== DATABASE SETUP =====
def init_db():
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id TEXT PRIMARY KEY, username TEXT, tier TEXT, 
                  key TEXT UNIQUE, created_at TEXT, expires_at TEXT,
                  requests INTEGER DEFAULT 0, last_request TEXT)''')
    
    # Requests log
    c.execute('''CREATE TABLE IF NOT EXISTS requests
                 (id TEXT PRIMARY KEY, user_id TEXT, query TEXT,
                  success BOOLEAN, response_time REAL, timestamp TEXT,
                  ip TEXT, user_agent TEXT)''')
    
    # API Keys table
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys
                 (key TEXT PRIMARY KEY, user_id TEXT, tier TEXT,
                  created_at TEXT, expires_at TEXT, max_requests INTEGER,
                  requests_used INTEGER DEFAULT 0, active BOOLEAN DEFAULT 1)''')
    
    conn.commit()
    conn.close()

init_db()

# ===== API KEY MANAGER =====
class AdvancedKeyManager:
    def __init__(self):
        self.master_key = MASTER_KEY
        self.cache = TTLCache(maxsize=500, ttl=60)
        self.rate_limits = {
            "free": {"per_minute": 5, "per_hour": 50, "per_day": 100},
            "premium": {"per_minute": 30, "per_hour": 500, "per_day": 2000},
            "enterprise": {"per_minute": 100, "per_hour": 2000, "per_day": 10000},
            "owner": {"per_minute": 1000, "per_hour": 50000, "per_day": 1000000}
        }
    
    async def validate_key(self, key: str, ip: str) -> tuple:
        """Advanced key validation with caching"""
        
        # Check cache first
        cache_key = f"key:{key}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        conn = sqlite3.connect('osint.db')
        c = conn.cursor()
        
        try:
            # Master key check
            if key == self.master_key:
                result = (True, "owner", "Master key", float('inf'), None)
                self.cache[cache_key] = result
                return result
            
            # Check in database
            c.execute("""SELECT tier, expires_at, max_requests, requests_used, active 
                        FROM api_keys WHERE key = ?""", (key,))
            row = c.fetchone()
            
            if not row:
                return (False, None, "Invalid API key", 0, None)
            
            tier, expires_at, max_requests, requests_used, active = row
            
            if not active:
                return (False, None, "Key is deactivated", 0, None)
            
            if expires_at and datetime.fromisoformat(expires_at) < datetime.now():
                return (False, None, "Key expired", 0, None)
            
            if requests_used >= max_requests:
                return (False, None, f"Request limit reached ({max_requests})", 0, None)
            
            # Check rate limits from Redis if available
            if app.state.redis:
                minute_key = f"rate:{key}:minute"
                minute_count = await app.state.redis.get(minute_key)
                if minute_count and int(minute_count) >= self.rate_limits[tier]["per_minute"]:
                    return (False, None, "Rate limit exceeded (per minute)", 0, None)
            
            result = (True, tier, "Valid", max_requests - requests_used, expires_at)
            self.cache[cache_key] = result
            return result
            
        finally:
            conn.close()
    
    async def increment_usage(self, key: str):
        """Increment key usage"""
        conn = sqlite3.connect('osint.db')
        c = conn.cursor()
        
        try:
            c.execute("""UPDATE api_keys 
                        SET requests_used = requests_used + 1,
                            last_request = ?
                        WHERE key = ?""", 
                     (datetime.now().isoformat(), key))
            conn.commit()
            
            # Update Redis rate limit
            if app.state.redis:
                minute_key = f"rate:{key}:minute"
                await app.state.redis.incr(minute_key)
                await app.state.redis.expire(minute_key, 60)
                
        finally:
            conn.close()
        
        # Clear cache
        cache_key = f"key:{key}"
        if cache_key in self.cache:
            del self.cache[cache_key]
    
    async def generate_key(self, tier: str, username: str, requester: str = "owner") -> dict:
        """Generate new API key"""
        key = f"ANTYRX-{secrets.token_urlsafe(16)}-{tier.upper()}"
        user_id = str(uuid.uuid4())
        
        expires_at = None
        if tier == "free":
            expires_at = (datetime.now() + timedelta(days=30)).isoformat()
            max_requests = 1000
        elif tier == "premium":
            expires_at = (datetime.now() + timedelta(days=90)).isoformat()
            max_requests = 10000
        else:  # enterprise
            expires_at = (datetime.now() + timedelta(days=365)).isoformat()
            max_requests = 100000
        
        conn = sqlite3.connect('osint.db')
        c = conn.cursor()
        
        try:
            # Insert user
            c.execute("""INSERT INTO users (id, username, tier, key, created_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                     (user_id, username, tier, key, datetime.now().isoformat(), expires_at))
            
            # Insert key
            c.execute("""INSERT INTO api_keys (key, user_id, tier, created_at, expires_at, max_requests)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                     (key, user_id, tier, datetime.now().isoformat(), expires_at, max_requests))
            
            conn.commit()
            
            return {
                "success": True,
                "key": key,
                "tier": tier,
                "expires": expires_at,
                "max_requests": max_requests,
                "message": "Keep this key safe! It won't be shown again"
            }
            
        finally:
            conn.close()

key_manager = AdvancedKeyManager()

# ===== MULTI-API FETCHER =====
class MultiAPIFetcher:
    def __init__(self):
        self.apis = [
            {
                "name": "Primary API",
                "url": "http://api.subhxcosmo.in/api",
                "params": {"key": "INTELX2", "type": "sms"},
                "priority": 1,
                "timeout": 10
            },
            {
                "name": "Backup API 1",
                "url": "https://api.telegram-osint.com/lookup",
                "params": {"apikey": "PUBLIC"},
                "priority": 2,
                "timeout": 8
            },
            {
                "name": "Backup API 2",
                "url": "https://tg-intel.com/api/v1/search",
                "params": {"token": "free"},
                "priority": 3,
                "timeout": 5
            }
        ]
        self.country_db = self.load_country_db()
    
    def load_country_db(self):
        """Load country database"""
        return {
            "india": {"code": "+91", "regex": r"^(?:\+?91|0)?[6-9]\d{9}$", "name": "India", "flag": "🇮🇳"},
            "canada": {"code": "+1", "regex": r"^(?:\+?1|0)?[2-9]\d{9}$", "name": "Canada", "flag": "🇨🇦"},
            "usa": {"code": "+1", "regex": r"^(?:\+?1|0)?[2-9]\d{9}$", "name": "USA", "flag": "🇺🇸"},
            "uk": {"code": "+44", "regex": r"^(?:\+?44|0)?[1-9]\d{9}$", "name": "United Kingdom", "flag": "🇬🇧"},
            "australia": {"code": "+61", "regex": r"^(?:\+?61|0)?[2-9]\d{8}$", "name": "Australia", "flag": "🇦🇺"},
            "germany": {"code": "+49", "regex": r"^(?:\+?49|0)?[1-9]\d{10}$", "name": "Germany", "flag": "🇩🇪"},
            "france": {"code": "+33", "regex": r"^(?:\+?33|0)?[1-9]\d{8}$", "name": "France", "flag": "🇫🇷"},
            "russia": {"code": "+7", "regex": r"^(?:\+?7|8)?[1-9]\d{9}$", "name": "Russia", "flag": "🇷🇺"},
            "china": {"code": "+86", "regex": r"^(?:\+?86|0)?[1-9]\d{9}$", "name": "China", "flag": "🇨🇳"},
            "japan": {"code": "+81", "regex": r"^(?:\+?81|0)?[1-9]\d{8,9}$", "name": "Japan", "flag": "🇯🇵"},
            "brazil": {"code": "+55", "regex": r"^(?:\+?55|0)?[1-9]\d{10}$", "name": "Brazil", "flag": "🇧🇷"},
            "uae": {"code": "+971", "regex": r"^(?:\+?971|0)?[1-9]\d{8}$", "name": "UAE", "flag": "🇦🇪"},
            "saudi": {"code": "+966", "regex": r"^(?:\+?966|0)?[1-9]\d{8}$", "name": "Saudi Arabia", "flag": "🇸🇦"},
            "pakistan": {"code": "+92", "regex": r"^(?:\+?92|0)?[1-9]\d{9}$", "name": "Pakistan", "flag": "🇵🇰"},
            "bangladesh": {"code": "+880", "regex": r"^(?:\+?880|0)?[1-9]\d{9}$", "name": "Bangladesh", "flag": "🇧🇩"},
            "sri_lanka": {"code": "+94", "regex": r"^(?:\+?94|0)?[1-9]\d{8}$", "name": "Sri Lanka", "flag": "🇱🇰"},
            "nepal": {"code": "+977", "regex": r"^(?:\+?977|0)?[1-9]\d{8}$", "name": "Nepal", "flag": "🇳🇵"}
        }
    
    def detect_country(self, number: str) -> dict:
        """Detect country from phone number"""
        clean_number = re.sub(r'\D', '', number)
        
        for country, info in self.country_db.items():
            if re.match(info["regex"], clean_number):
                return {
                    "country": info["name"],
                    "code": info["code"],
                    "flag": info["flag"],
                    "detected": True
                }
        
        return {
            "country": "Unknown",
            "code": "Unknown",
            "flag": "🌍",
            "detected": False
        }
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def call_api(self, api: dict, query: str) -> dict:
        """Call individual API with retry logic"""
        async with httpx.AsyncClient(timeout=api["timeout"]) as client:
            params = api["params"].copy()
            params["term"] = query
            
            try:
                logger.info(f"🌐 Calling {api['name']} for {query}")
                response = await client.get(api["url"], params=params)
                
                if response.status_code == 200:
                    return {
                        "success": True,
                        "data": response.json(),
                        "api": api["name"]
                    }
                else:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}",
                        "api": api["name"]
                    }
                    
            except Exception as e:
                logger.error(f"❌ {api['name']} failed: {str(e)}")
                return {
                    "success": False,
                    "error": str(e),
                    "api": api["name"]
                }
    
    async def lookup(self, query: str) -> dict:
        """Multi-API lookup with fallback"""
        
        # Sort APIs by priority
        sorted_apis = sorted(self.apis, key=lambda x: x["priority"])
        
        for api in sorted_apis:
            result = await self.call_api(api, query)
            
            if result["success"]:
                data = result["data"]
                
                # Parse response based on API format
                if api["name"] == "Primary API":
                    parsed = self.parse_primary_response(data, query)
                else:
                    parsed = self.parse_generic_response(data, query)
                
                if parsed.get("success"):
                    parsed["api_used"] = api["name"]
                    return parsed
        
        # All APIs failed
        return {
            "success": False,
            "error": "All APIs failed",
            "query": query,
            "suggestion": "Try again later or contact @Antyrx"
        }
    
    def parse_primary_response(self, data: dict, query: str) -> dict:
        """Parse Primary API response"""
        if data.get("success"):
            result = data.get("result", {})
            
            if result and result.get("msg") != "Telegram ID missing":
                formatted = {
                    "success": True,
                    "data": {
                        "telegram": {
                            "id": result.get("telegram_id", query),
                            "username": result.get("username", "N/A"),
                            "first_name": result.get("first_name", "N/A"),
                            "last_name": result.get("last_name", "N/A"),
                            "verified": result.get("verified", False)
                        }
                    }
                }
                
                # Phone number
                phone = result.get("phone")
                if phone:
                    country_info = self.detect_country(phone)
                    formatted["data"]["phone"] = {
                        "number": phone,
                        "international": f"+{phone}" if not phone.startswith('+') else phone,
                        "country": country_info["country"],
                        "country_code": country_info["code"],
                        "flag": country_info["flag"]
                    }
                
                # Additional data
                if result.get("bio"):
                    formatted["data"]["bio"] = result["bio"]
                if result.get("photo"):
                    formatted["data"]["photo"] = result["photo"]
                
                return formatted
        
        return {"success": False}
    
    def parse_generic_response(self, data: dict, query: str) -> dict:
        """Parse generic API response"""
        # Implement based on your backup APIs structure
        return {"success": False}

fetcher = MultiAPIFetcher()

# ===== RATE LIMITER WITH REDIS =====
class AdvancedRateLimiter:
    def __init__(self):
        self.local_limits = defaultdict(list)
    
    async def check(self, key: str, ip: str, tier: str) -> tuple:
        """Check rate limits with Redis support"""
        limits = key_manager.rate_limits[tier]
        
        if app.state.redis:
            # Use Redis for distributed rate limiting
            minute_key = f"rate:{key}:minute"
            hour_key = f"rate:{key}:hour"
            day_key = f"rate:{key}:day"
            
            minute_count = await app.state.redis.get(minute_key) or 0
            hour_count = await app.state.redis.get(hour_key) or 0
            day_count = await app.state.redis.get(day_key) or 0
            
            if int(minute_count) >= limits["per_minute"]:
                return False, "Rate limit exceeded (per minute)"
            if int(hour_count) >= limits["per_hour"]:
                return False, "Rate limit exceeded (per hour)"
            if int(day_count) >= limits["per_day"]:
                return False, "Rate limit exceeded (per day)"
            
            # Increment counters
            await app.state.redis.incr(minute_key)
            await app.state.redis.expire(minute_key, 60)
            await app.state.redis.incr(hour_key)
            await app.state.redis.expire(hour_key, 3600)
            await app.state.redis.incr(day_key)
            await app.state.redis.expire(day_key, 86400)
            
        else:
            # Fallback to local rate limiting
            now = time.time()
            key_ip = f"{key}:{ip}"
            
            # Clean old requests
            self.local_limits[key_ip] = [t for t in self.local_limits[key_ip] 
                                        if t > now - 86400]
            
            minute_count = len([t for t in self.local_limits[key_ip] if t > now - 60])
            hour_count = len([t for t in self.local_limits[key_ip] if t > now - 3600])
            day_count = len(self.local_limits[key_ip])
            
            if minute_count >= limits["per_minute"]:
                return False, "Rate limit exceeded (per minute)"
            if hour_count >= limits["per_hour"]:
                return False, "Rate limit exceeded (per hour)"
            if day_count >= limits["per_day"]:
                return False, "Rate limit exceeded (per day)"
            
            self.local_limits[key_ip].append(now)
        
        remaining = limits["per_minute"] - (int(minute_count) + 1)
        return True, f"{remaining} remaining"

rate_limiter = AdvancedRateLimiter()

# ===== MIDDLEWARE =====
@app.middleware("http")
async def middleware(request: Request, call_next):
    start = time.time()
    
    # Log request
    logger.info(f"📨 {request.method} {request.url.path} from {request.client.host}")
    
    response = await call_next(request)
    
    # Add headers
    process_time = (time.time() - start) * 1000
    response.headers["X-Response-Time"] = f"{process_time:.0f}ms"
    response.headers["X-Powered-By"] = "Antyrx's Global OSINT"
    
    # Update stats
    app.state.requests_processed += 1
    
    return response

# ===== OWNER AUTH =====
async def verify_owner(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or auth != f"Bearer {MASTER_KEY}":
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "error": "Only @Antyrx can access this",
                "message": "Ye endpoint sirf owner ke liye hai"
            }
        )
    return True

# ===== WEBSITE HOMEPAGE =====
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    uptime = datetime.now(pytz.UTC) - app.state.start_time
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>🌍 GLOBAL TELEGRAM OSINT - World's Most Advanced</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="World's Most Advanced Telegram OSINT Tool - Kisi bhi country ka Telegram ID se mobile number nikaalo">
        <meta name="keywords" content="telegram osint, telegram to phone, osint tool, telegram lookup, global osint">
        <meta name="author" content="@Antyrx">
        
        <style>
            :root {{
                --primary: #00ffff;
                --secondary: #4a90e2;
                --dark: #0a0a0a;
                --darker: #000000;
                --light: #ffffff;
                --success: #00ff88;
                --danger: #ff4444;
                --warning: #ffbb33;
            }}
            
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #000428 0%, #004e92 100%);
                color: white;
                min-height: 100vh;
                overflow-x: hidden;
            }}
            
            /* Animated Background */
            #particles-js {{
                position: fixed;
                width: 100%;
                height: 100%;
                top: 0;
                left: 0;
                z-index: 0;
            }}
            
            .globe {{
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                width: 800px;
                height: 800px;
                background: radial-gradient(circle, rgba(0,255,255,0.1) 0%, transparent 70%);
                border-radius: 50%;
                animation: rotate 60s linear infinite;
                z-index: 0;
                pointer-events: none;
            }}
            
            @keyframes rotate {{
                from {{ transform: translate(-50%, -50%) rotate(0deg); }}
                to {{ transform: translate(-50%, -50%) rotate(360deg); }}
            }}
            
            .container {{
                position: relative;
                z-index: 2;
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
            }}
            
            /* Navbar */
            .navbar {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 20px 0;
                margin-bottom: 40px;
                background: rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(10px);
                border-radius: 50px;
                padding: 15px 30px;
                border: 1px solid rgba(0, 255, 255, 0.2);
            }}
            
            .logo {{
                font-size: 28px;
                font-weight: bold;
                background: linear-gradient(45deg, #fff, var(--primary));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                animation: glow 2s ease-in-out infinite alternate;
            }}
            
            @keyframes glow {{
                from {{ text-shadow: 0 0 10px cyan; }}
                to {{ text-shadow: 0 0 20px cyan, 0 0 30px blue; }}
            }}
            
            .nav-links {{
                display: flex;
                gap: 30px;
                align-items: center;
            }}
            
            .nav-links a {{
                color: white;
                text-decoration: none;
                transition: 0.3s;
            }}
            
            .nav-links a:hover {{
                color: var(--primary);
            }}
            
            .owner-badge {{
                background: linear-gradient(45deg, gold, orange);
                color: black;
                padding: 8px 20px;
                border-radius: 25px;
                font-weight: bold;
                display: flex;
                align-items: center;
                gap: 5px;
            }}
            
            /* Hero Section */
            .hero {{
                text-align: center;
                padding: 60px 20px;
                background: rgba(255, 255, 255, 0.03);
                backdrop-filter: blur(10px);
                border-radius: 30px;
                margin-bottom: 40px;
                border: 1px solid rgba(0, 255, 255, 0.2);
            }}
            
            .hero h1 {{
                font-size: 52px;
                margin-bottom: 20px;
                background: linear-gradient(45deg, #fff, var(--primary));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            
            .hero p {{
                font-size: 18px;
                color: #ccc;
                max-width: 800px;
                margin: 0 auto;
                line-height: 1.6;
            }}
            
            /* Stats */
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 30px;
                margin: 50px 0;
            }}
            
            .stat-card {{
                background: rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(10px);
                padding: 30px;
                border-radius: 20px;
                text-align: center;
                border: 1px solid rgba(0, 255, 255, 0.2);
                transition: 0.3s;
                animation: float 3s ease-in-out infinite;
            }}
            
            .stat-card:hover {{
                transform: translateY(-10px);
                border-color: var(--primary);
                box-shadow: 0 10px 30px rgba(0, 255, 255, 0.2);
            }}
            
            @keyframes float {{
                0%, 100% {{ transform: translateY(0); }}
                50% {{ transform: translateY(-10px); }}
            }}
            
            .stat-number {{
                font-size: 42px;
                font-weight: bold;
                color: var(--primary);
                margin-bottom: 10px;
            }}
            
            .stat-label {{
                color: #ccc;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            
            /* Search Box */
            .search-container {{
                background: rgba(255, 255, 255, 0.03);
                backdrop-filter: blur(10px);
                border-radius: 30px;
                padding: 40px;
                margin: 40px 0;
                border: 1px solid rgba(0, 255, 255, 0.2);
            }}
            
            .search-header {{
                text-align: center;
                margin-bottom: 30px;
            }}
            
            .search-header h2 {{
                font-size: 32px;
                color: var(--primary);
                margin-bottom: 10px;
            }}
            
            .search-header p {{
                color: #ccc;
            }}
            
            .search-tabs {{
                display: flex;
                gap: 10px;
                justify-content: center;
                margin-bottom: 30px;
            }}
            
            .search-tab {{
                padding: 10px 30px;
                border-radius: 25px;
                background: rgba(255, 255, 255, 0.05);
                cursor: pointer;
                transition: 0.3s;
                border: 1px solid transparent;
            }}
            
            .search-tab.active {{
                background: var(--primary);
                color: black;
                border-color: var(--primary);
            }}
            
            .search-tab:hover {{
                border-color: var(--primary);
            }}
            
            .input-group {{
                display: flex;
                gap: 15px;
                max-width: 800px;
                margin: 0 auto;
            }}
            
            .input-group input {{
                flex: 1;
                padding: 20px 30px;
                border: none;
                border-radius: 50px;
                background: rgba(255, 255, 255, 0.1);
                color: white;
                font-size: 16px;
                border: 1px solid rgba(0, 255, 255, 0.3);
                transition: 0.3s;
            }}
            
            .input-group input:focus {{
                outline: none;
                border-color: var(--primary);
                box-shadow: 0 0 20px rgba(0, 255, 255, 0.3);
            }}
            
            .input-group button {{
                padding: 20px 50px;
                border: none;
                border-radius: 50px;
                background: linear-gradient(45deg, var(--primary), var(--secondary));
                color: white;
                font-weight: bold;
                font-size: 16px;
                cursor: pointer;
                transition: 0.3s;
                position: relative;
                overflow: hidden;
            }}
            
            .input-group button:hover {{
                transform: scale(1.05);
                box-shadow: 0 5px 30px var(--primary);
            }}
            
            .input-group button:active {{
                transform: scale(0.95);
            }}
            
            .input-group button.loading::after {{
                content: '';
                position: absolute;
                width: 20px;
                height: 20px;
                border: 2px solid white;
                border-top-color: transparent;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                right: 20px;
                top: 50%;
                transform: translateY(-50%);
            }}
            
            @keyframes spin {{
                to {{ transform: translateY(-50%) rotate(360deg); }}
            }}
            
            /* Country Tags */
            .country-cloud {{
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                justify-content: center;
                margin: 30px 0;
            }}
            
            .country-tag {{
                background: rgba(0, 255, 255, 0.1);
                padding: 8px 20px;
                border-radius: 25px;
                font-size: 14px;
                border: 1px solid rgba(0, 255, 255, 0.3);
                transition: 0.3s;
                cursor: default;
            }}
            
            .country-tag:hover {{
                background: rgba(0, 255, 255, 0.2);
                transform: scale(1.05);
            }}
            
            /* Result Box */
            .result-box {{
                background: rgba(0, 0, 0, 0.5);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                padding: 30px;
                margin: 30px 0;
                border-left: 4px solid var(--primary);
                display: none;
            }}
            
            .result-box.show {{
                display: block;
                animation: slideIn 0.5s ease;
            }}
            
            @keyframes slideIn {{
                from {{
                    opacity: 0;
                    transform: translateY(20px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
            
            .result-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 20px;
                border-bottom: 2px solid rgba(0, 255, 255, 0.2);
            }}
            
            .result-badge {{
                background: var(--primary);
                color: black;
                padding: 5px 15px;
                border-radius: 20px;
                font-weight: bold;
            }}
            
            .result-actions {{
                display: flex;
                gap: 10px;
            }}
            
            .result-action {{
                background: rgba(255, 255, 255, 0.1);
                padding: 8px 15px;
                border-radius: 15px;
                cursor: pointer;
                transition: 0.3s;
                font-size: 14px;
            }}
            
            .result-action:hover {{
                background: var(--primary);
                color: black;
            }}
            
            .result-content {{
                display: grid;
                gap: 20px;
            }}
            
            .info-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
            }}
            
            .info-card {{
                background: rgba(255, 255, 255, 0.05);
                padding: 20px;
                border-radius: 15px;
            }}
            
            .info-card h4 {{
                color: var(--primary);
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .info-item {{
                margin-bottom: 10px;
            }}
            
            .info-label {{
                color: #888;
                font-size: 12px;
                text-transform: uppercase;
                margin-bottom: 3px;
            }}
            
            .info-value {{
                font-size: 16px;
                word-break: break-word;
            }}
            
            .phone-number {{
                font-size: 24px;
                color: var(--success);
                font-weight: bold;
            }}
            
            .country-flag {{
                display: inline-block;
                padding: 3px 8px;
                border-radius: 5px;
                background: var(--primary);
                color: black;
                font-size: 12px;
                margin-left: 10px;
            }}
            
            /* Key Management Section */
            .key-section {{
                background: rgba(255, 255, 255, 0.03);
                border-radius: 20px;
                padding: 40px;
                margin: 40px 0;
                text-align: center;
            }}
            
            .key-tiers {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 30px;
                margin: 40px 0;
            }}
            
            .tier-card {{
                background: rgba(255, 255, 255, 0.05);
                padding: 30px;
                border-radius: 20px;
                border: 1px solid rgba(0, 255, 255, 0.2);
                transition: 0.3s;
            }}
            
            .tier-card:hover {{
                transform: translateY(-10px);
                border-color: var(--primary);
            }}
            
            .tier-card.free:hover {{
                border-color: #4a90e2;
            }}
            
            .tier-card.premium:hover {{
                border-color: gold;
            }}
            
            .tier-card.enterprise:hover {{
                border-color: var(--primary);
            }}
            
            .tier-name {{
                font-size: 24px;
                margin-bottom: 15px;
            }}
            
            .tier-price {{
                font-size: 36px;
                font-weight: bold;
                margin-bottom: 20px;
                color: var(--primary);
            }}
            
            .tier-features {{
                list-style: none;
                margin-bottom: 30px;
            }}
            
            .tier-features li {{
                margin-bottom: 10px;
                color: #ccc;
            }}
            
            .tier-features i {{
                color: var(--success);
                margin-right: 10px;
            }}
            
            .tier-btn {{
                background: linear-gradient(45deg, var(--primary), var(--secondary));
                color: white;
                border: none;
                padding: 12px 30px;
                border-radius: 25px;
                cursor: pointer;
                transition: 0.3s;
                width: 100%;
                font-weight: bold;
            }}
            
            .tier-btn:hover {{
                transform: scale(1.05);
            }}
            
            .key-form {{
                max-width: 600px;
                margin: 0 auto;
            }}
            
            .key-input-group {{
                display: flex;
                gap: 15px;
                margin: 20px 0;
            }}
            
            .key-input-group input,
            .key-input-group select {{
                flex: 1;
                padding: 15px;
                border-radius: 10px;
                border: 1px solid rgba(0, 255, 255, 0.3);
                background: rgba(0, 0, 0, 0.3);
                color: white;
            }}
            
            .key-input-group select option {{
                background: #333;
            }}
            
            /* Features */
            .features-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 30px;
                margin: 60px 0;
            }}
            
            .feature-card {{
                background: rgba(255, 255, 255, 0.03);
                padding: 40px 30px;
                border-radius: 20px;
                text-align: center;
                border: 1px solid rgba(0, 255, 255, 0.2);
                transition: 0.3s;
            }}
            
            .feature-card:hover {{
                transform: translateY(-10px);
                border-color: var(--primary);
                box-shadow: 0 10px 30px rgba(0, 255, 255, 0.2);
            }}
            
            .feature-icon {{
                font-size: 48px;
                margin-bottom: 20px;
            }}
            
            .feature-title {{
                font-size: 20px;
                margin-bottom: 15px;
                color: var(--primary);
            }}
            
            .feature-desc {{
                color: #ccc;
                line-height: 1.6;
            }}
            
            /* Footer */
            .footer {{
                text-align: center;
                padding: 50px 0;
                margin-top: 60px;
                border-top: 1px solid rgba(0, 255, 255, 0.2);
            }}
            
            .owner-highlight {{
                color: var(--primary);
                font-weight: bold;
                font-size: 20px;
                margin-bottom: 15px;
            }}
            
            .social-links {{
                display: flex;
                gap: 20px;
                justify-content: center;
                margin: 20px 0;
            }}
            
            .social-link {{
                color: white;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 25px;
                background: rgba(255, 255, 255, 0.05);
                transition: 0.3s;
            }}
            
            .social-link:hover {{
                background: var(--primary);
                color: black;
            }}
            
            /* Loading Animation */
            .loader {{
                width: 48px;
                height: 48px;
                border: 5px solid #FFF;
                border-bottom-color: var(--primary);
                border-radius: 50%;
                display: inline-block;
                box-sizing: border-box;
                animation: rotation 1s linear infinite;
            }}
            
            @keyframes rotation {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
            
            /* Toast Notifications */
            .toast-container {{
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999;
            }}
            
            .toast {{
                background: rgba(0, 0, 0, 0.9);
                color: white;
                padding: 15px 25px;
                border-radius: 10px;
                margin-bottom: 10px;
                border-left: 4px solid var(--primary);
                animation: slideInRight 0.3s ease;
                backdrop-filter: blur(10px);
            }}
            
            .toast.success {{
                border-left-color: var(--success);
            }}
            
            .toast.error {{
                border-left-color: var(--danger);
            }}
            
            .toast.warning {{
                border-left-color: var(--warning);
            }}
            
            @keyframes slideInRight {{
                from {{
                    transform: translateX(100%);
                    opacity: 0;
                }}
                to {{
                    transform: translateX(0);
                    opacity: 1;
                }}
            }}
            
            /* Responsive */
            @media (max-width: 768px) {{
                .navbar {{
                    flex-direction: column;
                    gap: 15px;
                    border-radius: 20px;
                }}
                
                .nav-links {{
                    flex-wrap: wrap;
                    justify-content: center;
                }}
                
                .hero h1 {{
                    font-size: 32px;
                }}
                
                .input-group {{
                    flex-direction: column;
                }}
                
                .key-input-group {{
                    flex-direction: column;
                }}
                
                .stats {{
                    grid-template-columns: 1fr;
                }}
                
                .key-tiers {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
        
        <!-- Particles.js for background -->
        <script src="https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js"></script>
    </head>
    <body>
        <div id="particles-js"></div>
        <div class="globe"></div>
        
        <div class="toast-container" id="toastContainer"></div>
        
        <div class="container">
            <!-- Navbar -->
            <nav class="navbar">
                <div class="logo">
                    <span>🌍 GLOBAL OSINT</span>
                </div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/docs">API Docs</a>
                    <a href="#features">Features</a>
                    <a href="#pricing">Pricing</a>
                    <span class="owner-badge">
                        <span>👑</span> @Antyrx
                    </span>
                </div>
            </nav>
            
            <!-- Hero Section -->
            <div class="hero">
                <h1>World's Most Advanced Telegram OSINT</h1>
                <p>Kisi bhi country ka Telegram ID se mobile number, location, device aur bhi bahut kuch nikaalo. 150+ countries support ke saath.</p>
            </div>
            
            <!-- Stats -->
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">150+</div>
                    <div class="stat-label">Countries</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">1.5M+</div>
                    <div class="stat-label">Lookups</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">99.9%</div>
                    <div class="stat-label">Success Rate</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{app.state.requests_processed}</div>
                    <div class="stat-label">Today's Requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{hours}h {minutes}m</div>
                    <div class="stat-label">Uptime</div>
                </div>
            </div>
            
            <!-- Country Cloud -->
            <div class="country-cloud">
                <span class="country-tag">🇮🇳 India</span>
                <span class="country-tag">🇨🇦 Canada</span>
                <span class="country-tag">🇺🇸 USA</span>
                <span class="country-tag">🇬🇧 UK</span>
                <span class="country-tag">🇦🇺 Australia</span>
                <span class="country-tag">🇩🇪 Germany</span>
                <span class="country-tag">🇫🇷 France</span>
                <span class="country-tag">🇷🇺 Russia</span>
                <span class="country-tag">🇨🇳 China</span>
                <span class="country-tag">🇯🇵 Japan</span>
                <span class="country-tag">🇧🇷 Brazil</span>
                <span class="country-tag">🇦🇪 UAE</span>
                <span class="country-tag">🇸🇦 Saudi</span>
                <span class="country-tag">🇵🇰 Pakistan</span>
                <span class="country-tag">🇧🇩 Bangladesh</span>
                <span class="country-tag">🇱🇰 Sri Lanka</span>
                <span class="country-tag">🇳🇵 Nepal</span>
                <span class="country-tag">🇿🇦 South Africa</span>
                <span class="country-tag">🇲🇽 Mexico</span>
                <span class="country-tag">🇮🇩 Indonesia</span>
            </div>
            
            <!-- Main Search Container -->
            <div class="search-container">
                <div class="search-header">
                    <h2>🔍 Global Telegram Lookup</h2>
                    <p>Enter any Telegram ID or Username from any country</p>
                </div>
                
                <div class="search-tabs">
                    <div class="search-tab active" onclick="switchTab('single')">Single Lookup</div>
                    <div class="search-tab" onclick="switchTab('bulk')">Bulk Lookup</div>
                    <div class="search-tab" onclick="switchTab('advanced')">Advanced</div>
                </div>
                
                <!-- Single Lookup -->
                <div id="singleTab" style="display: block;">
                    <div class="input-group">
                        <input type="text" id="telegramId" placeholder="e.g., 123456789 or @username (kisi bhi country ka)" 
                               onkeypress="if(event.key === 'Enter') searchTelegram()">
                        <button onclick="searchTelegram()" id="searchBtn">
                            <span id="btnText">Search Worldwide →</span>
                            <span id="btnLoader" style="display: none;" class="loader"></span>
                        </button>
                    </div>
                    
                    <div style="display: flex; gap: 15px; margin-top: 15px; justify-content: center;">
                        <label style="color: #ccc;">
                            <input type="checkbox" id="saveHistory" checked> Save to history
                        </label>
                        <select id="exportFormat" style="background: rgba(255,255,255,0.1); color: white; padding: 5px; border-radius: 5px;">
                            <option value="json">JSON Format</option>
                            <option value="csv">CSV Format</option>
                        </select>
                    </div>
                </div>
                
                <!-- Bulk Lookup -->
                <div id="bulkTab" style="display: none;">
                    <div style="margin-bottom: 20px;">
                        <textarea id="bulkIds" rows="5" placeholder="Enter multiple IDs (one per line)&#10;e.g.:&#10;123456789&#10;987654321&#10;@username1&#10;@username2" 
                                  style="width: 100%; padding: 15px; border-radius: 10px; background: rgba(255,255,255,0.1); color: white; border: 1px solid cyan;"></textarea>
                    </div>
                    <div class="input-group">
                        <button onclick="searchBulk()" style="width: 100%;">
                            <span id="bulkBtnText">Bulk Search (Max 50) →</span>
                            <span id="bulkBtnLoader" style="display: none;" class="loader"></span>
                        </button>
                    </div>
                </div>
                
                <!-- Advanced Tab -->
                <div id="advancedTab" style="display: none;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div>
                            <h4 style="color: cyan; margin-bottom: 15px;">Webhook URL</h4>
                            <input type="url" id="webhookUrl" placeholder="https://your-server.com/webhook" 
                                   style="width: 100%; padding: 15px; border-radius: 10px; background: rgba(255,255,255,0.1); color: white; border: 1px solid cyan;">
                        </div>
                        <div>
                            <h4 style="color: cyan; margin-bottom: 15px;">Additional Options</h4>
                            <label style="display: block; margin-bottom: 10px; color: #ccc;">
                                <input type="checkbox" id="includeMetadata"> Include metadata
                            </label>
                            <label style="display: block; margin-bottom: 10px; color: #ccc;">
                                <input type="checkbox" id="forceRefresh"> Force refresh (skip cache)
                            </label>
                        </div>
                    </div>
                    <div class="input-group" style="margin-top: 20px;">
                        <input type="text" id="advancedId" placeholder="Enter Telegram ID">
                        <button onclick="searchAdvanced()">Advanced Search →</button>
                    </div>
                </div>
                
                <div style="text-align: center; margin-top: 15px; color: #888; font-size: 14px;">
                    🔑 Use master key: <code style="background: #333; padding: 3px 8px; border-radius: 5px;">ANTYRX-MASTER-2024</code> ya request karo neeche se
                </div>
                
                <!-- Result Box -->
                <div id="resultBox" class="result-box">
                    <div class="result-header">
                        <div>
                            <span class="result-badge" id="resultBadge">RESULT</span>
                            <span style="margin-left: 10px; color: #888;" id="resultTime"></span>
                        </div>
                        <div class="result-actions">
                            <span class="result-action" onclick="copyResult()">📋 Copy</span>
                            <span class="result-action" onclick="downloadResult()">📥 Download</span>
                            <span class="result-action" onclick="shareResult()">📤 Share</span>
                        </div>
                    </div>
                    <div class="result-content" id="resultContent">
                        <!-- Results will be displayed here -->
                    </div>
                </div>
            </div>
            
            <!-- Key Tiers -->
            <div class="key-section" id="pricing">
                <h2 style="font-size: 36px; margin-bottom: 20px;">🔑 API Key Tiers</h2>
                <p style="color: #ccc; margin-bottom: 40px;">Sirf @Antyrx keys generate kar sakte hain. Request karo aur approval ka wait karo.</p>
                
                <div class="key-tiers">
                    <div class="tier-card free">
                        <div class="tier-name">🚀 Free</div>
                        <div class="tier-price">₹0</div>
                        <ul class="tier-features">
                            <li><i>✓</i> 5 requests/minute</li>
                            <li><i>✓</i> 50 requests/day</li>
                            <li><i>✓</i> Basic lookup</li>
                            <li><i>✓</i> 30 days expiry</li>
                            <li><i>✗</i> Bulk lookup</li>
                            <li><i>✗</i> Priority support</li>
                        </ul>
                        <button class="tier-btn" onclick="showKeyRequest('free')">Request Free Key</button>
                    </div>
                    
                    <div class="tier-card premium">
                        <div class="tier-name">💎 Premium</div>
                        <div class="tier-price">₹499</div>
                        <ul class="tier-features">
                            <li><i>✓</i> 30 requests/minute</li>
                            <li><i>✓</i> 500 requests/day</li>
                            <li><i>✓</i> Advanced lookup</li>
                            <li><i>✓</i> 90 days expiry</li>
                            <li><i>✓</i> Bulk lookup (10)</li>
                            <li><i>✗</i> Priority support</li>
                        </ul>
                        <button class="tier-btn" onclick="showKeyRequest('premium')">Request Premium Key</button>
                    </div>
                    
                    <div class="tier-card enterprise">
                        <div class="tier-name">👑 Enterprise</div>
                        <div class="tier-price">Custom</div>
                        <ul class="tier-features">
                            <li><i>✓</i> 100 requests/minute</li>
                            <li><i>✓</i> 10,000 requests/day</li>
                            <li><i>✓</i> Full features</li>
                            <li><i>✓</i> 1 year expiry</li>
                            <li><i>✓</i> Bulk lookup (50)</li>
                            <li><i>✓</i> Priority support</li>
                        </ul>
                        <button class="tier-btn" onclick="showKeyRequest('enterprise')">Contact @Antyrx</button>
                    </div>
                </div>
                
                <!-- Key Request Form -->
                <div id="keyRequestForm" style="display: none; margin-top: 40px;" class="key-form">
                    <h3 style="color: cyan; margin-bottom: 20px;">Request API Key</h3>
                    <div class="key-input-group">
                        <input type="text" id="requestUsername" placeholder="Your Telegram Username">
                        <select id="requestTier">
                            <option value="free">Free Tier</option>
                            <option value="premium">Premium Tier</option>
                            <option value="enterprise">Enterprise Tier</option>
                        </select>
                    </div>
                    <div style="margin-bottom: 20px;">
                        <textarea id="requestPurpose" rows="3" placeholder="Purpose of using this API (optional)" 
                                  style="width: 100%; padding: 15px; border-radius: 10px; background: rgba(255,255,255,0.1); color: white; border: 1px solid cyan;"></textarea>
                    </div>
                    <button class="tier-btn" onclick="submitKeyRequest()" style="width: auto; padding: 15px 50px;">
                        Send Request to @Antyrx
                    </button>
                    <p style="color: #888; margin-top: 15px;">⏳ Owner approve karega, wait karo</p>
                </div>
                
                <div id="keyRequestResult" style="margin-top: 20px;"></div>
            </div>
            
            <!-- Features Grid -->
            <div class="features-grid" id="features">
                <div class="feature-card">
                    <div class="feature-icon">🌍</div>
                    <div class="feature-title">150+ Countries</div>
                    <div class="feature-desc">Kisi bhi country ka Telegram ID se number nikaalo with country code detection</div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <div class="feature-title">Instant Results</div>
                    <div class="feature-desc">Under 2 seconds mein result with multi-API fallback system</div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">📱</div>
                    <div class="feature-title">Phone Number</div>
                    <div class="feature-desc">Exact mobile number with country code aur location detection</div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">🛡️</div>
                    <div class="feature-title">Enterprise Security</div>
                    <div class="feature-desc">AES-256 encryption, rate limiting, aur DDoS protection</div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">📊</div>
                    <div class="feature-title">Bulk Lookup</div>
                    <div class="feature-desc">Ek saath 50 IDs check karo with CSV export</div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">🔔</div>
                    <div class="feature-title">Webhook Support</div>
                    <div class="feature-desc">Async results apne server pe bhejo real-time</div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">💾</div>
                    <div class="feature-title">Auto Cache</div>
                    <div class="feature-desc">Repeated queries instantly deliver honge</div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">📈</div>
                    <div class="feature-title">Live Stats</div>
                    <div class="feature-desc">Real-time usage statistics and analytics</div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">🎯</div>
                    <div class="feature-title">99.9% Uptime</div>
                    <div class="feature-desc">Multi-server architecture with auto failover</div>
                </div>
            </div>
            
            <!-- Footer -->
            <div class="footer">
                <p class="owner-highlight">👑 Owned & Operated by @Antyrx</p>
                <p style="color: #ccc; margin-bottom: 20px;">Koi bhi key generate nahi kar sakta sirf owner - Request karo aur wait karo approval ke liye</p>
                
                <div class="social-links">
                    <a href="https://t.me/Antyrx" class="social-link" target="_blank">📱 Telegram</a>
                    <a href="/docs" class="social-link">📚 API Docs</a>
                    <a href="/stats" class="social-link">📊 Stats</a>
                    <a href="/health" class="social-link">💚 Health</a>
                </div>
                
                <p style="margin-top: 30px; color: #666;">© 2024 Global Telegram OSINT - Version 6.0.0</p>
            </div>
        </div>
        
        <script>
            // Initialize particles
            particlesJS('particles-js', {{
                particles: {{
                    number: {{ value: 80, density: {{ enable: true, value_area: 800 }} }},
                    color: {{ value: '#00ffff' }},
                    shape: {{ type: 'circle' }},
                    opacity: {{ value: 0.5, random: false }},
                    size: {{ value: 3, random: true }},
                    line_linked: {{
                        enable: true,
                        distance: 150,
                        color: '#00ffff',
                        opacity: 0.4,
                        width: 1
                    }},
                    move: {{
                        enable: true,
                        speed: 2,
                        direction: 'none',
                        random: false,
                        straight: false,
                        out_mode: 'out',
                        bounce: false
                    }}
                }},
                interactivity: {{
                    detect_on: 'canvas',
                    events: {{
                        onhover: {{ enable: true, mode: 'repulse' }},
                        onclick: {{ enable: true, mode: 'push' }},
                        resize: true
                    }}
                }},
                retina_detect: true
            }});
            
            // Tab switching
            function switchTab(tab) {{
                const tabs = document.querySelectorAll('.search-tab');
                tabs.forEach(t => t.classList.remove('active'));
                event.target.classList.add('active');
                
                document.getElementById('singleTab').style.display = tab === 'single' ? 'block' : 'none';
                document.getElementById('bulkTab').style.display = tab === 'bulk' ? 'block' : 'none';
                document.getElementById('advancedTab').style.display = tab === 'advanced' ? 'block' : 'none';
            }}
            
            // Show toast notification
            function showToast(message, type = 'info') {{
                const container = document.getElementById('toastContainer');
                const toast = document.createElement('div');
                toast.className = `toast ${{type}}`;
                toast.textContent = message;
                container.appendChild(toast);
                
                setTimeout(() => {{
                    toast.style.animation = 'slideOutRight 0.3s ease';
                    setTimeout(() => container.removeChild(toast), 300);
                }}, 3000);
            }}
            
            // Single lookup
            async function searchTelegram() {{
                const query = document.getElementById('telegramId').value.trim();
                const key = prompt('Enter your API key (use master key: ANTYRX-MASTER-2024):', 'ANTYRX-MASTER-2024');
                
                if (!query) {{
                    showToast('Please enter Telegram ID or username', 'error');
                    return;
                }}
                
                if (!key) {{
                    showToast('API key required', 'error');
                    return;
                }}
                
                const format = document.getElementById('exportFormat').value;
                const saveHistory = document.getElementById('saveHistory').checked;
                
                // Show loading
                document.getElementById('btnText').style.display = 'none';
                document.getElementById('btnLoader').style.display = 'inline-block';
                document.getElementById('searchBtn').disabled = true;
                
                try {{
                    const response = await fetch(`/lookup?query=${{encodeURIComponent(query)}}&key=${{encodeURIComponent(key)}}&format=${{format}}`);
                    const data = await response.json();
                    
                    document.getElementById('resultBox').classList.add('show');
                    document.getElementById('resultTime').textContent = new Date().toLocaleTimeString();
                    
                    if (data.success) {{
                        document.getElementById('resultBadge').textContent = '✅ SUCCESS - Global Hit!';
                        displayResult(data);
                        showToast('Lookup successful!', 'success');
                        
                        // Save to history if enabled
                        if (saveHistory) {{
                            saveToHistory(query, data);
                        }}
                    }} else {{
                        document.getElementById('resultBadge').textContent = '❌ NOT FOUND';
                        document.getElementById('resultContent').innerHTML = `
                            <div style="text-align: center; padding: 40px;">
                                <div style="font-size: 48px; margin-bottom: 20px;">😕</div>
                                <div style="color: #ff6b6b; font-size: 18px; margin-bottom: 15px;">${{data.error || 'No data found'}}</div>
                                <div style="color: #888;">Try with a different ID or contact @Antyrx</div>
                            </div>
                        `;
                        showToast(data.error || 'No data found', 'warning');
                    }}
                }} catch (error) {{
                    showToast('Error: ' + error.message, 'error');
                    document.getElementById('resultContent').innerHTML = `
                        <div style="color: #ff6b6b;">❌ Error: ${{error.message}}</div>
                    `;
                }} finally {{
                    document.getElementById('btnText').style.display = 'inline';
                    document.getElementById('btnLoader').style.display = 'none';
                    document.getElementById('searchBtn').disabled = false;
                }}
            }}
            
            // Display result
            function displayResult(data) {{
                let html = '<div class="info-grid">';
                
                // Telegram Info
                if (data.data?.telegram) {{
                    html += `
                        <div class="info-card">
                            <h4>📱 Telegram Info</h4>
                            <div class="info-item">
                                <div class="info-label">ID</div>
                                <div class="info-value">${{data.data.telegram.id || 'N/A'}}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Username</div>
                                <div class="info-value">@${{data.data.telegram.username || 'N/A'}}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Name</div>
                                <div class="info-value">${{data.data.telegram.first_name || ''}} ${{data.data.telegram.last_name || ''}}</div>
                            </div>
                    `;
                    
                    if (data.data.telegram.verified) {{
                        html += `<div style="color: cyan; margin-top: 10px;">✓ Verified Account</div>`;
                    }}
                    
                    html += `</div>`;
                }}
                
                // Phone Info
                if (data.data?.phone) {{
                    html += `
                        <div class="info-card">
                            <h4>📞 Phone Number</h4>
                            <div class="info-item">
                                <div class="info-label">Number</div>
                                <div class="info-value phone-number">${{data.data.phone.number}}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">International</div>
                                <div class="info-value">${{data.data.phone.international}}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Country</div>
                                <div class="info-value">
                                    ${{data.data.phone.country}} 
                                    <span class="country-flag">${{data.data.phone.country_code}} ${{data.data.phone.flag || ''}}</span>
                                </div>
                            </div>
                        </div>
                    `;
                }}
                
                // Additional Info
                if (data.data?.bio || data.data?.photo) {{
                    html += `<div class="info-card">`;
                    if (data.data.bio) {{
                        html += `
                            <h4>📝 Bio</h4>
                            <div class="info-value">${{data.data.bio}}</div>
                        `;
                    }}
                    if (data.data.photo) {{
                        html += `
                            <h4 style="margin-top: 15px;">🖼️ Photo</h4>
                            <img src="${{data.data.photo}}" style="max-width: 100%; border-radius: 10px;">
                        `;
                    }}
                    html += `</div>`;
                }}
                
                html += '</div>';
                
                // API Info
                if (data.api_used) {{
                    html += `
                        <div style="margin-top: 20px; padding: 15px; background: rgba(0,255,255,0.05); border-radius: 10px;">
                            <div style="color: #888;">API Used: <span style="color: cyan;">${{data.api_used}}</span></div>
                            <div style="color: #888;">Timestamp: ${{data.meta?.timestamp || new Date().toISOString()}}</div>
                            <div style="color: #888;">Remaining: ${{data.meta?.remaining || 'N/A'}}</div>
                        </div>
                    `;
                }}
                
                document.getElementById('resultContent').innerHTML = html;
            }}
            
            // Copy result
            function copyResult() {{
                const content = document.getElementById('resultContent').innerText;
                navigator.clipboard.writeText(content);
                showToast('Copied to clipboard!', 'success');
            }}
            
            // Download result
            function downloadResult() {{
                const content = document.getElementById('resultContent').innerText;
                const blob = new Blob([content], {{ type: 'text/plain' }});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `telegram_lookup_${{Date.now()}}.txt`;
                a.click();
                showToast('Download started!', 'success');
            }}
            
            // Share result
            function shareResult() {{
                const content = document.getElementById('resultContent').innerText;
                if (navigator.share) {{
                    navigator.share({{
                        title: 'Telegram Lookup Result',
                        text: content
                    }});
                }} else {{
                    showToast('Sharing not supported', 'warning');
                }}
            }}
            
            // Save to history
            function saveToHistory(query, data) {{
                const history = JSON.parse(localStorage.getItem('searchHistory') || '[]');
                history.unshift({{
                    query: query,
                    timestamp: new Date().toISOString(),
                    success: data.success,
                    hasPhone: !!data.data?.phone
                }});
                
                // Keep only last 50
                if (history.length > 50) history.pop();
                
                localStorage.setItem('searchHistory', JSON.stringify(history));
            }}
            
            // Show key request form
            function showKeyRequest(tier) {{
                document.getElementById('keyRequestForm').style.display = 'block';
                document.getElementById('requestTier').value = tier;
            }}
            
            // Submit key request
            async function submitKeyRequest() {{
                const username = document.getElementById('requestUsername').value.trim();
                const tier = document.getElementById('requestTier').value;
                const purpose = document.getElementById('requestPurpose').value.trim();
                
                if (!username) {{
                    showToast('Please enter your Telegram username', 'error');
                    return;
                }}
                
                const resultDiv = document.getElementById('keyRequestResult');
                resultDiv.innerHTML = '<div style="color: cyan;">⏳ Sending request to @Antyrx...</div>';
                
                try {{
                    const response = await fetch(`/request-key?username=${{encodeURIComponent(username)}}&tier=${{tier}}&purpose=${{encodeURIComponent(purpose)}}`);
                    const data = await response.json();
                    
                    if (data.success) {{
                        resultDiv.innerHTML = `
                            <div style="background: rgba(0,255,0,0.1); padding: 20px; border-radius: 10px;">
                                <div style="color: #4CAF50; font-size: 20px; margin-bottom: 10px;">✅ Request Sent!</div>
                                <div>Request ID: <span style="color: cyan;">${{data.request_id}}</span></div>
                                <div style="margin-top: 15px; color: #888;">⏳ Wait for @Antyrx to approve your request</div>
                                <div style="margin-top: 10px;">Contact owner: <a href="https://t.me/Antyrx" style="color: cyan;">@Antyrx</a></div>
                            </div>
                        `;
                        showToast('Request sent to owner!', 'success');
                    }} else {{
                        resultDiv.innerHTML = `<div style="color: #ff6b6b;">❌ ${{data.error}}</div>`;
                        showToast(data.error, 'error');
                    }}
                }} catch (error) {{
                    resultDiv.innerHTML = `<div style="color: #ff6b6b;">❌ ${{error.message}}</div>`;
                    showToast(error.message, 'error');
                }}
            }}
            
            // Bulk search
            async function searchBulk() {{
                const ids = document.getElementById('bulkIds').value.trim().split('\\n').filter(id => id.trim());
                const key = prompt('Enter your API key:');
                
                if (ids.length === 0) {{
                    showToast('Please enter at least one ID', 'error');
                    return;
                }}
                
                if (ids.length > 50) {{
                    showToast('Maximum 50 IDs allowed', 'error');
                    return;
                }}
                
                if (!key) {{
                    showToast('API key required', 'error');
                    return;
                }}
                
                document.getElementById('bulkBtnText').style.display = 'none';
                document.getElementById('bulkBtnLoader').style.display = 'inline-block';
                
                try {{
                    const response = await fetch('/bulk-lookup', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            queries: ids.map(id => id.trim()),
                            key: key
                        }})
                    }});
                    
                    const data = await response.json();
                    
                    document.getElementById('resultBox').classList.add('show');
                    
                    if (data.success) {{
                        let html = '<div class="info-grid">';
                        
                        data.results.forEach((result, index) => {{
                            html += `
                                <div class="info-card">
                                    <h4>#${{index + 1}}: ${{result.query}}</h4>
                            `;
                            
                            if (result.success) {{
                                if (result.data?.phone) {{
                                    html += `
                                        <div class="info-item">
                                            <div class="info-label">Phone</div>
                                            <div class="info-value" style="color: #4CAF50;">${{result.data.phone.number}}</div>
                                        </div>
                                    `;
                                }}
                                if (result.data?.telegram?.username) {{
                                    html += `
                                        <div class="info-item">
                                            <div class="info-label">Username</div>
                                            <div class="info-value">@${{result.data.telegram.username}}</div>
                                        </div>
                                    `;
                                }}
                            }} else {{
                                html += `<div style="color: #ff6b6b;">❌ ${{result.error}}</div>`;
                            }}
                            
                            html += `</div>`;
                        }});
                        
                        html += '</div>';
                        
                        // Add download button
                        html += `
                            <div style="margin-top: 20px; text-align: center;">
                                <button onclick="downloadBulkResults()" style="padding: 10px 30px; background: cyan; color: black; border: none; border-radius: 25px; cursor: pointer;">
                                    📥 Download Results (CSV)
                                </button>
                            </div>
                        `;
                        
                        document.getElementById('resultContent').innerHTML = html;
                        showToast(`Processed ${{data.results.length}} IDs`, 'success');
                        
                        // Store for download
                        window.lastBulkResults = data.results;
                    }}
                }} catch (error) {{
                    showToast('Error: ' + error.message, 'error');
                }} finally {{
                    document.getElementById('bulkBtnText').style.display = 'inline';
                    document.getElementById('bulkBtnLoader').style.display = 'none';
                }}
            }}
            
            // Download bulk results as CSV
            function downloadBulkResults() {{
                if (!window.lastBulkResults) return;
                
                let csv = 'Query,Success,Phone,Username,Error\\n';
                
                window.lastBulkResults.forEach(r => {{
                    csv += `"${{r.query}}",${{r.success}},"${{r.data?.phone?.number || ''}}","${{r.data?.telegram?.username || ''}}","${{r.error || ''}}"\\n`;
                }});
                
                const blob = new Blob([csv], {{ type: 'text/csv' }});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `bulk_results_${{Date.now()}}.csv`;
                a.click();
                showToast('CSV downloaded!', 'success');
            }}
            
            // Advanced search
            async function searchAdvanced() {{
                const query = document.getElementById('advancedId').value.trim();
                const key = prompt('Enter your API key:');
                const webhook = document.getElementById('webhookUrl').value.trim();
                const includeMetadata = document.getElementById('includeMetadata').checked;
                const forceRefresh = document.getElementById('forceRefresh').checked;
                
                if (!query) {{
                    showToast('Please enter Telegram ID', 'error');
                    return;
                }}
                
                showToast('Processing advanced search...', 'info');
                
                // Implement advanced search logic here
                if (webhook) {{
                    showToast('Webhook request sent', 'success');
                }}
            }}
            
            // Check key status
            async function checkKeyStatus() {{
                const key = prompt('Enter your API key to check status:');
                if (!key) return;
                
                try {{
                    const response = await fetch(`/key-status?key=${{encodeURIComponent(key)}}`);
                    const data = await response.json();
                    
                    if (data.success) {{
                        showToast(`Key valid: ${{data.remaining}} requests remaining`, 'success');
                    }} else {{
                        showToast(data.error, 'error');
                    }}
                }} catch (error) {{
                    showToast(error.message, 'error');
                }}
            }}
            
            // Keyboard shortcuts
            document.addEventListener('keydown', function(e) {{
                // Ctrl/Cmd + Enter to search
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {{
                    searchTelegram();
                }}
                
                // Esc to clear
                if (e.key === 'Escape') {{
                    document.getElementById('telegramId').value = '';
                    document.getElementById('resultBox').classList.remove('show');
                }}
            }});
            
            // Auto-focus on load
            window.onload = function() {{
                document.getElementById('telegramId').focus();
            }};
        </script>
    </body>
    </html>
    """

# ===== LOOKUP ENDPOINT =====
@app.get("/lookup")
async def lookup(
    request: Request,
    background_tasks: BackgroundTasks,
    query: str = Query(..., description="Telegram ID ya Username"),
    key: str = Query(..., description="API Key"),
    format: str = Query("json", regex="^(json|csv)$"),
    webhook: Optional[str] = Query(None)
):
    """Worldwide Telegram lookup with multiple API fallback"""
    
    # Validate key
    valid, tier, message, remaining, expires = await key_manager.validate_key(key, request.client.host)
    if not valid:
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "error": message,
                "contact": "@Antyrx"
            }
        )
    
    # Check rate limit
    allowed, rate_msg = await rate_limiter.check(key, request.client.host, tier)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={
                "success": False,
                "error": rate_msg,
                "contact": "@Antyrx"
            }
        )
    
    # Check cache
    cache_key = f"lookup:{query}"
    if cache_key in app.state.cache and not request.headers.get("X-Force-Refresh"):
        cached = app.state.cache[cache_key]
        cached["cached"] = True
        cached["meta"] = {
            "tier": tier,
            "remaining": rate_msg,
            "timestamp": datetime.now().isoformat(),
            "owner": "@Antyrx"
        }
        
        # Log request
        background_tasks.add_task(log_request, key, query, True, 0, request)
        
        return cached
    
    # Perform lookup
    start_time = time.time()
    result = await fetcher.lookup(query)
    response_time = (time.time() - start_time) * 1000
    
    # Cache successful results
    if result.get("success"):
        app.state.cache[cache_key] = result
    
    # Add metadata
    result["meta"] = {
        "tier": tier,
        "remaining": rate_msg,
        "timestamp": datetime.now().isoformat(),
        "response_time_ms": round(response_time, 2),
        "owner": "@Antyrx"
    }
    
    # Increment key usage
    await key_manager.increment_usage(key)
    
    # Log request
    background_tasks.add_task(log_request, key, query, result.get("success", False), response_time, request)
    
    # Handle webhook if provided
    if webhook and result.get("success"):
        background_tasks.add_task(send_webhook, webhook, result)
    
    # Handle format
    if format == "csv":
        return await generate_csv_response(result)
    
    return result

# ===== BULK LOOKUP =====
@app.post("/bulk-lookup")
async def bulk_lookup(
    request: Request,
    bulk_req: BulkLookupRequest
):
    """Bulk lookup for multiple IDs"""
    
    # Validate key
    valid, tier, message, remaining, expires = await key_manager.validate_key(bulk_req.key, request.client.host)
    if not valid:
        return JSONResponse(
            status_code=401,
            content={"success": False, "error": message}
        )
    
    # Check if tier allows bulk
    if tier == "free" and len(bulk_req.queries) > 10:
        return JSONResponse(
            status_code=403,
            content={"success": False, "error": "Free tier limited to 10 bulk queries"}
        )
    
    if tier == "premium" and len(bulk_req.queries) > 25:
        return JSONResponse(
            status_code=403,
            content={"success": False, "error": "Premium tier limited to 25 bulk queries"}
        )
    
    # Process queries
    results = []
    for query in bulk_req.queries[:50]:  # Max 50
        result = await fetcher.lookup(query)
        results.append({
            "query": query,
            "success": result.get("success", False),
            "data": result.get("data"),
            "error": result.get("error")
        })
        await asyncio.sleep(0.1)  # Rate limit between requests
    
    # Increment key usage
    await key_manager.increment_key_usage(bulk_req.key)
    
    return {
        "success": True,
        "total": len(results),
        "successful": sum(1 for r in results if r["success"]),
        "failed": sum(1 for r in results if not r["success"]),
        "results": results,
        "timestamp": datetime.now().isoformat()
    }

# ===== KEY REQUEST =====
@app.get("/request-key")
async def request_key(
    username: str = Query(..., min_length=3),
    tier: str = Query("free", regex="^(free|premium|enterprise)$"),
    purpose: Optional[str] = None
):
    """Request API key from owner"""
    
    request_id = str(uuid.uuid4())[:8]
    
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    c.execute("""INSERT INTO key_requests (id, username, tier, purpose, status, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)""",
              (request_id, username, tier, purpose, "pending", datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    # Notify owner (implement Telegram bot notification here)
    
    return {
        "success": True,
        "request_id": request_id,
        "message": f"Key request sent to @Antyrx. He will approve soon!",
        "contact": "@Antyrx",
        "estimated_time": "Usually within 24 hours"
    }

# ===== KEY STATUS =====
@app.get("/key-status")
async def key_status(key: str = Query(...)):
    """Check API key status"""
    
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    c.execute("""SELECT tier, expires_at, max_requests, requests_used, active, created_at
                 FROM api_keys WHERE key = ?""", (key,))
    row = c.fetchone()
    
    conn.close()
    
    if not row:
        return {"success": False, "error": "Invalid key"}
    
    tier, expires_at, max_requests, requests_used, active, created_at = row
    
    return {
        "success": True,
        "key": key,
        "tier": tier,
        "active": bool(active),
        "created": created_at,
        "expires": expires_at,
        "requests_used": requests_used,
        "requests_remaining": max_requests - requests_used,
        "total_limit": max_requests
    }

# ===== STATS ENDPOINT =====
@app.get("/stats")
async def stats():
    """Public statistics"""
    
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    # Get today's requests
    today = datetime.now().date().isoformat()
    c.execute("""SELECT COUNT(*) FROM requests WHERE date(timestamp) = ?""", (today,))
    today_requests = c.fetchone()[0]
    
    # Get total requests
    c.execute("SELECT COUNT(*) FROM requests")
    total_requests = c.fetchone()[0]
    
    # Get active keys
    c.execute("SELECT COUNT(*) FROM api_keys WHERE active = 1")
    active_keys = c.fetchone()[0]
    
    conn.close()
    
    return {
        "success": True,
        "stats": {
            "total_requests": total_requests,
            "today_requests": today_requests,
            "active_keys": active_keys,
            "uptime": str(datetime.now(pytz.UTC) - app.state.start_time),
            "countries_supported": len(fetcher.country_db),
            "apis_available": len(fetcher.apis)
        },
        "timestamp": datetime.now().isoformat()
    }

# ===== OWNER ENDPOINTS =====

@app.post("/owner/generate-key")
async def owner_generate_key(
    request: Request,
    tier: str = Query(..., regex="^(free|premium|enterprise)$"),
    username: str = Query(...)
):
    """Generate new API key (Owner only)"""
    await verify_owner(request)
    
    result = await key_manager.generate_key(tier, username, "owner")
    return result

@app.get("/owner/pending-requests")
async def owner_pending_requests(request: Request):
    """Get all pending key requests (Owner only)"""
    await verify_owner(request)
    
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    c.execute("""SELECT id, username, tier, purpose, created_at 
                 FROM key_requests WHERE status = 'pending'
                 ORDER BY created_at DESC""")
    rows = c.fetchall()
    
    conn.close()
    
    return {
        "success": True,
        "pending": [
            {
                "id": r[0],
                "username": r[1],
                "tier": r[2],
                "purpose": r[3],
                "created_at": r[4]
            }
            for r in rows
        ]
    }

@app.post("/owner/approve-key/{request_id}")
async def owner_approve_key(request: Request, request_id: str):
    """Approve key request and generate key (Owner only)"""
    await verify_owner(request)
    
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    # Get request details
    c.execute("SELECT username, tier FROM key_requests WHERE id = ? AND status = 'pending'", (request_id,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return {"success": False, "error": "Request not found"}
    
    username, tier = row
    
    # Generate key
    key_result = await key_manager.generate_key(tier, username, "owner")
    
    # Update request status
    c.execute("UPDATE key_requests SET status = 'approved' WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "message": f"Key approved for @{username}",
        "key": key_result["key"]
    }

@app.get("/owner/all-keys")
async def owner_all_keys(request: Request):
    """Get all API keys (Owner only)"""
    await verify_owner(request)
    
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    c.execute("""SELECT key, tier, username, created_at, expires_at, requests_used, max_requests, active
                 FROM api_keys JOIN users ON api_keys.user_id = users.id
                 ORDER BY created_at DESC""")
    rows = c.fetchall()
    
    conn.close()
    
    return {
        "success": True,
        "keys": [
            {
                "key": r[0][:20] + "...",  # Mask key
                "tier": r[1],
                "username": r[2],
                "created": r[3],
                "expires": r[4],
                "usage": f"{r[5]}/{r[6]}",
                "active": bool(r[7])
            }
            for r in rows
        ]
    }

# ===== HEALTH CHECK =====
@app.get("/health")
async def health():
    """Health check endpoint"""
    
    # Check database
    db_healthy = True
    try:
        conn = sqlite3.connect('osint.db')
        c = conn.cursor()
        c.execute("SELECT 1")
        c.fetchone()
        conn.close()
    except:
        db_healthy = False
    
    # Check Redis
    redis_healthy = False
    if app.state.redis:
        try:
            await app.state.redis.ping()
            redis_healthy = True
        except:
            pass
    
    return {
        "status": "healthy",
        "service": "Global Telegram OSINT",
        "owner": "@Antyrx",
        "version": "6.0.0",
        "timestamp": datetime.now().isoformat(),
        "uptime": str(datetime.now(pytz.UTC) - app.state.start_time),
        "requests_processed": app.state.requests_processed,
        "database": "connected" if db_healthy else "error",
        "redis": "connected" if redis_healthy else "disconnected",
        "cache_size": len(app.state.cache)
    }

# ===== HELPER FUNCTIONS =====

async def log_request(key: str, query: str, success: bool, response_time: float, request: Request):
    """Log request to database"""
    conn = sqlite3.connect('osint.db')
    c = conn.cursor()
    
    request_id = str(uuid.uuid4())
    
    c.execute("""INSERT INTO requests (id, user_id, query, success, response_time, timestamp, ip, user_agent)
                 VALUES (?, (SELECT user_id FROM api_keys WHERE key = ?), ?, ?, ?, ?, ?, ?)""",
              (request_id, key, query, success, response_time, 
               datetime.now().isoformat(), request.client.host, 
               request.headers.get("user-agent", "")))
    
    conn.commit()
    conn.close()

async def send_webhook(webhook_url: str, data: dict):
    """Send webhook notification"""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(webhook_url, json=data)
    except:
        pass  # Silently fail

async def generate_csv_response(data: dict) -> JSONResponse:
    """Generate CSV response"""
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(["Field", "Value"])
    
    if data.get("success") and data.get("data"):
        if data["data"].get("telegram"):
            for key, value in data["data"]["telegram"].items():
                writer.writerow([f"telegram_{key}", value])
        
        if data["data"].get("phone"):
            for key, value in data["data"]["phone"].items():
                writer.writerow([f"phone_{key}", value])
        
        if data["data"].get("bio"):
            writer.writerow(["bio", data["data"]["bio"]])
    
    output.seek(0)
    return JSONResponse(
        content={"csv": output.getvalue()},
        headers={"Content-Type": "application/json"}
    )

# ===== ERROR HANDLERS =====
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "path": request.url.path
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "message": "Contact @Antyrx if this persists"
        }
    )

# ===== DOCS =====
@app.get("/docs", response_class=HTMLResponse)
async def docs():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global OSINT API Docs - @Antyrx</title>
        <style>
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #000428, #004e92);
                color: white;
                padding: 40px;
            }
            .container {
                max-width: 1000px;
                margin: 0 auto;
            }
            h1 { color: cyan; }
            h2 { color: cyan; margin-top: 30px; }
            .endpoint {
                background: rgba(0,255,255,0.1);
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                border-left: 4px solid cyan;
            }
            code {
                background: #333;
                padding: 2px 5px;
                border-radius: 3px;
                color: cyan;
            }
            pre {
                background: #222;
                padding: 15px;
                border-radius: 10px;
                overflow-x: auto;
            }
            .badge {
                background: cyan;
                color: black;
                padding: 3px 10px;
                border-radius: 15px;
                font-size: 12px;
                margin-left: 10px;
            }
            .note {
                background: rgba(255,255,0,0.1);
                border-left: 4px solid yellow;
                padding: 15px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🌍 Global Telegram OSINT API Documentation</h1>
            <p>Owner: <strong>@Antyrx</strong> - World's Most Advanced Telegram OSINT</p>
            
            <div class="note">
                ⚠️ <strong>IMPORTANT:</strong> API keys sirf @Antyrx generate kar sakte hain. 
                Koi aur key nahi bana sakta. Request karo aur wait karo approval ke liye.
            </div>
            
            <h2>🔍 Single Lookup</h2>
            <div class="endpoint">
                <code>GET /lookup?query=TELEGRAM_ID&key=YOUR_KEY</code>
                <span class="badge">JSON/CSV</span>
                <p>Kisi bhi country ka Telegram ID se data nikaalo</p>
                
                <h4>Parameters:</h4>
                <ul>
                    <li><code>query</code> - Telegram ID ya Username (required)</li>
                    <li><code>key</code> - Your API key (required)</li>
                    <li><code>format</code> - json/csv (optional, default: json)</li>
                    <li><code>webhook</code> - Webhook URL for async results (optional)</li>
                </ul>
                
                <h4>Example:</h4>
                <pre>GET /lookup?query=123456789&key=ANTYRX-xxxx&format=json</pre>
            </div>
            
            <h2>📦 Bulk Lookup</h2>
            <div class="endpoint">
                <code>POST /bulk-lookup</code>
                <span class="badge">POST</span>
                
                <h4>Request Body:</h4>
                <pre>{
    "queries": ["123456789", "987654321", "@username"],
    "key": "ANTYRX-xxxx"
}</pre>
                
                <p>Max 50 IDs at once</p>
            </div>
            
            <h2>🔑 Key Management</h2>
            
            <div class="endpoint">
                <h3>Request Key</h3>
                <code>GET /request-key?username=YOUR_TELEGRAM&tier=free</code>
                <p>Key request karo - @Antyrx approve karega</p>
            </div>
            
            <div class="endpoint">
                <h3>Check Key Status</h3>
                <code>GET /key-status?key=YOUR_KEY</code>
                <p>Dekho kitne requests bachi hain</p>
            </div>
            
            <h2>📊 Statistics</h2>
            
            <div class="endpoint">
                <h3>Public Stats</h3>
                <code>GET /stats</code>
                <p>Global usage statistics</p>
            </div>
            
            <div class="endpoint">
                <h3>Health Check</h3>
                <code>GET /health</code>
                <p>Service health status</p>
            </div>
            
            <h2>🌍 Supported Countries</h2>
            <p>India, Canada, USA, UK, Australia, Germany, France, Russia, China, Japan, Brazil, UAE, Saudi, Pakistan, Bangladesh, Sri Lanka, Nepal, South Africa, Mexico, Indonesia + 150+ countries</p>
            
            <h2>📞 Support</h2>
            <p>Telegram: <strong>@Antyrx</strong> (Sirf yahi se milega key aur support)</p>
            <p>Response Time: Usually within 24 hours</p>
            
            <h2>⚠️ Rate Limits</h2>
            <ul>
                <li>Free: 5/minute, 50/day</li>
                <li>Premium: 30/minute, 500/day</li>
                <li>Enterprise: 100/minute, 10,000/day</li>
                <li>Owner: Unlimited</li>
            </ul>
            
            <h2>📝 Response Format</h2>
            <pre>{
    "success": true,
    "data": {
        "telegram": {
            "id": "123456789",
            "username": "username",
            "first_name": "John",
            "last_name": "Doe",
            "verified": false
        },
        "phone": {
            "number": "1234567890",
            "international": "+911234567890",
            "country": "India",
            "country_code": "+91",
            "flag": "🇮🇳"
        },
        "bio": "Bio here"
    },
    "meta": {
        "tier": "free",
        "remaining": "45 remaining",
        "timestamp": "2024-01-01T00:00:00",
        "response_time_ms": 1234.56,
        "owner": "@Antyrx"
    }
}</pre>
        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)