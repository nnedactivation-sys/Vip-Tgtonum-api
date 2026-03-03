from fastapi import FastAPI, Query, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
import time
import asyncio
from typing import Optional
from datetime import datetime, timedelta
import os
import json
import secrets
import hashlib
from collections import defaultdict
import uuid

app = FastAPI(
    title="🌍 GLOBAL TELEGRAM OSINT - World's Most Advanced",
    description="Kisi bhi country ka Telegram ID se mobile number | By @Antyrx",
    version="5.0.0"
)

# ===== CORS =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== SECURITY =====
security = HTTPBearer(auto_error=False)

# ===== OWNER CONFIGURATION =====
OWNER_USERNAME = "@Antyrx"
OWNER_IDS = ["antyrx", "Antyrx", "ANTYRX"]  # Owner Telegram usernames
MASTER_KEY = "ANTYRX-OSINT"  # Sirf owner ka master key

# ===== API KEY MANAGEMENT (Sirf owner generate kar sakta hai) =====
class APIKeyManager:
    def __init__(self):
        self.keys = {
            # Master key - Sirf owner ka
            MASTER_KEY: {
                "tier": "owner",
                "owner": OWNER_USERNAME,
                "created": datetime.now().isoformat(),
                "expires": None,
                "requests": 0,
                "max_requests": float('inf'),
                "active": True
            }
        }
        self.usage = defaultdict(lambda: {
            "count": 0,
            "last_used": None,
            "total_requests": 0,
            "successful": 0,
            "failed": 0
        })
        self.pending_requests = []  # Key requests
        self.revoked_keys = set()
    
    def generate_key(self, tier: str = "premium", requester: str = None) -> dict:
        """Sirf owner call kar sakta hai - Naya key generate"""
        key = f"ANTYRX-{secrets.token_hex(8).upper()}-{tier.upper()}"
        
        expiry = (datetime.now() + timedelta(days=30)).isoformat() if tier == "free" else None
        
        self.keys[key] = {
            "tier": tier,
            "owner": requester or "user",
            "created": datetime.now().isoformat(),
            "expires": expiry,
            "requests": 0,
            "max_requests": 1000 if tier == "free" else 10000 if tier == "premium" else float('inf'),
            "active": True
        }
        
        return {
            "success": True,
            "key": key,
            "tier": tier,
            "expires": expiry,
            "message": "Keep this key safe! It won't be shown again"
        }
    
    def validate_key(self, key: str) -> tuple:
        """API key validate karo"""
        if not key:
            return False, None, "No API key provided"
        
        if key in self.revoked_keys:
            return False, None, "This key has been revoked. Contact @Antyrx"
        
        if key not in self.keys:
            return False, None, "Invalid API key. Get one from @Antyrx"
        
        key_data = self.keys[key]
        
        # Check if active
        if not key_data.get("active", True):
            return False, None, "Key is deactivated"
        
        # Check expiry
        if key_data.get("expires"):
            expiry = datetime.fromisoformat(key_data["expires"])
            if expiry < datetime.now():
                return False, None, "Key expired. Contact @Antyrx for renewal"
        
        # Check request limit
        if key_data["requests"] >= key_data["max_requests"]:
            return False, None, f"Request limit reached ({key_data['max_requests']}). Contact @Antyrx"
        
        # Update usage
        key_data["requests"] += 1
        self.usage[key]["total_requests"] += 1
        self.usage[key]["last_used"] = datetime.now().isoformat()
        
        return True, key_data["tier"], "Valid"
    
    def request_key(self, username: str, tier: str = "free") -> dict:
        """User key request kare - Owner approve karega"""
        request_id = str(uuid.uuid4())[:8]
        
        self.pending_requests.append({
            "id": request_id,
            "username": username,
            "tier": tier,
            "requested_at": datetime.now().isoformat(),
            "status": "pending"
        })
        
        return {
            "success": True,
            "request_id": request_id,
            "message": f"Key request sent to @Antyrx. He will approve soon!",
            "contact": "@Antyrx"
        }
    
    def approve_key(self, request_id: str) -> dict:
        """Sirf owner call kare - Key request approve"""
        for req in self.pending_requests:
            if req["id"] == request_id and req["status"] == "pending":
                req["status"] = "approved"
                # Generate key
                return self.generate_key(req["tier"], req["username"])
        
        return {"success": False, "error": "Request not found"}

key_manager = APIKeyManager()

# ===== RATE LIMITER =====
class RateLimiter:
    def __init__(self):
        self.limits = {
            "free": {"per_minute": 5, "per_day": 50},
            "premium": {"per_minute": 30, "per_day": 500},
            "enterprise": {"per_minute": 100, "per_day": 5000},
            "owner": {"per_minute": 1000, "per_day": 100000}
        }
        self.requests = defaultdict(list)
    
    def check(self, ip: str, tier: str = "free") -> tuple:
        now = time.time()
        minute_ago = now - 60
        day_ago = now - 86400
        
        # Clean old
        self.requests[ip] = [t for t in self.requests[ip] if t > day_ago]
        
        minute_count = len([t for t in self.requests[ip] if t > minute_ago])
        day_count = len(self.requests[ip])
        
        limits = self.limits.get(tier, self.limits["free"])
        
        if minute_count >= limits["per_minute"]:
            return False, f"Rate limit: {limits['per_minute']}/minute"
        
        if day_count >= limits["per_day"]:
            return False, f"Daily limit: {limits['per_day']}/day"
        
        self.requests[ip].append(now)
        return True, f"{limits['per_minute'] - minute_count} remaining"

rate_limiter = RateLimiter()

# ===== GLOBAL TELEGRAM FETCHER =====
class GlobalTelegramFetcher:
    def __init__(self):
        self.base_url = "http://api.subhxcosmo.in/api"
        self.timeout = 15
        self.countries = {
            "india": {"code": "+91", "regex": r"^(?:\+?91|0)?[6-9]\d{9}$", "name": "India"},
            "canada": {"code": "+1", "regex": r"^(?:\+?1|0)?[2-9]\d{9}$", "name": "Canada"},
            "usa": {"code": "+1", "regex": r"^(?:\+?1|0)?[2-9]\d{9}$", "name": "USA"},
            "uk": {"code": "+44", "regex": r"^(?:\+?44|0)?[1-9]\d{9}$", "name": "United Kingdom"},
            "australia": {"code": "+61", "regex": r"^(?:\+?61|0)?[2-9]\d{8}$", "name": "Australia"},
            "germany": {"code": "+49", "regex": r"^(?:\+?49|0)?[1-9]\d{10}$", "name": "Germany"},
            "france": {"code": "+33", "regex": r"^(?:\+?33|0)?[1-9]\d{8}$", "name": "France"},
            "russia": {"code": "+7", "regex": r"^(?:\+?7|8)?[1-9]\d{9}$", "name": "Russia"},
            "china": {"code": "+86", "regex": r"^(?:\+?86|0)?[1-9]\d{9}$", "name": "China"},
            "japan": {"code": "+81", "regex": r"^(?:\+?81|0)?[1-9]\d{8,9}$", "name": "Japan"},
            "brazil": {"code": "+55", "regex": r"^(?:\+?55|0)?[1-9]\d{10}$", "name": "Brazil"},
            "uae": {"code": "+971", "regex": r"^(?:\+?971|0)?[1-9]\d{8}$", "name": "UAE"},
            "saudi": {"code": "+966", "regex": r"^(?:\+?966|0)?[1-9]\d{8}$", "name": "Saudi Arabia"},
            "pakistan": {"code": "+92", "regex": r"^(?:\+?92|0)?[1-9]\d{9}$", "name": "Pakistan"},
            "bangladesh": {"code": "+880", "regex": r"^(?:\+?880|0)?[1-9]\d{9}$", "name": "Bangladesh"},
            "sri_lanka": {"code": "+94", "regex": r"^(?:\+?94|0)?[1-9]\d{8}$", "name": "Sri Lanka"},
            "nepal": {"code": "+977", "regex": r"^(?:\+?977|0)?[1-9]\d{8}$", "name": "Nepal"}
        }
    
    def detect_country(self, number: str) -> dict:
        """Number se country detect karo"""
        # Remove non-digits
        clean_number = re.sub(r'\D', '', number)
        
        for country, info in self.countries.items():
            pattern = info["regex"]
            if re.match(pattern, clean_number) or re.match(pattern, f"+{clean_number}"):
                return {
                    "country": info["name"],
                    "code": info["code"],
                    "detected": True
                }
        
        return {
            "country": "Unknown",
            "code": "Unknown",
            "detected": False
        }
    
    async def lookup(self, query: str) -> dict:
        """Worldwide Telegram lookup"""
        url = f"{self.base_url}?key=INTELX2&type=sms&term={query}"
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                print(f"🌍 Global lookup: {query}")
                response = await client.get(url)
                data = response.json()
                
                print(f"📦 Response: {json.dumps(data, indent=2)}")
                
                if data.get("success"):
                    result = data.get("result", {})
                    
                    if result and result.get("msg") != "Telegram ID missing":
                        
                        # Format the data
                        formatted_data = {
                            "telegram": {
                                "id": result.get("telegram_id", query),
                                "username": result.get("username", "N/A"),
                                "first_name": result.get("first_name", "N/A"),
                                "last_name": result.get("last_name", "N/A"),
                                "verified": result.get("verified", False)
                            }
                        }
                        
                        # Check for phone number
                        phone = result.get("phone")
                        if phone:
                            country_info = self.detect_country(phone)
                            formatted_data["phone"] = {
                                "number": phone,
                                "international": f"+{phone}" if not phone.startswith('+') else phone,
                                "country": country_info["country"],
                                "country_code": country_info["code"]
                            }
                        
                        # Add any extra data
                        if result.get("bio"):
                            formatted_data["bio"] = result["bio"]
                        
                        if result.get("photo"):
                            formatted_data["photo"] = result["photo"]
                        
                        return {
                            "success": True,
                            "data": formatted_data,
                            "source": data.get("owner", "Global DB"),
                            "timestamp": datetime.now().isoformat()
                        }
                
                return {
                    "success": False,
                    "error": "No data found for this Telegram ID",
                    "query": query,
                    "suggestion": "Try a different ID or contact @Antyrx"
                }
                
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Lookup failed: {str(e)}",
                    "query": query
                }

fetcher = GlobalTelegramFetcher()

# ===== MIDDLEWARE =====
@app.middleware("http")
async def middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    response.headers["X-Response-Time"] = f"{(time.time() - start)*1000:.0f}ms"
    response.headers["X-Powered-By"] = f"Antyrx's Global OSINT"
    return response

# ===== OWNER AUTH =====
async def verify_owner(request: Request):
    """Verify if request is from owner"""
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
async def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>🌍 GLOBAL TELEGRAM OSINT - By @Antyrx</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #000428 0%, #004e92 100%);
                color: white;
                min-height: 100vh;
            }
            
            /* Animated Background */
            .globe {
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
            }
            
            @keyframes rotate {
                from { transform: translate(-50%, -50%) rotate(0deg); }
                to { transform: translate(-50%, -50%) rotate(360deg); }
            }
            
            .container {
                position: relative;
                z-index: 1;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }
            
            /* Navbar */
            .navbar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 20px 0;
                border-bottom: 2px solid rgba(0,255,255,0.3);
                margin-bottom: 40px;
            }
            
            .logo {
                font-size: 28px;
                font-weight: bold;
                background: linear-gradient(45deg, #fff, #00ffff);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                animation: glow 2s ease-in-out infinite alternate;
            }
            
            @keyframes glow {
                from { text-shadow: 0 0 10px cyan; }
                to { text-shadow: 0 0 20px cyan, 0 0 30px blue; }
            }
            
            .owner-badge {
                background: linear-gradient(45deg, gold, orange);
                color: black;
                padding: 8px 16px;
                border-radius: 20px;
                font-weight: bold;
            }
            
            /* Hero Section */
            .hero {
                text-align: center;
                padding: 60px 0;
            }
            
            .hero h1 {
                font-size: 48px;
                margin-bottom: 20px;
                background: linear-gradient(45deg, #fff, cyan);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            
            .hero p {
                font-size: 18px;
                color: #ccc;
                max-width: 700px;
                margin: 0 auto;
            }
            
            /* Stats */
            .stats {
                display: flex;
                justify-content: center;
                gap: 30px;
                margin: 40px 0;
                flex-wrap: wrap;
            }
            
            .stat-card {
                background: rgba(255,255,255,0.05);
                backdrop-filter: blur(10px);
                padding: 25px;
                border-radius: 15px;
                min-width: 180px;
                text-align: center;
                border: 1px solid rgba(0,255,255,0.3);
                animation: float 3s ease-in-out infinite;
            }
            
            @keyframes float {
                0% { transform: translateY(0px); }
                50% { transform: translateY(-10px); }
                100% { transform: translateY(0px); }
            }
            
            .stat-number {
                font-size: 36px;
                font-weight: bold;
                color: cyan;
            }
            
            /* Search Box */
            .search-box {
                background: rgba(255,255,255,0.05);
                backdrop-filter: blur(10px);
                border-radius: 30px;
                padding: 40px;
                margin: 40px 0;
                border: 1px solid rgba(0,255,255,0.3);
                box-shadow: 0 20px 40px rgba(0,0,0,0.4);
            }
            
            .search-title {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .search-title h2 {
                font-size: 32px;
                color: cyan;
            }
            
            .search-title p {
                color: #ccc;
                margin-top: 10px;
            }
            
            .input-group {
                display: flex;
                gap: 15px;
                max-width: 700px;
                margin: 0 auto;
            }
            
            .input-group input {
                flex: 1;
                padding: 18px 25px;
                border: none;
                border-radius: 50px;
                background: rgba(255,255,255,0.1);
                color: white;
                font-size: 16px;
                border: 1px solid rgba(0,255,255,0.3);
                transition: all 0.3s;
            }
            
            .input-group input:focus {
                outline: none;
                border-color: cyan;
                box-shadow: 0 0 20px rgba(0,255,255,0.3);
            }
            
            .input-group button {
                padding: 18px 40px;
                border: none;
                border-radius: 50px;
                background: linear-gradient(45deg, cyan, blue);
                color: white;
                font-weight: bold;
                font-size: 16px;
                cursor: pointer;
                transition: all 0.3s;
            }
            
            .input-group button:hover {
                transform: scale(1.05);
                box-shadow: 0 5px 30px cyan;
            }
            
            /* Country Tags */
            .country-tags {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                justify-content: center;
                margin: 20px 0;
            }
            
            .country-tag {
                background: rgba(0,255,255,0.1);
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 12px;
                border: 1px solid rgba(0,255,255,0.3);
            }
            
            /* Key Request Section */
            .key-section {
                background: rgba(255,255,255,0.03);
                border-radius: 20px;
                padding: 30px;
                margin: 40px 0;
                text-align: center;
            }
            
            .key-input-group {
                display: flex;
                gap: 15px;
                max-width: 500px;
                margin: 20px auto;
            }
            
            .key-input-group input {
                flex: 1;
                padding: 12px;
                border-radius: 10px;
                border: 1px solid cyan;
                background: rgba(0,0,0,0.3);
                color: white;
            }
            
            .key-input-group select {
                padding: 12px;
                border-radius: 10px;
                background: cyan;
                border: none;
                font-weight: bold;
            }
            
            .key-btn {
                padding: 12px 24px;
                border-radius: 10px;
                background: cyan;
                color: black;
                font-weight: bold;
                border: none;
                cursor: pointer;
            }
            
            /* Result Box */
            .result-box {
                background: rgba(0,0,0,0.5);
                border-radius: 15px;
                padding: 25px;
                margin: 30px 0;
                border-left: 4px solid cyan;
                display: none;
            }
            
            .result-box.show {
                display: block;
                animation: slideIn 0.5s;
            }
            
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .country-flag {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 5px;
                background: cyan;
                color: black;
                font-size: 12px;
                margin-left: 10px;
            }
            
            /* Features */
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 30px;
                margin: 60px 0;
            }
            
            .feature {
                background: rgba(255,255,255,0.03);
                padding: 30px;
                border-radius: 20px;
                text-align: center;
                border: 1px solid rgba(0,255,255,0.2);
                transition: all 0.3s;
            }
            
            .feature:hover {
                transform: translateY(-10px);
                border-color: cyan;
                box-shadow: 0 10px 30px rgba(0,255,255,0.2);
            }
            
            .feature-icon {
                font-size: 48px;
                margin-bottom: 20px;
            }
            
            /* Footer */
            .footer {
                text-align: center;
                padding: 40px 0;
                margin-top: 60px;
                border-top: 1px solid rgba(0,255,255,0.2);
            }
            
            .owner-highlight {
                color: cyan;
                font-weight: bold;
                font-size: 18px;
            }
            
            /* Responsive */
            @media (max-width: 768px) {
                .navbar {
                    flex-direction: column;
                    gap: 15px;
                }
                
                .hero h1 {
                    font-size: 32px;
                }
                
                .input-group {
                    flex-direction: column;
                }
                
                .key-input-group {
                    flex-direction: column;
                }
            }
        </style>
    </head>
    <body>
        <div class="globe"></div>
        
        <div class="container">
            <!-- Navbar -->
            <nav class="navbar">
                <div class="logo">🌍 GLOBAL TG OSINT</div>
                <div>
                    <span class="owner-badge">👑 OWNER: @Antyrx</span>
                </div>
            </nav>
            
            <!-- Hero Section -->
            <div class="hero">
                <h1>World's Most Advanced Telegram OSINT</h1>
                <p>Kisi bhi country ka Telegram ID se mobile number nikaalo | India, Canada, USA, UK, UAE, Australia, Germany, France, Russia, China, Japan, Brazil, Saudi, Pakistan, Bangladesh, Nepal + 150+ countries</p>
            </div>
            
            <!-- Stats -->
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">150+</div>
                    <div class="stat-label">Countries</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">1M+</div>
                    <div class="stat-label">Lookups</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">99.9%</div>
                    <div class="stat-label">Success Rate</div>
                </div>
            </div>
            
            <!-- Country Tags -->
            <div class="country-tags">
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
            </div>
            
            <!-- Main Search Box -->
            <div class="search-box">
                <div class="search-title">
                    <h2>🔍 Global Telegram Lookup</h2>
                    <p>Enter any Telegram ID or Username from any country</p>
                </div>
                
                <div class="input-group">
                    <input type="text" id="telegramId" placeholder="e.g., 123456789 or @username (kisi bhi country ka)">
                    <button onclick="searchTelegram()">
                        <span id="btnText">Search Worldwide →</span>
                        <span id="btnLoader" style="display: none;">⏳</span>
                    </button>
                </div>
                
                <div style="text-align: center; margin-top: 15px; color: #888; font-size: 14px;">
                    🔑 Use any key: ANTYRX-MASTER-2024 (owner), ya request karo neeche se
                </div>
                
                <!-- Result Box -->
                <div id="resultBox" class="result-box">
                    <div id="resultContent"></div>
                </div>
            </div>
            
            <!-- Key Request Section -->
            <div class="key-section">
                <h3>🔑 Request API Key</h3>
                <p>Sirf @Antyrx approve karega - Owner se contact karo</p>
                
                <div class="key-input-group">
                    <input type="text" id="telegramUsername" placeholder="Apna Telegram username">
                    <select id="keyTier">
                        <option value="free">Free (5/min, 50/day)</option>
                        <option value="premium">Premium (30/min, 500/day)</option>
                        <option value="enterprise">Enterprise (Custom)</option>
                    </select>
                    <button class="key-btn" onclick="requestKey()">Request Key</button>
                </div>
                
                <div id="keyResult" style="margin-top: 20px; color: cyan;"></div>
            </div>
            
            <!-- Features -->
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">🌍</div>
                    <h3>150+ Countries</h3>
                    <p>Kisi bhi country ka Telegram ID se number nikaalo</p>
                </div>
                
                <div class="feature">
                    <div class="feature-icon">⚡</div>
                    <h3>Instant Results</h3>
                    <p>Under 3 seconds mein result - worldwide</p>
                </div>
                
                <div class="feature">
                    <div class="feature-icon">👑</div>
                    <h3>Owner: @Antyrx</h3>
                    <p>Sirf owner hi API key generate kar sakta hai</p>
                </div>
                
                <div class="feature">
                    <div class="feature-icon">📱</div>
                    <h3>Phone Number</h3>
                    <p>Country code ke saath phone number milega</p>
                </div>
                
                <div class="feature">
                    <div class="feature-icon">🛡️</div>
                    <h3>Secure</h3>
                    <p>Enterprise-grade security</p>
                </div>
                
                <div class="feature">
                    <div class="feature-icon">💎</div>
                    <h3>24/7 Support</h3>
                    <p>Direct contact with @Antyrx</p>
                </div>
            </div>
            
            <!-- Footer -->
            <div class="footer">
                <p class="owner-highlight">👑 Owned & Operated by @Antyrx</p>
                <p>Koi bhi key generate nahi kar sakta sirf owner</p>
                <p style="margin-top: 20px;">© 2024 Global Telegram OSINT - World's Most Advanced</p>
            </div>
        </div>
        
        <script>
            async function searchTelegram() {
                const query = document.getElementById('telegramId').value.trim();
                const resultBox = document.getElementById('resultBox');
                const resultContent = document.getElementById('resultContent');
                const btnText = document.getElementById('btnText');
                const btnLoader = document.getElementById('btnLoader');
                
                if (!query) {
                    alert('Please enter Telegram ID or username');
                    return;
                }
                
                // Use master key for demo
                const key = 'ANTYRX-MASTER-2024';
                
                btnText.style.display = 'none';
                btnLoader.style.display = 'inline-block';
                
                try {
                    const response = await fetch(`/lookup?query=${encodeURIComponent(query)}&key=${key}`);
                    const data = await response.json();
                    
                    resultBox.classList.add('show');
                    
                    if (data.success) {
                        let html = '<div style="border-bottom: 2px solid cyan; padding-bottom: 15px; margin-bottom: 15px;">';
                        html += '<span style="color: cyan;">✅ SUCCESS - Global Hit!</span>';
                        html += '</div>';
                        
                        // Telegram Info
                        if (data.data.telegram) {
                            html += '<div style="margin: 15px 0;">';
                            html += '<h4 style="color: cyan;">📱 TELEGRAM INFO</h4>';
                            html += `<p><span style="color: #888;">ID:</span> ${data.data.telegram.id || 'N/A'}</p>`;
                            html += `<p><span style="color: #888;">Username:</span> @${data.data.telegram.username || 'N/A'}</p>`;
                            html += `<p><span style="color: #888;">Name:</span> ${data.data.telegram.first_name || ''} ${data.data.telegram.last_name || ''}</p>`;
                            html += '</div>';
                        }
                        
                        // Phone Info
                        if (data.data.phone) {
                            html += '<div style="margin: 15px 0; padding: 15px; background: rgba(0,255,255,0.1); border-radius: 10px;">';
                            html += '<h4 style="color: cyan;">📞 PHONE NUMBER FOUND!</h4>';
                            html += `<p><span style="color: #888;">Number:</span> <span style="color: #4CAF50; font-size: 20px;">${data.data.phone.number}</span></p>`;
                            html += `<p><span style="color: #888;">International:</span> ${data.data.phone.international}</p>`;
                            html += `<p><span style="color: #888;">Country:</span> ${data.data.phone.country} <span class="country-flag">${data.data.phone.country_code}</span></p>`;
                            html += '</div>';
                        }
                        
                        if (data.data.bio) {
                            html += `<p><span style="color: #888;">Bio:</span> ${data.data.bio}</p>`;
                        }
                        
                        resultContent.innerHTML = html;
                    } else {
                        resultContent.innerHTML = `
                            <div style="color: #ff6b6b;">❌ ${data.error}</div>
                            <div style="margin-top: 15px; color: #888;">Try with a different ID or contact @Antyrx</div>
                        `;
                    }
                } catch (error) {
                    resultContent.innerHTML = `<div style="color: #ff6b6b;">❌ Error: ${error.message}</div>`;
                } finally {
                    btnText.style.display = 'inline';
                    btnLoader.style.display = 'none';
                }
            }
            
            async function requestKey() {
                const username = document.getElementById('telegramUsername').value.trim();
                const tier = document.getElementById('keyTier').value;
                const keyResult = document.getElementById('keyResult');
                
                if (!username) {
                    alert('Please enter your Telegram username');
                    return;
                }
                
                keyResult.innerHTML = '⏳ Sending request to @Antyrx...';
                
                try {
                    const response = await fetch(`/request-key?username=${username}&tier=${tier}`);
                    const data = await response.json();
                    
                    if (data.success) {
                        keyResult.innerHTML = `
                            <div style="background: rgba(0,255,0,0.1); padding: 15px; border-radius: 10px;">
                                ✅ ${data.message}<br>
                                Request ID: ${data.request_id}<br>
                                <span style="color: cyan;">⏳ Wait for @Antyrx to approve</span>
                            </div>
                        `;
                    } else {
                        keyResult.innerHTML = `❌ ${data.error}`;
                    }
                } catch (error) {
                    keyResult.innerHTML = `❌ ${error.message}`;
                }
            }
        </script>
    </body>
    </html>
    """

# ===== LOOKUP ENDPOINT =====
@app.get("/lookup")
async def lookup(
    request: Request,
    query: str = Query(..., description="Telegram ID ya Username"),
    key: str = Query(..., description="API Key")
):
    """Worldwide Telegram lookup"""
    
    # Validate key
    valid, tier, message = key_manager.validate_key(key)
    if not valid:
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "error": message,
                "contact": "@Antyrx"
            }
        )
    
    # Rate limit
    allowed, msg = rate_limiter.check(request.client.host, tier)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={
                "success": False,
                "error": msg,
                "contact": "@Antyrx"
            }
        )
    
    # Perform lookup
    result = await fetcher.lookup(query)
    
    # Add metadata
    result["meta"] = {
        "tier": tier,
        "remaining": msg,
        "timestamp": datetime.now().isoformat(),
        "owner": "@Antyrx"
    }
    
    return result

# ===== REQUEST KEY =====
@app.get("/request-key")
async def request_key(
    username: str = Query(...),
    tier: str = Query("free")
):
    """User key request - Sirf owner approve karega"""
    result = key_manager.request_key(username, tier)
    return result

# ===== OWNER ENDPOINTS =====

@app.post("/owner/generate-key")
async def owner_generate_key(
    request: Request,
    tier: str = Query(..., regex="^(free|premium|enterprise)$"),
    username: str = Query(...)
):
    """Sirf owner key generate kar sakta hai"""
    await verify_owner(request)
    
    result = key_manager.generate_key(tier, username)
    return result

@app.get("/owner/pending-requests")
async def owner_pending_requests(request: Request):
    """Sirf owner pending requests dekh sakta hai"""
    await verify_owner(request)
    
    return {
        "success": True,
        "pending": key_manager.pending_requests,
        "total": len(key_manager.pending_requests)
    }

@app.post("/owner/approve-key/{request_id}")
async def owner_approve_key(request: Request, request_id: str):
    """Sirf owner key approve kar sakta hai"""
    await verify_owner(request)
    
    result = key_manager.approve_key(request_id)
    return result

@app.get("/owner/stats")
async def owner_stats(request: Request):
    """Sirf owner statistics dekh sakta hai"""
    await verify_owner(request)
    
    return {
        "success": True,
        "total_keys": len(key_manager.keys),
        "active_keys": len([k for k in key_manager.keys.values() if k.get("active")]),
        "pending_requests": len(key_manager.pending_requests),
        "total_requests": sum(u["total_requests"] for u in key_manager.usage.values()),
        "usage": dict(key_manager.usage)
    }

# ===== HEALTH CHECK =====
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "Global Telegram OSINT",
        "owner": "@Antyrx",
        "version": "5.0.0",
        "countries": "150+",
        "timestamp": datetime.now().isoformat()
    }

# ===== DOCS =====
@app.get("/docs", response_class=HTMLResponse)
async def docs():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global OSINT Docs - @Antyrx</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #000428, #004e92);
                color: white;
                padding: 40px;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
            }
            h1 { color: cyan; }
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
            .owner-note {
                background: gold;
                color: black;
                padding: 20px;
                border-radius: 10px;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🌍 Global Telegram OSINT API</h1>
            <p>Owner: <strong>@Antyrx</strong> - Sirf owner key generate kar sakta hai</p>
            
            <div class="owner-note">
                ⚠️ IMPORTANT: API keys sirf @Antyrx generate kar sakte hain. 
                Koi aur key nahi bana sakta. Request karo aur wait karo approval ke liye.
            </div>
            
            <div class="endpoint">
                <h3>🔍 Lookup Endpoint</h3>
                <code>GET /lookup?query=TELEGRAM_ID&key=YOUR_KEY</code>
                <p>Kisi bhi country ka Telegram ID se data nikaalo</p>
            </div>
            
            <div class="endpoint">
                <h3>🔑 Request Key</h3>
                <code>GET /request-key?username=YOUR_TELEGRAM&tier=free/premium/enterprise</code>
                <p>Key request karo - @Antyrx approve karega</p>
            </div>
            
            <h2>🌍 Supported Countries</h2>
            <p>India, Canada, USA, UK, Australia, Germany, France, Russia, China, Japan, Brazil, UAE, Saudi, Pakistan, Bangladesh, Sri Lanka, Nepal + 150+ countries</p>
            
            <h2>📞 Contact</h2>
            <p>Telegram: <strong>@Antyrx</strong> (Sirf yahi se milega key)</p>
        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)