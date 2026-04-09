"""Sentinel-Core: Autonomous Cloud-Native SOC Analyst FastAPI Backend Server"""
import sys
import os
import time
import random
import hashlib
import jwt
import uvicorn
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy.orm import Session

# ---------- Setup Pathing ----------
# Ensures local imports like 'database' and 'models' work inside the container
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from database import engine, SessionLocal, get_db
    import models
    # Initialize DB tables
    models.Base.metadata.create_all(bind=engine)
except ImportError:
    print("Warning: database.py or models.py not found. Running in Simulation-only mode.")
    def get_db(): yield None

# ---------- Config ----------
SECRET_KEY = os.getenv("SECRET_KEY", "sentinel-core-soc-2024-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 8

app = FastAPI(
    title="Sentinel-Core API",
    description="Autonomous Cloud-Native SOC Analyst Backend",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ---------- Schema Definitions ----------
class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

class AlertStatus(str, Enum):
    open = "open"
    investigating = "investigating"
    blocked = "blocked"
    isolated = "isolated"
    ignored = "ignored"
    escalated = "escalated"
    resolved = "resolved"

class Alert(BaseModel):
    id: str
    ts: int
    type: str
    severity: Severity
    confidence: float
    srcIp: str
    host: str
    status: AlertStatus
    actionTaken: Optional[str] = None

class Host(BaseModel):
    id: str
    compromised: bool
    risk: float
    cpu: float
    lastSeen: int

class LogEntry(BaseModel):
    id: str
    ts: int
    msg: str
    kind: str
    reward: Optional[float] = None

class Metrics(BaseModel):
    compromisedHosts: int
    anomalyScore: float
    cpu: float
    threatLevel: float

class HistoryPoint(BaseModel):
    step: int
    anomaly: float
    cpu: float
    threats: int
    compromised: int

class StateSnapshot(BaseModel):
    step: int
    score: float
    alerts: List[Alert]
    hosts: List[Host]
    metrics: Metrics
    history: List[HistoryPoint]
    logs: List[LogEntry]

class StepRequest(BaseModel):
    kind: str
    alertId: Optional[str] = None

class StepResponse(BaseModel):
    state: StateSnapshot
    reward: float
    done: bool
    info: str

class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

class User(BaseModel):
    username: str
    role: str
    name: str
    avatar: str

# ---------- Demo Data ----------
DEMO_USERS = {
    "analyst": {
        "password_hash": hashlib.sha256("soc2024".encode()).hexdigest(),
        "user": {"username": "analyst", "role": "analyst", "name": "Alex Rivera", "avatar": "AR"},
        "mfa_required": False
    },
    "admin": {
        "password_hash": hashlib.sha256("sentinel".encode()).hexdigest(),
        "user": {"username": "admin", "role": "admin", "name": "Dr. Samir Patel", "avatar": "SP"},
        "mfa_required": True
    },
}

# ---------- Logic Engine ----------
class SentinelCore:
    def __init__(self, seed: int = None):
        self.rng = random.Random(seed or int(time.time()))
        self.state = self._initial_state()

    def _initial_state(self) -> Dict[str, Any]:
        """
        Fixed: Provided the properly indented block for initial state generation.
        """
        current_time = int(time.time())
        return {
            "step": 0,
            "score": 100.0,
            "alerts": [],
            "hosts": [
                {
                    "id": f"host-{i}",
                    "compromised": False,
                    "risk": 0.0,
                    "cpu": self.rng.uniform(10.0, 45.0),
                    "lastSeen": current_time
                } for i in range(1, 4)
            ],
            "metrics": {
                "compromisedHosts": 0,
                "anomalyScore": 0.0,
                "cpu": 35.0,
                "threatLevel": 0.0
            },
            "history": [],
            "logs": [{
                "id": "log-0",
                "ts": current_time,
                "msg": "Sentinel-Core initialized successfully.",
                "kind": "system",
                "reward": 0.0
            }]
        }

# Initialize the global engine
engine_core = SentinelCore()

# ---------- API Endpoints ----------

@app.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """Basic mock authentication."""
    user_record = DEMO_USERS.get(request.username)
    
    if not user_record:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    hashed_pw = hashlib.sha256(request.password.encode()).hexdigest()
    if user_record["password_hash"] != hashed_pw:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    # Mock token generation
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    token_payload = {
        "sub": request.username,
        "exp": expire
    }
    access_token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_record["user"]
    )

@app.post("/api/step", response_model=StepResponse)
async def process_step(request: StepRequest, token: HTTPAuthorizationCredentials = Depends(security)):
    """Mock processing step for the SOC simulation engine."""
    # In a real app, you would process the request.kind (e.g., 'investigate', 'isolate') here.
    
    # Increment step
    engine_core.state["step"] += 1
    
    return StepResponse(
        state=StateSnapshot(**engine_core.state),
        reward=10.0,
        done=False,
        info=f"Action '{request.kind}' processed."
    )

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
