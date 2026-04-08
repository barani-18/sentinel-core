"""Sentinel-Core: Autonomous Cloud-Native SOC Analyst FastAPI Backend Server"""

import time
import random
import hashlib
import jwt
import os
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy.orm import Session

# Correct Absolute Imports
from database import engine, SessionLocal, get_db
import models

# This creates the tables in the database as soon as the app starts
models.Base.metadata.create_all(bind=engine)

# ---------- Config ----------
SECRET_KEY = os.getenv("SECRET_KEY", "sentinel-core-soc-2024-secret-key-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 8

app = FastAPI(
    title="Sentinel-Core API",
    description="Autonomous Cloud-Native SOC Analyst Backend",
    version="1.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ---------- Models ----------
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

# ---------- Demo Users ----------
DEMO_USERS = {
    "analyst": {
        "password_hash": hashlib.sha256("soc2024".encode()).hexdigest(),
        "user": {"username": "analyst", "role": "analyst", "name": "Alex Rivera", "avatar": "AR"},
        "mfa_required": False
    },
    "senior": {
        "password_hash": hashlib.sha256("soc2024".encode()).hexdigest(),
        "user": {"username": "senior", "role": "senior_analyst", "name": "Jordan Kim", "avatar": "JK"},
        "mfa_required": True
    },
    "lead": {
        "password_hash": hashlib.sha256("soc2024".encode()).hexdigest(),
        "user": {"username": "lead", "role": "soc_lead", "name": "Morgan Chen", "avatar": "MC"},
        "mfa_required": True
    },
    "admin": {
        "password_hash": hashlib.sha256("sentinel".encode()).hexdigest(),
        "user": {"username": "admin", "role": "admin", "name": "Dr. Samir Patel", "avatar": "SP"},
        "mfa_required": True
    },
}

# ---------- Sentinel-Core Simulation ----------
class SentinelCore:
    def __init__(self, seed: int = None):
        self.rng = random.Random(seed or int(time.time()))
        self.state = self._initial_state()

    def _initial_state(self) -> Dict:
        hosts = []
        for i in range(12):
            hosts.append({
                "id": f"h-{(i+1):02d}",
                "compromised": False,
                "risk": 0.1 + self.rng.random() * 0.2,
                "cpu": 0.2 + self.rng.random() * 0.3,
                "lastSeen": int(time.time() * 1000),
            })
        
        alerts = self._gen_initial_alerts(6)
        metrics = self._compute_metrics(hosts, alerts)
        
        return {
            "step": 0,
            "score": 0.72,
            "alerts": alerts,
            "hosts": hosts,
            "metrics": metrics,
            "history": [{"step": 0, "anomaly": 0.35, "cpu": 0.32, "threats": 3, "compromised": 0}],
            "logs": [
                {"id": self._uid(), "ts": int(time.time() * 1000), "kind": "info", "msg": "Sentinel-Core online. Cloud-native SOC initialized."},
                {"id": self._uid(), "ts": int(time.time() * 1000), "kind": "success", "msg": "Telemetry ingestion: vpc-flow, EDR, WAF, CloudTrail"},
            ]
        }

    def _gen_initial_alerts(self, n: int) -> List[Dict]:
        types = ["PortScan", "BruteForce", "Phishing", "Malware", "Lateral", "Exfiltration", "Ransomware"]
        alerts = []
        for i in range(n):
            sev_roll = self.rng.random()
            severity = "high" if sev_roll > 0.7 else "medium" if sev_roll > 0.35 else "low"
            alerts.append({
                "id": f"A-{1000 + i}",
                "ts": int(time.time() * 1000) - int(self.rng.random() * 1000 * 60 * 8),
                "type": self.rng.choice(types),
                "severity": severity,
                "confidence": round(0.55 + self.rng.random() * 0.4, 2),
                "srcIp": f"203.{self.rng.randint(0,255)}.{self.rng.randint(0,255)}.{self.rng.randint(0,255)}",
                "host": f"h-{self.rng.randint(1,12):02d}",
                "status": "open",
            })
        return alerts

    def _compute_metrics(self, hosts, alerts):
        compromised = sum(1 for h in hosts if h["compromised"])
        active_high = sum(1 for a in alerts if a["status"] in ["open", "investigating"] and a["severity"] == "high")
        anomaly = max(0, min(1, 0.2 + active_high * 0.12 + compromised * 0.08 + self.rng.random() * 0.1))
        cpu = max(0, min(1, 0.25 + self.rng.random() * 0.2 + compromised * 0.05 + active_high * 0.03))
        threat = max(0, min(1, 0.3 + active_high * 0.1 + compromised * 0.12 + self.rng.random() * 0.08))
        return {
            "compromisedHosts": compromised,
            "anomalyScore": anomaly,
            "cpu": cpu,
            "threatLevel": threat
        }

    def _mutate(self):
        state = self.state
        hosts = state["hosts"]
        alerts = state["alerts"]
        
        if self.rng.random() > 0.35:
            new_a = self._gen_initial_alerts(1)[0]
            new_a["id"] = f"A-{1000 + self.rng.randint(0, 8999)}"
            new_a["ts"] = int(time.time() * 1000)
            alerts.insert(0, new_a)
            state["logs"].insert(0, {
                "id": self._uid(),
                "ts": int(time.time() * 1000),
                "kind": "warn",
                "msg": f"New alert {new_a['id']} ({new_a['type']}) from {new_a['srcIp']} → {new_a['host']}"
            })
            
        for h in hosts:
            h["cpu"] = max(0, min(1, h["cpu"] + (self.rng.random() - 0.5) * 0.06))
            h["risk"] = max(0, min(1, h["risk"] + (self.rng.random() - 0.5) * 0.05 + (0.02 if h["compromised"] else 0)))
            h["lastSeen"] = int(time.time() * 1000) - self.rng.randint(0, 60000)
            if not h["compromised"] and h["risk"] > 0.85 and self.rng.random() > 0.6:
                h["compromised"] = True
                state["logs"].insert(0, {
                    "id": self._uid(),
                    "ts": int(time.time() * 1000),
                    "kind": "error",
                    "msg": f"Host {h['id']} compromised (risk {int(h['risk']*100)}%)"
                })
        
        for a in alerts:
            if a["status"] == "open" and self.rng.random() > 0.85:
                a["confidence"] = max(0, min(1, a["confidence"] + 0.05))
                
        state["metrics"] = self._compute_metrics(hosts, alerts)
        state["history"].append({
            "step": state["step"],
            "anomaly": round(state["metrics"]["anomalyScore"], 3),
            "cpu": round(state["metrics"]["cpu"], 3),
            "threats": sum(1 for a in alerts if a["status"] in ["open", "investigating"]),
            "compromised": sum(1 for h in hosts if h["compromised"]),
        })
        if len(state["history"]) > 120:
            state["history"].pop(0)

    def reset(self):
        self.state = self._initial_state()
        self.state["logs"].insert(0, {
            "id": self._uid(),
            "ts": int(time.time() * 1000),
            "kind": "info",
            "msg": "Environment reset."
        })
        return self.state

    def get_state(self):
        return self.state

    def step(self, action: dict):
        prev_score = self.state["score"]
        self.state["step"] += 1
        
        alert = None
        if action.get("alertId"):
            alert = next((a for a in self.state["alerts"] if a["id"] == action["alertId"]), None)
            
        reward = 0
        info = ""
        
        if not alert and action["kind"] != "noop":
            reward = -0.05
            info = "No such alert."
            self.state["logs"].insert(0, {
                "id": self._uid(), "ts": int(time.time() * 1000), "kind": "warn",
                "msg": f"Action failed: alert {action.get('alertId')} not found", "reward": reward
            })
        elif alert:
            kind = action["kind"]
            if kind == "investigate":
                if alert["status"] == "open":
                    alert["status"] = "investigating"
                    alert["confidence"] = min(1, alert["confidence"] + 0.08)
                    reward = 0.05
                    info = "Investigation started."
                    self.state["logs"].insert(0, {
                        "id": self._uid(), "ts": int(time.time() * 1000), "kind": "info",
                        "msg": f"Investigating {alert['id']} ({alert['type']}) on {alert['host']}", "reward": reward
                    })
                else:
                    reward = -0.01
                    info = "Already in progress."
            elif kind == "block_ip":
                alert["status"] = "blocked"
                alert["actionTaken"] = f"Blocked {alert['srcIp']}"
                host = next((h for h in self.state["hosts"] if h["id"] == alert["host"]), None)
                if host:
                    host["risk"] = max(0, host["risk"] - 0.15)
                reward = 0.12 if alert["severity"] == "high" else 0.08 if alert["severity"] == "medium" else 0.04
                info = f"IP {alert['srcIp']} blocked."
                self.state["logs"].insert(0, {
                    "id": self._uid(), "ts": int(time.time() * 1000), "kind": "success",
                    "msg": f"{alert['id']}: {info}", "reward": reward
                })
            elif kind == "isolate_host":
                alert["status"] = "isolated"
                host = next((h for h in self.state["hosts"] if h["id"] == alert["host"]), None)
                if host:
                    host["compromised"] = False
                    host["risk"] = max(0, host["risk"] - 0.35)
                    host["cpu"] = max(0, host["cpu"] - 0.1)
                alert["actionTaken"] = f"Isolated {alert['host']}"
                reward = 0.15
                info = f"Host {alert['host']} isolated."
                self.state["logs"].insert(0, {
                    "id": self._uid(), "ts": int(time.time() * 1000), "kind": "success",
                    "msg": f"{alert['id']}: {info}", "reward": reward
                })
            elif kind == "ignore":
                alert["status"] = "ignored"
                reward = -0.15 if alert["severity"] == "high" else -0.07 if alert["severity"] == "medium" else -0.02
                info = "Alert ignored."
                self.state["logs"].insert(0, {
                    "id": self._uid(), "ts": int(time.time() * 1000),
                    "kind": "error" if alert["severity"] == "high" else "warn",
                    "msg": f"{alert['id']} ignored ({alert['severity']})", "reward": reward
                })
            elif kind == "escalate":
                alert["status"] = "escalated"
                alert["confidence"] = min(1, alert["confidence"] + 0.05)
                reward = 0.03
                info = "Escalated to Tier-2."
                self.state["logs"].insert(0, {
                    "id": self._uid(), "ts": int(time.time() * 1000), "kind": "info",
                    "msg": f"{alert['id']}: {info}", "reward": reward
                })
            elif kind == "resolve":
                alert["status"] = "resolved"
                reward = 0.06
                info = "Resolved."
                self.state["logs"].insert(0, {
                    "id": self._uid(), "ts": int(time.time() * 1000), "kind": "success",
                    "msg": f"{alert['id']}: resolved", "reward": reward
                })
        
        self._mutate()
        unhealthy = self.state["metrics"]["compromisedHosts"] * 0.05 + self.state["metrics"]["anomalyScore"] * 0.08
        self.state["score"] = max(0, min(1, prev_score * 0.9 + 0.1 * (0.5 + reward) - unhealthy * 0.1 + 0.05))
        done = self.state["step"] >= 200 or self.state["score"] < 0.15
        
        return {
            "state": self.state,
            "reward": reward,
            "done": done,
            "info": info
        }

    def _uid(self):
        return hashlib.md5(str(time.time() + self.rng.random()).encode()).hexdigest()[:8]

# ---------- Global State ----------
sessions: Dict[str, SentinelCore] = {}

def get_core(session_id: str = "default") -> SentinelCore:
    if session_id not in sessions:
        sessions[session_id] = SentinelCore()
    return sessions[session_id]

# ---------- Auth Helpers ----------
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in DEMO_USERS:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ---------- API Routes ----------
@app.get("/")
def root():
    return {
        "name": "Sentinel-Core API",
        "version": "1.0.0",
        "description": "Autonomous Cloud-Native SOC Analyst",
        "endpoints": ["/login", "/reset", "/step", "/state", "/health", "/alerts/create"]
    }

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": int(time.time() * 1000)}

@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    user_data = DEMO_USERS.get(req.username.lower())
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    pwd_hash = hashlib.sha256(req.password.encode()).hexdigest()
    if pwd_hash != user_data["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    if user_data["mfa_required"]:
        if not req.mfa_code or req.mfa_code != "123456":
            raise HTTPException(status_code=401, detail="Invalid MFA code")
            
    token = create_access_token({"sub": req.username.lower()})
    get_core(req.username.lower())
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user_data["user"]
    }

@app.post("/reset", response_model=StateSnapshot)
def reset_environment():
    core = get_core("default")
    return core.reset()

# NEW: The missing step endpoint
@app.post("/step", response_model=StepResponse)
def take_action(req: StepRequest):
    core = get_core("default")
    return core.step(req.dict())

@app.post("/alerts/create")
def create_alert(alert_data: dict, db: Session = Depends(get_db)):
    new_alert = models.AlertRecord(
        id=f"A-{random.randint(1000, 9999)}",
        type=alert_data.get("type", "Unknown"),
        severity=alert_data.get("severity", "medium"),
        confidence=alert_data.get("confidence", 0.9),
        status="open",
        host=alert_data.get("host", "unknown-host")
    )
    db.add(new_alert)
    db.commit()
    return {"status": "success", "id": new_alert.id}

@app.get("/state")
def get_state(db: Session = Depends(get_db), username: str = Depends(verify_token)):
    # Try to pull real rows from the Database
    db_alerts = db.query(models.AlertRecord).all()
    
    if db_alerts:
        return {
            "step": 0,
            "score": 0.92,
            "alerts": db_alerts,
            "hosts": [], 
            "metrics": {"compromisedHosts": 0, "anomalyScore": 0.05, "cpu": 0.1, "threatLevel": 0.1},
            "history": [],
            "logs": [{"id": "1", "ts": int(time.time()*1000), "kind": "success", "msg": "Connected to Database"}]
        }
        
    # Fallback to simulation if DB is empty
    core = get_core(username)
    return core.get_state()

@app.get("/me", response_model=User)
def get_me(username: str = Depends(verify_token)):
    return DEMO_USERS[username]["user"]

# ---------- Run ----------
# ... (all your imports at the top) ...

# Move the DB creation inside a safe function
def init_db():
    try:
        print("Connecting to database...")
        models.Base.metadata.create_all(bind=engine)
        print("Database connected and tables created.")
    except Exception as e:
        print(f"Database connection failed: {e}")
        # We don't crash here so the server can still start and show an error 
        # instead of an "Unhandled Exception"
        pass

# ... (keep all your Models, SentinelCore class, and Routes) ...

def main():
    import uvicorn
    # Initialize the DB right before starting the server
    init_db()
    
    # Use the 'import string' format to satisfy the validator warning.
    # We use "server.app:app" because the validator runs from the root directory.
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)

if __name__ == "__main__":
    main()
