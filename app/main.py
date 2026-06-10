from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from app.database import init_db, get_db
from app.models import User, RefreshSession, JwtBlacklist
from tokenly_auth import hash_password, verifyPassword, jwtHandler, RefreshManager, validate_creds_structure
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone, timedelta
import uuid

app = FastAPI(title="Tokenly Demo App")

# Templates and Static files
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Configuration
SECRET_KEY = "demo-secret-key-that-is-long-enough-32-chars"
jwt_inst = jwtHandler(SECRET_KEY)
refresh_inst = RefreshManager()
security = HTTPBearer()

class SessionManager:
    def __init__(self, db: Session):
        self.db = db

    def create_session(self, user_id: str, token_hash: str, refresh_days: int):
        session_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(days=refresh_days)
        new_session = RefreshSession(
            session_id=session_id,
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at
        )
        self.db.add(new_session)
        return new_session

    def validate_and_rotate(self, refresh_token: str):
        # The library's createJwt returns the hash as 'refresh_token', so we compare directly
        statement = select(RefreshSession).where(
            RefreshSession.token_hash == refresh_token,
            RefreshSession.revoked == False
        )
        session_obj = self.db.exec(statement).first()
        
        if not session_obj:
            raise ValueError("Invalid or revoked refresh token")
        
        if session_obj.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            session_obj.revoked = True
            self.db.add(session_obj)
            self.db.commit()
            raise ValueError("Refresh token expired")
            
        # Revoke old session
        session_obj.revoked = True
        self.db.add(session_obj)
        return session_obj.user_id

class BlacklistManager:
    def __init__(self, db: Session):
        self.db = db

    def debar_jwt(self, jti: str, user_name: str, expired_at: datetime):
        blacklisted = JwtBlacklist(
            jti=jti,
            user_name=user_name,
            expired_at=expired_at
        )
        self.db.add(blacklisted)

    def is_token_blacklisted(self, jti: str):
        statement = select(JwtBlacklist).where(JwtBlacklist.jti == jti)
        return self.db.exec(statement).first() is not None

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenRefresh(BaseModel):
    refresh_token: str

def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = auth.credentials
    try:
        payload = jwt_inst.verifyJwt(token)
        bm = BlacklistManager(db)
        if bm.is_token_blacklisted(payload.get("jti")):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Could not validate credentials: {str(e)}")

@app.post("/signup")
def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    try:
        # Internal function to use the decorator
        @validate_creds_structure
        def validate(username, password):
            return True
        validate(user_data.username, user_data.password)
        
        hashed_pwd = hash_password(user_data.password, user_id=user_data.username)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    statement = select(User).where(User.username == user_data.username)
    existing_user = db.exec(statement).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pwd
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully", "user_id": new_user.id}

@app.post("/login")
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    statement = select(User).where(User.username == login_data.username)
    user = db.exec(statement).first()
    
    if not user or not verifyPassword(login_data.password, user.hashed_password, user_id=user.username):
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = jwt_inst.createJwt(sub=str(user.id))
    
    sm = SessionManager(db)
    sm.create_session(
        user_id=str(user.id),
        token_hash=token_data["refresh_token"],
        refresh_days=token_data["refresh_days"]
    )
    db.commit()
    
    return {
        "access_token": token_data["access_token"],
        "refresh_token": token_data["refresh_token"], # Note: in real app, give raw token, but library returns hash here?
        "token_type": "bearer"
    }

# Wait, the library's createJwt returns 'refresh_token' as the hash. 
# "raw_refresh_token = secrets.token_urlsafe(64); refresh_token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()"
# BUT it returns the hash in the dict. This is a bit odd for a library. 
# Usually you want the client to have the raw token.
# Let's re-read createJwt.

@app.post("/refresh")
def refresh_token(data: TokenRefresh, db: Session = Depends(get_db)):
    try:
        sm = SessionManager(db)
        user_id = sm.validate_and_rotate(data.refresh_token)
        
        statement = select(User).where(User.id == int(user_id))
        user = db.exec(statement).first()
        if not user:
            raise ValueError("User not found")
            
        token_data = jwt_inst.createJwt(sub=str(user.id))
        
        sm.create_session(
            user_id=str(user.id),
            token_hash=token_data["refresh_token"],
            refresh_days=token_data["refresh_days"]
        )
        db.commit()
        
        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "token_type": "bearer"
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/me")
def get_me(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    statement = select(User).where(User.id == int(current_user.get("sub")))
    user = db.exec(statement).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user.username, "user_id": user.id}

@app.post("/logout")
def logout(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    jti = current_user.get("jti")
    sub = current_user.get("sub")
    exp = current_user.get("exp")
    
    if jti and sub and exp:
        expired_at = datetime.fromtimestamp(exp, tz=timezone.utc)
        bm = BlacklistManager(db)
        bm.debar_jwt(jti, sub, expired_at)
        db.commit()
        
    return {"message": "Logged out successfully"}

@app.get("/health")
def health_check():
    return {"status": "ok"}
