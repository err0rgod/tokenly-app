from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from app.database import init_db, get_db
from app.models import User
from tokenly.secure import hash_password, verifyPassword
from tokenly.session.jwt_handler import jwtHandler
from tokenly.session.blacklist import handleJwtBlacklist
from tokenly.session import RefreshManager
from tokenly.validations import validate_creds_structure
from tokenly.model.models import userdata
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import os

# --- Workaround for tokenly timezone bug ---
import tokenly.session.refresh_handler
class NaiveDatetime:
    @staticmethod
    def now(tz=None):
        return datetime.now(timezone.utc).replace(tzinfo=None)
tokenly.session.refresh_handler.datetime = NaiveDatetime
# -------------------------------------------

app = FastAPI(title="Tokenly Demo App")

# Templates and Static files
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Configuration
SECRET_KEY = "demo-secret-key-that-is-long-enough-32-chars"
jwt_inst = jwtHandler(SECRET_KEY)
security = HTTPBearer()

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
        blacklist = handleJwtBlacklist(db)
        if blacklist.is_token_blacklisted(payload.get("jti")):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Could not validate credentials: {str(e)}")

@app.post("/signup")
def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    try:
        u_obj = userdata(user_id="pending", user_name=user_data.username, password=user_data.password)
        u_obj_hashed = hash_password(u_obj)
        hashed_pwd = u_obj_hashed.password
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
    
    if not user:
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    u_obj = userdata(
        user_id=str(user.id),
        user_name=user.username,
        password=user.hashed_password
    )
    
    if not verifyPassword(u_obj, login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_data_for_jwt = userdata(
        user_id=str(user.id),
        user_name=user.username,
        password=user.hashed_password
    )
    
    access_token, refresh_token, session_obj = jwt_inst.createJwt(user_data_for_jwt)
    
    db.add(session_obj)
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/refresh")
def refresh_token(data: TokenRefresh, db: Session = Depends(get_db)):
    try:
        rm = RefreshManager(db)
        user_id = rm.validate_and_rotate(data.refresh_token)
        
        statement = select(User).where(User.id == int(user_id))
        user = db.exec(statement).first()
        if not user:
            raise ValueError("User not found")
            
        user_data_for_jwt = userdata(
            user_id=str(user.id),
            user_name=user.username,
            password=user.hashed_password
        )
        
        access_token, new_refresh_token, new_session_obj = jwt_inst.createJwt(user_data_for_jwt)
        
        db.add(new_session_obj)
        db.commit()
        
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user.get("user_name"), "user_id": current_user.get("sub")}

@app.post("/logout")
def logout(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    jti = current_user.get("jti")
    user_name = current_user.get("user_name")
    exp = current_user.get("exp")
    
    if jti and user_name and exp:
        expired_at = datetime.fromtimestamp(exp, tz=timezone.utc)
        blacklist = handleJwtBlacklist(db)
        blacklist.debarJwt(jti, user_name, expired_at)
        
    return {"message": "Logged out successfully"}

@app.get("/health")
def health_check():
    return {"status": "ok"}
