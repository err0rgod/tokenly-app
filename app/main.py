from fastapi import FastAPI, Depends, HTTPException, status
from sqlmodel import Session, select
from app.database import init_db, get_db
from app.models import User
from tokenly.auth import hash_password, verifyPassword, jwtHandler, validate_creds_structure, require_auth
from pydantic import BaseModel

app = FastAPI(title="Tokenly Demo App")

@app.on_event("startup")
def on_startup():
    init_db()

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenRefresh(BaseModel):
    refresh_token: str

@app.post("/signup")
def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    # Validate credentials structure
    if not validate_creds_structure(user_data.username, user_data.password):
        raise HTTPException(status_code=400, detail="Invalid username or password format")
    
    # Check if user exists
    statement = select(User).where(User.username == user_data.username)
    existing_user = db.exec(statement).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash password and create user
    hashed_pwd = hash_password(user_data.password)
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
    
    if not user or not verifyPassword(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate tokens
    access_token = jwtHandler.create_access_token(data={"sub": user.username})
    refresh_token = jwtHandler.create_refresh_token(data={"sub": user.username})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/refresh")
def refresh_token(data: TokenRefresh):
    try:
        new_tokens = jwtHandler.refresh_access_token(data.refresh_token)
        return new_tokens
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/me")
def get_me(current_user: str = Depends(require_auth)):
    return {"username": current_user}

@app.post("/logout")
def logout(token: str = Depends(require_auth)):
    # jwtHandler might have a blacklist method
    jwtHandler.blacklist_token(token)
    return {"message": "Logged out successfully"}

@app.get("/health")
def health_check():
    return {"status": "ok"}
