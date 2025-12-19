from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import List, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
REFRESH_TOKEN_EXPIRE_DAYS = 7


MAX_PASSWORD_LENGTH = 72

SQLALCHEMY_DATABASE_URL = "sqlite:///../database.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserDB(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime, nullable=True)

Base.metadata.create_all(bind=engine)

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    created_at: datetime
    is_active: bool
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None

class TokenData(BaseModel):
    username: Optional[str] = None

class RefreshToken(BaseModel):
    refresh_token: str

pwd_context = CryptContext(
    schemes=["sha256_crypt"],
    deprecated="auto",
    sha256_crypt__default_rounds=10000
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

app = FastAPI(
    title="Authentication API",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.debug(f"Request: {request.method} {request.url}")
    
    auth_header = request.headers.get("authorization")
    if auth_header:
        logger.debug(f"Authorization header: {auth_header[:50]}...")
    
    response = await call_next(request)
    logger.debug(f"Response status: {response.status_code}")
    return response

def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def get_password_hash(password):
    if len(password) > MAX_PASSWORD_LENGTH:
        password = password[:MAX_PASSWORD_LENGTH]
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        logger.warning(f"User not found: {username}")
        return False
    
    if not verify_password(password, user.password):
        logger.warning(f"Invalid password for user: {username}")
        return False
    
    return user

def create_token(data: dict, expires_delta: timedelta, token_type: str = "access"):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": token_type,
        "sub": data.get("sub")
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Created {token_type} token for user: {data.get('sub')}, expires: {expire}")
    return encoded_jwt, expire

def create_access_token(data: dict):
    access_token_expires = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    access_token, expires_at = create_token(data, access_token_expires, "access")
    return access_token, expires_at

def create_refresh_token(data: dict):
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token, expires_at = create_token(data, refresh_token_expires, "refresh")
    return refresh_token, expires_at

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
):
    logger.debug(f"get_current_user called with token: {token[:50] if token else 'None'}...")
    
    if not token:
        logger.warning("No token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        if token.startswith("Bearer "):
            token = token[7:]
        
        logger.debug(f"Decoding token: {token[:50]}...")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logger.debug(f"Token payload: {payload}")
        
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if username is None:
            logger.error("No username in token payload")
            raise credentials_exception
        
        if token_type != "access":
            logger.error(f"Wrong token type: {token_type}")
            raise credentials_exception
        
        token_data = TokenData(username=username)
        
    except JWTError as e:
        logger.error(f"JWT Error: {e}")
        raise credentials_exception
    
    user = get_user(db, username=token_data.username)
    if user is None:
        logger.error(f"User not found in database: {token_data.username}")
        raise credentials_exception
    
    if not user.is_active:
        logger.error(f"User inactive: {token_data.username}")
        raise credentials_exception
    
    logger.debug(f"User authenticated: {user.username}")
    return user

async def get_current_user_from_refresh(token: str, db: Session):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_type = payload.get("type")
        
        if token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    except JWTError as e:
        logger.error(f"Refresh token JWT Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    user = get_user(db, username=username)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    return user

@app.get("/")
def read_root():
    return {"message": "Authentication API is working!"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

@app.post("/register/", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user(db, username=user.username)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    hashed_password = get_password_hash(user.password)
    
    db_user = UserDB(
        username=user.username,
        password=hashed_password,
        is_active=True
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    logger.info(f"User registered: {user.username}")
    return db_user

@app.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    if len(form_data.password) > MAX_PASSWORD_LENGTH:
        form_data.password = form_data.password[:MAX_PASSWORD_LENGTH]
    
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    access_token, access_expires = create_access_token(data={"sub": user.username})
    refresh_token, refresh_expires = create_refresh_token(data={"sub": user.username})
    
    logger.info(f"User logged in: {user.username}")
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_HOURS * 3600
    }

@app.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_data: RefreshToken,
    db: Session = Depends(get_db)
):
    user = await get_current_user_from_refresh(refresh_data.refresh_token, db)
    
    access_token, access_expires = create_access_token(data={"sub": user.username})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_data.refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_HOURS * 3600
    }

@app.post("/logout")
async def logout(
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    logger.info(f"User logged out: {current_user.username}")
    return {"message": "Successfully logged out"}

@app.get("/users/me/", response_model=UserResponse)
async def read_users_me(current_user: UserDB = Depends(get_current_user)):
    logger.debug(f"Returning user data for: {current_user.username}")
    return current_user

@app.get("/protected/")
async def protected_route(current_user: UserDB = Depends(get_current_user)):
    return {
        "message": f"Hello {current_user.username}!",
        "user_id": current_user.id,
        "created_at": current_user.created_at,
        "last_login": current_user.last_login
    }

