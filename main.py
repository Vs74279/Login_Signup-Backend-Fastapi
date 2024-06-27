from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import re  # Import regular expression module

from database import engine, SessionLocal
from schemas import UserCreate, UserLogin
from models import User, Base

app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update with your frontend URL during production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Regular expression for password validation
password_regex = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$'
)

# Routes
@app.post("/signup/")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    # Validate password
    if not password_regex.match(user.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters long, include at least one uppercase letter, one lowercase letter, and one special character (@$!%*?&)",
        )

    hashed_password = pwd_context.hash(user.password)
    db_user = User(
        firstName=user.firstName,
        lastName=user.lastName,
        email=user.email,
        phone=user.phone,
        password=hashed_password,
        qualification=user.qualification,
    )
    db.add(db_user)
    db.commit()
    return {"message": "User created successfully"}

@app.post("/login/")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Login successful", "user": db_user}

# Create tables
Base.metadata.create_all(bind=engine)
