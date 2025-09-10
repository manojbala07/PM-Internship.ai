from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
import uvicorn

# Constants for JWT tokens
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# FastAPI app
app = FastAPI(title="Insight Innovators Backend API")

# Database connection (MongoDB)
client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client.insight_innovators

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    user_type: Optional[str] = None  # 'student', 'organization', 'admin'

class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    user_type: str   # 'student', 'organization', 'admin'

class StudentProfile(BaseModel):
    skills: List[str] = []
    academic_background: str
    interests: List[str] = []
    career_goals: str
    cgpa: Optional[float] = None

class OrganizationProfile(BaseModel):
    organization_name: str
    description: Optional[str] = None

class UserCreate(UserBase):
    password: str
    student_profile: Optional[StudentProfile] = None
    organization_profile: Optional[OrganizationProfile] = None

class InternshipBase(BaseModel):
    title: str
    description: str
    required_skills: List[str]
    cgpa_requirement: Optional[float] = None
    organization_id: str

class InternshipCreate(InternshipBase):
    pass

class Internship(InternshipBase):
    id: str

class ApplicationStatus(str):
    APPLIED = "Applied"
    UNDER_REVIEW = "Under Review"
    ACCEPTED = "Accepted"
    REJECTED = "Rejected"

class InternshipApplication(BaseModel):
    student_id: str
    internship_id: str
    status: ApplicationStatus = ApplicationStatus.APPLIED
    feedback: Optional[str] = None
    applied_at: datetime = Field(default_factory=datetime.utcnow)

# Utility functions

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(email: str):
    user = await db.users.find_one({"email": email})
    return user

async def authenticate_user(email: str, password: str):
    user = await get_user(email)
    if not user:
        return False
    if not verify_password(password, user['hashed_password']):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_type: str = payload.get("user_type")
        if email is None or user_type is None:
            raise credentials_exception
        token_data = TokenData(username=email, user_type=user_type)
    except JWTError:
        raise credentials_exception
    user = await get_user(email=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    # Additional checks like is_active can be added
    return current_user

# Routes

# User registration (both student and organization)
@app.post("/register", status_code=201)
async def register_user(user: UserCreate):
    existing_user = await db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict['hashed_password'] = hashed_password
    user_dict.pop('password')
    # Insert user
    await db.users.insert_one(user_dict)
    return {"msg": "User registered successfully"}

# Token endpoint for login
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"], "user_type": user["user_type"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Get student profile
@app.get("/students/me", response_model=StudentProfile)
async def read_student_profile(current_user: dict = Depends(get_current_active_user)):
    if current_user['user_type'] != "student":
        raise HTTPException(status_code=403, detail="Not authorized")
    profile = current_user.get("student_profile")
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile

# Update student profile
@app.put("/students/me")
async def update_student_profile(profile: StudentProfile, current_user: dict = Depends(get_current_active_user)):
    if current_user['user_type'] != "student":
        raise HTTPException(status_code=403, detail="Not authorized")
    await db.users.update_one({"email": current_user['email']}, {"$set": {"student_profile": profile.dict()}})
    return {"msg": "Profile updated"}

# Post internship (organization)
@app.post("/internships", status_code=201)
async def create_internship(internship: InternshipCreate, current_user: dict = Depends(get_current_active_user)):
    if current_user['user_type'] != "organization":
        raise HTTPException(status_code=403, detail="Not authorized")
    internship_dict = internship.dict()
    internship_dict["organization_id"] = current_user["_id"]
    result = await db.internships.insert_one(internship_dict)
    return {"id": str(result.inserted_id)}

# List internships with optional filters
@app.get("/internships", response_model=List[Internship])
async def list_internships():
    internships = []
    cursor = db.internships.find()
    async for internship in cursor:
        internship['id'] = str(internship['_id'])
        internships.append(internship)
    return internships

# Apply for internship (student)
@app.post("/applications", status_code=201)
async def apply_for_internship(application: InternshipApplication, current_user: dict = Depends(get_current_active_user)):
    if current_user['user_type'] != "student":
        raise HTTPException(status_code=403, detail="Not authorized")
    application_dict = application.dict()
    application_dict['student_id'] = current_user["_id"]
    application_dict['applied_at'] = datetime.utcnow()
    await db.applications.insert_one(application_dict)
    return {"msg": "Application submitted"}

# Get applications for current user
@app.get("/applications/me", response_model=List[InternshipApplication])
async def get_my_applications(current_user: dict = Depends(get_current_active_user)):
    if current_user['user_type'] == "student":
        cursor = db.applications.find({"student_id": current_user["_id"]})
    elif current_user['user_type'] == "organization":
        # Get internships by organization
        internships_cursor = db.internships.find({"organization_id": current_user["_id"]})
        internship_ids = [internship['_id'] async for internship in internships_cursor]
        cursor = db.applications.find({"internship_id": {"$in": internship_ids}})
    else:
        raise HTTPException(status_code=403, detail="Not authorized")
    applications = []
    async for app in cursor:
        applications.append({
            "student_id": app["student_id"],
            "internship_id": app["internship_id"],
            "status": app.get("status"),
            "feedback": app.get("feedback"),
            "applied_at": app["applied_at"]
        })
    return applications

# Submit feedback (organization or student)
@app.post("/applications/feedback")
async def submit_feedback(application_id: str, feedback: str, current_user: dict = Depends(get_current_active_user)):
    # Allow organization or student to submit feedback for an application
    app_query = {"_id": application_id}
    application = await db.applications.find_one(app_query)
    if application is None:
        raise HTTPException(status_code=404, detail="Application not found")
    # Authorization check omitted for brevity
    await db.applications.update_one(app_query, {"$set": {"feedback": feedback}})
    return {"msg": "Feedback submitted"}

# AI/ML Recommendation endpoint (stub)
@app.get("/recommendations/me")
async def get_recommendations(current_user: dict = Depends(get_current_active_user)):
    if current_user['user_type'] != "student":
        raise HTTPException(status_code=403, detail="Not authorized")
    # Load user profile, skills, CGPA, etc.
    # Call AI/ML model to generate ranked list (stubbed here)
    recommendations = [
        {"internship_id": "123", "title": "AI Research Intern", "score": 0.95},
        {"internship_id": "124", "title": "Data Science Intern", "score": 0.90},
        # etc.
    ]
    return {"recommendations": recommendations}

if _name_ == "_main_":
    uvicorn.run(app, host="0.0.0.0", port=8000)