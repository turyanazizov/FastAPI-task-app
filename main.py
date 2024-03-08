from fastapi import FastAPI, Request, HTTPException, Depends, status, Security
from database import database
from models import *
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
import ipdata
from fastapi import FastAPI, HTTPException
import httpx
from celery_worker import celery_app
app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return user_dict


def authenticate_user(username: str, password: str):
    user = User.get_or_none(User.username == username)
    if not user or not User.verify_password(password, user.password):
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


async def get_current_user(token: str = Security(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        # Retrieve the user from the database using the User model
        user = User.get_or_none(User.username == username)
        if user is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user

# Middleware to open and close database connections


@app.middleware("http")
async def db_session_middleware(request: Request, call_next):
    try:
        database.connect()
        response = await call_next(request)
    finally:
        if not database.is_closed():
            database.close()
    return response


@app.get("/api/v1/user", response_model=List[UserResponseModel])
async def get_all_users(current_user: User = Depends(get_current_user)):
    users_query = User.select()
    users = list(users_query)
    users_data = [UserResponseModel(id=user.id, firstname=user.firstname,
                                    lastname=user.lastname, age=user.age, username=user.username) for user in users]
    return users_data


@app.post("/api/v1/signup")
async def create_user(user_request: UserCreateRequest):
    user = User.create(username=user_request.username, firstname=user_request.firstname,
                       lastname=user_request.lastname, age=user_request.age, password=pwd_context.hash(user_request.password))
    return {"id": user.id, "username": user.username, "firstname": user.firstname, "lastname": user.lastname}


@app.get("/api/v1/user/{user_id}")
async def get_user(user_id: int, current_user: User = Depends(get_current_user)):
    user = User.get_or_none(User.id == user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": user.username, "firstname": user.firstname, "lastname": user.lastname, "age": user.age}


@app.put("/api/v1/user/{user_id}")
async def update_user(user_id: int, user_request: UserUpdateRequest, current_user: User = Depends(get_current_user)):
    user = User.get_or_none(User.id == user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.username = user_request.username
    user.firstname = user_request.firstname
    user.lastname = user_request.lastname
    user.age = user_request.age
    user.save()
    return {"id": user.id, "username": user.username, "firstname": user.firstname, "lastname": user.lastname, "age": user.age}


@app.delete("/api/v1/user/{user_id}")
async def delete_user(user_id: int, current_user: User = Depends(get_current_user)):
    user = User.get_or_none(User.id == user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.delete_instance()
    return {"message": "User deleted successfully"}


@app.post("/api/v1/auth", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        # Use dot notation to access `username` attribute
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/v1/refresh", response_model=Token)
async def refresh_access_token(current_user: User = Depends(get_current_user)):
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": current_user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=UserResponseModel)
async def read_users_me(current_user: User = Depends(get_current_user)):
    # Convert Peewee model to Pydantic model instance
    user_data = UserResponseModel(
        id=current_user.id,
        username=current_user.username,
        firstname=current_user.firstname,
        lastname=current_user.lastname,
        age=current_user.age
    )
    return user_data


class IPDataRequest(BaseModel):
    ip_address: str


class IPDataRequest(BaseModel):
    ip_address: str


@app.post("/api/v1/testtask/")
async def create_task(ip_data_request: IPDataRequest, current_user: User = Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        ipdata_api_key = "28bcdcd34d48c2223d0ce2d85a7608d67d1e8ac4b644620dfb0b5097"

        response = await client.get(f"https://api.ipdata.co/{ip_data_request.ip_address}?api-key={ipdata_api_key}")

        if response.status_code != 200:
            raise HTTPException(
                status_code=400, detail="Failed to fetch IP data")

        data = response.json()

        # Create a task with the IP data for the current user
        task = Task.create(
            user=current_user.id,  # Use the ID of the authenticated user
            ip_address=ip_data_request.ip_address,
            data=json.dumps(data)  # Store the fetched IP data as a JSON string
        )

        return {"message": "Task created successfully", "task_id": task.id, "ip_data": data}


class IPDataRequest(BaseModel):
    ip_address: str

# Async task to fetch IP data


@celery_app.task(name="task_fetch_ip_data")
def task_fetch_ip_data(ip_address, user_id):
    try:
        api_key = "28bcdcd34d48c2223d0ce2d85a7608d67d1e8ac4b644620dfb0b5097"
        url = f"https://api.ipdata.co/{ip_address}?api-key={api_key}"
        response = httpx.get(url)
        if response.status_code == 200:
            data = response.json()
            # Simulating DB operation. Replace with your actual DB interaction
            # Create a task with the IP data for the current user
            task = Task.create(
                user=user_id,  # Use the ID of the authenticated user
                ip_address=ip_address,
                # Store the fetched IP data as a JSON string
                data=json.dumps(data)
            )
            return {"status": "success", "data": data}
        else:
            return {"status": "error", "detail": "Failed to fetch IP data"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@app.post("/api/v1/task/")
async def create_task(ip_data_request: IPDataRequest, current_user: User = Depends(get_current_user)):  # Example user_id
    task = task_fetch_ip_data.delay(
        ip_data_request.ip_address, current_user.id)
    return {"message": "Task created successfully", "task_id": task.id}


@app.get("/api/v1/status/{task_id}")
async def get_task_status(task_id: str, current_user: User = Depends(get_current_user)):
    task_result = celery_app.AsyncResult(task_id)
    if task_result.ready():
        return task_result.get()
    else:
        return {"status": "pending"}
