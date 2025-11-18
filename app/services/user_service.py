from fastapi import Depends, HTTPException, status
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import jwt, JWTError, ExpiredSignatureError
from typing import Optional
from sqlmodel import Session
from fastapi.security import OAuth2PasswordBearer
from app.repositories.user_repository import UserRepository
from app.models.user_model import User
from app.config.database import get_session, get_engine

SECRET_KEY = "12354477463543"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login")

class UserService:

    @staticmethod
    def hash_password(password: str) -> str:
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        data.update({"exp": expire})
        return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def decode_token(token: str):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email = payload.get("sub")
            if not email:
                raise HTTPException(status_code=401, detail="Invalid token")
            return email
        except ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
        
    @staticmethod
    def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
        not_logged_in = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="User is not logged in or token is invalid",
                                    headers={"WWW-Authenticate": "Bearer"})
        try:
            email: Optional[str] = UserService.decode_token(token)
            if email is None:
                raise not_logged_in
            
        except ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Token has expired. Please log in again.",
                                headers={"WWW-Authenticate": "Bearer"})
        except JWTError:
            raise not_logged_in
        
        user = UserRepository.get_user_by_email(session, email)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="User not found. Please log in again.")
        if not user.isActive:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="User account is inactive. Contact admin.")
        return user

    @staticmethod
    def register_admin(session, user_data: dict):
        if user_data["designation"].lower() != "hr":
            raise HTTPException(status_code=403, detail="Only HR can register as admin")
        if UserRepository.get_user_by_email(session, user_data["email"]):
            raise HTTPException(status_code=400, detail="User already exists")

        user = User(
            email=user_data["email"],
            userFirstName=user_data["userFirstName"],
            userLastName=user_data["userLastName"],
            password=UserService.hash_password(user_data["password"]),
            designation=user_data["designation"],
            phoneNumber=user_data["phoneNumber"],
            address=user_data.get("address"),
            isSuperUser=user_data.get("isSuperUser", True)
        )
        return UserRepository.create_user(session, user)

    @staticmethod
    def login_user(session, email: str, password: str):
        user = UserRepository.get_user_by_email(session, email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        if not user.isActive:
            raise HTTPException(status_code=401, detail="User not active")
        if not UserService.verify_password(password, user.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = UserService.create_access_token({"sub": email})
        UserRepository.log_login(session, email, token)
        return token

    @staticmethod
    def employee_creation(creation, current_user, session):
        if not current_user.isSuperUser:
            raise HTTPException(status_code=403, detail="Only admins can create employees")
        existing_user = UserRepository.get_user_by_email(session, creation["email"])
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        hashed_password = UserService.hash_password(creation["password"])
        employee = User(
            email=creation["email"],
            password=UserService.hash_password(creation["password"]),
            userFirstName=creation["userFirstName"],
            userLastName=creation["userLastName"],
            designation=creation["designation"],
            phoneNumber=creation["phoneNumber"],
            address=creation.get("address"),
            isActive=True,
            isSuperUser=False
        )
        created_employee = UserRepository.employee_details_add(session, employee)
        return created_employee
    
    @staticmethod
    def user_update(data:dict, current_user, session, admin):
        if not admin:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin is not logged in")
    
        if not current_user.isSuperUser:
            raise HTTPException(status_code=403, detail="Only admins can view details")
        
        if not current_user.isActive:
            raise HTTPException(status_code=403, detail="Access denied. Account is not active.")
        
        if "password" in data:
            data["password"] = UserService.hash_password(data["password"])

        updated_admin = UserRepository.user_update(session, admin, data)

        return updated_admin
    
    @staticmethod
    def employee_update(data:dict, employeeEmail:Optional[str], current_user:User, session):
        if not current_user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not logged in")
    
        if current_user.isSuperUser:
            if not employeeEmail:
                raise HTTPException(status_code=400, detail="Employee email is required for admin updates")
            employee = UserRepository.get_user_by_email(session, employeeEmail)
            if not employee:
                raise HTTPException(status_code=404, detail="Employee not found")
        else:
            employee = UserRepository.get_user_by_email(session, current_user.email)

        if "password" in data:
            data["password"] = UserService.hash_password(data["password"])

        # update_data = data.model_dump(exclude_unset=True)
        updated_admin = UserRepository.user_update(session, employee, data)
        return updated_admin
    
    @staticmethod
    def user_deletion(session, admin, adminOrEmployeeEmail: str):
        if not admin:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin is not logged in")
        if not admin.isSuperUser:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin can only delete the user")
        record = UserRepository.get_user_by_email(session, adminOrEmployeeEmail)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No admin or employee found with email: {adminOrEmployeeEmail}")
        if not record.isActive:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"admin or employee is not active : {adminOrEmployeeEmail}")
        return UserRepository.mark_inactive(session, record)
    
    @staticmethod
    def delete_inactivate_user_from_table():
        engine = get_engine()
        now = datetime.now()
        with Session(engine) as session:
            UserRepository.cleanup_inactive_users(now, session)
        
    @staticmethod
    def logout_user():
        now = datetime.now()
        with next(get_session()) as session:
            UserRepository.update_logout_time(now, session)