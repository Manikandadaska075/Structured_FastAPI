from fastapi import APIRouter, Depends, Security, Header
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session
from typing import *
from app.config.database import get_session
from app.services.user_service import UserService
from app.utils.validators.user_validator import UserValidator
from app.repositories.user_repository import UserRepository
from app.models.user_model import User
from app.utils import condition_cheacking
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

user_router = APIRouter(prefix="/user", tags=["User"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

@user_router.post("/admin/registration")
def register_admin(user: dict, session: Session = Depends(get_session)):
    user_data = UserValidator.validate_creation(user)
    return UserService.register_admin(session, user_data)

@user_router.post("/login")
def login(email: str = Header(description="User email address"),password: str = Header(description="User password"),
          session: Session = Depends(get_session)):
    token = UserService.login_user(session, email, password)
    logger.info("Login service called successfully")
    return {"accessToken": token, "tokenType": "bearer"}

@user_router.post("/logout")
def logout(session: Session = Depends(get_session),current_user: User = Security(UserService.get_current_user)):
    UserRepository.log_logout(session, current_user.email)
    return {"message": f"{current_user.email} logged out successfully"}

@user_router.post("/employee/creation")
def admin_employee_creation(creation: dict, session: Session = Depends(get_session),
                            current_user: User = Security(UserService.get_current_user)):
    creation_data = UserValidator.validate_creation(creation) 
    employee = UserService.employee_creation(creation_data, current_user, session)
    return {"message": "Employee created successfully", "employee": 
            {
                "email": employee.email,
                "first_name": employee.userFirstName,
                "last_name": employee.userLastName,
                "phone_number": employee.phoneNumber,
                "address": employee.address,
                "isActive": employee.isActive,
                "isSuperUser": employee.isSuperUser,
            }
        }

@user_router.get("/employee/details")
def view_employee_details(current_user: User = Security(UserService.get_current_user), session: Session = Depends(get_session)):
    condition_cheacking.check_its_employee(current_user.isSuperUser)
    employee = UserRepository.get_user_by_email(session, current_user.email)
    return {
        "Role": "Employee",
        "Details": {
            "email": employee.email,
            "first_name": employee.userFirstName,
            "last_name": employee.userLastName,
            "phone_number": employee.phoneNumber,
            "address": employee.address,
            "isActive": employee.isActive,
            "designation":employee.designation
        }
    }

@user_router.get("/admin/details")
def view_admin_details(current_user: User = Security(UserService.get_current_user), session: Session = Depends(get_session)):
    condition_cheacking.check_its_admin(current_user.isSuperUser)
    admin = UserRepository.get_user_by_email(session, current_user.email)
    return {
        "Role": "Admin",
        "Details": {
            "email": admin.email,
            "first_name": admin.userFirstName,
            "last_name": admin.userLastName,
            "phone_number": admin.phoneNumber,
            "address": admin.address,
            "isActive": admin.isActive
        }
    }

@user_router.get("/all/admin/details/views")
def all_admin_details_views(current_user: User = Security(UserService.get_current_user), session: Session = Depends(get_session)):
    condition_cheacking.check_its_admin(current_user.isSuperUser)
    admin = UserRepository.get_all_admins(session)
    return {
        "Role": "Admin",
        "Count": len(admin),
        "Details":[ {
                "email": ad.email,
                "first_name": ad.userFirstName,
                "last_name": ad.userLastName,
                "phone_number": ad.phoneNumber,
                "address": ad.address,
                "isActive": ad.isActive,
                "isSuperUser": ad.isSuperUser
            }
            for ad in admin
        ],
        }

@user_router.get("/admin/views/employee/details")
def admin_view_employee_details(employeeEmail: Optional[str] = None, current_user: User = Security(UserService.get_current_user),
                          session: Session = Depends(get_session)):
    condition_cheacking.check_its_admin(current_user.isSuperUser)
    employee = UserRepository.get_all_or_single_employee(session, employeeEmail)
    condition_cheacking.check_employee(employee)
    return {
        "Role": "Employee Details",
        "Details": [
            {
                "email": emp.email,
                "first_name": emp.userFirstName,
                "last_name": emp.userLastName,
                "phone_number": emp.phoneNumber,
                "address": emp.address,
                "isActive": emp.isActive,
                "isSuperUser": emp.isSuperUser,
            }
            for emp in employee
        ],
    }

@user_router.get("/admin/views/all/not/active/admin/employee/details")
def admin_view_not_active_employee_details(admin: Optional[bool] = None, current_user: User = Security(UserService.get_current_user),
                          session: Session = Depends(get_session)):
    condition_cheacking.check_its_admin(current_user.isSuperUser)
    users = UserRepository.get_all_not_active_user(session, admin)
    condition_cheacking.check_not_active_user(users)
    return {
        "Details": [
            {
                "email": user.email,
                "first_name": user.userFirstName,
                "last_name": user.userLastName,
                "phone_number": user.phoneNumber,
                "address": user.address,
                "isActive": user.isActive,
                "isSuperUser": user.isSuperUser,
            }
            for user in users
        ],
    }

@user_router.patch("/admin/profile/update")
def admin_profile_update(data: dict, current_user: User = Security(UserService.get_current_user), session: Session = Depends(get_session)):
    admin_details = UserRepository.get_user_by_email(session, current_user.email)
    data = UserValidator.validate_update(data)
    admin = UserService.user_update(data, current_user, session, admin_details)
    return {"message": "Admin profile updated successfully", "admin": 
            {
                "email": admin.email,
                "first_name": admin.userFirstName,
                "last_name": admin.userLastName,
                "phone_number": admin.phoneNumber,
                "address": admin.address,
                "isActive": admin.isActive,
                "isSuperUser": admin.isSuperUser
            }
        }

@user_router.patch("/employee/profile/update")
def employee_profile_update( data: dict, employeeEmail: Optional[str] =None, current_user: User = Security(UserService.get_current_user),
                   session: Session = Depends(get_session)):
    data = UserValidator.validate_update(data)
    employee = UserService.employee_update(data, employeeEmail ,current_user, session)
    return {"message": "Profile updated successfully", "employee": 
            {
                "email": employee.email,
                "first_name": employee.userFirstName,
                "last_name": employee.userLastName,
                "phone_number": employee.phoneNumber,
                "address": employee.address,
                "isActive": employee.isActive,
                "isSuperUser": employee.isSuperUser
            }
        }

@user_router.delete("/admin/employee/deletion")
def admin_or_employee_delete(adminOrEmployeeEmail: str,current_user: User = Security(UserService.get_current_user),
                             session: Session = Depends(get_session)):
    admin = UserRepository.get_user_by_email(session, current_user.email)
    UserService.user_deletion(session,admin, adminOrEmployeeEmail)
    return {"message": f"User with email '{adminOrEmployeeEmail}' marked inactive. Will be deleted after 3 hours."}