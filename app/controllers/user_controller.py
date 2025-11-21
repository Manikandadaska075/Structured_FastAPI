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

logger = logging.getLogger(__name__)

user_router = APIRouter(prefix="/user", tags=["User"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

@user_router.post("/admin/registration")
def register_admin(user: dict, session: Session = Depends(get_session)):
    logger.info("Admin registration API called")
    logger.debug(f"Request data: {user}")
    user_data = UserValidator.validate_creation(user)
    logger.info(f"Validated admin creation data for: {user_data.get('email')}")
    return UserService.register_admin(session, user_data)

@user_router.post("/login")
def login(email: str = Header(description="User email address"),password: str = Header(description="User password"),
          session: Session = Depends(get_session)):
    logger.info(f"Login attempt for email: {email}")
    token = UserService.login_user(session, email, password)
    logger.info("Login successful")
    return {"accessToken": token, "tokenType": "bearer"}

@user_router.post("/logout")
def logout(session: Session = Depends(get_session),current_user: User = Security(UserService.get_current_user)):
    logger.info(f"Logout request for: {current_user.email}")
    UserRepository.log_logout(session, current_user.email)
    logger.info(f"{current_user.email} logged out successfully")
    return {"message": f"{current_user.email} logged out successfully"}

@user_router.post("/employee/creation")
def admin_employee_creation(creation: dict, session: Session = Depends(get_session),
                            current_user: User = Security(UserService.get_current_user)):
    logger.info(f"Admin {current_user.email} requested employee creation")
    logger.debug(f"Employee creation raw data: {creation}")
    creation_data = UserValidator.validate_creation(creation) 
    employee = UserService.employee_creation(creation_data, current_user, session)
    logger.info(f"Employee created successfully: {employee.email}")
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
    logger.info(f"Employee details requested for: {current_user.email}")
    condition_cheacking.check_its_employee(current_user.isSuperUser)
    employee = UserRepository.get_user_by_email(session, current_user.email)
    logger.debug(f"Employee data fetched: {employee}")
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
    logger.info(f"Admin details requested for: {current_user.email}")
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
    logger.info("Admin requested all admin details")
    condition_cheacking.check_its_admin(current_user.isSuperUser)
    admin = UserRepository.get_all_admins(session)
    logger.info(f"Total admins found: {len(admin)}")
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
    logger.info(f"Admin {current_user.email} requested employee details for: {employeeEmail}")
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
    logger.info("Admin requested inactive user list")
    users = UserRepository.get_all_not_active_user(session, admin)
    condition_cheacking.check_not_active_user(users)
    logger.info(f"Inactive users found: {len(users)}")
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
    condition_cheacking.check_its_admin(current_user.isSuperUser)
    logger.info(f"Admin profile update request from: {current_user.email}")
    admin_details = UserRepository.get_user_by_email(session, current_user.email)
    data = UserValidator.validate_update(data)
    updated_admin = UserService.user_update(data, session, admin_details)
    logger.info(f"Admin profile updated: {current_user.email}")

    return {
        "message": "Admin profile updated successfully",
        "admin": {
            "email": updated_admin.email,
            "first_name": updated_admin.userFirstName,
            "last_name": updated_admin.userLastName,
            "phone_number": updated_admin.phoneNumber,
            "address": updated_admin.address,
            "isActive": updated_admin.isActive,
            "isSuperUser": updated_admin.isSuperUser
        }
    }

@user_router.patch("/employee/profile/update")
def employee_profile_update( data: dict, employeeEmail: Optional[str] =None, current_user: User = Security(UserService.get_current_user),
                   session: Session = Depends(get_session)):
    logger.info(f"Employee profile update request. Admin: {current_user.isSuperUser}, Target: {employeeEmail}")
    data = UserValidator.validate_update(data)
    employee = UserService.employee_update(data, employeeEmail ,current_user, session)
    logger.info(f"Employee updated successfully: {employee.email}")
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
    logger.warning(f"Admin {current_user.email} requested deletion of user: {adminOrEmployeeEmail}")
    admin = UserRepository.get_user_by_email(session, current_user.email)
    UserService.user_deletion(session,admin, adminOrEmployeeEmail)
    logger.info(f"User deletion marked inactive: {adminOrEmployeeEmail}")
    return {"message": f"User with email '{adminOrEmployeeEmail}' marked inactive. Will be deleted after 3 hours."}