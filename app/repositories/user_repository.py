from sqlmodel import Session, select, and_
from app.models.user_model import User, LoginDetails
from datetime import datetime, timedelta

class UserRepository:
    @staticmethod
    def get_user_by_email(session: Session, email: str):
        return session.exec(select(User).where(User.email == email)).first()

    @staticmethod
    def create_user(session: Session, user: User):
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    @staticmethod
    def get_all_admins(session: Session):
        return session.exec(select(User).where(User.isSuperUser == True)).all()

    @staticmethod
    def get_all_or_single_employee(session: Session, employeeEmail):
        if employeeEmail != None:
            return [session.exec(
                select(User).where(and_(User.email == employeeEmail, User.isActive == True, User.isSuperUser == False))).first()]
        else:
            return session.exec(select(User).where(and_(User.isSuperUser == False, User.isActive == True))).all()

    @staticmethod
    def get_all_not_active_user(session: Session, admin):    
        if admin == False:
            return session.exec(select(User).where(and_(User.isActive == False, User.isSuperUser == False))).all()
        else:
            return session.exec(select(User).where(and_(User.isActive == False, User.isSuperUser == True))).all()

    @staticmethod
    def log_login(session: Session, email: str, token: str):
        now = datetime.now()
        login_entry = LoginDetails(
            userEmail=email, logInTime=now.time(),
            dateOfLoginLogOut=now.date(), token=token
        )
        session.add(login_entry)
        session.commit()
        return login_entry

    @staticmethod
    def log_logout(session: Session, email: str):
        entry = session.exec(select(LoginDetails).where(LoginDetails.userEmail == email).order_by(LoginDetails.id.desc())).first()
        if entry and not entry.logOutTime:
            entry.logOutTime = datetime.now().time()
            session.add(entry)
            session.commit()
        return entry

    @staticmethod
    def mark_inactive(session: Session, user: User):
        user.isActive = False
        user.scheduledDeletion = datetime.now() + timedelta(minutes=10)
        session.add(user)
        session.commit()
    
    @staticmethod
    def employee_details_add(session: Session, employee: User):
        session.add(employee)
        session.commit()
        session.refresh(employee)
        return employee

    @staticmethod
    def user_update(session: Session, user: User, update_data: dict):
        for key, value in update_data.items():
            setattr(user, key, value)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
    
    @staticmethod
    def cleanup_inactive_users(now, session: Session):
        users_to_delete = session.exec(select(User).where(User.isActive == False,User.scheduledDeletion != None,User.scheduledDeletion <= now)).all()
        for user in users_to_delete:
            login_records = session.exec(select(LoginDetails).where(LoginDetails.userEmail == user.email)).all()
            for login in login_records:
                session.delete(login)
            session.delete(user)
        session.commit()

    @staticmethod
    def update_logout_time(now, session):
        expired_entries = session.exec(select(LoginDetails).where(LoginDetails.logOutTime == None)).all()

        for entry in expired_entries:
            login_datetime = datetime.combine(entry.dateOfLoginLogOut, entry.logInTime)
            token_expiry_time = login_datetime + timedelta(minutes=10)
            
            if token_expiry_time <= now:
                entry.logOutTime = token_expiry_time.time()
                session.add(entry)

        session.commit()
   