from fastapi import FastAPI
from app.config.database import init_db
from app.controllers.user_controller import user_router
from app.services.user_service import UserService
from apscheduler.schedulers.background import BackgroundScheduler


app = FastAPI(title="E-Commerce")
scheduler = BackgroundScheduler()

@app.on_event("startup")
def on_startup():
    init_db()
    UserService.delete_inactivate_user_from_table()
    UserService.logout_user()
    scheduler.add_job(UserService.logout_user, "interval", minutes=60)
    scheduler.add_job(UserService.delete_inactivate_user_from_table, "interval", minutes = 60)
    scheduler.start()

@app.on_event("shutdown")
def on_shutdown():
    scheduler.shutdown()

app.include_router(user_router, prefix="/fastapi/app")