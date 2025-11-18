from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler
from app.config.database import init_db
from app.services.user_service import UserService

scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app):
    print("🚀 Starting Application...")
    init_db()

    UserService.delete_inactivate_user_from_table()
    UserService.logout_user()

    scheduler.add_job(UserService.logout_user, "interval", minutes=2)
    scheduler.add_job(UserService.delete_inactivate_user_from_table, "interval", minutes=10)
    scheduler.start()

    yield
    scheduler.shutdown(wait=False)