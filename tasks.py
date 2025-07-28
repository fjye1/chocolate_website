import os
from celery import Celery

redis_url = os.getenv("REDIS_URL")
celery = Celery("tasks", broker=redis_url)

@celery.task
def simple_task():
    print("🔥 Task ran successfully on Render!")