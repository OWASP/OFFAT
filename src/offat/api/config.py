from fastapi import FastAPI
from redis import Redis
from rq import Queue
from dotenv import load_dotenv
from os import environ

from .auth_utils import generate_random_secret_key_string


load_dotenv()

app = FastAPI(
    title='OFFAT - API'
)

auth_secret_key = environ.get(
    'AUTH_SECRET_KEY', generate_random_secret_key_string())
redis_con = Redis(host=environ.get('REDIS_HOST', 'localhost'),
                  port=int(environ.get('REDIS_PORT', 6379)))
task_queue = Queue(name='offat_task_queue', connection=redis_con)
task_timeout = 60 * 60  # 3600 s = 1 hour
