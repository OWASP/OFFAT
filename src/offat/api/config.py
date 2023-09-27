from fastapi import FastAPI
from redis import Redis
from rq import Queue
from dotenv import load_dotenv
from os import environ

load_dotenv()

app = FastAPI(
    title='OFFAT - API'
)

redis_con = Redis(host=environ.get('REDIS_HOST','localhost'), port=int(environ.get('REDIS_PORT',6379)))
task_queue = Queue(name='offat_task_queue', connection=redis_con)
task_timeout = 60 * 60 # 3600 s = 1 hour