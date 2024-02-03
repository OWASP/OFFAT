from fastapi import status, Request, Response
from offat.api.config import app, task_queue, task_timeout, auth_secret_key
from offat.api.jobs import scan_api
from offat.api.models import CreateScanModel
from offat.logger import logger
# from os import uname, environ


logger.info('Secret Key: %s', auth_secret_key)


# if uname().sysname == 'Darwin' and environ.get('OBJC_DISABLE_INITIALIZE_FORK_SAFETY') != 'YES':
# logger.warning('Mac Users might need to configure OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES in env\nVisit StackOverFlow link for more info: https://stackoverflow.com/questions/50168647/multiprocessing-causes-python-to-crash-and-gives-an-error-may-have-been-in-progr')


@app.get('/', status_code=status.HTTP_200_OK)
async def root():
    return {
        "name": "OFFAT API",
        "project": "https://github.com/OWASP/offat",
        "license": "https://github.com/OWASP/offat/blob/main/LICENSE",
    }


@app.post('/api/v1/scan', status_code=status.HTTP_201_CREATED)
async def add_scan_task(scan_data: CreateScanModel, request: Request, response: Response):
   # for auth
    client_ip = request.client.host
    secret_key = request.headers.get('SECRET-KEY', None)
    if secret_key != auth_secret_key:
        # return 404 for better endpoint security
        response.status_code = status.HTTP_401_UNAUTHORIZED
        logger.warning('INTRUSION: %s tried to create a new scan job', client_ip)
        return {"message": "Unauthorized"}

    msg = {
        "msg": "Scan Task Created",
        "job_id": None
    }

    job = task_queue.enqueue(scan_api, scan_data,  job_timeout=task_timeout)
    msg['job_id'] = job.id

    logger.info('SUCCESS: %s created new scan job - %s', client_ip, job.id)

    return msg


@app.get('/api/v1/scan/{job_id}/result')
async def get_scan_task_result(job_id: str, request: Request, response: Response):
    # for auth
    client_ip = request.client.host
    secret_key = request.headers.get('SECRET-KEY', None)
    if secret_key != auth_secret_key:
        # return 404 for better endpoint security
        response.status_code = status.HTTP_401_UNAUTHORIZED
        logger.warning('INTRUSION: %s tried to access %s job scan results', client_ip, job_id)
        return {"message": "Unauthorized"}

    scan_results_job = task_queue.fetch_job(job_id=job_id)

    logger.info('SUCCESS: %s accessed %s job scan results', client_ip, job_id)

    msg = 'Task Remaining or Invalid Job Id'
    results = None
    response.status_code = status.HTTP_202_ACCEPTED

    if scan_results_job and scan_results_job.is_started:
        msg = 'Job In Progress'

    elif scan_results_job and scan_results_job.is_finished:
        msg = 'Task Completed'
        results = scan_results_job.result
        response.status_code = status.HTTP_200_OK

    elif scan_results_job and scan_results_job.is_failed:
        msg = 'Task Failed. Try Creating Task Again.'
        response.status_code = status.HTTP_200_OK

    msg = {
        'msg': msg,
        'results': results,
    }
    return msg
