from fastapi import status, Request, Response
from json import loads as json_loads
from yaml import SafeLoader, load as yaml_loads
from .config import app, task_queue, task_timeout, auth_secret_key
from .jobs import scan_api
from .models import CreateScanModel
from ..logger import create_logger


logger = create_logger(__name__)
logger.info(f'Secret Key: {auth_secret_key}')


@app.get('/', status_code=status.HTTP_200_OK)
async def root():
    return {
        "name":"OFFAT API",
        "project":"https://github.com/dmdhrumilmistry/offat",
        "license":"https://github.com/dmdhrumilmistry/offat/blob/main/LICENSE",
    }


@app.post('/api/v1/scan', status_code=status.HTTP_201_CREATED)
async def add_scan_task(scan_data: CreateScanModel, request:Request ,response: Response):
   # for auth
    client_ip = request.client.host
    secret_key = request.headers.get('SECRET-KEY', None)
    if secret_key != auth_secret_key:
        # return 404 for better endpoint security
        response.status_code = status.HTTP_401_UNAUTHORIZED
        logger.warning(f'INTRUSION: {client_ip} tried to create a new scan job')
        return {"message":"Unauthorized"}
    
    openapi_doc = scan_data.openAPI
    file_data_type = scan_data.type

    msg = {
        "msg":"Scan Task Created",
        "job_id": None
    }
    create_task = True

    match file_data_type:
        case 'json':
            openapi_doc = json_loads(openapi_doc)
        case 'yaml':
            openapi_doc = yaml_loads(openapi_doc, SafeLoader)
        case _:
            response.status_code = status.HTTP_400_BAD_REQUEST
            msg = {
                "msg":"Invalid Request Data"
            }
            create_task = False
    
    if create_task:
        job = task_queue.enqueue(scan_api, openapi_doc, job_timeout=task_timeout)
        msg['job_id'] = job.id

        logger.info(f'SUCCESS: {client_ip} created new scan job - {job.id}')
    else: 
        logger.error(f'FAILED: {client_ip} tried creating new scan job but it failed due to unknown file data type')

    return msg


@app.get('/api/v1/scan/{job_id}/result')
async def get_scan_task_result(job_id:str, request: Request, response:Response):
    # for auth
    client_ip = request.client.host
    secret_key = request.headers.get('SECRET-KEY', None)
    if secret_key != auth_secret_key:
        # return 404 for better endpoint security
        response.status_code = status.HTTP_401_UNAUTHORIZED
        logger.warning(f'INTRUSION: {client_ip} tried to access {job_id} job scan results')
        return {"message":"Unauthorized"}
    
    scan_results = task_queue.fetch_job(job_id=job_id)
    logger.info(f'SUCCESS: {client_ip} accessed {job_id} job scan results')

    msg = {
        'msg':'Task Remaining or Invalid Job Id',
        'results': None,
    }
    response.status_code = status.HTTP_202_ACCEPTED

    if scan_results and scan_results.is_finished: 
        msg = {
            'msg':'Task Completed',
            'results': scan_results.result,
        }
        response.status_code = status.HTTP_200_OK


    elif scan_results and scan_results.is_failed:
        msg = {
            'msg':'Task Failed. Try Creating Task Again.',
            'results': None,
        }
        response.status_code = status.HTTP_200_OK

    return msg