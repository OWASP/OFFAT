from fastapi import status, Response
from json import loads as json_loads
from yaml import SafeLoader, load as yaml_loads
from .config import app, task_queue, task_timeout
from .jobs import scan_api
from .models import CreateScanModel
from ..logger import create_logger


logger = create_logger(__name__)


@app.get('/', status_code=status.HTTP_200_OK)
async def root():
    return {
        "name":"OFFAT API",
        "project":"https://github.com/dmdhrumilmistry/offat",
        "license":"https://github.com/dmdhrumilmistry/offat/blob/main/LICENSE",
    }


@app.post('/api/v1/scan', status_code=status.HTTP_201_CREATED)
async def add_scan_task(postData: CreateScanModel, response: Response):
    openapi_doc = postData.openAPI
    file_data_type = postData.type

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

    return msg


@app.get('/api/v1/scan/{job_id}/result')
async def get_scan_task_result(job_id:str, response:Response):
    
    scan_results = task_queue.fetch_job(job_id=job_id)

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