from typing import Optional
from pydantic import BaseModel


class CreateScanSchema(BaseModel):
    openapi: str
    regex_pattern: Optional[str] = None
    req_headers: Optional[dict] = {'User-Agent': 'offat-api'}
    rate_limit: Optional[int] = 60
    test_data_config: Optional[dict] = None
    proxies: Optional[list[str]] = None
    capture_failed: Optional[bool] = False
    remove_unused_data: Optional[bool] = True
