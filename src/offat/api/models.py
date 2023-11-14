from typing import Optional
from pydantic import BaseModel


class CreateScanModel(BaseModel):
    openAPI: str
    regex_pattern: Optional[str] = None
    req_headers: Optional[dict] = None
    rate_limit: Optional[int] = None
    delay: Optional[float] = None
    test_data_config: Optional[dict] = None
