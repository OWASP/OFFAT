from pydantic import BaseModel

class CreateScanModel(BaseModel):
    openAPI: str
    type: str 
