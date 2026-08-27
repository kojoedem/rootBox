from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class SampleBase(BaseModel):
    threat_type: str
    file_format: str
    description: Optional[str] = ""
    analysis_notes: Optional[str] = ""

class SampleCreate(SampleBase):
    pass

class SampleResponse(SampleBase):
    id: int
    original_filename: str
    vault_filename: str
    file_size: int
    sha256: str
    md5: str
    uploaded_at: str

    class Config:
        from_attributes = True
