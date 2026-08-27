from pydantic import BaseModel
from typing import Optional, List
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
    entropy: float
    entropy_level: str
    magic_type: str
    extracted_strings: str
    hex_dump: str
    yara_rule: str
    threat_score: int
    threat_level: str
    uploaded_at: str

    class Config:
        from_attributes = True
