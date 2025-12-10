from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class IOCRequest(BaseModel):
    ioc: str = Field(..., min_length=1)
    ioc_type: Optional[str] = Field(default="domain", pattern="^(ip|domain|hash)$")

class IOCResponse(BaseModel):
    ioc: str
    ioc_type: str
    score: int = Field(ge=0, le=100)
    risk_level: str
    sources: List[str]
    vt: Optional[Dict[str, Any]] = None
    st: Optional[Dict[str, Any]] = None
    whois: Optional[Dict[str, Any]] = None
    created_at: str

class IOCSummary(BaseModel):
    ioc: str
    ioc_type: str
    score: int
    risk_level: str
    sources: List[str]
    created_at: str

class IOCHistoryEntry(BaseModel):
    ioc: str
    ioc_type: str
    score: int
    risk_level: str
    sources: List[str]
    created_at: str

class IOCTimeline(BaseModel):
    timestamp: str
    score: int
    risk_level: str
    phase: str
    burned: bool

class QueryResult(BaseModel):
    success: bool
    data: Optional[IOCResponse] = None
    error: Optional[str] = None
