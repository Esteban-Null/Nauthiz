from fastapi import APIRouter, Header, HTTPException, Depends
from app.models.schemas import IOCRequest, IOCResponse, IOCSummary, IOCHistoryEntry, IOCTimeline
from app.core.config import settings
from app.core.scoring import score_ioc
from app.core.db import init_db, save_query, get_ioc_summary, get_ioc_history, get_ioc_timeline
from app.core.providers import vt_lookup, securitytrails_lookup_domain, hunter_lookup_domain
import asyncio

init_db()

router = APIRouter()

def verify_api_key(x_api_key: str = Header(...)):
    """Verify API key"""
    if x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

@router.post("/query", response_model=IOCResponse)
async def query_ioc(request: IOCRequest, api_key: str = Depends(verify_api_key)):
    """Enrich IOC with external data"""
    
    ioc = request.ioc
    ioc_type = request.ioc_type or "domain"
    
    vt_data = None
    st_data = None
    whois_data = None
    
    tasks = []
    
    if ioc_type in ["domain", "ip"]:
        tasks.append(vt_lookup(ioc))
        tasks.append(securitytrails_lookup_domain(ioc))
        tasks.append(hunter_lookup_domain(ioc))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    vt_data = results[0] if isinstance(results[0], dict) else None
    st_data = results[1] if isinstance(results[1], dict) else None
    whois_data = results[2] if isinstance(results[2], dict) else None
    
    score, risk_level, sources = score_ioc(vt_data=vt_data, st_data=st_data, whois_data=whois_data)
    
    save_query(ioc, ioc_type, score, risk_level, sources, vt_data, st_data, whois_data)
    
    from datetime import datetime
    return IOCResponse(
        ioc=ioc,
        ioc_type=ioc_type,
        score=score,
        risk_level=risk_level,
        sources=sources,
        vt=vt_data,
        st=st_data,
        whois=whois_data,
        created_at=datetime.utcnow().isoformat()
    )

@router.get("/summary/{ioc}", response_model=IOCSummary)
async def get_summary(ioc: str, api_key: str = Depends(verify_api_key)):
    """Get latest summary for IOC"""
    data = get_ioc_summary(ioc)
    if not data:
        raise HTTPException(status_code=404, detail="IOC not found")
    return IOCSummary(**data)

@router.get("/history/{ioc}", response_model=list[IOCHistoryEntry])
async def get_history(ioc: str, api_key: str = Depends(verify_api_key)):
    """Get query history for IOC"""
    history = get_ioc_history(ioc)
    if not history:
        raise HTTPException(status_code=404, detail="IOC not found")
    return [IOCHistoryEntry(**h) for h in history]

@router.get("/timeline/{ioc}", response_model=list[IOCTimeline])
async def get_timeline(ioc: str, api_key: str = Depends(verify_api_key)):
    """Get temporal timeline for IOC"""
    timeline = get_ioc_timeline(ioc)
    if not timeline:
        raise HTTPException(status_code=404, detail="IOC not found")
    return [IOCTimeline(**t) for t in timeline]
