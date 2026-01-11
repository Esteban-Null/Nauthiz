"""
IOC Query Endpoints
- POST /api/query       → Enrich IOC with all sources
- GET  /api/summary/{ioc}  → Latest assessment
- GET  /api/history/{ioc}  → Query history
- GET  /api/timeline/{ioc} → Temporal timeline
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Depends
from app.models.schemas import (
    IOCRequest, IOCResponse, IOCSummary, IOCHistoryEntry, IOCTimeline
)
from app.core.config import settings
from app.core.scoring import score_ioc
from app.core.db import init_db, save_query, get_ioc_summary, get_ioc_history, get_ioc_timeline
from app.core.providers import vt_lookup, securitytrails_lookup_domain, hunter_lookup_domain

#===============================================
# LOGGING SETUP
#===============================================
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#===============================================
# ROUTER INITIALIZATION
#===============================================
router = APIRouter(prefix="/api", tags=["threat-intelligence"])

# Initialize database on app startup (not on import)
_db_initialized = False

def _ensure_db():
    """Initialize database once on first request"""
    global _db_initialized
    if not _db_initialized:
        try:
            init_db()
            _db_initialized = True
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"DB init failed: {e}")
            raise

#===============================================
# AUTHENTICATION
#===============================================
def verify_api_key(x_api_key: str = Header(...)) -> str:
    """
    Verify X-API-Key header matches configured API_KEY
    
    Args:
        x_api_key: API key from request header
        
    Returns:
        The API key if valid
        
    Raises:
        HTTPException 401: If key doesn't match
    """
    if x_api_key != settings.API_KEY:
        logger.warning(f"Invalid API key attempt: {x_api_key[:4]}...")
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

#===============================================
# HELPER FUNCTIONS
#===============================================

async def _enrich_ioc_parallel(
    ioc: str, 
    ioc_type: str, 
    timeout: int = 10
) -> tuple[Optional[dict], Optional[dict], Optional[dict]]:
    """
    Fetch enrichment data from multiple providers in parallel
    
    Flow:
    1. Create async tasks for each provider (VT, SecurityTrails, Hunter)
    2. Run all tasks concurrently with timeout
    3. Handle individual provider failures gracefully
    4. Return tuple of results (or None if provider failed)
    
    Args:
        ioc: The indicator (IP, domain, hash)
        ioc_type: Type of indicator (ip, domain, hash)
        timeout: Max seconds to wait per provider
        
    Returns:
        (vt_data, st_data, whois_data) - each is dict or None
    """
    
    vt_data = None
    st_data = None
    whois_data = None
    
    # Only query external providers for ip/domain (not hashes)
    if ioc_type not in ["domain", "ip"]:
        logger.info(f"Skipping providers for {ioc_type} type")
        return vt_data, st_data, whois_data
    
    # Create async tasks
    tasks = [
        asyncio.create_task(vt_lookup(ioc)),
        asyncio.create_task(securitytrails_lookup_domain(ioc)),
        asyncio.create_task(hunter_lookup_domain(ioc)),
    ]
    
    try:
        # Run all tasks in parallel, catch individual exceptions
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout
        )
        
        # Process results, skip if exception
        vt_data = results[0] if isinstance(results[0], dict) else None
        st_data = results[1] if isinstance(results[1], dict) else None
        whois_data = results[2] if isinstance(results[2], dict) else None
        
        if isinstance(results[0], Exception):
            logger.warning(f"VT lookup failed: {results[0]}")
        if isinstance(results[1], Exception):
            logger.warning(f"SecurityTrails lookup failed: {results[1]}")
        if isinstance(results[2], Exception):
            logger.warning(f"Hunter lookup failed: {results[2]}")
            
    except asyncio.TimeoutError:
        logger.error(f"Provider timeout after {timeout}s for {ioc}")
        return None, None, None
    
    return vt_data, st_data, whois_data

def _validate_ioc(ioc: str) -> bool:
    """
    Simple IOC validation (length, format)
    
    Args:
        ioc: The indicator to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not ioc or len(ioc) < 3 or len(ioc) > 255:
        return False
    return True

#===============================================
# ENDPOINTS
#===============================================

@router.post("/query", response_model=IOCResponse)
async def query_ioc(
    request: IOCRequest,
    api_key: str = Depends(verify_api_key)
) -> IOCResponse:
    """
    Query & Enrich an Indicator of Compromise

    **What happens:**
    1. Validate IOC format
    2. Enrich from VirusTotal, WHOIS, SecurityTrails, Hunter (parallel)
    3. Calculate threat score (0-100)
    4. Save to database
    5. Return enriched response

    **Example:**
    ```bash
    curl -X POST http://127.0.0.1:8000/api/query \\
      -H "X-API-Key: your-key" \\
      -d '{"ioc": "1.1.1.1", "ioc_type": "ip"}'
    ```

    **Status Codes:**
    - 200: Success
    - 401: Invalid API key
    - 422: Validation error
    - 504: Provider timeout

    Args:
        request: IOCRequest with ioc and ioc_type
        api_key: X-API-Key header

    Returns:
        IOCResponse with enriched data and score
    """

    _ensure_db()

    ioc = request.ioc.strip()
    ioc_type = request.ioc_type or "domain"

    # Validate IOC
    if not _validate_ioc(ioc):
        logger.warning(f"Invalid IOC format: {ioc}")
        raise HTTPException(
            status_code=422,
            detail="Invalid IOC format (3-255 chars)"
        )

    logger.info(f"Querying {ioc_type}: {ioc}")

    try:
        # Step 1: Fetch enrichment data in parallel
        start_time = datetime.utcnow()
        vt_data, st_data, whois_data = await _enrich_ioc_parallel(ioc, ioc_type)
        elapsed_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        logger.info(f"Enrichment completed in {elapsed_ms:.0f}ms")

        # Step 2: Calculate threat score
        score, risk_level, sources = score_ioc(
            vt_data=vt_data,
            st_data=st_data,
            whois_data=whois_data
        )
        logger.info(f"Score: {score}/100 | Risk: {risk_level} | Sources: {sources}")

        # Step 3: Save to database
        save_query(
            ioc, ioc_type, score, risk_level, sources,
            vt_data, st_data, whois_data
        )
        logger.info(f"Saved to database")

        # Step 4: Return response
        response = IOCResponse(
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
        logger.debug(f"Response ready for {ioc}")
        return response

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error querying {ioc}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/summary/{ioc}", response_model=IOCSummary)
async def get_summary(
    ioc: str,
    api_key: str = Depends(verify_api_key)
) -> IOCSummary:
    """
    Get Latest Threat Summary for IOC

    Returns the most recent assessment without drilling into details.

    **Example:**
    ```bash
    curl -H "X-API-Key: key" http://127.0.0.1:8000/api/summary/1.1.1.1
    ```

    Args:
        ioc: The indicator to summarize
        api_key: X-API-Key header

    Returns:
        IOCSummary with score, risk_level, last_updated

    Raises:
        404: IOC not found in database
    """
    _ensure_db()

    ioc = ioc.strip()
    logger.info(f"Getting summary for {ioc}")

    try:
        data = get_ioc_summary(ioc)
        if not data:
            logger.warning(f"Summary not found for {ioc}")
            raise HTTPException(status_code=404, detail="IOC not found")

        logger.debug(f"Summary found: {data}")
        return IOCSummary(**data)
        
    except Exception as e:
        logger.error(f"Error getting summary for {ioc}: {e}")
        raise

@router.get("/history/{ioc}", response_model=list[IOCHistoryEntry])
async def get_history(
    ioc: str, 
    api_key: str = Depends(verify_api_key)
) -> list[IOCHistoryEntry]:
    """
    Get Query History for IOC (All Historical Scores)

    Returns all times this IOC was queried with scoring at each time.
    Useful for tracking how threat assessment changes over time.

    **Example:**
    ```bash
    curl -H "X-API-Key: key" http://127.0.0.1:8000/api/history/1.1.1.1 | jq
    ```

    Args:
        ioc: The indicator to get history for
        api_key: X-API-Key header

    Returns:
        List of IOCHistoryEntry with score, risk_level, created_at

    Raises:
        404: IOC not found in database
    """
    _ensure_db()

    ioc = ioc.strip()
    logger.info(f"Getting history for {ioc}")

    try:
        history = get_ioc_history(ioc)
        if not history:
            logger.warning(f"History not found for {ioc}")
            raise HTTPException(status_code=404, detail="IOC not found")

        logger.info(f"Found {len(history)} history entries")
        return [IOCHistoryEntry(**h) for h in history]

    except Exception as e:
        logger.error(f"Error getting history for {ioc}: {e}")
        raise

@router.get("/timeline/{ioc}", response_model=list[IOCTimeline])
async def get_timeline(
    ioc: str,
    api_key: str = Depends(verify_api_key)
) -> list[IOCTimeline]:
    """
    Get Activity Timeline (Temporal Analysis)

    Returns a timeline showing:
    - When IOC was first seen globally
    - When it was active
    - Whether it's burned/dormant
    - Activity phases (active, dormant, resurrected)

    Useful for determining if infrastructure is currently in use.

    **Example:**
    ```bash
    curl -H "X-API-Key: key" http://127.0.0.1:8000/api/timeline/1.1.1.1 | jq
    ```

    Args:
        ioc: The indicator to timeline
        api_key: X-API-Key header

    Returns:
        List of IOCTimeline with timestamp, phase, burned flag

    Raises:
        404: IOC not found in database
    """
    _ensure_db()

    ioc = ioc.strip()
    logger.info(f"Getting timeline for {ioc}")

    try:
        timeline = get_ioc_timeline(ioc)
        if not timeline:
            logger.warning(f"Timeline not found for {ioc}")
            raise HTTPException(status_code=404, detail="IOC not found")

        logger.info(f"Found {len(timeline)} timeline points")
        return [IOCTimeline(**t) for t in timeline]

    except Exception as e:
        logger.error(f"Error getting timeline for {ioc}: {e}")
        raise
