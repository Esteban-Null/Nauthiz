import httpx
from app.core.config import settings

async def vt_lookup(ioc: str) -> dict:
    """Lookup IOC in VirusTotal"""
    if not settings.VT_API_KEY:
        return None
    
    try:
        async with httpx.AsyncClient() as client:
            headers = {"x-apikey": settings.VT_API_KEY}
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            resp = await client.get(url, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                last_analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "detections": last_analysis.get("malicious", 0),
                    "total": 0,
                    "url": f"https://www.virustotal.com/gui/domain/{ioc}"
                }
    except Exception as e:
        print(f"VT error: {e}")
    return None

async def securitytrails_lookup_domain(domain: str) -> dict:
    """Lookup domain in SecurityTrails"""
    if not settings.SECURITYTRAILS_API_KEY:
        return None
    
    try:
        async with httpx.AsyncClient() as client:
            headers = {"apikey": settings.SECURITYTRAILS_API_KEY}
            url = f"https://api.securitytrails.com/v1/domain/{domain}/dns"
            resp = await client.get(url, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                return {"resolutions": data.get("records", [])}
    except Exception as e:
        print(f"SecurityTrails error: {e}")
    return None

async def hunter_lookup_domain(domain: str) -> dict:
    """Lookup domain in Hunter.io (email/OSINT)"""
    if not settings.HUNTER_API_KEY:
        return None
    
    try:
        async with httpx.AsyncClient() as client:
            url = "https://api.hunter.io/v2/domain-search"
            params = {"domain": domain, "api_key": settings.HUNTER_API_KEY}
            resp = await client.get(url, params=params, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                return {"emails": len(data.get("emails", []))}
    except Exception as e:
        print(f"Hunter error: {e}")
    return None
