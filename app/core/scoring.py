from typing import Tuple, List

def score_ioc(vt_data: dict = None, st_data: dict = None, whois_data: dict = None) -> Tuple[int, str, List[str]]:
    """
    Calculate IOC score (0-100) and risk level based on enrichment data.
    Returns: (score, risk_level, sources_list)
    """
    score = 0
    sources = []
    
    # VirusTotal scoring
    if vt_data:
        sources.append("virustotal")
        detections = vt_data.get("detections", 0)
        if detections:
            score += min(detections * 5, 50)  # Max 50 from VT
    
    # SecurityTrails scoring
    if st_data:
        sources.append("securitytrails")
        if st_data.get("resolutions"):
            score += 10
    
    # WHOIS scoring
    if whois_data:
        sources.append("whois")
        if whois_data.get("registrar"):
            score += 5
    
    # Normalize score to 0-100
    score = min(max(score, 0), 100)
    
    # Map score to risk level
    if score >= 70:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return score, risk_level, sources
