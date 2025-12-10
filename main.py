from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.ioc import router as ioc_router
from app.core.config import settings

app = FastAPI(title="Nauthiz", version="0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ioc_router, prefix="/api", tags=["IOC"])

@app.get("/")
def root():
    return {"message": "Nauthiz API", "status": "online"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=settings.PORT, reload=True)
