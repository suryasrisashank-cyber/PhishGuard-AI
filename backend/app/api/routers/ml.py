from fastapi import APIRouter
from ...services.ml_service import train_and_save_models

router = APIRouter()


@router.post("/train")
def train_models() -> dict:
    result = train_and_save_models()
    return {"message": "Training completed", **result}
