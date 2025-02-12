import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.templating import Jinja2Templates

from schemas.creature import Creature

if os.getenv("CRYPTID_UNIT_TEST"):
    from fake import creature as service
else:
    from services import creature_service as service
from error import Missing, Duplicate

router = APIRouter(prefix="/creature")
top = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=f"{top}/template")


@router.get("/")
def get_all() -> list[Creature]:
    return service.get_all()


@router.get("/{name}")
def get_one(name: str) -> Creature:
    try:
        return service.get_one(name)
    except Missing as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.msg)


@router.post("/", status_code=201)
def create(creature: Creature) -> Creature:
    try:
        return service.create(creature)
    except Duplicate as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.msg)


@router.patch("/{name}")
def modify(name: str, creature: Creature) -> Creature:
    try:
        return service.modify(name, creature)
    except Missing as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.msg)


@router.delete("/{name}")
def delete(name: str) -> None:
    try:
        return service.delete(name)
    except Missing as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.msg)
