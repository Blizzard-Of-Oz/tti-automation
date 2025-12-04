from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..db import get_db
from .. import models, schemas

router = APIRouter(
    prefix="/clients",
    tags=["clients"],
)


# ---------- Clients ----------


@router.post("/", response_model=schemas.ClientRead, status_code=status.HTTP_201_CREATED)
def create_client(client_in: schemas.ClientCreate, db: Session = Depends(get_db)):
    existing = (
        db.query(models.Client)
        .filter(models.Client.name == client_in.name)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client with this name already exists.",
        )

    client = models.Client(
        name=client_in.name,
        code=client_in.code,
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    return client


@router.get("/", response_model=List[schemas.ClientRead])
def list_clients(db: Session = Depends(get_db)):
    clients = db.query(models.Client).order_by(models.Client.id).all()
    return clients


@router.get("/{client_id}", response_model=schemas.ClientDetail)
def get_client_detail(client_id: int, db: Session = Depends(get_db)):
    client = (
        db.query(models.Client)
        .filter(models.Client.id == client_id)
        .first()
    )
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


# ---------- Contacts ----------


@router.post(
    "/{client_id}/contacts",
    response_model=schemas.ClientContactRead,
    status_code=status.HTTP_201_CREATED,
)
def add_client_contact(
    client_id: int,
    contact_in: schemas.ClientContactCreate,
    db: Session = Depends(get_db),
):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    contact = models.ClientContact(
        client_id=client_id,
        name=contact_in.name,
        email=contact_in.email,
        role=contact_in.role,
        is_primary=contact_in.is_primary,
    )
    db.add(contact)
    db.commit()
    db.refresh(contact)
    return contact


@router.get(
    "/{client_id}/contacts",
    response_model=List[schemas.ClientContactRead],
)
def list_client_contacts(client_id: int, db: Session = Depends(get_db)):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    contacts = (
        db.query(models.ClientContact)
        .filter(models.ClientContact.client_id == client_id)
        .order_by(models.ClientContact.id)
        .all()
    )
    return contacts


# ---------- Assets ----------


@router.post(
    "/{client_id}/assets",
    response_model=schemas.AssetRead,
    status_code=status.HTTP_201_CREATED,
)
def add_asset(
    client_id: int,
    asset_in: schemas.AssetCreate,
    db: Session = Depends(get_db),
):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    asset = models.Asset(
        client_id=client_id,
        hostname=asset_in.hostname,
        ip_address=asset_in.ip_address,
        asset_type=asset_in.asset_type,
        criticality=asset_in.criticality,
        owner=asset_in.owner,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get(
    "/{client_id}/assets",
    response_model=List[schemas.AssetWithSoftware],
)
def list_assets(client_id: int, db: Session = Depends(get_db)):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    assets = (
        db.query(models.Asset)
        .filter(models.Asset.client_id == client_id)
        .order_by(models.Asset.id)
        .all()
    )
    return assets


# ---------- Software on asset ----------


@router.post(
    "/assets/{asset_id}/software",
    response_model=schemas.SoftwareRead,
    status_code=status.HTTP_201_CREATED,
)
def add_software_to_asset(
    asset_id: int,
    sw_in: schemas.SoftwareCreate,
    db: Session = Depends(get_db),
):
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    sw = models.Software(
        asset_id=asset_id,
        vendor=sw_in.vendor,
        product=sw_in.product,
        version=sw_in.version,
        cpe_uri=sw_in.cpe_uri,
    )
    db.add(sw)
    db.commit()
    db.refresh(sw)
    return sw


@router.get(
    "/assets/{asset_id}/software",
    response_model=List[schemas.SoftwareRead],
)
def list_software_for_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    software = (
        db.query(models.Software)
        .filter(models.Software.asset_id == asset_id)
        .order_by(models.Software.id)
        .all()
    )
    return software
