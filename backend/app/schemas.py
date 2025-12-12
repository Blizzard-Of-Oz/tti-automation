from typing import Optional, List
from pydantic import BaseModel, EmailStr


# ---------- Client ----------

class ClientBase(BaseModel):
    name: str
    code: Optional[str] = None


class ClientCreate(ClientBase):
    pass


class ClientRead(ClientBase):
    id: int

    class Config:
        orm_mode = True


# ---------- Client Contact ----------

class ClientContactBase(BaseModel):
    name: str
    email: EmailStr
    role: Optional[str] = None
    is_primary: bool = True


class ClientContactCreate(ClientContactBase):
    pass


class ClientContactRead(ClientContactBase):
    id: int
    client_id: int

    class Config:
        orm_mode = True


# ---------- Asset ----------

class AssetBase(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    asset_type: Optional[str] = None
    criticality: Optional[str] = None
    owner: Optional[str] = None


class AssetCreate(AssetBase):
    pass


class AssetRead(AssetBase):
    id: int
    client_id: int

    class Config:
        orm_mode = True


# ---------- Software ----------

class SoftwareBase(BaseModel):
    vendor: str
    product: str
    version: Optional[str] = None
    cpe_uri: Optional[str] = None


class SoftwareCreate(SoftwareBase):
    pass


class SoftwareRead(SoftwareBase):
    id: int
    asset_id: int

    class Config:
        orm_mode = True


# ---------- Nested views (for convenience) ----------

class AssetWithSoftware(AssetRead):
    software: List[SoftwareRead] = []


class ClientDetail(ClientRead):
    contacts: List[ClientContactRead] = []
    assets: List[AssetWithSoftware] = []


class ClientMatchResult(BaseModel):
    client_id: int
    assets_seen: int
    software_seen: int
    matches_created: int
    matches_skipped_existing: int


class AdvisoryStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int


class ClientAdvisoryResponse(BaseModel):
    client_id: int
    email_log_id: Optional[int] = None  # we are not logging to DB (for now)
    subject: str
    body_html: str
    body_text: str
    stats: AdvisoryStats
