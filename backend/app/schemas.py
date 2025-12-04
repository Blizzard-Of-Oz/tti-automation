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
