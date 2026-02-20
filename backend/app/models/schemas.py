# backend/app/models/schemas.py
from pydantic import BaseModel, EmailStr
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    username: str
    password: str
    role: Optional[str] = "user"

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    username: str
    password: str

class PasswordResetRequest(BaseModel):
    email: str

# 🔑 CORRECTION ICI : champs alignés avec Device
class DeviceResponse(BaseModel):
    id: int
    ip_address: str      
    mac_address: str     
    name: str
    type: str            
    vendor: str
    status: str
    first_seen: str
    last_seen: str
    signal_strength: int
    uptime: str
    is_authorized: bool
    is_new: bool

    class Config:
        from_attributes = True

class AlertResponse(BaseModel):
    id: int
    alert_type: str
    message: str
    severity: str
    timestamp: str
    resolved: bool
    resolved_at: Optional[str] = None
    device_ip: Optional[str] = None
    device_mac: Optional[str] = None
    user_id: Optional[int] = None

    class Config:
        from_attributes = True