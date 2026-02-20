from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    Column, Integer, String, Boolean,
    DateTime, ForeignKey, create_engine
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from passlib.context import CryptContext

# ======================
# DATABASE CONFIG
# ======================

BASE_DIR = Path(__file__).resolve().parents[2]  # backend/
DATABASE_PATH = BASE_DIR / "netmon.db"

SQLALCHEMY_DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# ======================
# PASSWORD HASHING
# ======================

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# ======================
# MODELS
# ======================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    alerts = relationship("Alert", back_populates="user")


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    ip_address = Column(String, index=True)
    mac_address = Column(String, unique=True, index=True)
    vendor = Column(String)
    type = Column(String)
    status = Column(String)  # Active / Offline
    signal_strength = Column(Integer, default=100)
    uptime = Column(String)
    is_authorized = Column(Boolean, default=False)
    is_new = Column(Boolean, default=True)

    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    alert_type = Column(String)
    message = Column(String)
    severity = Column(String)  # info / warning / critical

    device_ip = Column(String)
    device_mac = Column(String)

    timestamp = Column(DateTime, default=datetime.utcnow)
    resolved = Column(Boolean, default=False)

    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="alerts")


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True)
    scanned_at = Column(DateTime, default=datetime.utcnow)

    devices_found = Column(Integer)
    new_devices = Column(Integer)

# ======================
# DEPENDENCIES
# ======================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ======================
# DEFAULT ADMIN CREATION
# ======================

def create_default_admin():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@netmon.local",
                full_name="Administrator",
                hashed_password=get_password_hash("admin123"),
                role="admin",
                is_active=True
            )
            db.add(admin)
            db.commit()
            print("✅ Admin created: admin / admin123")
    finally:
        db.close()