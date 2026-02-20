from __future__ import annotations

from datetime import datetime, timedelta
from io import BytesIO, StringIO
from pathlib import Path
import csv
import json
import secrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.core.auth import (
    get_current_active_user,
    require_admin,
    get_db,
    authenticate_user,
    create_access_token,
    get_password_hash,
)
from app.core.scanner import scanner
from app.models.database import User, Device, Alert, ScanHistory, DATABASE_PATH
from app.models.schemas import (
    UserCreate,
    UserUpdate,
    UserResponse,
    DeviceResponse,
    AlertResponse,
    LoginRequest,
    Token,
    PasswordResetRequest,
)

# WeasyPrint (PDF)
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except Exception:
    WEASYPRINT_AVAILABLE = False


router = APIRouter()


# =========================
# Helpers
# =========================

def _time_ago(dt: datetime) -> str:
    if not dt:
        return ""
    delta = datetime.utcnow() - dt
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h"
    days = hours // 24
    return f"{days}j"


def _settings_file() -> Path:
    # backend/settings.json (à côté de netmon.db)
    base = Path(DATABASE_PATH).parent
    return base / "settings.json"


def _load_settings() -> Dict[str, Any]:
    f = _settings_file()
    if not f.exists():
        return {
            "ip_range": "192.168.1.0/24",
            "scan_interval": "Désactivé",
            "signal_threshold": 30,
        }
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {
            "ip_range": "192.168.1.0/24",
            "scan_interval": "Désactivé",
            "signal_threshold": 30,
        }


def _save_settings(data: Dict[str, Any]) -> None:
    f = _settings_file()
    f.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# =========================
# AUTH
# =========================

@router.post("/auth/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password),
        role=user_data.role or "user",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/auth/login", response_model=Token)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    # Support: username ou email
    user = None
    if "@" in payload.username:
        user = db.query(User).filter(User.email == payload.username).first()
        if user and not authenticate_user(db, user.username, payload.password):
            user = None
    else:
        user = authenticate_user(db, payload.username, payload.password)

    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username/email or password")
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account inactive")

    access_token_expires = timedelta(minutes=60 * 24)
    token = create_access_token(
        data={"sub": user.username, "role": user.role, "id": user.id},
        expires_delta=access_token_expires,
    )
    return {"access_token": token, "token_type": "bearer"}


@router.post("/auth/forgot-password")
def forgot_password(req: PasswordResetRequest, db: Session = Depends(get_db)):
    """
    Démo: génère un mot de passe temporaire et le renvoie.
    (En prod: envoi email + token signé.)
    """
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        return {"message": "If this email exists, a reset link has been sent."}

    tmp = secrets.token_urlsafe(12)[:10]
    user.hashed_password = get_password_hash(tmp)
    db.commit()
    return {
        "message": "Password reset successful",
        "email": user.email,
        "temporary_password": tmp,
    }


# =========================
# DASHBOARD
# =========================

@router.get("/dashboard/stats")
def dashboard_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    total = db.query(Device).count()
    active = db.query(Device).filter(Device.status == "Active").count()
    inactive = db.query(Device).filter(Device.status == "Inactive").count()
    offline = db.query(Device).filter(Device.status == "Offline").count()

    return {
        "total_devices": total,
        "active_devices": active,
        "inactive_devices": inactive,
        "offline_devices": offline,
        "last_scan": scanner.last_scan.isoformat() if scanner.last_scan else None,
        "scanning": scanner.scanning,
    }


@router.get("/dashboard/chart-data")
def dashboard_chart_data(current_user: User = Depends(get_current_active_user)):
    # Données simples; tu peux remplacer par ScanHistory si tu veux
    days = ["Lun", "Mar", "Mer", "Jeu", "Ven", "Sam", "Dim"]
    return [
        {"date": day, "active": 8 + i, "inactive": 2 + (i % 3), "offline": i % 2}
        for i, day in enumerate(days)
    ]


# =========================
# NETWORK SCAN + DEVICES
# =========================

@router.post("/network/scan")
def start_scan(
    background_tasks: BackgroundTasks,
    ip_range: str = Query(default=None),
    current_user: User = Depends(get_current_active_user),
):
    # si pas fourni -> settings
    settings = _load_settings()
    target = ip_range or settings.get("ip_range", "192.168.1.0/24")

    background_tasks.add_task(scanner.scan_network, target, current_user.id)
    return {"message": "Scan démarré", "ip_range": target}


@router.get("/network/devices", response_model=List[DeviceResponse])
def get_devices(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    return db.query(Device).order_by(Device.last_seen.desc()).all()


# =========================
# ALERTS
# =========================

@router.get("/alerts")
def get_alerts(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Alert)
        .order_by(Alert.timestamp.desc())
        .limit(50)
        .all()
    )

    # On enrichit pour le frontend (time_ago)
    return [
        {
            "id": a.id,
            "alert_type": a.alert_type,
            "message": a.message,
            "severity": a.severity,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "resolved": bool(getattr(a, "resolved", False)),
            "resolved_at": getattr(a, "resolved_at", None).isoformat() if getattr(a, "resolved_at", None) else None,
            "device_ip": a.device_ip,
            "device_mac": a.device_mac,
            "user_id": a.user_id,
            "time_ago": _time_ago(a.timestamp) if a.timestamp else "",
        }
        for a in rows
    ]


@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    a = db.query(Alert).filter(Alert.id == alert_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")

    # champs possibles selon ton modèle
    if hasattr(a, "resolved"):
        a.resolved = True
    if hasattr(a, "resolved_at"):
        a.resolved_at = datetime.utcnow()

    db.commit()
    return {"message": "Alert resolved"}


# =========================
# SETTINGS
# =========================

@router.get("/settings")
def get_settings(current_user: User = Depends(require_admin)):
    return _load_settings()


@router.put("/settings")
def update_settings(
    payload: Dict[str, Any],
    current_user: User = Depends(require_admin),
):
    # Validation minimale
    ip_range = payload.get("ip_range", "192.168.1.0/24")
    scan_interval = payload.get("scan_interval", "Désactivé")
    signal_threshold = int(payload.get("signal_threshold", 30))

    data = {
        "ip_range": ip_range,
        "scan_interval": scan_interval,
        "signal_threshold": signal_threshold,
    }
    _save_settings(data)
    return {"message": "Settings updated", "settings": data}


# =========================
# ADMIN USERS
# =========================

@router.get("/admin/users", response_model=List[UserResponse])
def admin_list_users(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return db.query(User).order_by(User.id.asc()).all()


@router.post("/admin/users")
def admin_create_user(
    payload: Dict[str, Any],
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    username = (payload.get("username") or "").strip()
    email = (payload.get("email") or "").strip()
    full_name = (payload.get("full_name") or "").strip()
    role = payload.get("role") or "user"
    is_active = bool(payload.get("is_active", True))

    if not username or not email:
        raise HTTPException(status_code=400, detail="username and email are required")

    existing = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    # Mot de passe: fourni ou généré
    password = payload.get("password") or secrets.token_urlsafe(10)[:10]

    user = User(
        username=username,
        email=email,
        full_name=full_name,
        role=role,
        is_active=is_active,
        hashed_password=get_password_hash(password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "User created",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
        },
        "temporary_password": password,
    }


@router.put("/admin/users/{user_id}", response_model=UserResponse)
def admin_update_user(
    user_id: int,
    user_update: UserUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_update.full_name is not None:
        user.full_name = user_update.full_name
    if user_update.email is not None:
        user.email = user_update.email
    if user_update.role is not None:
        user.role = user_update.role
    if user_update.is_active is not None:
        user.is_active = user_update.is_active
    if user_update.password is not None and user_update.password.strip():
        user.hashed_password = get_password_hash(user_update.password)

    db.commit()
    db.refresh(user)
    return user


@router.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return {"message": "User deleted"}


@router.post("/admin/users/{user_id}/reset-password")
def admin_reset_password(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    tmp = secrets.token_urlsafe(12)[:10]
    user.hashed_password = get_password_hash(tmp)
    db.commit()
    return {"message": "Password reset", "temporary_password": tmp}


# =========================
# EXPORTS
# =========================

def _csv_response(filename: str, rows: List[Dict[str, Any]]) -> Response:
    sio = StringIO()
    if not rows:
        # entêtes par défaut
        writer = csv.writer(sio)
        writer.writerow(["empty"])
    else:
        writer = csv.DictWriter(sio, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    data = sio.getvalue().encode("utf-8")
    return Response(
        content=data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/exports/devices")
def export_devices(
    format: str = Query("csv", pattern="^(csv|json)$"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    devices = db.query(Device).all()
    rows = [
        {
            "id": d.id,
            "name": d.name,
            "ip_address": d.ip_address,
            "mac_address": d.mac_address,
            "vendor": d.vendor,
            "type": d.type,
            "status": d.status,
            "signal_strength": d.signal_strength,
            "first_seen": d.first_seen.isoformat() if d.first_seen else None,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            "is_authorized": d.is_authorized,
            "is_new": d.is_new,
        }
        for d in devices
    ]

    if format == "json":
        return rows
    return _csv_response("devices.csv", rows)


@router.get("/exports/alerts")
def export_alerts(
    format: str = Query("csv", pattern="^(csv|json)$"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    rows = [
        {
            "id": a.id,
            "alert_type": a.alert_type,
            "message": a.message,
            "severity": a.severity,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "resolved": bool(getattr(a, "resolved", False)),
            "device_ip": a.device_ip,
            "device_mac": a.device_mac,
            "user_id": a.user_id,
        }
        for a in alerts
    ]

    if format == "json":
        return rows
    return _csv_response("alerts.csv", rows)


@router.get("/exports/logs")
def export_logs(
    format: str = Query("csv", pattern="^(csv|json)$"),
    current_user: User = Depends(get_current_active_user),
):
    # Ton frontend a des logs mock. Ici on exporte une structure simple.
    rows = [
        {
            "time": datetime.utcnow().isoformat(),
            "action": "scan_network",
            "user": current_user.username,
            "status": "ok",
        }
    ]
    if format == "json":
        return rows
    return _csv_response("logs.csv", rows)


# =========================
# REPORTS (PDF)
# =========================

@router.get("/reports/export")
def export_report(
    format: str = Query("pdf", pattern="^(pdf)$"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    if not WEASYPRINT_AVAILABLE:
        raise HTTPException(
            status_code=500,
            detail="WeasyPrint not installed. Install: pip install weasyprint",
        )

    devices = db.query(Device).all()
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(25).all()
    stats = {
        "total": len(devices),
        "active": len([d for d in devices if d.status == "Active"]),
        "offline": len([d for d in devices if d.status == "Offline"]),
    }

    html = f"""
    <html>
      <head>
        <meta charset="utf-8"/>
        <style>
          body {{ font-family: Arial, sans-serif; font-size: 12px; }}
          h1 {{ font-size: 18px; }}
          table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
          th, td {{ border: 1px solid #ddd; padding: 6px; }}
          th {{ background: #f3f3f3; }}
        </style>
      </head>
      <body>
        <h1>Rapport NetMon+</h1>
        <p>Généré le: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</p>
        <p>Utilisateur: {current_user.username}</p>

        <h2>Résumé</h2>
        <ul>
          <li>Total équipements: {stats["total"]}</li>
          <li>Actifs: {stats["active"]}</li>
          <li>Hors ligne: {stats["offline"]}</li>
        </ul>

        <h2>Équipements</h2>
        <table>
          <thead>
            <tr>
              <th>Nom</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Type</th><th>Status</th><th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {''.join([f"<tr><td>{d.name or ''}</td><td>{d.ip_address or ''}</td><td>{d.mac_address or ''}</td><td>{d.vendor or ''}</td><td>{d.type or ''}</td><td>{d.status or ''}</td><td>{(d.last_seen.isoformat() if d.last_seen else '')}</td></tr>" for d in devices])}
          </tbody>
        </table>

        <h2>Alertes récentes</h2>
        <table>
          <thead>
            <tr><th>Date</th><th>Sévérité</th><th>Type</th><th>Message</th></tr>
          </thead>
          <tbody>
            {''.join([f"<tr><td>{(a.timestamp.isoformat() if a.timestamp else '')}</td><td>{a.severity}</td><td>{a.alert_type}</td><td>{a.message}</td></tr>" for a in alerts])}
          </tbody>
        </table>

      </body>
    </html>
    """

    pdf_bytes = HTML(string=html).write_pdf()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="rapport_netmon.pdf"'},
    )


# =========================
# MAINTENANCE
# =========================

@router.get("/maintenance/backup")
def maintenance_backup(
    current_user: User = Depends(require_admin),
):
    if not DATABASE_PATH.exists():
        raise HTTPException(status_code=404, detail="Database file not found")
    data = DATABASE_PATH.read_bytes()
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="netmon_backup.db"'},
    )


@router.get("/maintenance/check-updates")
def maintenance_check_updates(current_user: User = Depends(require_admin)):
    return {"status": "ok", "message": "Aucune mise à jour disponible (démo)."}


@router.post("/maintenance/restart")
def maintenance_restart(current_user: User = Depends(require_admin)):
    # En vrai: orchestration système (systemd/docker/k8s). Ici: réponse démo.
    return {"status": "ok", "message": "Redémarrage demandé (démo)."}


# =========================
# SCANS HISTORY + EVOLUTION
# =========================

@router.get("/scans/history")
def scan_history(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    rows = db.query(ScanHistory).order_by(ScanHistory.scanned_at.desc()).limit(30).all()
    return [
        {
            "id": r.id,
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
            "devices_found": r.devices_found,
            "new_devices": r.new_devices,
        }
        for r in rows
    ]


@router.get("/statistics/devices-evolution")
def devices_evolution(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    rows = db.query(ScanHistory).order_by(ScanHistory.scanned_at.asc()).limit(60).all()
    return [
        {
            "date": r.scanned_at.strftime("%d/%m") if r.scanned_at else "",
            "devices": r.devices_found,
            "new": r.new_devices,
        }
        for r in rows
    ]