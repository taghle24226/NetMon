import subprocess
import re
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.database import Device, Alert, SessionLocal

IP_REGEX = re.compile(r"Nmap scan report for ([\d\.]+)")
MAC_REGEX = re.compile(r"MAC Address: ([0-9A-F:]+) \((.+)\)")

class NetworkScanner:
    def __init__(self):
        self.scanning = False
        self.last_scan = None

    def scan_network(self, ip_range: str, user_id: int):
        self.scanning = True
        db: Session = SessionLocal()

        try:
            # 🔹 Lancer Nmap (scan ping)
            result = subprocess.run(
                ["nmap", "-sn", ip_range],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                raise RuntimeError("Nmap failed")

            output = result.stdout.splitlines()

            current_ip = None
            devices_found = []

            for line in output:
                ip_match = IP_REGEX.search(line)
                if ip_match:
                    current_ip = ip_match.group(1)
                    continue

                mac_match = MAC_REGEX.search(line)
                if mac_match and current_ip:
                    mac, vendor = mac_match.groups()
                    devices_found.append((current_ip, mac, vendor))
                    current_ip = None

            # 🔹 Récupérer anciens appareils
            existing_devices = {
                d.mac_address: d for d in db.query(Device).all()
            }

            seen_macs = set()

            for ip, mac, vendor in devices_found:
                seen_macs.add(mac)

                if mac in existing_devices:
                    device = existing_devices[mac]
                    device.last_seen = datetime.utcnow()
                    device.status = "Active"
                else:
                    device = Device(
                        name=f"{vendor} device",
                        ip_address=ip,
                        mac_address=mac,
                        vendor=vendor,
                        type="Unknown",
                        status="Active",
                        signal_strength=100,
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        is_new=True,
                        is_authorized=False
                    )
                    db.add(device)

                    # 🔔 Alerte nouvel appareil
                    alert = Alert(
                        alert_type="New device",
                        message=f"Nouvel appareil détecté ({mac})",
                        severity="warning",
                        device_ip=ip,
                        device_mac=mac,
                        user_id=user_id
                    )
                    db.add(alert)

            # 🔻 Marquer les absents comme Offline
            for mac, device in existing_devices.items():
                if mac not in seen_macs:
                    device.status = "Offline"

            db.commit()

        except Exception as e:
            print("Scan error:", e)

        finally:
            db.close()
            self.last_scan = datetime.utcnow()
            self.scanning = False


scanner = NetworkScanner()