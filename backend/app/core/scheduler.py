from apscheduler.schedulers.background import BackgroundScheduler
from app.core.scanner import scanner

scheduler = BackgroundScheduler()

def start_scheduler():
    scheduler.add_job(
        scanner.scan_network,
        "interval",
        minutes=15,
        args=["192.168.1.0/24", 1],  # admin user
        id="network_scan",
        replace_existing=True
    )
    scheduler.start()