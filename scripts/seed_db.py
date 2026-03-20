"""
THREATSHIELD  ·  scripts/seed_db.py
Seeds the database with realistic demo data for development.
Run: python scripts/seed_db.py
"""
import asyncio
import random
import uuid
from datetime import datetime, timezone, timedelta
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import init_db, AsyncSessionLocal
from app.models.scan   import ScanResult, ThreatStats, ScanType, ThreatLevel, ScanStatus


DEMO_SCANS = [
    # Danger
    ("url",   "http://bit.ly/3xYmK9",                "danger", 94, ["Phishing","Credential Steal","Banking Trojan"]),
    ("url",   "http://paypal-secure-update.tk/login", "danger", 89, ["Phishing","SSL Spoof","Redirect"]),
    ("file",  "invoice_2024.exe",                     "danger", 87, ["Malware","Trojan","Keylogger"]),
    ("apk",   "free-netflix-premium.apk",             "danger", 91, ["Adware","Spyware","Dangerous Perms"]),
    ("email", "security@paypa1-support.com",          "danger", 82, ["Phishing","Email Spoof","Impersonation"]),
    ("url",   "http://secure-bankofamerica.xyz",      "danger", 95, ["Phishing","Credential Steal"]),
    ("file",  "crack_photoshop.zip",                  "danger", 78, ["Malware","Ransomware","Warez"]),

    # Warn
    ("url",   "http://free-vpn-download.net",         "warn", 52, ["Adware","Trackers","Unverified"]),
    ("file",  "setup_free_tool.exe",                  "warn", 45, ["Adware","PUP"]),
    ("url",   "http://torrent-movies-hd.com",         "warn", 55, ["Adware","Copyright Risk"]),
    ("apk",   "com.free.vpn.proxy.secure",            "warn", 48, ["Adware","Permissions"]),
    ("email", "offer@win-prize-now.com",              "warn", 60, ["Spam","Suspicious Sender"]),

    # Safe
    ("url",   "https://github.com/torvalds/linux",    "safe",  5,  ["SSL Verified","Domain Trusted"]),
    ("url",   "https://docs.python.org/3/",           "safe",  3,  ["SSL Verified","Domain Trusted"]),
    ("file",  "report_q3_2024.pdf",                   "safe",  4,  ["PDF Clean","No Macros"]),
    ("url",   "https://stackoverflow.com/questions",  "safe",  6,  ["SSL Verified","Domain Trusted"]),
    ("url",   "https://npmjs.com/package/react",      "safe",  4,  ["SSL Verified","Domain Trusted"]),
    ("apk",   "com.google.android.apps.maps",         "safe",  2,  ["Verified Publisher","Google Play"]),
    ("email", "hello@github.com",                     "safe",  3,  ["SSL Verified","DKIM Valid"]),
    ("url",   "https://cloudflare.com",               "safe",  2,  ["SSL Verified","CDN Trusted"]),
]

SCAN_TYPE_MAP = {
    "url":   ScanType.URL,
    "file":  ScanType.FILE,
    "apk":   ScanType.APK,
    "email": ScanType.EMAIL,
}

LEVEL_MAP = {
    "safe":   ThreatLevel.SAFE,
    "warn":   ThreatLevel.WARN,
    "danger": ThreatLevel.DANGER,
}

VERDICT_MAP = {
    "safe":   "SAFE",
    "warn":   "SUSPICIOUS",
    "danger": "THREAT DETECTED",
}

DETAIL_MAP = {
    "safe":   "No threats detected. Content verified safe.",
    "warn":   "Suspicious indicators found. Proceed with caution.",
    "danger": "Active threat detected. Access blocked. VM self-healed.",
}


async def seed():
    print("🌱 Seeding ThreatShield database...")
    await init_db()

    async with AsyncSessionLocal() as db:
        records_created = 0
        now = datetime.now(timezone.utc)

        for i, (scan_type, input_val, level, score, tags) in enumerate(DEMO_SCANS):
            # Spread across last 30 days with some randomness
            created = now - timedelta(
                days  = random.randint(0, 29),
                hours = random.randint(0, 23),
                minutes = random.randint(0, 59),
            )
            duration = random.randint(800, 4500)

            meter_scores = {}
            if scan_type == "url":
                meter_scores = {
                    "phishing":   score if level == "danger" else max(0, score - 20),
                    "malware":    max(0, score - 10),
                    "data_steal": max(0, score - 5),
                    "redirect":   random.randint(5, score),
                    "adware":     random.randint(0, score - 10),
                }
            elif scan_type in ("file","apk"):
                meter_scores = {
                    "malware":       score,
                    "data_steal":    max(0, score - 15),
                    "ransomware":    max(0, score - 30) if level == "danger" else 0,
                    "spyware":       max(0, score - 20),
                    "dangerous_perm": max(0, score - 10) if scan_type == "apk" else 0,
                }

            record = ScanResult(
                id               = str(uuid.uuid4()),
                scan_type        = SCAN_TYPE_MAP[scan_type],
                status           = ScanStatus.COMPLETED,
                threat_level     = LEVEL_MAP[level],
                input_value      = input_val,
                risk_score       = score,
                confidence       = round(random.uniform(0.82, 0.99), 2),
                verdict          = VERDICT_MAP[level],
                verdict_detail   = DETAIL_MAP[level],
                threat_tags      = tags,
                meter_scores     = meter_scores,
                api_results      = {"heuristics": {"score": score, "tags": tags, "source": "heuristics"}},
                device_id        = f"DEMO-DEV-{(i % 3) + 1:03d}",
                scan_started_at  = created,
                scan_finished_at = created + timedelta(milliseconds=duration),
                scan_duration_ms = duration,
                created_at       = created,
            )
            db.add(record)
            records_created += 1

        # Seed daily stats for last 7 days
        for day_offset in range(7):
            day = (now - timedelta(days=day_offset)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            stats = ThreatStats(
                id            = str(uuid.uuid4()),
                date          = day,
                total_scans   = random.randint(35, 55),
                safe_count    = random.randint(25, 40),
                warn_count    = random.randint(3, 8),
                danger_count  = random.randint(2, 9),
                phishing_count= random.randint(1, 5),
                malware_count = random.randint(0, 4),
                adware_count  = random.randint(0, 3),
                vm_self_heals = random.randint(0, 4),
            )
            db.add(stats)

        await db.commit()

    print(f"✅ Seeded {records_created} scan records + 7 days of stats")
    print("   Run: python main.py  →  http://localhost:8000/docs")


if __name__ == "__main__":
    asyncio.run(seed())
