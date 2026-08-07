import os
import json
import logging
from typing import Optional

logger = logging.getLogger("threatshield.firebase")

_firebase_initialized = False

def init_firebase():
    global _firebase_initialized
    if _firebase_initialized:
        return
    try:
        import firebase_admin
        from firebase_admin import credentials

        cred_path = os.path.join(os.path.dirname(__file__), "..", "..", "serviceAccountKey.json")
        
        if os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
            _firebase_initialized = True
            logger.info("✅ Firebase Admin SDK initialized from serviceAccountKey.json")
        elif os.environ.get("FIREBASE_SERVICE_ACCOUNT"):
            cred_dict = json.loads(os.environ["FIREBASE_SERVICE_ACCOUNT"])
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            _firebase_initialized = True
            logger.info("✅ Firebase Admin SDK initialized from env var")
        else:
            # Initialize with default app credentials if in GCP environment
            firebase_admin.initialize_app()
            _firebase_initialized = True
            logger.info("✅ Firebase Admin SDK initialized with default app credentials")
    except Exception as e:
        logger.warning(f"⚠️ Firebase Admin SDK initialization skipped/failed: {e}")

def verify_firebase_id_token(token: str) -> Optional[dict]:
    init_firebase()
    try:
        from firebase_admin import auth
        decoded_token = auth.verify_id_token(token)
        return decoded_token
    except Exception as e:
        logger.debug(f"Firebase token verification failed: {e}")
        return None
