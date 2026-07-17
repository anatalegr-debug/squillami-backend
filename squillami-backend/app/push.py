"""Invio notifiche push.

Se Firebase è configurato (variabile GOOGLE_APPLICATION_CREDENTIALS che punta
al file JSON del service account) le push vengono inviate davvero via FCM.
Altrimenti vengono solo registrate nel log: utile per i primi test senza app.
"""
import logging
import os

log = logging.getLogger("squillami.push")

_firebase_ready = False
try:
    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        import firebase_admin
        from firebase_admin import messaging

        firebase_admin.initialize_app()
        _firebase_ready = True
        log.info("Firebase inizializzato: push reali attive")
except Exception as exc:  # pragma: no cover
    log.warning("Firebase non disponibile (%s): push simulate", exc)


def send_ring_and_locate(push_token: str, platform: str, event_id: int,
                         ring_seconds: int = 120) -> bool:
    """Invia la push RING_AND_LOCATE al dispositivo. Ritorna True se inviata."""
    data = {
        "type": "RING_AND_LOCATE",
        "event_id": str(event_id),
        "ring_seconds": str(ring_seconds),
        "locate": "true",
    }
    if not _firebase_ready:
        log.info("PUSH SIMULATA -> token=%s platform=%s data=%s",
                 (push_token or "")[:12] + "…", platform, data)
        return True
    try:  # pragma: no cover - richiede credenziali reali
        from firebase_admin import messaging
        msg = messaging.Message(
            token=push_token,
            data=data,
            android=messaging.AndroidConfig(priority="high"),
            apns=messaging.APNSConfig(
                headers={"apns-priority": "10"},
                payload=messaging.APNSPayload(aps=messaging.Aps(
                    alert=messaging.ApsAlert(title="MiChiami richiesto"),
                    sound=messaging.CriticalSound(name="alarm.caf",
                                                  critical=True, volume=1.0),
                )),
            ),
        )
        messaging.send(msg)
        return True
    except Exception as exc:
        log.error("Errore invio push: %s", exc)
        return False
