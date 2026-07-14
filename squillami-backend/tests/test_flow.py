"""Test end-to-end del backend (senza Twilio né Firebase reali)."""
import os
import sys
import tempfile

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["SECRET_KEY"] = "test-secret"
os.environ.pop("TWILIO_AUTH_TOKEN", None)   # firma disattivata nei test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402
from app import db  # noqa: E402

client = TestClient(app)
db.init_db()


def register(code="123456", name="Andrea"):
    return client.post("/v1/register", json={"name": name, "code": code})


def test_register_and_duplicate_code():
    r = register()
    assert r.status_code == 200
    assert "api_token" in r.json()
    r2 = register(name="Altro")            # stesso codice -> rifiutato
    assert r2.status_code == 409


def test_register_bad_code():
    assert register(code="abc").status_code == 422      # troppo corto/non numerico
    assert register(code="12ab56").status_code == 400   # formato errato


def test_ivr_wrong_code_then_right():
    token = register(code="654321", name="B").json()["api_token"]
    h = {"Authorization": f"Bearer {token}"}
    client.put("/v1/devices/token", headers=h,
               json={"push_token": "fake-token", "platform": "android"})

    # Risposta iniziale dell'IVR
    r = client.post("/twilio/voice", data={"From": "+391110000"})
    assert r.status_code == 200 and "<Gather" in r.text

    # Codice sbagliato -> nuovo Gather
    r = client.post("/twilio/gather", data={"Digits": "000000", "From": "+391110000"})
    assert "non riconosciuto" in r.text

    # Codice giusto -> squillo + redirect allo status
    r = client.post("/twilio/gather", data={"Digits": "654321", "From": "+391110000"})
    assert "Codice corretto" in r.text and "/twilio/status" in r.text

    # L'evento esiste ed è in stato ringing
    ev = client.get("/v1/events", headers=h).json()["events"]
    assert ev and ev[0]["status"] == "ringing"
    event_id = ev[0]["id"]

    # Prima dello status: l'app carica la posizione (come farebbe il telefono)
    r = client.post("/v1/locations", headers=h,
                    json={"lat": 41.9028, "lon": 12.4964, "accuracy_m": 8,
                          "battery": 74, "event_id": event_id})
    assert r.status_code == 200

    # Lo status ora annuncia la posizione (indirizzo o coordinate)
    r = client.post(f"/twilio/status?event_id={event_id}")
    assert "squillando" in r.text and "<Hangup/>" in r.text

    # Evento marcato come localizzato
    ev = client.get("/v1/events", headers=h).json()["events"]
    assert ev[0]["status"] == "located"


def test_status_without_location_retries_then_fallback():
    token = register(code="777777", name="C").json()["api_token"]
    h = {"Authorization": f"Bearer {token}"}
    client.post("/twilio/gather", data={"Digits": "777777", "From": "+39222"})
    ev_id = client.get("/v1/events", headers=h).json()["events"][0]["id"]

    # Nessuna posizione: i primi tentativi devono mettere in attesa
    r = client.post(f"/twilio/status?event_id={ev_id}&try=1")
    assert "Pause" in r.text
    # Al quarto tentativo, nessuna posizione mai inviata -> messaggio di cortesia
    r = client.post(f"/twilio/status?event_id={ev_id}&try=4")
    assert "non è stato possibile" in r.text


def test_rate_limiting_per_caller():
    caller = "+39999"
    for _ in range(5):
        client.post("/twilio/gather", data={"Digits": "111111", "From": caller})
    r = client.post("/twilio/gather", data={"Digits": "111111", "From": caller})
    assert "Troppi tentativi" in r.text


def test_api_requires_token():
    r = client.post("/v1/locations", json={"lat": 1, "lon": 2})
    assert r.status_code == 401
