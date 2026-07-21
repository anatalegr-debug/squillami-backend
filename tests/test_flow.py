"""Test end-to-end del backend (senza Twilio né Firebase reali).

Modello: il NUMERO identifica l'utente (univoco), il CODICE è libero.
"""
import os
import sys
import tempfile

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["SECRET_KEY"] = "test-secret"
os.environ.pop("TWILIO_AUTH_TOKEN", None)   # firma disattivata nei test
os.environ["POW_BITS"] = "0"                # proof-of-work disattivata nei test di flusso
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402
from app import db  # noqa: E402

client = TestClient(app)
db.init_db()


def register(phone="3401110001", code="1234", name="Andrea"):
    return client.post("/v1/register", json={"name": name, "phone": phone, "code": code})


def identify(phone, caller="+39555"):
    return client.post("/twilio/identify", data={"Digits": phone, "From": caller})


def enter_code(uid, code, caller="+39555"):
    return client.post(f"/twilio/gather?uid={uid}", data={"Digits": code, "From": caller})


def test_register_and_duplicate_phone():
    r = register(phone="3400000001", code="1234")
    assert r.status_code == 200 and "api_token" in r.json()
    # Stesso NUMERO -> rifiutato
    assert register(phone="3400000001", code="9999").status_code == 409


def test_same_code_different_phone_is_allowed():
    # Libertà di scelta: due utenti possono usare lo STESSO codice
    assert register(phone="3400000010", code="1111").status_code == 200
    assert register(phone="3400000011", code="1111").status_code == 200


def test_register_bad_input():
    assert register(phone="3400000020", code="ab").status_code == 422   # troppo corto
    assert register(phone="3400000021", code="12ab").status_code == 400  # non numerico
    assert register(phone="abcdef", code="1234").status_code == 400      # numero senza cifre


def test_ivr_two_step_flow():
    reg = register(phone="3491234567", code="4242", name="B").json()
    uid = reg["user_id"]
    h = {"Authorization": f"Bearer {reg['api_token']}"}
    client.put("/v1/devices/token", headers=h,
               json={"push_token": "fake", "platform": "ios"})

    # Voce iniziale -> chiede il numero
    assert "<Gather" in client.post("/twilio/voice", data={"From": "+39555"}).text

    # Numero sbagliato -> non riconosciuto
    assert "non riconosciuto" in identify("3400000099").text

    # Numero giusto -> riconosciuto, chiede il codice per QUESTO uid
    r = identify("3491234567")
    assert "riconosciuto" in r.text and f"uid={uid}" in r.text

    # Codice errato -> riprova
    assert "errato" in enter_code(uid, "0000").text

    # Codice giusto -> squillo + status
    r = enter_code(uid, "4242")
    assert "Codice corretto" in r.text and "/twilio/status" in r.text

    ev = client.get("/v1/events", headers=h).json()["events"]
    assert ev and ev[0]["status"] == "ringing"
    event_id = ev[0]["id"]
    client.post("/v1/locations", headers=h,
                json={"lat": 41.9, "lon": 12.5, "event_id": event_id})
    r = client.post(f"/twilio/status?event_id={event_id}")
    assert "squillando" in r.text and "<Hangup/>" in r.text


def test_sms_sent_with_last_location():
    reg = register(phone="3405550001", code="5678", name="D").json()
    h = {"Authorization": f"Bearer {reg['api_token']}"}
    client.post("/v1/locations", headers=h, json={"lat": 45.46, "lon": 9.19, "kind": "cached"})
    r = enter_code(reg["user_id"], "5678")
    assert "SMS con l'ultima posizione" in r.text


def test_status_fallback_without_location():
    reg = register(phone="3407770001", code="7777", name="C").json()
    enter_code(reg["user_id"], "7777")
    ev_id = client.get("/v1/events",
                       headers={"Authorization": f"Bearer {reg['api_token']}"}).json()["events"][0]["id"]
    assert "Pause" in client.post(f"/twilio/status?event_id={ev_id}&try=1").text
    assert "non è stato possibile" in client.post(f"/twilio/status?event_id={ev_id}&try=4").text


def test_rate_limiting_per_caller():
    caller = "+39888"
    for _ in range(5):
        identify("3400000099", caller=caller)   # numero inesistente = tentativo fallito
    assert "Troppi tentativi" in identify("3400000099", caller=caller).text


def test_api_requires_token():
    assert client.post("/v1/locations", json={"lat": 1, "lon": 2}).status_code == 401


def test_web_ring_success_and_find():
    reg = register(phone="3406660001", code="6060", name="W").json()
    h = {"Authorization": f"Bearer {reg['api_token']}"}
    client.post("/v1/locations", headers=h, json={"lat": 45.07, "lon": 7.69, "kind": "cached"})
    # Squillo dal web con numero + codice corretti
    r = client.post("/v1/ring", json={"phone": "3406660001", "code": "6060"})
    assert r.status_code == 200 and r.json()["ringing"] is True
    token = r.json()["find_token"]
    # La pagina legge la posizione dalla sessione
    r = client.get(f"/v1/find/{token}")
    assert r.status_code == 200 and r.json()["ready"] is True
    assert abs(r.json()["lat"] - 45.07) < 0.01


def test_web_ring_generic_error_and_lockout():
    register(phone="3406660002", code="1212", name="X")
    # Numero inesistente -> errore generico (niente enumerazione)
    r = client.post("/v1/ring", json={"phone": "3409999999", "code": "0000"})
    assert r.status_code == 401 and "non corretti" in r.json()["detail"]
    # 3 codici sbagliati -> account bloccato
    for _ in range(3):
        client.post("/v1/ring", json={"phone": "3406660002", "code": "9999"})
    r = client.post("/v1/ring", json={"phone": "3406660002", "code": "1212"})
    assert r.status_code == 423   # bloccato anche col codice giusto


def test_change_code():
    reg = register(phone="3402223334", code="1111", name="Z").json()
    h = {"Authorization": f"Bearer {reg['api_token']}"}
    # Cambio codice
    r = client.patch("/v1/code", headers=h, json={"code": "8899"})
    assert r.status_code == 200 and r.json()["updated"] is True
    # Il nuovo codice fa squillare, il vecchio no
    assert client.post("/v1/ring", json={"phone": "3402223334", "code": "8899"}).status_code == 200
    assert client.post("/v1/ring", json={"phone": "3402223334", "code": "1111"}).status_code == 401
    # Codice non valido rifiutato
    assert client.patch("/v1/code", headers=h, json={"code": "ab"}).status_code == 400
    # Senza token: 401
    assert client.patch("/v1/code", json={"code": "7777"}).status_code == 401


def test_delete_account_removes_everything():
    reg = register(phone="3409090001", code="9090", name="E").json()
    h = {"Authorization": f"Bearer {reg['api_token']}"}
    client.post("/v1/locations", headers=h, json={"lat": 44.0, "lon": 8.0, "kind": "cached"})
    r = client.delete("/v1/account", headers=h)
    assert r.status_code == 200 and r.json()["deleted"] is True
    assert client.get("/v1/events", headers=h).status_code == 401


def test_pow_roundtrip_and_tamper():
    """La proof-of-work: soluzione valida accettata, manomissioni rifiutate."""
    import hashlib
    from app import security as s
    orig = s.POW_BITS
    s.POW_BITS = 16
    try:
        now = 1700000000
        ch = s.make_pow(now)
        seed, ts, bits, sig = ch["seed"], ch["ts"], ch["bits"], ch["sig"]
        pref = "0" * (bits // 4)
        n = 0
        while not hashlib.sha256(f"{seed}.{ts}.{bits}.{n}".encode()).hexdigest().startswith(pref):
            n += 1
        assert s.verify_pow(seed, ts, bits, sig, str(n), now) is True       # valida
        assert s.verify_pow(seed, ts, bits, "bad", str(n), now) is False    # firma errata
        assert s.verify_pow(seed, ts, bits, sig, str(n + 1), now) is False  # nonce errato
        assert s.verify_pow(seed, ts, bits, sig, str(n), now + 10**5) is False  # scaduta
    finally:
        s.POW_BITS = orig
