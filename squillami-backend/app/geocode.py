"""Reverse geocoding con Nominatim (OpenStreetMap), gratuito.

Nota: per un uso pubblico ad alto volume servirebbe una istanza propria o
Google Geocoding; per l'MVP il servizio pubblico con user-agent corretto basta.
"""
import logging
import urllib.parse
import urllib.request
import json

log = logging.getLogger("squillami.geocode")


def reverse(lat: float, lon: float, timeout: float = 5.0) -> str | None:
    """Ritorna un indirizzo leggibile, o None se non disponibile."""
    try:
        url = ("https://nominatim.openstreetmap.org/reverse?format=jsonv2&" +
               urllib.parse.urlencode({"lat": lat, "lon": lon, "accept-language": "it"}))
        req = urllib.request.Request(url, headers={"User-Agent": "MiChiamiApp/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
        return data.get("display_name")
    except Exception as exc:
        log.warning("Reverse geocoding fallito: %s", exc)
        return None
