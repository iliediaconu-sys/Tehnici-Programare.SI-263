"""parse_auth.py - scoate esecurile de autentificare din auth.log si le numara pe IP.

Rulare din radacina depozitului:
    python -m arsenal.aparare.parse_auth arsenal/aparare/start/auth.log
"""
import argparse
import re
from collections import Counter
from datetime import datetime

TIPAR = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")


# ---------- A1: o functie care intoarce o fisa ----------
def esec(linie):
    """(user, ip) daca randul e un esec de autentificare, altfel None.
    None nu e o eroare: inseamna doar "aici nu e nimic de raportat"."""
    m = TIPAR.search(linie)
    if m is None:
        return None
    return (m.group(1), m.group(2))


def timp(linie):
    """Ora de la inceputul randului ('Jan 10 03:12:19') ca datetime, sau None
    daca randul e stricat. Folosita de optiunea --fereastra din detector."""
    try:
        return datetime.strptime(linie[:15], "%b %d %H:%M:%S")
    except ValueError:
        return None


# ---------- A2: lista de esecuri, robusta ----------
def citeste_esecuri(cale):
    """Lista de dictionare {"user", "ip", "timp"}, cate unul pe esec.
    Randurile care nu sunt esecuri (sau sunt stricate) sunt sarite."""
    esecuri = []
    try:
        f = open(cale, encoding="utf-8")
    except FileNotFoundError:
        print("nu gasesc", cale)
        return esecuri
    with f:
        for linie in f:
            r = esec(linie)
            if r is not None:
                esecuri.append({"user": r[0], "ip": r[1], "timp": linie[:15]})
    return esecuri


# ---------- A3: numararea pe IP ----------
def pe_ip(esecuri):
    """Counter: de cate ori apare fiecare adresa IP in esecuri."""
    return Counter(e["ip"] for e in esecuri)


# ---------- A4: rezumatul ----------
def rezumat(esecuri, counts):
    """Intoarce randurile rezumatului (nu le tipareste)."""
    randuri = [f"Esecuri de autentificare: {len(esecuri)}"]
    randuri += [f"  {ip}: {n}" for ip, n in counts.most_common()]
    return randuri


def main():
    p = argparse.ArgumentParser(description="Esecurile de autentificare din auth.log.")
    p.add_argument("log", help="calea catre auth.log")
    a = p.parse_args()

    esecuri = citeste_esecuri(a.log)
    for r in rezumat(esecuri, pe_ip(esecuri)):
        print(r)


if __name__ == "__main__":
    main()
