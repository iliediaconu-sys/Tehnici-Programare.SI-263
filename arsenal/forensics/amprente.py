"""amprente.py - tipul fisierelor dupa primii octeti si amprenta lor SHA-256.

Rulare din radacina depozitului:
    python -m arsenal.forensics.amprente arsenal/forensics/probe
"""
import argparse
import hashlib
import os

# Semnaturile de la inceputul fisierelor (magic bytes)
MAGIC = {b"\x89PNG": "PNG", b"%PDF": "PDF", b"PK\x03\x04": "ZIP"}


# ---------- A1: tipul dupa magic bytes ----------
def tip(head):
    """Tipul fisierului dupa primii octeti."""
    for semnatura, nume in MAGIC.items():
        if head.startswith(semnatura):
            return nume
    return "necunoscut"          # DUPA bucla: abia dupa ce am verificat toate semnaturile


# ---------- A2: amprenta unui fisier, citit cu with ----------
def amprenta_fisier(cale):
    """Fisa unui fisier: nume, tip si primele 16 caractere din SHA-256."""
    with open(cale, "rb") as f:  # "rb" = citire binara; with inchide fisierul singur
        date = f.read()
    return {"nume": os.path.basename(cale),
            "tip": tip(date[:8]),
            "sha256": hashlib.sha256(date).hexdigest()[:16]}


# ---------- A3: tot folderul ----------
def scaneaza(folder):
    """Lista fiselor pentru toate fisierele din folder, in ordine alfabetica."""
    rez = []
    for nume in sorted(os.listdir(folder)):
        cale = os.path.join(folder, nume)
        if os.path.isfile(cale):
            rez.append(amprenta_fisier(cale))
    return rez


# ---------- Optional: generator cu yield ----------
def amprente_lenes(folder):
    """La fel ca scaneaza, dar da cate o fisa, la cerere, fara sa tina tot in memorie."""
    for nume in sorted(os.listdir(folder)):
        cale = os.path.join(folder, nume)
        if os.path.isfile(cale):
            yield amprenta_fisier(cale)


def main():
    p = argparse.ArgumentParser(description="Tipul si amprenta SHA-256 a fisierelor dintr-un folder.")
    p.add_argument("folder", help="folderul cu probe")
    a = p.parse_args()
    for f in scaneaza(a.folder):
        print(f"{f['nume']:14} {f['tip']:11} {f['sha256']}")


if __name__ == "__main__":
    main()
