"""diferenta.py - SUID aparute fata de o instalare curata.

Rulare din radacina depozitului:
    python -m arsenal.privesc.diferenta
"""
import os

from arsenal.privesc.enum import citeste_linii, nume, GTFO

START = os.path.join(os.path.dirname(__file__), "start")


# ---------- B1: doua multimi ----------
def cai(fisier):
    """MULTIMEA cailor din fisier (dublurile dispar)."""
    return set(citeste_linii(fisier))


# ---------- B2 + B3 ----------
def noi_fata_de_baza(acum, baza):
    """Ce e in 'acum' si nu e in 'baza': un singur operator, nu bucla dubla."""
    return acum - baza


def main():
    baza = cai(os.path.join(START, "baza_suid.txt"))
    acum = cai(os.path.join(START, "suid.txt"))
    print("baza:", len(baza), " acum:", len(acum))

    noi = noi_fata_de_baza(acum, baza)
    print(len(noi), "SUID noi fata de sistemul curat")
    for c in sorted(noi):
        print(" ", c)

    risc = {nume(c): ("mare" if nume(c) in GTFO else "normal") for c in noi}   # dict comprehension
    periculoase = [c for c in sorted(noi) if nume(c) in GTFO]                   # list comprehension cu if
    print("risc:", dict(sorted(risc.items())))
    print("periculoase NOI:", periculoase)


if __name__ == "__main__":
    main()
