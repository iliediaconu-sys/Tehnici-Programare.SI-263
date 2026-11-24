"""detector.py - detectorul de brute force, cu prag reglabil si raport JSON.

Rulare din radacina depozitului:
    python -m arsenal.aparare.detector arsenal/aparare/start/auth.log
    python -m arsenal.aparare.detector arsenal/aparare/start/auth.log --prag 2
    python -m arsenal.aparare.detector arsenal/aparare/start/auth.log --json
    python -m arsenal.aparare.detector arsenal/aparare/start/auth.log --fereastra 60
    python -m arsenal.aparare.detector arsenal/aparare/start/auth.log --top 1
"""
import argparse
import json
from collections import Counter

from arsenal.aparare.parse_auth import citeste_esecuri, pe_ip, rezumat, timp


# ---------- B1: suspecti, cu valoare implicita si validare ----------
def suspecti(counts, prag=10):
    """Lista de (ip, n) cu n >= prag, sortata descrescator dupa n.
    Un prag sub 1 nu are sens, asa ca il oprim la intrare cu raise."""
    if prag < 1:
        raise ValueError(f"prag invalid: {prag} (cel putin 1)")
    return sorted(((ip, n) for ip, n in counts.items() if n >= prag),
                  key=lambda x: x[1], reverse=True)


# ---------- Optional 1: fereastra de timp ----------
def in_fereastra(esecuri, secunde):
    """Pentru fiecare IP: cel mai mare numar de esecuri din orice interval
    de `secunde` secunde (un atac e dens in timp)."""
    if secunde < 1:
        raise ValueError(f"fereastra invalida: {secunde} (cel putin 1)")
    ore = {}
    for e in esecuri:
        t = timp(e["timp"])
        if t is not None:                       # randurile fara ora sunt sarite
            ore.setdefault(e["ip"], []).append(t)
    rezultat = Counter()
    for ip, lista in ore.items():
        lista.sort()
        start = 0
        for i, t in enumerate(lista):           # fereastra glisanta
            while (t - lista[start]).total_seconds() > secunde:
                start += 1
            rezultat[ip] = max(rezultat[ip], i - start + 1)
    return rezultat


# ---------- Optional 3: primele N adrese ----------
def top(counts, n):
    """Primele n adrese dupa numarul de esecuri."""
    return [(ip, k) for ip, k in counts.most_common(n)]


# ---------- B3: argparse si raportul ----------
def main():
    p = argparse.ArgumentParser(description="Detector de brute force din auth.log.")
    p.add_argument("log", help="calea catre auth.log")
    p.add_argument("--prag", type=int, default=10, help="esecuri minime pentru suspect (implicit 10)")
    p.add_argument("--json", action="store_true", help="scoate raportul JSON")
    p.add_argument("--fereastra", type=int, help="numara doar esecurile dintr-un interval de N secunde")
    p.add_argument("--top", type=int, help="arata doar primele N adrese")
    a = p.parse_args()

    esecuri = citeste_esecuri(a.log)
    counts = in_fereastra(esecuri, a.fereastra) if a.fereastra else pe_ip(esecuri)
    if a.top:
        counts = Counter(dict(top(counts, a.top)))
    try:
        sus = suspecti(counts, a.prag)
    except ValueError as err:
        p.error(str(err))                        # mesaj clar, fara traceback

    if a.json:
        raport = {"esecuri": esecuri, "pe_ip": dict(counts.most_common()),
                  "suspecti": [{"ip": ip, "incercari": n} for ip, n in sus]}
        print(json.dumps(raport, indent=2, ensure_ascii=False))
        return

    for r in rezumat(esecuri, counts):
        print(r)
    eticheta = f"prag {a.prag}" + (f", fereastra {a.fereastra}s" if a.fereastra else "")
    print(f"Suspecti ({eticheta}):")
    for ip, n in sus:
        print(f"  {ip} ({n} incercari) BRUTE FORCE")
    if not sus:
        print("  niciunul")


if __name__ == "__main__":
    main()
