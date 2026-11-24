"""enum.py - enumerare spre root din capturi (SUID, sudo, cron).

Rulare din radacina depozitului:
    python -m arsenal.privesc.enum arsenal/privesc/start
    python -m arsenal.privesc.enum arsenal/privesc/start --json
    python -m arsenal.privesc.enum arsenal/privesc/start --risc mare
    python -m arsenal.privesc.enum arsenal/privesc/start --grupare
"""
import argparse
import json
import os

# Multime (set): verificarea "nume in GTFO" e O(1) si nu are dubluri.
GTFO = {"find", "vim.basic", "vim", "nmap", "cp", "bash",
        "less", "awk", "python3", "perl"}


# ---------- A1: lista de linii curate ----------
def citeste_linii(cale):
    """Lista liniilor fara spatii la capete, fara goale si fara comentarii.
    Lista, nu multime: pastreaza ordinea si dublurile, exact ca in captura."""
    with open(cale, encoding="utf-8") as f:
        return [ln.strip() for ln in f
                if ln.strip() and not ln.strip().startswith("#")]


# ---------- A2: numele fisierului ----------
def nume(cale):
    """Ce e dupa ultimul '/': '/usr/bin/find' -> 'find'."""
    return cale.rsplit("/", 1)[-1]


# ---------- A3: constatarile SUID ----------
def suid_constatari(cale):
    """Lista de dictionare, cate unul pe cale UNICA, in ordine sortata."""
    cai = citeste_linii(cale)
    return [
        {"cale": c,
         "nume": nume(c),
         "risc": "mare" if nume(c) in GTFO else "normal"}
        for c in sorted(set(cai))          # set -> fara dubluri, sorted -> ordine
    ]


# ---------- A4: sudo si cron ----------
def sudo_constatari(cale):
    out = []
    for ln in citeste_linii(cale):
        user, drept = ln.split(" : ", 1)   # despachetare in tuplu
        out.append({"user": user.strip(),
                    "drept": drept.strip(),
                    "risc": "mare" if "NOPASSWD" in drept else "normal"})
    return out


def cron_constatari(cale):
    out = []
    for ln in citeste_linii(cale):
        campuri = ln.split()               # split() fara argument trateaza si TAB-urile
        user = campuri[5]                  # 5 campuri de program (0..4), apoi userul
        comanda = " ".join(campuri[6:])
        out.append({"user": user, "comanda": comanda})
    return out


def enumereaza(d):
    """Dictionar: categorie -> lista ei de constatari."""
    return {
        "suid": suid_constatari(os.path.join(d, "suid.txt")),
        "sudo": sudo_constatari(os.path.join(d, "sudo.txt")),
        "cron": cron_constatari(os.path.join(d, "crontab.txt")),
    }


# ---------- Optional 1: doar riscul mare ----------
def filtreaza_risc(raport, nivel):
    """Pastreaza doar constatarile cu riscul cerut, din toate categoriile.
    .get: intrarile cron nu au cheia 'risc'."""
    return {cat: [c for c in lista if c.get("risc") == nivel]
            for cat, lista in raport.items()}


# ---------- Optional 3: grupare dupa risc ----------
def grupeaza_dupa_risc(raport):
    """risc -> lista de etichete, din toate categoriile deodata."""
    grupe = {}
    for cat, lista in raport.items():
        for c in lista:
            eticheta = c.get("nume") or c.get("drept") or c.get("comanda")
            grupe.setdefault(c.get("risc", "necunoscut"), []).append(f"{cat}: {eticheta}")
    return grupe


# ---------- A5: raportul ----------
def main():
    p = argparse.ArgumentParser(description="Enumerare spre root din capturi.")
    p.add_argument("capturi", help="folderul cu suid.txt, sudo.txt, crontab.txt")
    p.add_argument("--json", action="store_true", help="scoate raportul JSON pe ecran")
    p.add_argument("--risc", choices=["mare", "normal"],
                   help="pastreaza doar constatarile cu acest risc")
    p.add_argument("--grupare", action="store_true",
                   help="afiseaza constatarile grupate dupa risc")
    a = p.parse_args()

    raport = enumereaza(a.capturi)
    if a.risc:
        raport = filtreaza_risc(raport, a.risc)

    if a.json:
        print(json.dumps(raport, indent=2, ensure_ascii=False))
        return

    if a.grupare:
        for risc, etichete in grupeaza_dupa_risc(raport).items():
            print(f"{risc}:")
            for e in etichete:
                print("  ", e)
        return

    for categorie, lista in raport.items():
        mari = [c for c in lista if c.get("risc") == "mare"]
        print(f"{categorie}: {len(lista)} gasite, {len(mari)} cu risc mare")

    # reuniunea multimilor: userii din sudo | userii din cron
    useri = ({c["user"] for c in raport["sudo"]}
             | {c["user"] for c in raport["cron"]})
    print("utilizatori implicati:", ", ".join(sorted(useri)))

    # langa enum.py (arsenal/privesc/enum.json), oricare ar fi folderul curent
    iesire = os.path.join(os.path.dirname(os.path.abspath(__file__)), "enum.json")
    with open(iesire, "w", encoding="utf-8") as f:
        json.dump(raport, f, indent=2, ensure_ascii=False)
    print("Raport salvat in enum.json")


if __name__ == "__main__":
    main()
