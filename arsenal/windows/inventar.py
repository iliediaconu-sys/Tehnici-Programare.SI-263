"""inventar.py - procesele si evenimentele unei masini Windows, ca obiecte.

Rulare din radacina depozitului:
    python -m arsenal.windows.inventar arsenal/windows/start
    python -m arsenal.windows.inventar arsenal/windows/start --json
    python -m arsenal.windows.inventar arsenal/windows/start --explica
"""
import argparse
import json
from dataclasses import asdict, dataclass

# Cai din folderul utilizatorului: un program normal nu ruleaza de acolo.
CAI_SUSPECTE = ("\\Temp\\", "\\Roaming\\")

# 4625 logon esuat, 1102 jurnal sters, 7045 serviciu instalat
SUSPECTE_ID = {4625, 1102, 7045}

EXPLICATII = {
    4625: "logon esuat - posibil brute force",
    1102: "jurnalul de audit a fost sters - cineva isi acopera urmele",
    7045: "serviciu nou instalat - posibila persistenta",
}


# ---------- A1 + A2: clasa Proces ----------
@dataclass
class Proces:
    pid: int
    nume: str
    user: str
    cale: str

    def e_suspect(self):
        """True daca procesul ruleaza din Temp sau Roaming."""
        return any(c in self.cale for c in CAI_SUSPECTE)


# ---------- A3: clasa Eveniment ----------
@dataclass
class Eveniment:
    id: int
    nivel: str
    sursa: str
    cont: str
    mesaj: str

    def e_suspect(self):
        """True daca ID-ul e unul de alarma sau nivelul e critical."""
        return self.id in SUSPECTE_ID or self.nivel == "critical"

    # Optional 2
    def explica(self):
        """Un text scurt pentru ID-urile cunoscute."""
        return EXPLICATII.get(self.id, "fara explicatie")


# ---------- A4: din JSON in obiecte ----------
def procese_din_json(cale):
    with open(cale, encoding="utf-8") as f:
        return [Proces(**d) for d in json.load(f)]


def evenimente_din_json(cale):
    with open(cale, encoding="utf-8") as f:
        return [Eveniment(**d) for d in json.load(f)]


# ---------- B1 + B2: clasa-container Inventar ----------
@dataclass
class Inventar:
    procese: list

    @classmethod
    def din_json(cls, cale):
        """Constructor alternativ: umple inventarul dintr-un fisier JSON."""
        with open(cale, encoding="utf-8") as f:
            return cls([Proces(**d) for d in json.load(f)])

    def __len__(self):
        return len(self.procese)

    def suspecte(self):
        """Procesele care se declara singure suspecte."""
        return [p for p in self.procese if p.e_suspect()]

    def pe_user(self):
        """Dictionar user -> lista de nume de procese."""
        grupe = {}
        for p in self.procese:
            grupe.setdefault(p.user, []).append(p.nume)
        return grupe

    # Optional 3
    def scor(self, evenimente):
        """Numarul de risc: procese suspecte + evenimente de alarma."""
        return len(self.suspecte()) + sum(1 for e in evenimente if e.e_suspect())


# ---------- B3: raportul ----------
def main():
    p = argparse.ArgumentParser(description="Inventar de procese si evenimente Windows.")
    p.add_argument("capturi", help="folderul cu procese.json si evenimente.json")
    p.add_argument("--json", action="store_true", help="scoate raportul JSON")
    p.add_argument("--explica", action="store_true", help="explica fiecare alarma")
    a = p.parse_args()

    inv = Inventar.din_json(a.capturi + "/procese.json")
    ev = evenimente_din_json(a.capturi + "/evenimente.json")
    alarma = [e for e in ev if e.e_suspect()]

    if a.json:
        raport = {"procese": len(inv),
                  "suspecte": [asdict(x) for x in inv.suspecte()],
                  "evenimente": len(ev),
                  "alarma": [asdict(e) for e in alarma],
                  "scor": inv.scor(ev)}
        print(json.dumps(raport, indent=2, ensure_ascii=False))
        return

    print(f"Procese: {len(inv)} | suspecte: {len(inv.suspecte())}")
    for x in inv.suspecte():
        print(f"  [{x.pid}] {x.nume} ({x.user}) {x.cale}")
    print(f"Evenimente: {len(ev)} | alarma: {len(alarma)}")
    for e in alarma:
        rand = f"  {e.id} [{e.nivel}] {e.cont}: {e.mesaj}"
        print(rand + (f"  -> {e.explica()}" if a.explica else ""))
    print(f"Scor de risc: {inv.scor(ev)}")


if __name__ == "__main__":
    main()
