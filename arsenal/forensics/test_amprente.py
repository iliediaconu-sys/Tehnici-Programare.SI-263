import os

from arsenal.forensics.amprente import amprenta_fisier, scaneaza, tip

PROBE = os.path.join(os.path.dirname(__file__), "probe")


def test_tip_din_magic():
    assert tip(b"\x89PNG") == "PNG"
    assert tip(b"%PDF-1.4") == "PDF"
    assert tip(b"text") == "necunoscut"


def test_amprenta_png():
    r = amprenta_fisier(os.path.join(PROBE, "imagine.png"))
    assert r["tip"] == "PNG"
    assert r["sha256"] == "ea3a9848da7e6c1d"


def test_scaneaza_toate():
    rez = scaneaza(PROBE)
    assert len(rez) == 4
    assert [f["nume"] for f in rez] == ["arhiva.zip", "imagine.png", "note.txt", "raport.pdf"]
