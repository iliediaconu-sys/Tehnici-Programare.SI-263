from arsenal.privesc.diferenta import noi_fata_de_baza


def test_doar_ce_e_nou():
    acum = {"a", "b", "c"}
    baza = {"a", "b"}
    assert acum - baza == {"c"}
    assert noi_fata_de_baza(acum, baza) == {"c"}
