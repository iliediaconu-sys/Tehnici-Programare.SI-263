from collections import Counter

import pytest

from arsenal.aparare.detector import suspecti
from arsenal.aparare.parse_auth import pe_ip


def test_pragul_taie():
    # numararea, pe date scrise de mana: 13 esecuri de la "a", 2 de la "b"
    esecuri = [{"ip": "a"}] * 13 + [{"ip": "b"}] * 2
    c = pe_ip(esecuri)
    assert c == Counter({"a": 13, "b": 2})
    # pragul taie unde trebuie
    assert suspecti(c, 10) == [("a", 13)]


def test_prag_invalid():
    with pytest.raises(ValueError):
        suspecti({}, 0)
