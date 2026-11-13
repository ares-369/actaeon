from actaeon.hunt.attack_names import check, data_components, name, tactics, version


def test_dataset_loaded():
    assert version() and name("T1059.001") == "PowerShell"
    assert "execution" in tactics("T1059.001")
    assert data_components("T1003.001")


def test_check_follows_replacements_and_rejects_unknown():
    good, notes = check(["T1059.001", "t1003.001", "T1070.001", "T9999", "X1", "T1059.001"])
    assert good[:2] == ["T1059.001", "T1003.001"]
    assert any("replaced by" in n for n in notes) and len(good) == 3   # T1070.001 -> its replacement
    assert any("does not exist" in n for n in notes) and any("not an ATT&CK" in n for n in notes)


def test_starters_use_current_ids():
    from actaeon.hunt.library import starters
    ids = [t for s in starters() for t in s["attack"]]
    assert check(ids)[1] == []
