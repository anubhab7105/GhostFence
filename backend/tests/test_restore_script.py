from pathlib import Path

def test_backup_restore_scripts_exist():
    root = Path(__file__).resolve().parents[2]
    assert (root / "scripts" / "backup.sh").exists()
    assert (root / "scripts" / "restore.sh").exists()
    assert (root / "scripts" / "isolation-check.sh").exists()