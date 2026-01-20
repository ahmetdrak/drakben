import pathlib


def test_entrypoint_uses_refactored_agent():
    """Static check: ensure `drakben.py` imports RefactoredDrakbenAgent.

    This test does not execute the agent loop; it only checks the file
    contents to avoid running legacy code during CI.
    """
    p = pathlib.Path(__file__).parent.parent / "drakben.py"
    content = p.read_text(encoding="utf-8")
    assert "from core.refactored_agent import RefactoredDrakbenAgent" in content
