import subprocess
import sys


def test_refinement_map_covers_python_and_tla_names():
    result = subprocess.run([sys.executable, "tools/check_tla_refinement_map.py"],
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert '"mapped_transitions": 12' in result.stdout
