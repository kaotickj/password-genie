import ast
import re
import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
module = ast.parse((root / 'vault_core.py').read_text())
version = next(ast.literal_eval(node.value) for node in module.body
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'VERSION' for t in node.targets))
android = (root / 'android/app/build.gradle').read_text()
if len(sys.argv) != 2 or sys.argv[1] != f'v{version}':
    raise SystemExit(f'Release tag must be v{version}')
if re.search(r"versionName '([^']+)'", android).group(1) != version:
    raise SystemExit('Android and desktop versions must match')
print(f'Release version verified: {version}')
