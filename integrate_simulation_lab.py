"""Safely add Simulation Lab navigation to the existing root app.py."""
from datetime import datetime
from pathlib import Path
import shutil
import sys

app_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("app.py")
if not app_path.exists():
    raise SystemExit(f"Could not find {app_path.resolve()}. Run this script from the project root or pass the app.py path.")

source = app_path.read_text(encoding="utf-8")
original = source

import_anchor = "from soc_demo.graph import run_alert_through_pipeline"
import_line = "from soc_demo.simulation_lab import show_simulation_lab"
nav_old = '["Alert Dashboard", "Case Review", "Approval Queue", "System Status"]'
nav_new = '["Alert Dashboard", "Simulation Lab", "Case Review", "Approval Queue", "System Status"]'
dispatch_anchor = '    elif page == "Case Review":\n        show_case_review()'
dispatch_new = '    elif page == "Simulation Lab":\n        show_simulation_lab(lambda alert: get_or_create_case(alert, run_alert_through_pipeline(alert)))\n    elif page == "Case Review":\n        show_case_review()'

if import_line not in source:
    if import_anchor not in source:
        raise SystemExit(f"Import anchor not found in {app_path}; source unchanged.")
    source = source.replace(import_anchor, import_anchor + "\n" + import_line, 1)

if nav_new not in source:
    if nav_old not in source:
        raise SystemExit(f"Navigation anchor not found in {app_path}; source unchanged.")
    source = source.replace(nav_old, nav_new, 1)

if 'show_simulation_lab(lambda alert: get_or_create_case(alert, run_alert_through_pipeline(alert)))' not in source:
    if dispatch_anchor not in source:
        raise SystemExit(f"Page-dispatch anchor not found in {app_path}; source unchanged.")
    source = source.replace(dispatch_anchor, dispatch_new, 1)

if source == original:
    print("Simulation Lab integration already present; no changes made.")
    raise SystemExit(0)

backup = app_path.with_name(f"{app_path.stem}.backup-before-simulation-lab-{datetime.now():%Y%m%d-%H%M%S}{app_path.suffix}")
shutil.copy2(app_path, backup)
app_path.write_text(source, encoding="utf-8")
print(f"Simulation Lab integrated into {app_path.resolve()}")
print(f"Backup: {backup.resolve()}")
print("No other app logic was intentionally changed.")
