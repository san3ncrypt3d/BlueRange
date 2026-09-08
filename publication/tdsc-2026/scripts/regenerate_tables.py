#!/usr/bin/env python3
"""Read-only deterministic summary of released canonical_results.json."""
import json, pathlib
p=pathlib.Path(__file__).parents[1]/"data"/"canonical_results.json"
d=json.loads(p.read_text())
for scope, rows in d.items():
 print(f"[{scope}]")
 if isinstance(rows,dict):
  for k,v in rows.items(): print(k, json.dumps(v, sort_keys=True) if isinstance(v,dict) else v)
