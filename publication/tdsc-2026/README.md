# BlueRange TDSC 2026 reproducibility release

BlueRange is an open-source benchmark for evaluating autonomous LLM cyber defenders under explicit authority constraints. This curated publication-data release accompanies **“BlueRange: Evaluating the Safety–Effectiveness Trade-off of Autonomous LLM Cyber Defenders.”**

It contains machine-readable aggregate results, data definitions, provenance and deterministic table-regeneration material. It does **not** publish the manuscript, the full private research archive, private execution infrastructure, credentials, raw provider responses or unnecessary evaluator-only material.

BlueRange public software release: `v0.1.0`
Commit: `558a2f99518f4a205f44862e1b3db5e7ad245d9e`
Repository: https://github.com/san3ncrypt3d/BlueRange

The aggregate counts are curated from the authenticated final remediated evidence package. The included JSON/CSV files store reported aggregate results directly; percentages and grouped table views are deterministically derived from those counts. No experiments or models were rerun to create this release.

Run the deterministic summary (no providers or network required):

```bash
python3 publication/tdsc-2026/scripts/regenerate_tables.py
```

Qwen and Sonnet execution remains provider/runtime-dependent and may not be byte-identical across reruns.
