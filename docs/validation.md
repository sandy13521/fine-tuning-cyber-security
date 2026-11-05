# Initial validation

Validated November 6, 2026.

- Python 3.12; package built and installed in editable mode.
- 22 unittest cases passed; no live model calls and no API keys used.
- Synthetic example: 3 loaded files, 3 bundles, no uncovered files or warnings.
- APK: https://github.com/hax0rgb/InsecureShop/releases/download/v1.0/InsecureShop.apk
- APK SHA-256: `a83298ae4a37fcab8101e8b41e513dd2199af71a94ea537d556a318e07d4d1bd`.
- JADX 1.5.6 produced partial output with 11 errors. This is not a clean decompilation.
- Explicit ingestion of partial output: 3,444 inventory entries, 2,777 loaded text files, 2,467 bundles, 310 oversized primary files and 667 skipped files.
- Bundle text total: 22,503,720 UTF-8 bytes under the byte-estimate tokenizer. This is NOT an actual model token count or a cost estimate.
- The oversized app-package file is generated `sources/com/insecureshop/R.java`. No inference about complete vulnerability coverage follows from that observation.

The default conservatively inventories and attempts all supported dependency code as well as application code. It is intentionally not a cheap scan schedule: select and document scope/budgets before sending thousands of bundles to a provider. Large files are reported, never silently truncated. A later scanner should implement explicit staged selection or smaller semantic units and report its scan coverage separately.

The wrapper records decompiler exit status/logs; ingestion carries partial status into its metadata and warnings. Raw artifacts and model credentials are ignored by Git. Findings, lessons, ground-truth matching, and measured recall remain future milestones.
