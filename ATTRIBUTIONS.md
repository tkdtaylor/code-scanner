# Attributions

Code Scanner is original work licensed under the PolyForm Noncommercial License 1.0.0
(see [LICENSE](LICENSE)). It incorporates ideas and publicly-known threat indicators
from the third-party sources below. No source code from these projects is copied into
this repository; the detection logic here is written independently for this skill.

## NVIDIA SkillSpector — agentic-skill threat taxonomy

- **Project:** https://github.com/NVIDIA/SkillSpector
- **License:** Apache License 2.0
- **What was used:** The *organisation* of agentic-skill threats that informed the
  categories added to `code-scanner/references/patterns.md` — trigger / activation
  abuse (9.6), excessive agency (9.7), tool misuse (9.8), memory poisoning (9.9),
  system-prompt leakage (9.10), rogue agent (9.11), and MCP server threats
  (Category 10). These are concepts and category names, not copyrighted expression;
  every detection pattern in this repo is an original grep-oriented expression, not
  copied from SkillSpector's Python source. Attribution is provided as a courtesy and
  for provenance.
- **Underlying frameworks:** These categories map to public industry taxonomies —
  the OWASP LLM Top 10 (LLM06 excessive agency, LLM07 system-prompt leakage), the
  OWASP Agentic Security Initiative (ASI02, ASI06, ASI10), and MITRE ATLAS
  (AML.T0080).

## Neo23x0/signature-base — malware indicators

- **Project:** https://github.com/Neo23x0/signature-base
- **License:** Detection Rule License (DRL) 1.0/1.1
- **What was used:** Publicly-known cryptominer indicators (mining-pool domains,
  stratum protocol method names) in `patterns.md` Category 6, and web-shell
  indicators (dynamic-input-to-execution sinks) in Category 11. These are adapted
  as grep patterns; no YARA rule files were copied.
