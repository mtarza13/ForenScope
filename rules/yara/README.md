# YARA rules (local-only)

EviForge will scan evidence copies using rules from this folder by default:

- Repo path: `rules/yara/`
- Docker path (inside containers): `/app/rules/yara`

You can also override with `EVIFORGE_YARA_RULES_DIR`.

Notes:
- Keep rules **defensive** and scoped to your investigation authorization.
- EviForge never uploads evidence or calls cloud services.
