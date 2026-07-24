#!/usr/bin/env python3
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
plugin = root / "Plugin" / "prefunk"
manifest = json.loads((plugin / ".codex-plugin" / "plugin.json").read_text())

assert manifest["name"] == plugin.name
assert manifest["version"] == "0.1.0"
assert manifest["skills"] == "./skills/"
assert "mcpServers" not in manifest
assert not (plugin / ".mcp.json").exists()

skill_path = plugin / "skills" / "prefunk-security-preflight" / "SKILL.md"
text = skill_path.read_text()
assert text.startswith("---\n")
frontmatter = text.split("---", 2)[1]
assert f"name: {skill_path.parent.name}" in frontmatter
assert "description:" in frontmatter and "Prefunk" in frontmatter
assert "[TODO:" not in text

launcher = (plugin / "scripts" / "prefunk-scan").read_text()
assert "/Applications/Prefunk.app/Contents/Resources/prefunk" in launcher
assert "command -v prefunk" not in launcher
assert "PREFUNK_ALLOW_DEV_OVERRIDE" in launcher

print("Plugin invariants passed: manifest, skill, no MCP, trusted launcher.")
