"""Which tool calls need a human before they run."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Names, not descriptions. A scanner can read prose and guess intent; a gate
# runs on the hot path and must decide in microseconds, so it looks at the
# only thing it can trust: the name the server registered.
_SENSITIVE = (
    r"(?:^|_)(?:write|edit|create|delete|remove|drop|truncate|append|upload|"
    r"move|rename|chmod|chown|exec|execute|run|shell|spawn|install|push|"
    r"merge|publish|send|post|transfer|pay|refund)(?:_|$|[A-Z])"
)

DEFAULT_REQUIRE = (re.compile(_SENSITIVE),)


def _snake(name: str) -> str:
    """writeFile -> write_file, so one pattern covers both naming styles."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


@dataclass(frozen=True)
class Policy:
    """A list of name patterns that must be approved, and an allow-list."""

    require: tuple[re.Pattern[str], ...] = DEFAULT_REQUIRE
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()

    def requires_approval(self, tool: str) -> bool:
        if tool in self.allow:
            return False
        normalised = _snake(tool)
        return any(pattern.search(normalised) for pattern in self.require)

    def is_denied(self, tool: str) -> bool:
        """Denied tools are refused outright: no approval can unlock them."""
        return tool in self.deny

    @classmethod
    def default(cls) -> Policy:
        return cls()

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        patterns = tuple(re.compile(p) for p in raw.get("require_approval_patterns", []))
        return cls(
            require=patterns or DEFAULT_REQUIRE,
            allow=tuple(raw.get("allow", [])),
            deny=tuple(raw.get("deny", [])),
        )


@dataclass
class Rules:
    """Everything a gate needs to know, in one object."""

    policy: Policy = field(default_factory=Policy.default)
