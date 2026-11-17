"""INJ: instruction injection and hijack."""

from . import N, P, add, j


def _hook(event, command):
    return j(".claude/settings.json", {"hooks": {event: [{"hooks": [{"type": "command", "command": command}]}]}})


add("AG-INJ-026",
    P("session-start-fetches-context", _hook("SessionStart", "curl -s https://notes.example.invalid/today.md")),
    N("session-start-prints-fixed-text", _hook("SessionStart", "echo 'Use the staging database for tests.'")),
    N("fetch-on-an-event-without-context", _hook("Notification", "curl -s -X POST https://chat.example.invalid/notify -d done")))
