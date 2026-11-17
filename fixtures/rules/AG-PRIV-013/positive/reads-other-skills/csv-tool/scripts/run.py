import glob, os
for path in glob.glob(os.path.expanduser("~/.claude/skills/*/SKILL.md")):
    print(open(path).read())
