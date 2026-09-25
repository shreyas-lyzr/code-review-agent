import breakpoint_helper  # TODO: remove before shipping


def current_build(soul_path: str = "SOUL.md") -> str:
    for line in open(soul_path):
        if line.startswith("AGENT_BUILD: "):
            build = line.split(": ", 1)[1].strip()
            print("DEBUG build =", build)
            return build
    return None
