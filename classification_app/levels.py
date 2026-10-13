from enum import IntEnum


class Level(IntEnum):
    UNCLASS = 0
    CONFIDENTIAL = 1
    SECRET = 2
    TOP_SECRET = 3


LABELS = {
    Level.UNCLASS: "UNCLASSIFIED",
    Level.CONFIDENTIAL: "CONFIDENTIAL // NOFORN",
    Level.SECRET: "SECRET // NOFORN",
    Level.TOP_SECRET: "TOP SECRET // NOFORN",
}

COLORS = {
    Level.UNCLASS: "#66b97e",
    Level.CONFIDENTIAL: "#3971b5",
    Level.SECRET: "#c01c28",
    Level.TOP_SECRET: "#e66100",
}


def parse_level(value: str | int | Level) -> Level:
    if isinstance(value, Level):
        return value
    if isinstance(value, int):
        return Level(value)
    normalized = value.strip().upper().replace("-", "_").replace(" ", "_")
    if normalized == "TOPSECRET":
        normalized = "TOP_SECRET"
    return Level[normalized]
