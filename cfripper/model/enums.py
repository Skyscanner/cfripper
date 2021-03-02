from enum import Enum


class RuleMode(str, Enum):
    # Rule modes
    BLOCKING = "BLOCKING"
    MONITOR = "MONITOR"
    DEBUG = "DEBUG"
    ALLOWED = "ALLOWED"
    DISABLED = "DISABLED"


class RuleRisk(str, Enum):
    # Rule risk severity
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RuleGranularity(str, Enum):
    # Rule
    ACTION = "ACTION"
    RESOURCE = "RESOURCE"
    STACK = "STACK"
