from enum import Enum

class StatusEnum(str, Enum):
    """Standard status values"""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"