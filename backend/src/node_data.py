import threading

from dataclasses import dataclass
from typing import Optional, List


@dataclass
class StoredItem:
    hash: str
    data: str


@dataclass
class NodeData:
    addr: str
    stored_items: List[StoredItem]
    pred: Optional[str] = None
    succ: Optional[str] = None
    lock = threading.Lock()
