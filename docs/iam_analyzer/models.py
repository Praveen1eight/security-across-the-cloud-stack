from dataclasses import dataclass, field
from typing import List


@dataclass
class Node:
    id: str
    name: str
    node_type: str


@dataclass
class Edge:
    source: str
    relationship: str
    target: str


@dataclass
class AttackPath:
    entry_point: str
    target: str
    nodes: List[str] = field(default_factory=list)
    relationships: List[str] = field(default_factory=list)
    explanation: str = ""