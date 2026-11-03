from __future__ import annotations

from pathlib import Path
from typing import Any


class Har2TreeAdapterError(RuntimeError):
    """har2tree was unable to construct a usable tree."""


def build_har2tree(har_path: Path, scan_id: str) -> dict[str, Any]:
    """Build a stable, compact graph from har2tree's public tree objects."""
    try:
        from har2tree import CrawledTree, Har2TreeError

        crawled = CrawledTree([Path(har_path)], scan_id)
        root = crawled.root_hartree.url_tree
        nodes = list(root.traverse("preorder"))
        stable_ids = {id(node): f"url-node-{index:06d}" for index, node in enumerate(nodes, 1)}
        serialized_nodes = []
        edges = []
        for node in nodes:
            serialized_nodes.append({
                "id": stable_ids[id(node)],
                "url": str(node.name),
                "hostname": str(node.hostname) if getattr(node, "hostname", None) else None,
                "mime_type": str(node.mimetype) if getattr(node, "mimetype", None) else None,
            })
            for child in node.children:
                edges.append({"source": stable_ids[id(node)],
                              "target": stable_ids[id(child)],
                              "relation": "har2tree_parent"})
        return {
            "root_id": stable_ids[id(root)],
            "nodes": serialized_nodes,
            "edges": edges,
            "redirect_chain": list(crawled.redirects),
        }
    except Exception as exc:
        raise Har2TreeAdapterError(f"har2tree failed: {exc}") from exc
