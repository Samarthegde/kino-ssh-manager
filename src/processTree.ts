import type { ProcessInfo } from "./store";

/**
 * Turning a flat `ps` listing into the tree it describes.
 *
 * Two things make this less trivial than a parent map. The listing is capped at
 * 500 rows, so a process's parent is very often not in it - those have to
 * surface as roots rather than vanish. And `ppid` comes off a live machine, so
 * a cycle (or a process that is its own parent) is possible; every walk here is
 * guarded so a malformed listing can't hang the panel.
 */

export interface TreeNode {
  proc: ProcessInfo;
  children: TreeNode[];
}

/** One rendered line: a process, how deep it sits, and whether it can fold. */
export interface TreeRow {
  proc: ProcessInfo;
  depth: number;
  hasChildren: boolean;
  /** Processes hidden underneath, when this row is collapsed. */
  hiddenCount: number;
}

export function buildTree(procs: ProcessInfo[]): TreeNode[] {
  const byPid = new Map<number, ProcessInfo>();
  for (const p of procs) byPid.set(p.pid, p);

  const childrenOf = new Map<number, ProcessInfo[]>();
  const roots: ProcessInfo[] = [];
  for (const p of procs) {
    // Self-parenting, or a parent that didn't make the 500-row cut: it's a root.
    if (p.ppid === p.pid || !byPid.has(p.ppid)) {
      roots.push(p);
    } else {
      const siblings = childrenOf.get(p.ppid);
      if (siblings) siblings.push(p);
      else childrenOf.set(p.ppid, [p]);
    }
  }

  const placed = new Set<number>();
  const build = (proc: ProcessInfo): TreeNode => {
    placed.add(proc.pid);
    const kids = childrenOf.get(proc.pid) ?? [];
    return {
      proc,
      // The guard that makes a ppid cycle finite instead of fatal.
      children: kids.filter((k) => !placed.has(k.pid)).map(build),
    };
  };

  const tree = roots.map(build);
  // Anything left is part of a cycle with no root; show it rather than drop it.
  for (const p of procs) {
    if (!placed.has(p.pid)) tree.push(build(p));
  }
  return tree;
}

/** Sort siblings at every level by the same comparator used for the flat table. */
export function sortTree(nodes: TreeNode[], cmp: (a: ProcessInfo, b: ProcessInfo) => number): TreeNode[] {
  return [...nodes]
    .sort((a, b) => cmp(a.proc, b.proc))
    .map((n) => ({ proc: n.proc, children: sortTree(n.children, cmp) }));
}

/**
 * Keep matching processes *and their ancestors*.
 *
 * Dropping the ancestors would leave matches floating with no indication of
 * what spawned them, which is the one thing the tree view is for.
 */
export function filterTree(nodes: TreeNode[], match: (p: ProcessInfo) => boolean): TreeNode[] {
  const out: TreeNode[] = [];
  for (const node of nodes) {
    const children = filterTree(node.children, match);
    if (children.length > 0 || match(node.proc)) {
      out.push({ proc: node.proc, children });
    }
  }
  return out;
}

function countDescendants(node: TreeNode): number {
  return node.children.reduce((n, c) => n + 1 + countDescendants(c), 0);
}

/** Depth-first walk into render rows, stopping at collapsed nodes. */
export function flattenTree(nodes: TreeNode[], collapsed: Set<number>): TreeRow[] {
  const rows: TreeRow[] = [];
  const walk = (node: TreeNode, depth: number) => {
    const hasChildren = node.children.length > 0;
    const isCollapsed = hasChildren && collapsed.has(node.proc.pid);
    rows.push({
      proc: node.proc,
      depth,
      hasChildren,
      hiddenCount: isCollapsed ? countDescendants(node) : 0,
    });
    if (!isCollapsed) for (const child of node.children) walk(child, depth + 1);
  };
  for (const node of nodes) walk(node, 0);
  return rows;
}
