#!/usr/bin/env python3
"""
Módulo pequeño para generación automática de fragmentos/ejemplos de código
separado desde `piper_cli.py` para mantener el CLI más limpio.

Exporta `generate_code(prompt_text, file_path, ...) -> bool` que intenta
detectar patrones simples (delaunay, sorting, bfs/dfs, dijkstra/astar)
y escribe un archivo Python con una plantilla autocontenida. Devuelve True
si el archivo fue escrito.
"""
from __future__ import annotations
from pathlib import Path
from typing import Callable
import re

def generate_code(
    prompt_text: str,
    file_path: Path,
    *,
    search_web_func: Callable[[str, int], list] | None = None,
    research_urls_func: Callable[[list], str] | None = None,
    normalize_func: Callable[[str], str] | None = None,
    write_file_func: Callable[[Path, str], None] | None = None,
    auto_code: bool = True,
) -> bool:
    """Genera código basado en heurísticas simples.

    Parámetros opcionales permiten inyectar utilidades del CLI (búsqueda web,
    normalización, escritura de archivos) sin crear dependencias circulares.
    """
    if not auto_code:
        return False
    pt = (normalize_func(prompt_text) if normalize_func else (prompt_text or "")).lower()
    out = None

    algo_term = None
    keys = [
        "delaunay", "bfs", "dfs", "a*", "a star", "dijkstra",
        "quicksort", "merge sort", "mergesort", "astar", "k-means", "kmeans",
    ]
    for key in keys:
        if key.replace(" ", "") in pt.replace(" ", ""):
            algo_term = key
            break

    web_inspo = ""
    if algo_term and search_web_func and research_urls_func:
        try:
            q = f"python {algo_term} algorithm explanation"
            urls = search_web_func(q, max_results=3)[:2]
            if urls:
                web_inspo = research_urls_func(urls)
        except Exception:
            web_inspo = ""

    def _header(doc: str) -> str:
        if not web_inspo:
            return doc
        lines = ["# " + ln[:160] for ln in web_inspo.splitlines() if ln.strip()]
        if len(lines) > 15:
            lines = lines[:15]
        return doc + "\n# Contexto (resumen web, sin código literal):\n" + "\n".join(lines) + "\n"

    if algo_term and algo_term.startswith("delaunay"):
        out = _header(
            "#!/usr/bin/env python3\n" 
            "\"\"\"Triangulación de Delaunay - ejemplo autocontenido con matplotlib.\n\n" 
            "Requisitos: scipy, numpy, matplotlib (instálalos en tu venv).\n\"\"\"\n\n"
            "import numpy as np\n"
            "import matplotlib.pyplot as plt\n"
            "from scipy.spatial import Delaunay\n\n"
            "def demo_points():\n"
            "    return np.array([[1.0,1.0],[3.0,0.5],[5.0,4.0],[7.0,6.0],[2.0,4.0],[6.0,2.0],[4.0,3.0],[3.5,5.5]])\n\n"
            "def plot_delaunay(points: np.ndarray) -> None:\n"
            "    tri = Delaunay(points)\n"
            "    fig, ax = plt.subplots(figsize=(6, 5))\n"
            "    ax.plot(points[:, 0], points[:, 1], 'ko', label='Puntos')\n"
            "    for simplex in tri.simplices:\n"
            "        triangle = np.vstack([points[simplex], points[simplex[0]]])\n"
            "        ax.plot(triangle[:, 0], triangle[:, 1], '-', color='#1f77b4', linewidth=1.8)\n"
            "    ax.set_title('Triangulación de Delaunay')\n"
            "    ax.set_xlabel('x')\n"
            "    ax.set_ylabel('y')\n"
            "    ax.set_aspect('equal', adjustable='box')\n"
            "    ax.grid(True, alpha=0.3)\n"
            "    ax.legend(loc='best')\n"
            "    plt.tight_layout()\n"
            "    plt.savefig('delaunay.png')\n\n"
            "if __name__ == '__main__':\n"
            "    pts = demo_points()\n"
            "    plot_delaunay(pts)\n"
        )
    elif algo_term in ("quicksort", "mergesort", "merge sort"):
        out = _header(
            "#!/usr/bin/env python3\n"
            "\"\"\"Implementación educativa de QuickSort y MergeSort con pruebas simples.\n\"\"\"\n\n"
            "from __future__ import annotations\nimport random\n\n"
            "def quicksort(arr):\n    if len(arr) < 2: return arr[:]\n    pivot = arr[len(arr)//2]\n    left = [x for x in arr if x < pivot]\n    mid  = [x for x in arr if x == pivot]\n    right= [x for x in arr if x > pivot]\n    return quicksort(left) + mid + quicksort(right)\n\n"
            "def mergesort(arr):\n    if len(arr) < 2: return arr[:]\n    m = len(arr)//2\n    return _merge(mergesort(arr[:m]), mergesort(arr[m:]))\n\n"
            "def _merge(a,b):\n    i=j=0; out=[]\n    while i < len(a) and j < len(b):\n        if a[i] <= b[j]: out.append(a[i]); i+=1\n        else: out.append(b[j]); j+=1\n    out.extend(a[i:]); out.extend(b[j:]); return out\n\n"
            "if __name__=='__main__':\n    data = [random.randint(0,50) for _ in range(15)]\n    print('Original', data)\n    print('QuickSort', quicksort(data))\n    print('MergeSort', mergesort(data))\n"
        )
    elif algo_term in ("bfs", "dfs"):
        out = _header(
            "#!/usr/bin/env python3\n\"\"\"BFS y DFS sobre grafo no dirigido representado con listas de adyacencia.\n\"\"\"\n\n"
            "from collections import deque\n\n"
            "def bfs(graph, start):\n    visited=set([start]); order=[]; q=deque([start])\n    while q:\n        v=q.popleft(); order.append(v)\n        for w in graph.get(v,[]):\n            if w not in visited:\n                visited.add(w); q.append(w)\n    return order\n\n"
            "def dfs(graph, start):\n    visited=set(); order=[]\n    def _rec(v):\n        visited.add(v); order.append(v)\n        for w in graph.get(v,[]):\n            if w not in visited: _rec(w)\n    _rec(start); return order\n\n"
            "if __name__=='__main__':\n    g={'A':['B','C'],'B':['D'],'C':['E'],'D':[],'E':[]}\n    print('BFS', bfs(g,'A'))\n    print('DFS', dfs(g,'A'))\n"
        )
    elif algo_term in ("dijkstra","a*","astar","a star"):
        out = _header(
            "#!/usr/bin/env python3\n\"\"\"Dijkstra y A* (heurística Manhattan) sobre grafo ponderado.\n\"\"\"\n\n"
            "import heapq\n\n"
            "def dijkstra(graph, start):\n    dist={start:0}; pq=[(0,start)]; prev={}\n    while pq:\n        d,v=heapq.heappop(pq)\n        if d>dist.get(v,1e18): continue\n        for w,c in graph.get(v,[]):\n            nd=d+c\n            if nd<dist.get(w,1e18):\n                dist[w]=nd; prev[w]=v; heapq.heappush(pq,(nd,w))\n    return dist, prev\n\n"
            "def heuristic(a,b): x1,y1=a; x2,y2=b; return abs(x1-x2)+abs(y1-y2)\n\n"
            "def astar(graph, start, goal):\n    open=[(0,start)]; g={start:0}; came={}\n    while open:\n        _,current=heapq.heappop(open)\n        if current==goal: break\n        for neigh,cost in graph.get(current,[]):\n            tentative=g[current]+cost\n            if tentative < g.get(neigh,1e18):\n                g[neigh]=tentative; f=tentative+heuristic(neigh,goal); heapq.heappush(open,(f,neigh)); came[neigh]=current\n    return g, came\n\n"
            "if __name__=='__main__':\n    G={(0,0):[((1,0),1),((0,1),1)],(1,0):[((1,1),1)],(0,1):[((1,1),1)],(1,1):[]}\n    print('Dijkstra', dijkstra(G,(0,0))[0])\n    print('A*', astar(G,(0,0),(1,1))[0])\n"
        )

    if out and write_file_func:
        write_file_func(file_path, out + "\n")
        return True
    if out and not write_file_func:
        # No podemos escribir, pero indicamos que habría salida
        return True
    return False
