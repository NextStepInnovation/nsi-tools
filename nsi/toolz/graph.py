import typing as T
import networkx as nx
import functools

from .common import curry, pipe, do

__all__ = [
    # graph
    'bfs_tree', 'from_edgelist', 
    # 'to_graph', 'to_digraph',
]

# ----------------------------------------------------------------------
#
# Graph functions
#
# ----------------------------------------------------------------------

@curry
def from_edgelist(edgelist, factory=None):
    '''Curried nx.from_edgelist

    '''
    return nx.from_edgelist(edgelist, create_using=factory)

@curry
def bfs_tree(G, source, reverse=False, depth_limit=None):
    '''Curried nx.tranversal.bfs_tree

    '''
    return nx.traversal.bfs_tree(
        G, source, reverse=reverse,
        depth_limit=depth_limit
    )

# EdgeList = T.Iterable[
#     T.Tuple[T.Hashable, T.Hashable]
# ]

# def _to_graph(factory_f: T.Callable[[EdgeList], nx.Graph]):
#     def deco(func):
#         @functools.wraps(func)
#         def digraph_maker(*args, **kwargs):
#             return pipe(
#                 func(*args, **kwargs),
#                 tuple,
#                 do(print),
#                 lambda el: nx.from_edgelist(el, factory_f)
#             )
#         return digraph_maker
#     return deco

# to_graph = _to_graph(nx.Graph)
# to_digraph = _to_graph(nx.DiGraph)
