import networkx as nx

from .common import curry

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


