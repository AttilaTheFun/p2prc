import ConvoFoundation

/// §13.1 `RV(key, k)`: the top-k nodes of a directory ranked by
/// `H("convo/rv" ‖ key ‖ node_pk)` ascending. Rendezvous hashing: a node
/// joining or leaving the directory changes only the sets it belongs to.
/// The caller passes its directory's healthy nodes not proven faulty.
public enum Rendezvous {
    public static func rank(key: Hash32, node: Hash32) -> Hash32 {
        Hashing.hash(Domain.rendezvous, key.bytes, node.bytes)
    }

    public static func select(key: Hash32, from nodes: [Hash32], count: Int) -> [Hash32] {
        Array(nodes.sorted { rank(key: key, node: $0) < rank(key: key, node: $1) }.prefix(count))
    }
}
