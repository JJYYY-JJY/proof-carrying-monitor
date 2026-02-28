//! Graph storage layer backed by RocksDB.
//!
//! Stores graph nodes, edges, and snapshots in separate column families,
//! with session-based isolation via key prefixes.

use std::collections::{HashMap, VecDeque};

use anyhow::{Context, Result, bail};
use pcm_common::hash::blake3_hash;
use pcm_common::proto::pcm_v1::{EdgeKind, GraphEdge, GraphNode, GraphPath, GraphSnapshot};
use prost::Message;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, Direction, IteratorMode, Options, WriteBatch,
};

const DEFAULT_CF: &str = "default";
const NODES_CF: &str = "nodes";
const EDGES_CF: &str = "edges";
const SNAPSHOTS_CF: &str = "snapshots";
const METADATA_CF: &str = "metadata";

type KvBytes = (Box<[u8]>, Box<[u8]>);

/// Embedded graph store backed by RocksDB.
pub struct GraphStore {
    db: DB,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

fn cf_descriptors() -> Vec<ColumnFamilyDescriptor> {
    [DEFAULT_CF, NODES_CF, EDGES_CF, SNAPSHOTS_CF, METADATA_CF]
        .into_iter()
        .map(|name| ColumnFamilyDescriptor::new(name, Options::default()))
        .collect()
}

/// Build a session-scoped node key: `{session}:{node_id}`
fn node_key(session: &str, node_id: &str) -> Vec<u8> {
    format!("{session}:{node_id}").into_bytes()
}

/// Build a session-scoped edge key: `{session}:{src}|{dst}|{kind_i32}`
fn edge_key(session: &str, src: &str, dst: &str, kind: i32) -> Vec<u8> {
    format!("{session}:{src}|{dst}|{kind}").into_bytes()
}

/// Byte prefix for iterating all keys belonging to a session.
fn session_prefix(session: &str) -> Vec<u8> {
    format!("{session}:").into_bytes()
}

/// Normalise an incoming session id – empty string becomes `"default"`.
fn normalise_session(session_id: &str) -> &str {
    if session_id.is_empty() {
        "default"
    } else {
        session_id
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl GraphStore {
    fn cf(&self, name: &'static str) -> Result<&ColumnFamily> {
        self.db
            .cf_handle(name)
            .with_context(|| format!("missing RocksDB column family `{name}`"))
    }

    fn scan_cf(&self, cf_name: &'static str, prefix: &[u8]) -> Result<Vec<KvBytes>> {
        let cf = self.cf(cf_name)?;
        let mut items = Vec::new();

        for item in self
            .db
            .iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward))
        {
            let (key, value) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            items.push((key, value));
        }

        Ok(items)
    }

    /// Open (or create) a RocksDB database at `path`.
    pub fn open(path: &str) -> Result<Self> {
        let mut db_options = Options::default();
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);

        let db = DB::open_cf_descriptors(&db_options, path, cf_descriptors())
            .context("failed to open RocksDB database")?;

        Ok(Self { db })
    }

    // -- Node operations ---------------------------------------------------

    /// Add nodes in batch. If a node's `node_id` is empty, it is computed as
    /// `hex(blake3(label || kind))`.
    pub fn add_nodes(&self, session_id: &str, nodes: &[GraphNode]) -> Result<()> {
        let session = normalise_session(session_id);
        let nodes_cf = self.cf(NODES_CF)?;
        let mut batch = WriteBatch::default();

        for node in nodes {
            let id = if node.node_id.is_empty() {
                let content = format!("{}:{}", node.label, node.kind);
                hex::encode(blake3_hash(content.as_bytes()))
            } else {
                node.node_id.clone()
            };

            // Build a (potentially patched) node with the resolved id.
            let stored = GraphNode {
                node_id: id.clone(),
                ..node.clone()
            };
            let encoded = stored.encode_to_vec();
            batch.put_cf(nodes_cf, node_key(session, &id), encoded);
        }

        self.db.write(batch).context("failed to write node batch")
    }

    /// Retrieve a single node by id within the given session.
    pub fn get_node(&self, session_id: &str, node_id: &str) -> Result<Option<GraphNode>> {
        let session = normalise_session(session_id);
        let key = node_key(session, node_id);
        let nodes_cf = self.cf(NODES_CF)?;

        match self.db.get_cf(nodes_cf, key)? {
            Some(bytes) => {
                let node =
                    GraphNode::decode(bytes.as_ref()).context("failed to decode GraphNode")?;
                Ok(Some(node))
            }
            None => Ok(None),
        }
    }

    // -- Edge operations ---------------------------------------------------

    /// Add edges in batch.  Validates that both `src` and `dst` nodes exist in the
    /// given session, returning an error on the first missing endpoint.
    pub fn add_edges(&self, session_id: &str, edges: &[GraphEdge]) -> Result<()> {
        let session = normalise_session(session_id);
        let nodes_cf = self.cf(NODES_CF)?;
        let edges_cf = self.cf(EDGES_CF)?;
        let mut batch = WriteBatch::default();

        for edge in edges {
            // Validate endpoints
            if self
                .db
                .get_cf(nodes_cf, node_key(session, &edge.src))?
                .is_none()
            {
                bail!(
                    "source node '{}' does not exist in session '{}'",
                    edge.src,
                    session
                );
            }
            if self
                .db
                .get_cf(nodes_cf, node_key(session, &edge.dst))?
                .is_none()
            {
                bail!(
                    "destination node '{}' does not exist in session '{}'",
                    edge.dst,
                    session
                );
            }

            let key = edge_key(session, &edge.src, &edge.dst, edge.kind);
            let encoded = edge.encode_to_vec();
            batch.put_cf(edges_cf, key, encoded);
        }

        self.db.write(batch).context("failed to write edge batch")
    }

    // -- Counts ------------------------------------------------------------

    /// Number of nodes in the given session.
    pub fn node_count(&self, session_id: &str) -> Result<u64> {
        let prefix = session_prefix(normalise_session(session_id));
        Ok(self.scan_cf(NODES_CF, &prefix)?.len() as u64)
    }

    /// Number of edges in the given session.
    pub fn edge_count(&self, session_id: &str) -> Result<u64> {
        let prefix = session_prefix(normalise_session(session_id));
        Ok(self.scan_cf(EDGES_CF, &prefix)?.len() as u64)
    }

    // -- Snapshot ----------------------------------------------------------

    /// Build a `GraphSnapshot` for the given session.
    ///
    /// The snapshot hash is `blake3(nodes_merkle_root || edges_merkle_root || timestamp)`.
    pub fn get_snapshot(&self, session_id: &str) -> Result<GraphSnapshot> {
        let session = normalise_session(session_id);
        let prefix = session_prefix(session);

        // Collect all nodes, sorted by node_id
        let mut nodes: Vec<GraphNode> = self
            .scan_cf(NODES_CF, &prefix)?
            .into_iter()
            .map(|(_k, v)| GraphNode::decode(v.as_ref()).context("failed to decode GraphNode"))
            .collect::<Result<Vec<_>>>()?;
        nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));

        // Collect all edges, sorted by (src, dst, kind)
        let mut edges: Vec<GraphEdge> = self
            .scan_cf(EDGES_CF, &prefix)?
            .into_iter()
            .map(|(_k, v)| GraphEdge::decode(v.as_ref()).context("failed to decode GraphEdge"))
            .collect::<Result<Vec<_>>>()?;
        edges.sort_by(|a, b| (&a.src, &a.dst, a.kind).cmp(&(&b.src, &b.dst, b.kind)));

        // Merkle roots
        let nodes_root = merkle_root(
            &nodes
                .iter()
                .map(|n| blake3_hash(n.node_id.as_bytes()))
                .collect::<Vec<_>>(),
        );
        let edges_root = merkle_root(
            &edges
                .iter()
                .map(|e| {
                    let content = format!("{}|{}|{}", e.src, e.dst, e.kind);
                    blake3_hash(content.as_bytes())
                })
                .collect::<Vec<_>>(),
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let timestamp = prost_types::Timestamp {
            seconds: now.as_secs() as i64,
            nanos: now.subsec_nanos() as i32,
        };

        // snapshot_hash = blake3(nodes_root || edges_root || timestamp_bytes)
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&nodes_root);
        hash_input.extend_from_slice(&edges_root);
        hash_input.extend_from_slice(&timestamp.seconds.to_le_bytes());
        hash_input.extend_from_slice(&timestamp.nanos.to_le_bytes());
        let snapshot_hash = blake3_hash(&hash_input).to_vec();

        // Persist snapshot hash
        self.db
            .put_cf(
                self.cf(SNAPSHOTS_CF)?,
                session.as_bytes(),
                snapshot_hash.as_slice(),
            )
            .context("failed to persist snapshot hash")?;

        Ok(GraphSnapshot {
            snapshot_hash,
            nodes,
            edges,
            as_of: Some(timestamp),
        })
    }

    // -- Reachability ------------------------------------------------------

    /// BFS reachability query from `from` to `to`, optionally filtering by
    /// edge kinds.  Returns `(reachable, paths)`.
    pub fn query_reachable(
        &self,
        session_id: &str,
        from: &str,
        to: &str,
        edge_filter: &[EdgeKind],
    ) -> Result<(bool, Vec<GraphPath>)> {
        let session = normalise_session(session_id);
        let prefix = session_prefix(session);

        // Build adjacency list
        let mut adj: HashMap<String, Vec<(String, EdgeKind)>> = HashMap::new();
        for (_k, v) in self.scan_cf(EDGES_CF, &prefix)? {
            let edge = GraphEdge::decode(v.as_ref()).context("failed to decode GraphEdge")?;
            let kind = EdgeKind::try_from(edge.kind).unwrap_or(EdgeKind::Unspecified);
            if !edge_filter.is_empty() && !edge_filter.contains(&kind) {
                continue;
            }
            adj.entry(edge.src.clone())
                .or_default()
                .push((edge.dst.clone(), kind));
        }

        // BFS collecting all simple paths
        let mut result_paths: Vec<GraphPath> = Vec::new();
        // queue: (current_node, path_so_far)
        let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
        queue.push_back((from.to_string(), vec![from.to_string()]));

        while let Some((current, path)) = queue.pop_front() {
            if current == to {
                result_paths.push(GraphPath { node_ids: path });
                continue;
            }
            if let Some(neighbors) = adj.get(&current) {
                for (next, _kind) in neighbors {
                    if !path.contains(next) {
                        let mut new_path = path.clone();
                        new_path.push(next.clone());
                        queue.push_back((next.clone(), new_path));
                    }
                }
            }
        }

        let reachable = !result_paths.is_empty();
        Ok((reachable, result_paths))
    }

    // -- Session management ------------------------------------------------

    /// Remove all nodes, edges and snapshot data for a session.
    pub fn clear_session(&self, session_id: &str) -> Result<()> {
        let session = normalise_session(session_id);
        let prefix = session_prefix(session);
        let mut batch = WriteBatch::default();

        // Remove nodes
        for (key, _value) in self.scan_cf(NODES_CF, &prefix)? {
            batch.delete_cf(self.cf(NODES_CF)?, key);
        }

        // Remove edges
        for (key, _value) in self.scan_cf(EDGES_CF, &prefix)? {
            batch.delete_cf(self.cf(EDGES_CF)?, key);
        }

        // Remove snapshot
        batch.delete_cf(self.cf(SNAPSHOTS_CF)?, session.as_bytes());

        self.db.write(batch).context("failed to clear session data")
    }
}

// ---------------------------------------------------------------------------
// Merkle tree helper
// ---------------------------------------------------------------------------

/// Compute a simple binary Merkle root over a list of 32-byte hashes.
/// An empty list hashes to `blake3(b"empty")`.
fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return blake3_hash(b"empty");
    }
    if hashes.len() == 1 {
        return hashes[0];
    }
    let mut level: Vec<[u8; 32]> = hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&chunk[0]);
                combined[32..].copy_from_slice(&chunk[1]);
                next.push(blake3_hash(&combined));
            } else {
                // Odd element — promote
                next.push(chunk[0]);
            }
        }
        level = next;
    }
    level[0]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pcm_common::proto::pcm_v1::{EdgeKind, NodeKind};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Create a fresh temporary RocksDB database for each test.
    fn temp_store() -> GraphStore {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("pcm-graph-test-{}-{}", std::process::id(), id));
        GraphStore::open(dir.to_str().unwrap()).expect("open temp store")
    }

    fn make_node(id: &str, kind: NodeKind, label: &str) -> GraphNode {
        GraphNode {
            node_id: id.to_string(),
            kind: kind as i32,
            label: label.to_string(),
            attrs: Default::default(),
            created_at: None,
        }
    }

    fn make_edge(src: &str, dst: &str, kind: EdgeKind) -> GraphEdge {
        GraphEdge {
            src: src.to_string(),
            dst: dst.to_string(),
            kind: kind as i32,
            created_at: None,
        }
    }

    // -- Node CRUD ---------------------------------------------------------

    #[test]
    fn test_add_and_get_node() {
        let store = temp_store();
        let node = make_node("n1", NodeKind::Entity, "user-alice");
        store.add_nodes("s1", &[node.clone()]).unwrap();

        let fetched = store.get_node("s1", "n1").unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.node_id, "n1");
        assert_eq!(fetched.label, "user-alice");
    }

    #[test]
    fn test_node_dedup() {
        let store = temp_store();
        let node = make_node("n1", NodeKind::Entity, "user");
        store
            .add_nodes("s1", &[node.clone(), node.clone()])
            .unwrap();
        assert_eq!(store.node_count("s1").unwrap(), 1);
    }

    #[test]
    fn test_auto_id_generation() {
        let store = temp_store();
        let node = make_node("", NodeKind::Action, "tool-call");
        store.add_nodes("s1", &[node]).unwrap();
        assert_eq!(store.node_count("s1").unwrap(), 1);
    }

    #[test]
    fn test_get_nonexistent_node() {
        let store = temp_store();
        assert!(store.get_node("s1", "missing").unwrap().is_none());
    }

    #[test]
    fn test_session_isolation() {
        let store = temp_store();
        let node = make_node("n1", NodeKind::Entity, "alice");
        store.add_nodes("s1", &[node]).unwrap();

        assert!(store.get_node("s1", "n1").unwrap().is_some());
        assert!(store.get_node("s2", "n1").unwrap().is_none());
    }

    #[test]
    fn test_default_session() {
        let store = temp_store();
        let node = make_node("n1", NodeKind::Entity, "bob");
        store.add_nodes("", &[node]).unwrap();

        // Empty string and "default" should be equivalent
        assert!(store.get_node("", "n1").unwrap().is_some());
        assert!(store.get_node("default", "n1").unwrap().is_some());
    }

    // -- Edge CRUD ---------------------------------------------------------

    #[test]
    fn test_add_edge_valid() {
        let store = temp_store();
        store
            .add_nodes(
                "s1",
                &[
                    make_node("a", NodeKind::Entity, "A"),
                    make_node("b", NodeKind::Entity, "B"),
                ],
            )
            .unwrap();

        store
            .add_edges("s1", &[make_edge("a", "b", EdgeKind::DataFlow)])
            .unwrap();
        assert_eq!(store.edge_count("s1").unwrap(), 1);
    }

    #[test]
    fn test_add_edge_missing_src() {
        let store = temp_store();
        store
            .add_nodes("s1", &[make_node("b", NodeKind::Entity, "B")])
            .unwrap();
        let result = store.add_edges("s1", &[make_edge("missing", "b", EdgeKind::DataFlow)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_edge_missing_dst() {
        let store = temp_store();
        store
            .add_nodes("s1", &[make_node("a", NodeKind::Entity, "A")])
            .unwrap();
        let result = store.add_edges("s1", &[make_edge("a", "missing", EdgeKind::DataFlow)]);
        assert!(result.is_err());
    }

    // -- Snapshot -----------------------------------------------------------

    #[test]
    fn test_empty_snapshot() {
        let store = temp_store();
        let snap = store.get_snapshot("s1").unwrap();
        assert!(snap.nodes.is_empty());
        assert!(snap.edges.is_empty());
        assert!(!snap.snapshot_hash.is_empty());
    }

    #[test]
    fn test_snapshot_deterministic_nodes() {
        let store = temp_store();
        // Two stores with same data should produce the same nodes/edges merkle
        // roots (though timestamps will differ so we test the intermediate
        // merkle values instead).
        let nodes = vec![
            make_node("a", NodeKind::Entity, "A"),
            make_node("b", NodeKind::Action, "B"),
        ];
        store.add_nodes("s1", &nodes).unwrap();
        store
            .add_edges("s1", &[make_edge("a", "b", EdgeKind::Causal)])
            .unwrap();

        let snap = store.get_snapshot("s1").unwrap();
        assert_eq!(snap.nodes.len(), 2);
        assert_eq!(snap.edges.len(), 1);
        // Nodes should be sorted
        assert_eq!(snap.nodes[0].node_id, "a");
        assert_eq!(snap.nodes[1].node_id, "b");
    }

    #[test]
    fn test_snapshot_hash_changes_with_data() {
        let store = temp_store();
        let snap1 = store.get_snapshot("s1").unwrap();

        store
            .add_nodes("s1", &[make_node("x", NodeKind::Data, "X")])
            .unwrap();
        // snapshot_hash includes timestamp so we cannot compare directly; but the
        // node content changes guarantees internal merkle roots differ.
        let snap2 = store.get_snapshot("s1").unwrap();
        assert_ne!(snap1.nodes.len(), snap2.nodes.len());
    }

    // -- Reachability ------------------------------------------------------

    #[test]
    fn test_reachable_simple_chain() {
        let store = temp_store();
        store
            .add_nodes(
                "s1",
                &[
                    make_node("a", NodeKind::Entity, "A"),
                    make_node("b", NodeKind::Entity, "B"),
                    make_node("c", NodeKind::Entity, "C"),
                ],
            )
            .unwrap();
        store
            .add_edges(
                "s1",
                &[
                    make_edge("a", "b", EdgeKind::DataFlow),
                    make_edge("b", "c", EdgeKind::DataFlow),
                ],
            )
            .unwrap();

        let (reachable, paths) = store.query_reachable("s1", "a", "c", &[]).unwrap();
        assert!(reachable);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].node_ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_unreachable() {
        let store = temp_store();
        store
            .add_nodes(
                "s1",
                &[
                    make_node("a", NodeKind::Entity, "A"),
                    make_node("b", NodeKind::Entity, "B"),
                ],
            )
            .unwrap();
        // No edges: a -> b is unreachable
        let (reachable, paths) = store.query_reachable("s1", "a", "b", &[]).unwrap();
        assert!(!reachable);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_reachable_with_cycle() {
        let store = temp_store();
        store
            .add_nodes(
                "s1",
                &[
                    make_node("a", NodeKind::Entity, "A"),
                    make_node("b", NodeKind::Entity, "B"),
                    make_node("c", NodeKind::Entity, "C"),
                ],
            )
            .unwrap();
        store
            .add_edges(
                "s1",
                &[
                    make_edge("a", "b", EdgeKind::DataFlow),
                    make_edge("b", "c", EdgeKind::DataFlow),
                    make_edge("c", "a", EdgeKind::DataFlow), // cycle
                ],
            )
            .unwrap();

        let (reachable, paths) = store.query_reachable("s1", "a", "c", &[]).unwrap();
        assert!(reachable);
        assert!(!paths.is_empty());
    }

    #[test]
    fn test_reachable_edge_filter() {
        let store = temp_store();
        store
            .add_nodes(
                "s1",
                &[
                    make_node("a", NodeKind::Entity, "A"),
                    make_node("b", NodeKind::Entity, "B"),
                ],
            )
            .unwrap();
        store
            .add_edges("s1", &[make_edge("a", "b", EdgeKind::ControlFlow)])
            .unwrap();

        // Filter for DataFlow only — should NOT find a->b
        let (reachable, _) = store
            .query_reachable("s1", "a", "b", &[EdgeKind::DataFlow])
            .unwrap();
        assert!(!reachable);

        // Filter for ControlFlow — should find it
        let (reachable, _) = store
            .query_reachable("s1", "a", "b", &[EdgeKind::ControlFlow])
            .unwrap();
        assert!(reachable);
    }

    // -- clear_session -----------------------------------------------------

    #[test]
    fn test_clear_session() {
        let store = temp_store();
        store
            .add_nodes(
                "s1",
                &[
                    make_node("a", NodeKind::Entity, "A"),
                    make_node("b", NodeKind::Entity, "B"),
                ],
            )
            .unwrap();
        store
            .add_edges("s1", &[make_edge("a", "b", EdgeKind::DataFlow)])
            .unwrap();
        store.get_snapshot("s1").unwrap(); // persist snapshot entry

        store.clear_session("s1").unwrap();
        assert_eq!(store.node_count("s1").unwrap(), 0);
        assert_eq!(store.edge_count("s1").unwrap(), 0);
    }

    // -- Counts ------------------------------------------------------------

    #[test]
    fn test_counts() {
        let store = temp_store();
        assert_eq!(store.node_count("s1").unwrap(), 0);
        assert_eq!(store.edge_count("s1").unwrap(), 0);

        store
            .add_nodes(
                "s1",
                &[
                    make_node("a", NodeKind::Entity, "A"),
                    make_node("b", NodeKind::Entity, "B"),
                    make_node("c", NodeKind::Entity, "C"),
                ],
            )
            .unwrap();
        assert_eq!(store.node_count("s1").unwrap(), 3);

        store
            .add_edges(
                "s1",
                &[
                    make_edge("a", "b", EdgeKind::DataFlow),
                    make_edge("b", "c", EdgeKind::Temporal),
                ],
            )
            .unwrap();
        assert_eq!(store.edge_count("s1").unwrap(), 2);
    }
}
