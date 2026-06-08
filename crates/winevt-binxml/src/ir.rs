//! The in-memory tree (IR) produced by the BinXml deserializer.
//!
//! A decoded fragment is a list of [`Node`]s; an [`Element`] owns its
//! attributes and child nodes. The tree is intentionally simple and owned
//! (no borrows into the chunk) so it survives past the decode and can be
//! projected to JSON/XML independently.

/// A node in the decoded tree: either an element or a run of text.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    /// An XML element with a name, attributes and children.
    Element(Element),
    /// Character data / a substituted value rendered to text.
    Text(String),
}

/// An XML element.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Element {
    /// The element (tag) name.
    pub name: String,
    /// Attributes as `(name, value)` pairs, in document order.
    pub attributes: Vec<(String, String)>,
    /// Child nodes, in document order.
    pub children: Vec<Node>,
}
