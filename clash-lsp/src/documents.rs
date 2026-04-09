//! In-memory store of open documents.

use lsp_types::Url;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::analysis::{ParsedPolicy, parse};

#[derive(Default)]
pub struct DocumentStore {
    inner: RwLock<HashMap<Url, Entry>>,
}

struct Entry {
    text: String,
    parsed: ParsedPolicy,
}

impl DocumentStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&self, uri: Url, text: String) -> ParsedPolicy {
        let parsed = parse(uri.as_str(), &text);
        let snapshot = parsed.clone();
        self.inner
            .write()
            .unwrap()
            .insert(uri, Entry { text, parsed });
        snapshot
    }

    pub fn change(&self, uri: Url, text: String) -> ParsedPolicy {
        self.open(uri, text)
    }

    pub fn close(&self, uri: &Url) {
        self.inner.write().unwrap().remove(uri);
    }

    pub fn get(&self, uri: &Url) -> Option<ParsedPolicy> {
        self.inner
            .read()
            .unwrap()
            .get(uri)
            .map(|e| e.parsed.clone())
    }

    pub fn get_text(&self, uri: &Url) -> Option<String> {
        self.inner.read().unwrap().get(uri).map(|e| e.text.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_then_get_returns_parsed() {
        let store = DocumentStore::new();
        let uri: Url = "file:///x.star".parse().unwrap();
        let _ = store.open(
            uri.clone(),
            r#"policy("test", {tool("Bash"): allow()})"#.into(),
        );
        assert!(store.get(&uri).is_some());
    }

    #[test]
    fn close_removes_entry() {
        let store = DocumentStore::new();
        let uri: Url = "file:///x.star".parse().unwrap();
        store.open(
            uri.clone(),
            r#"policy("test", {tool("Bash"): allow()})"#.into(),
        );
        store.close(&uri);
        assert!(store.get(&uri).is_none());
    }
}
