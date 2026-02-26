//! Search: find, highlight, and navigate matches in the policy tree.

use super::super::tree;
use super::{App, Mode};

impl App {
    /// Enter search mode.
    pub fn start_search(&mut self) {
        self.search_input.clear();
        self.mode = Mode::Search;
    }

    /// Commit the search query and jump to first match.
    pub fn commit_search(&mut self) {
        let query = self.search_input.value().to_string();
        if query.is_empty() {
            self.search_query = None;
            self.search_matches.clear();
        } else {
            self.search_query = Some(query);
            self.expand_search_ancestors();
            self.rebuild_flat();
            // Jump to first match
            if let Some(&idx) = self.search_matches.first() {
                self.cursor = idx;
                self.search_match_cursor = 0;
            }
        }
        self.mode = Mode::Normal;
    }

    /// Cancel search mode without applying.
    pub fn cancel_search(&mut self) {
        self.mode = Mode::Normal;
    }

    /// Clear the active search.
    pub fn clear_search(&mut self) {
        self.search_query = None;
        self.search_matches.clear();
        self.search_match_cursor = 0;
    }

    /// Jump to the next search match.
    pub fn next_search_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        self.search_match_cursor = (self.search_match_cursor + 1) % self.search_matches.len();
        self.cursor = self.search_matches[self.search_match_cursor];
    }

    /// Jump to the previous search match.
    pub fn prev_search_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        if self.search_match_cursor == 0 {
            self.search_match_cursor = self.search_matches.len() - 1;
        } else {
            self.search_match_cursor -= 1;
        }
        self.cursor = self.search_matches[self.search_match_cursor];
    }

    /// Live-update search matches as the user types.
    pub fn update_search_live(&mut self) {
        let query = self.search_input.value().to_string();
        if query.is_empty() {
            self.search_query = None;
            self.search_matches.clear();
        } else {
            self.search_query = Some(query);
            self.expand_search_ancestors();
            self.rebuild_flat();
        }
    }

    /// Re-index search matches from the current flat rows.
    pub(super) fn update_search_matches(&mut self) {
        self.search_matches.clear();
        self.search_match_cursor = 0;

        let Some(query) = &self.search_query else {
            return;
        };
        let query_lower = query.to_lowercase();
        if query_lower.is_empty() {
            return;
        }

        for (i, row) in self.flat_rows.iter().enumerate() {
            let text = tree::node_search_text(&row.kind);
            if text.to_lowercase().contains(&query_lower) {
                self.search_matches.push(i);
            }
        }
    }

    /// Search the full tree and expand ancestors of all matching nodes
    /// so they become visible in flat rows.
    fn expand_search_ancestors(&mut self) {
        let Some(query) = &self.search_query else {
            return;
        };
        let matching_paths = tree::search_tree(&self.roots, query);
        for path in &matching_paths {
            for prefix_len in 1..path.len() {
                if let Some(node) = tree::node_at_path_mut(&mut self.roots, &path[..prefix_len]) {
                    node.expanded = true;
                }
            }
        }
    }
}
