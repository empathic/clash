//! Search: find, highlight, and navigate matches in the policy tree.

use super::super::tree;
use super::{App, Mode};

impl App {
    /// Enter search mode.
    pub fn start_search(&mut self) {
        self.search.input.clear();
        self.mode = Mode::Search;
    }

    /// Commit the search query and jump to first match.
    pub fn commit_search(&mut self) {
        let query = self.search.input.value().to_string();
        if query.is_empty() {
            self.search.query = None;
            self.search.matches.clear();
        } else {
            self.search.query = Some(query);
            self.expand_search_ancestors();
            self.rebuild_flat();
            // Jump to first match
            if let Some(&idx) = self.search.matches.first() {
                self.tree.cursor = idx;
                self.search.match_cursor = 0;
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
        self.search.query = None;
        self.search.matches.clear();
        self.search.match_cursor = 0;
    }

    /// Jump to the next search match.
    pub fn next_search_match(&mut self) {
        if self.search.matches.is_empty() {
            return;
        }
        self.search.match_cursor = (self.search.match_cursor + 1) % self.search.matches.len();
        self.tree.cursor = self.search.matches[self.search.match_cursor];
    }

    /// Jump to the previous search match.
    pub fn prev_search_match(&mut self) {
        if self.search.matches.is_empty() {
            return;
        }
        if self.search.match_cursor == 0 {
            self.search.match_cursor = self.search.matches.len() - 1;
        } else {
            self.search.match_cursor -= 1;
        }
        self.tree.cursor = self.search.matches[self.search.match_cursor];
    }

    /// Live-update search matches as the user types.
    pub fn update_search_live(&mut self) {
        let query = self.search.input.value().to_string();
        if query.is_empty() {
            self.search.query = None;
            self.search.matches.clear();
        } else {
            self.search.query = Some(query);
            self.expand_search_ancestors();
            self.rebuild_flat();
        }
    }

    /// Re-index search matches from the current flat rows using fuzzy matching.
    /// Matches are sorted by score (best first), then by position.
    pub(super) fn update_search_matches(&mut self) {
        self.search.matches.clear();
        self.search.match_cursor = 0;

        let Some(query) = &self.search.query else {
            return;
        };
        if query.is_empty() {
            return;
        }

        let mut scored: Vec<(usize, u16)> = Vec::new();
        for (i, row) in self.tree.flat_rows.iter().enumerate() {
            let text = tree::node_search_text(&self.tree.arena[row.node_id].kind);
            if let Some(score) = tree::fuzzy_match(&text, query) {
                scored.push((i, score));
            }
        }
        // Sort by score descending, then by position ascending for stability
        scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        self.search.matches = scored.into_iter().map(|(i, _)| i).collect();
    }

    /// Search the full tree and expand ancestors of all matching nodes
    /// so they become visible in flat rows.
    fn expand_search_ancestors(&mut self) {
        let Some(query) = &self.search.query else {
            return;
        };
        let matching_ids = tree::search_tree(&self.tree.arena, query);
        for id in matching_ids {
            let ancestors = self.tree.arena.ancestors(id);
            // Expand all ancestors except the matching node itself
            for &aid in &ancestors[..ancestors.len().saturating_sub(1)] {
                self.tree.arena[aid].expanded = true;
            }
        }
    }
}
