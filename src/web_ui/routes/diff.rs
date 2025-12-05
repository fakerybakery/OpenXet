//! Diff computation utilities for commits and file changes.

use crate::git::{ObjectId, Repository, TreeEntry};
use std::collections::HashMap;

/// File change info for commit view
#[derive(serde::Serialize)]
pub struct FileChange {
    pub path: String,
    pub status: String, // "added", "modified", "deleted"
    pub additions: usize,
    pub deletions: usize,
    pub diff_lines: Vec<DiffLine>,
    pub is_binary: bool,
}

/// A single line in a diff
#[derive(serde::Serialize)]
pub struct DiffLine {
    pub line_type: String, // "add", "del", "context", "header"
    pub content: String,
    pub old_line: Option<usize>,
    pub new_line: Option<usize>,
}

/// Compute diff between two trees
pub fn compute_diff(
    repo: &Repository,
    old_tree: Option<&ObjectId>,
    new_tree: &ObjectId,
) -> Vec<FileChange> {
    let mut changes = Vec::new();

    // Collect entries from both trees
    let old_entries = old_tree
        .and_then(|t| repo.parse_tree(t))
        .unwrap_or_default();
    let new_entries = repo.parse_tree(new_tree).unwrap_or_default();

    // Build maps for lookup
    let old_map: HashMap<&str, &TreeEntry> =
        old_entries.iter().map(|e| (e.name.as_str(), e)).collect();
    let new_map: HashMap<&str, &TreeEntry> =
        new_entries.iter().map(|e| (e.name.as_str(), e)).collect();

    // Find added and modified files
    for new_entry in &new_entries {
        if new_entry.is_dir {
            // Recursively diff directories
            let old_subdir = old_map.get(new_entry.name.as_str())
                .filter(|e| e.is_dir)
                .map(|e| e.oid);
            let sub_changes = compute_diff_recursive(
                repo,
                old_subdir.as_ref(),
                &new_entry.oid,
                &new_entry.name,
            );
            changes.extend(sub_changes);
        } else {
            match old_map.get(new_entry.name.as_str()) {
                Some(old_entry) if old_entry.oid == new_entry.oid => {
                    // Unchanged
                }
                Some(old_entry) => {
                    // Modified
                    let diff = compute_file_diff(repo, &old_entry.oid, &new_entry.oid, &new_entry.name);
                    changes.push(diff);
                }
                None => {
                    // Added
                    let diff = compute_file_diff(repo, &ObjectId::from_raw([0; 20]), &new_entry.oid, &new_entry.name);
                    changes.push(diff);
                }
            }
        }
    }

    // Find deleted files
    for old_entry in &old_entries {
        if !new_map.contains_key(old_entry.name.as_str()) {
            if old_entry.is_dir {
                // Recursively mark deleted
                let sub_changes = compute_diff_recursive(
                    repo,
                    Some(&old_entry.oid),
                    &ObjectId::from_raw([0; 20]),
                    &old_entry.name,
                );
                changes.extend(sub_changes);
            } else {
                let diff = compute_file_diff(repo, &old_entry.oid, &ObjectId::from_raw([0; 20]), &old_entry.name);
                changes.push(diff);
            }
        }
    }

    changes
}

/// Recursively compute diff for subdirectories
fn compute_diff_recursive(
    repo: &Repository,
    old_tree: Option<&ObjectId>,
    new_tree: &ObjectId,
    prefix: &str,
) -> Vec<FileChange> {
    let mut changes = Vec::new();

    let is_empty_tree = new_tree.as_bytes() == &[0; 20];

    let old_entries = old_tree
        .and_then(|t| repo.parse_tree(t))
        .unwrap_or_default();
    let new_entries = if is_empty_tree {
        vec![]
    } else {
        repo.parse_tree(new_tree).unwrap_or_default()
    };

    let old_map: HashMap<&str, &TreeEntry> =
        old_entries.iter().map(|e| (e.name.as_str(), e)).collect();
    let new_map: HashMap<&str, &TreeEntry> =
        new_entries.iter().map(|e| (e.name.as_str(), e)).collect();

    for new_entry in &new_entries {
        let full_path = format!("{}/{}", prefix, new_entry.name);
        if new_entry.is_dir {
            let old_subdir = old_map.get(new_entry.name.as_str())
                .filter(|e| e.is_dir)
                .map(|e| e.oid);
            let sub_changes = compute_diff_recursive(repo, old_subdir.as_ref(), &new_entry.oid, &full_path);
            changes.extend(sub_changes);
        } else {
            match old_map.get(new_entry.name.as_str()) {
                Some(old_entry) if old_entry.oid == new_entry.oid => {}
                Some(old_entry) => {
                    let diff = compute_file_diff(repo, &old_entry.oid, &new_entry.oid, &full_path);
                    changes.push(diff);
                }
                None => {
                    let diff = compute_file_diff(repo, &ObjectId::from_raw([0; 20]), &new_entry.oid, &full_path);
                    changes.push(diff);
                }
            }
        }
    }

    for old_entry in &old_entries {
        if !new_map.contains_key(old_entry.name.as_str()) {
            let full_path = format!("{}/{}", prefix, old_entry.name);
            if old_entry.is_dir {
                let sub_changes = compute_diff_recursive(repo, Some(&old_entry.oid), &ObjectId::from_raw([0; 20]), &full_path);
                changes.extend(sub_changes);
            } else {
                let diff = compute_file_diff(repo, &old_entry.oid, &ObjectId::from_raw([0; 20]), &full_path);
                changes.push(diff);
            }
        }
    }

    changes
}

/// Compute diff for a single file
fn compute_file_diff(
    repo: &Repository,
    old_id: &ObjectId,
    new_id: &ObjectId,
    path: &str,
) -> FileChange {
    let is_empty = |id: &ObjectId| id.as_bytes() == &[0; 20];

    let old_content = if is_empty(old_id) {
        None
    } else {
        repo.get_blob_content(old_id)
    };

    let new_content = if is_empty(new_id) {
        None
    } else {
        repo.get_blob_content(new_id)
    };

    // Check for binary content
    let is_binary = old_content.as_ref().map(|c| c.iter().take(8000).any(|&b| b == 0)).unwrap_or(false)
        || new_content.as_ref().map(|c| c.iter().take(8000).any(|&b| b == 0)).unwrap_or(false);

    if is_binary {
        let status = match (&old_content, &new_content) {
            (None, Some(_)) => "added",
            (Some(_), None) => "deleted",
            _ => "modified",
        };
        return FileChange {
            path: path.to_string(),
            status: status.to_string(),
            additions: 0,
            deletions: 0,
            diff_lines: vec![DiffLine {
                line_type: "header".to_string(),
                content: "Binary file changed".to_string(),
                old_line: None,
                new_line: None,
            }],
            is_binary: true,
        };
    }

    let old_text = old_content
        .as_ref()
        .map(|c| String::from_utf8_lossy(c).to_string())
        .unwrap_or_default();
    let new_text = new_content
        .as_ref()
        .map(|c| String::from_utf8_lossy(c).to_string())
        .unwrap_or_default();

    let status = match (&old_content, &new_content) {
        (None, Some(_)) => "added",
        (Some(_), None) => "deleted",
        _ => "modified",
    };

    // Generate simple line-by-line diff
    let (diff_lines, additions, deletions) = generate_diff(&old_text, &new_text);

    FileChange {
        path: path.to_string(),
        status: status.to_string(),
        additions,
        deletions,
        diff_lines,
        is_binary: false,
    }
}

/// Generate a simple line-by-line diff
fn generate_diff(old: &str, new: &str) -> (Vec<DiffLine>, usize, usize) {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    let mut diff_lines = Vec::new();
    let mut additions = 0;
    let mut deletions = 0;

    if old_lines.is_empty() {
        // All additions
        for (i, line) in new_lines.iter().enumerate() {
            diff_lines.push(DiffLine {
                line_type: "add".to_string(),
                content: ammonia::clean(line),
                old_line: None,
                new_line: Some(i + 1),
            });
            additions += 1;
        }
    } else if new_lines.is_empty() {
        // All deletions
        for (i, line) in old_lines.iter().enumerate() {
            diff_lines.push(DiffLine {
                line_type: "del".to_string(),
                content: ammonia::clean(line),
                old_line: Some(i + 1),
                new_line: None,
            });
            deletions += 1;
        }
    } else {
        // Use simple line comparison with LCS
        let lcs = compute_lcs(&old_lines, &new_lines);
        let (lines, adds, dels) = build_diff_from_lcs(&old_lines, &new_lines, &lcs);
        diff_lines = lines;
        additions = adds;
        deletions = dels;
    }

    (diff_lines, additions, deletions)
}

/// Compute LCS (Longest Common Subsequence) indices
fn compute_lcs<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<(usize, usize)> {
    let m = old.len();
    let n = new.len();

    // Build LCS length table
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if old[i - 1] == new[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }

    // Backtrack to find LCS
    let mut result = Vec::new();
    let mut i = m;
    let mut j = n;
    while i > 0 && j > 0 {
        if old[i - 1] == new[j - 1] {
            result.push((i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] > dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    result.reverse();
    result
}

/// Build diff lines from LCS
fn build_diff_from_lcs(old: &[&str], new: &[&str], lcs: &[(usize, usize)]) -> (Vec<DiffLine>, usize, usize) {
    let mut lines = Vec::new();
    let mut additions = 0;
    let mut deletions = 0;

    let mut old_idx = 0;
    let mut new_idx = 0;
    let mut lcs_idx = 0;

    while old_idx < old.len() || new_idx < new.len() {
        if lcs_idx < lcs.len() {
            let (lcs_old, lcs_new) = lcs[lcs_idx];

            // Output deletions before this LCS element
            while old_idx < lcs_old {
                lines.push(DiffLine {
                    line_type: "del".to_string(),
                    content: ammonia::clean(old[old_idx]),
                    old_line: Some(old_idx + 1),
                    new_line: None,
                });
                deletions += 1;
                old_idx += 1;
            }

            // Output additions before this LCS element
            while new_idx < lcs_new {
                lines.push(DiffLine {
                    line_type: "add".to_string(),
                    content: ammonia::clean(new[new_idx]),
                    old_line: None,
                    new_line: Some(new_idx + 1),
                });
                additions += 1;
                new_idx += 1;
            }

            // Output the common line
            lines.push(DiffLine {
                line_type: "context".to_string(),
                content: ammonia::clean(old[old_idx]),
                old_line: Some(old_idx + 1),
                new_line: Some(new_idx + 1),
            });
            old_idx += 1;
            new_idx += 1;
            lcs_idx += 1;
        } else {
            // No more LCS elements, output remaining
            while old_idx < old.len() {
                lines.push(DiffLine {
                    line_type: "del".to_string(),
                    content: ammonia::clean(old[old_idx]),
                    old_line: Some(old_idx + 1),
                    new_line: None,
                });
                deletions += 1;
                old_idx += 1;
            }
            while new_idx < new.len() {
                lines.push(DiffLine {
                    line_type: "add".to_string(),
                    content: ammonia::clean(new[new_idx]),
                    old_line: None,
                    new_line: Some(new_idx + 1),
                });
                additions += 1;
                new_idx += 1;
            }
        }
    }

    (lines, additions, deletions)
}
