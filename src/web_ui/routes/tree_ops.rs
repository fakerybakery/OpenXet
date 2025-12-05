//! Git tree manipulation operations.

use crate::git::{ObjectId, ObjectType, Repository, TreeEntry};

/// Build an updated tree with a file changed at the given path
pub fn build_updated_tree(
    repo: &Repository,
    current_tree: &ObjectId,
    path: &str,
    new_blob_id: &ObjectId,
) -> Option<ObjectId> {
    let parts: Vec<&str> = path.split('/').collect();
    build_tree_recursive(repo, current_tree, &parts, new_blob_id)
}

fn build_tree_recursive(
    repo: &Repository,
    current_tree: &ObjectId,
    path_parts: &[&str],
    new_blob_id: &ObjectId,
) -> Option<ObjectId> {
    if path_parts.is_empty() {
        return None;
    }

    let entries = repo.parse_tree(current_tree)?;
    let target_name = path_parts[0];
    let is_final = path_parts.len() == 1;

    let mut new_entries: Vec<TreeEntry> = Vec::new();
    let mut found = false;

    for entry in entries {
        if entry.name == target_name {
            found = true;
            if is_final {
                // Replace this blob with the new one
                new_entries.push(TreeEntry {
                    mode: entry.mode,
                    name: entry.name,
                    oid: *new_blob_id,
                    is_dir: false,
                    is_executable: false,
                    is_symlink: false,
                });
            } else {
                // Recurse into subdirectory
                let new_subtree_id = build_tree_recursive(
                    repo,
                    &entry.oid,
                    &path_parts[1..],
                    new_blob_id,
                )?;
                new_entries.push(TreeEntry {
                    mode: entry.mode,
                    name: entry.name,
                    oid: new_subtree_id,
                    is_dir: true,
                    is_executable: false,
                    is_symlink: false,
                });
            }
        } else {
            new_entries.push(entry);
        }
    }

    if !found {
        return None;
    }

    // Serialize the new tree
    let tree_data = serialize_tree(&new_entries);
    let new_tree_id = repo.create_object(ObjectType::Tree, &tree_data);
    Some(new_tree_id)
}

/// Build a tree with a new file added at the given path
pub fn build_tree_with_addition(
    repo: &Repository,
    current_tree: &ObjectId,
    path: &str,
    new_blob_id: &ObjectId,
) -> Option<ObjectId> {
    let parts: Vec<&str> = path.split('/').collect();
    add_to_tree_recursive(repo, Some(current_tree), &parts, new_blob_id)
}

fn add_to_tree_recursive(
    repo: &Repository,
    current_tree: Option<&ObjectId>,
    path_parts: &[&str],
    new_blob_id: &ObjectId,
) -> Option<ObjectId> {
    if path_parts.is_empty() {
        return None;
    }

    let mut entries: Vec<TreeEntry> = current_tree
        .and_then(|t| repo.parse_tree(t))
        .unwrap_or_default();

    let target_name = path_parts[0];
    let is_final = path_parts.len() == 1;

    if is_final {
        // Add or replace the file
        entries.retain(|e| e.name != target_name);
        entries.push(TreeEntry {
            mode: "100644".to_string(),
            name: target_name.to_string(),
            oid: *new_blob_id,
            is_dir: false,
            is_executable: false,
            is_symlink: false,
        });
    } else {
        // Find or create subdirectory
        let existing_subtree = entries.iter().find(|e| e.name == target_name && e.is_dir);
        let subtree_oid = existing_subtree.map(|e| e.oid);

        let new_subtree_id = add_to_tree_recursive(
            repo,
            subtree_oid.as_ref(),
            &path_parts[1..],
            new_blob_id,
        )?;

        entries.retain(|e| e.name != target_name);
        entries.push(TreeEntry {
            mode: "40000".to_string(),
            name: target_name.to_string(),
            oid: new_subtree_id,
            is_dir: true,
            is_executable: false,
            is_symlink: false,
        });
    }

    let tree_data = serialize_tree(&entries);
    Some(repo.create_object(ObjectType::Tree, &tree_data))
}

/// Build a tree with a file deleted at the given path
pub fn build_tree_with_deletion(
    repo: &Repository,
    current_tree: &ObjectId,
    path: &str,
) -> Option<ObjectId> {
    let parts: Vec<&str> = path.split('/').collect();
    delete_from_tree_recursive(repo, current_tree, &parts)
}

fn delete_from_tree_recursive(
    repo: &Repository,
    current_tree: &ObjectId,
    path_parts: &[&str],
) -> Option<ObjectId> {
    if path_parts.is_empty() {
        return None;
    }

    let entries = repo.parse_tree(current_tree)?;
    let target_name = path_parts[0];
    let is_final = path_parts.len() == 1;

    let mut new_entries: Vec<TreeEntry> = Vec::new();

    for entry in entries {
        if entry.name == target_name {
            if is_final {
                // Skip this entry (delete it)
                continue;
            } else {
                // Recurse into subdirectory
                let new_subtree_id = delete_from_tree_recursive(
                    repo,
                    &entry.oid,
                    &path_parts[1..],
                )?;
                new_entries.push(TreeEntry {
                    mode: entry.mode,
                    name: entry.name,
                    oid: new_subtree_id,
                    is_dir: true,
                    is_executable: false,
                    is_symlink: false,
                });
            }
        } else {
            new_entries.push(entry);
        }
    }

    let tree_data = serialize_tree(&new_entries);
    Some(repo.create_object(ObjectType::Tree, &tree_data))
}

/// Serialize tree entries to git tree format
pub fn serialize_tree(entries: &[TreeEntry]) -> Vec<u8> {
    let mut data = Vec::new();

    // Sort entries (git requires sorted trees)
    let mut sorted_entries: Vec<_> = entries.iter().collect();
    sorted_entries.sort_by(|a, b| {
        // Directories end with / for sorting purposes
        let a_name = if a.is_dir { format!("{}/", a.name) } else { a.name.clone() };
        let b_name = if b.is_dir { format!("{}/", b.name) } else { b.name.clone() };
        a_name.cmp(&b_name)
    });

    for entry in sorted_entries {
        // Format: mode SP name NUL oid
        data.extend_from_slice(entry.mode.as_bytes());
        data.push(b' ');
        data.extend_from_slice(entry.name.as_bytes());
        data.push(0);
        data.extend_from_slice(entry.oid.as_bytes());
    }

    data
}
