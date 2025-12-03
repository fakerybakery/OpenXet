//! Template engine setup and HTML templates.

use once_cell::sync::Lazy;
use tera::{Context, Tera};

/// Global template engine instance with embedded templates.
pub static TEMPLATES: Lazy<Tera> = Lazy::new(|| {
    let mut tera = Tera::default();

    // Embed templates directly in the binary (no external files needed)
    tera.add_raw_templates(vec![
        ("base.html", BASE_TEMPLATE),
        ("index.html", INDEX_TEMPLATE),
        ("repos.html", REPOS_TEMPLATE),
        ("repo.html", REPO_TEMPLATE),
        ("tree.html", TREE_TEMPLATE),
        ("blob.html", BLOB_TEMPLATE),
        ("edit.html", EDIT_TEMPLATE),
        ("error.html", ERROR_TEMPLATE),
    ])
    .expect("Failed to load templates");

    tera
});

/// Render a template with context
pub fn render(template: &str, context: &Context) -> Result<String, tera::Error> {
    TEMPLATES.render(template, context)
}

// =============================================================================
// Embedded Templates - OpenXet Dark Mode Design
// =============================================================================

const BASE_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}OpenXet{% endblock %}</title>
    <style>
        :root {
            --bg: #0a0a0a;
            --bg-secondary: #141414;
            --foreground: #fafafa;
            --foreground-secondary: rgba(250, 250, 250, 0.7);
            --foreground-tertiary: rgba(250, 250, 250, 0.4);
            --border: #262626;
            --border-subtle: #1a1a1a;
            --accent: #fafafa;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--foreground);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        a {
            color: var(--foreground);
            text-decoration: none;
            transition: opacity 0.15s;
        }
        a:hover { opacity: 0.7; }

        /* Header */
        .header {
            border-bottom: 1px solid var(--border-subtle);
            padding: 20px 32px;
        }
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .logo {
            font-size: 18px;
            font-weight: 600;
            letter-spacing: -0.02em;
            color: var(--foreground);
        }
        .nav {
            display: flex;
            gap: 32px;
        }
        .nav a {
            color: var(--foreground-secondary);
            font-size: 14px;
        }
        .nav a:hover {
            color: var(--foreground);
            opacity: 1;
        }

        /* Layout */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 48px 32px;
        }

        /* Typography */
        h1 {
            font-size: 32px;
            font-weight: 600;
            letter-spacing: -0.02em;
            margin-bottom: 32px;
        }
        h2 {
            font-size: 14px;
            font-weight: 500;
            color: var(--foreground-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 16px;
        }

        /* Cards */
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
        }
        .card + .card {
            margin-top: 24px;
        }

        /* Lists */
        .list { list-style: none; }
        .list-item {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            gap: 16px;
            transition: background 0.15s;
        }
        .list-item:last-child { border-bottom: none; }
        .list-item:hover { background: rgba(255, 255, 255, 0.02); }
        .list-item a { flex: 1; }

        /* Icons */
        .icon {
            width: 18px;
            height: 18px;
            color: var(--foreground-tertiary);
            flex-shrink: 0;
        }
        .icon-folder { color: var(--foreground-secondary); }

        /* Badges */
        .badge {
            font-size: 11px;
            font-weight: 500;
            padding: 4px 10px;
            border-radius: 100px;
            background: var(--border);
            color: var(--foreground-secondary);
            text-transform: uppercase;
            letter-spacing: 0.02em;
        }
        .badge-success {
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
        }
        .badge-warning {
            background: rgba(234, 179, 8, 0.15);
            color: #facc15;
        }
        .badge-info {
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
        }

        /* Stats */
        .stats {
            display: flex;
            gap: 16px;
            margin-bottom: 48px;
        }
        .stat {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px 32px;
            min-width: 160px;
        }
        .stat-value {
            font-size: 36px;
            font-weight: 600;
            letter-spacing: -0.02em;
        }
        .stat-label {
            color: var(--foreground-tertiary);
            font-size: 13px;
            margin-top: 4px;
        }

        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            border-radius: 100px;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.15s;
            border: none;
            cursor: pointer;
        }
        .btn-primary {
            background: var(--foreground);
            color: var(--bg);
        }
        .btn-primary:hover {
            opacity: 0.9;
        }
        .btn-secondary {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--foreground);
        }
        .btn-secondary:hover {
            background: var(--bg-secondary);
            border-color: var(--foreground-tertiary);
        }

        /* Code */
        code {
            font-family: 'SF Mono', 'Consolas', 'Liberation Mono', Menlo, monospace;
            font-size: 13px;
            background: var(--bg);
            border: 1px solid var(--border);
            padding: 12px 16px;
            border-radius: 8px;
            display: block;
            color: var(--foreground-secondary);
        }

        /* Breadcrumb */
        .breadcrumb {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 24px;
            font-size: 14px;
            color: var(--foreground-tertiary);
        }
        .breadcrumb a { color: var(--foreground-secondary); }
        .breadcrumb a:hover { color: var(--foreground); opacity: 1; }
        .breadcrumb-sep { color: var(--foreground-tertiary); }

        /* Empty state */
        .empty {
            text-align: center;
            padding: 64px 32px;
            color: var(--foreground-tertiary);
        }
        .empty p + p { margin-top: 8px; }

        /* Utility */
        .text-secondary { color: var(--foreground-secondary); }
        .text-tertiary { color: var(--foreground-tertiary); }
        .text-sm { font-size: 13px; }
        .mt-2 { margin-top: 8px; }
        .mt-4 { margin-top: 16px; }
        .mt-6 { margin-top: 24px; }
        .mb-4 { margin-bottom: 16px; }
        .flex { display: flex; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .gap-3 { gap: 12px; }
        .gap-4 { gap: 16px; }

        /* Section headers */
        .section-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .section-title {
            font-size: 13px;
            font-weight: 500;
            color: var(--foreground-secondary);
        }

        /* Mobile */
        @media (max-width: 768px) {
            .header { padding: 16px 20px; }
            .container { padding: 32px 20px; }
            .stats { flex-wrap: wrap; }
            .stat { min-width: calc(50% - 8px); }
            h1 { font-size: 24px; }
            .nav { gap: 20px; }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <a href="/" class="logo">OpenXet</a>
            <nav class="nav">
                <a href="/ui/repos">Repositories</a>
            </nav>
        </div>
    </header>
    <main class="container">
        {% block content %}{% endblock %}
    </main>
</body>
</html>"##;

const INDEX_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}OpenXet{% endblock %}
{% block content %}
<h1>Dashboard</h1>

<div class="stats">
    <div class="stat">
        <div class="stat-value">{{ repo_count }}</div>
        <div class="stat-label">Repositories</div>
    </div>
    <div class="stat">
        <div class="stat-value">{{ block_count }}</div>
        <div class="stat-label">Blocks</div>
    </div>
    <div class="stat">
        <div class="stat-value">{{ chunk_count }}</div>
        <div class="stat-label">Chunks</div>
    </div>
</div>

<h2>Quick Start</h2>
<div class="card">
    <div style="padding: 24px;">
        <p class="text-secondary mb-4">Clone a repository</p>
        <code>git clone http://localhost:8080/REPO_NAME.git</code>

        <p class="text-secondary mb-4 mt-6">Push to create a new repository</p>
        <code>git push http://localhost:8080/my-repo.git main</code>
    </div>
</div>

{% if repos %}
<h2 class="mt-6">Recent Repositories</h2>
<div class="card">
    <ul class="list">
        {% for repo in repos %}
        <li class="list-item">
            <svg class="icon icon-folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
            </svg>
            <a href="/ui/repos/{{ repo }}">{{ repo }}</a>
        </li>
        {% endfor %}
    </ul>
</div>
{% endif %}
{% endblock %}"##;

const REPOS_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}Repositories - OpenXet{% endblock %}
{% block content %}
<h1>Repositories</h1>

<div class="card">
    <div class="section-header">
        <span class="section-title">All repositories</span>
        <span class="badge">{{ repos | length }}</span>
    </div>
    {% if repos %}
    <ul class="list">
        {% for repo in repos %}
        <li class="list-item">
            <svg class="icon icon-folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
            </svg>
            <a href="/ui/repos/{{ repo }}">{{ repo }}</a>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <div class="empty">
        <p>No repositories yet</p>
        <p class="text-sm mt-2">Push to create your first repository</p>
        <code class="mt-4" style="display: inline-block; text-align: left;">git push http://localhost:8080/my-repo.git main</code>
    </div>
    {% endif %}
</div>
{% endblock %}"##;

const REPO_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}{{ repo_name }} - OpenXet{% endblock %}
{% block content %}
<div class="breadcrumb">
    <a href="/ui/repos">Repositories</a>
    <span class="breadcrumb-sep">/</span>
    <span>{{ repo_name }}</span>
</div>

<h1>{{ repo_name }}</h1>

<h2>Clone</h2>
<div class="card">
    <div style="padding: 20px;">
        <code>git clone http://localhost:8080/{{ repo_name }}.git</code>
    </div>
</div>

<h2 class="mt-6">Branches</h2>
<div class="card">
    {% if refs %}
    <ul class="list">
        {% for ref in refs %}
        <li class="list-item">
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
            </svg>
            <a href="/ui/repos/{{ repo_name }}/tree/{{ ref.name }}">{{ ref.name }}</a>
            <span class="badge">{{ ref.short_hash }}</span>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <div class="empty">
        <p>No branches yet</p>
        <p class="text-sm">This repository is empty</p>
    </div>
    {% endif %}
</div>
{% endblock %}"##;

const TREE_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}{{ repo_name }}/{{ path }} - OpenXet{% endblock %}
{% block content %}
<div class="breadcrumb">
    <a href="/ui/repos">Repositories</a>
    <span class="breadcrumb-sep">/</span>
    <a href="/ui/repos/{{ repo_name }}">{{ repo_name }}</a>
    <span class="breadcrumb-sep">/</span>
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}">{{ ref_name }}</a>
    {% for crumb in breadcrumbs %}
    <span class="breadcrumb-sep">/</span>
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}/{{ crumb.path }}">{{ crumb.name }}</a>
    {% endfor %}
</div>

<h1 class="flex items-center gap-3">
    <svg class="icon icon-folder" style="width: 28px; height: 28px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
    </svg>
    {{ current_name }}
</h1>

<div class="card">
    <div class="section-header">
        <span class="section-title">Files</span>
        <span class="badge">{{ entries | length }}</span>
    </div>
    {% if entries or parent_path %}
    <ul class="list">
        {% if parent_path %}
        <li class="list-item">
            <svg class="icon icon-folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
            </svg>
            <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}{% if parent_path != "" %}/{{ parent_path }}{% endif %}">..</a>
        </li>
        {% endif %}
        {% for entry in entries %}
        <li class="list-item">
            {% if entry.is_dir %}
            <svg class="icon icon-folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
            </svg>
            <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}/{{ entry.full_path }}">{{ entry.name }}</a>
            {% else %}
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            <a href="/ui/repos/{{ repo_name }}/blob/{{ ref_name }}/{{ entry.full_path }}">{{ entry.name }}</a>
            {% if entry.is_lfs %}
                {% if entry.lfs_status == "chunked" %}
                <span class="badge badge-success">Xet</span>
                {% elif entry.lfs_status == "processing" %}
                <span class="badge badge-warning">Processing</span>
                {% elif entry.lfs_status == "raw" %}
                <span class="badge badge-info">LFS</span>
                {% else %}
                <span class="badge">LFS</span>
                {% endif %}
            {% endif %}
            {% endif %}
            <div class="flex items-center gap-3" style="margin-left: auto;">
                {% if entry.lfs_size %}
                <span class="text-tertiary text-sm">{{ entry.lfs_size }}</span>
                {% endif %}
                {% if entry.is_lfs and entry.lfs_status and entry.lfs_oid %}
                <a href="/{{ repo_name }}.git/info/lfs/objects/{{ entry.lfs_oid }}" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;">
                    <svg style="width: 14px; height: 14px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
                    </svg>
                </a>
                {% endif %}
            </div>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <div class="empty">
        <p>Empty directory</p>
    </div>
    {% endif %}
</div>
{% endblock %}"##;

const BLOB_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}{{ repo_name }}/{{ path }} - OpenXet{% endblock %}
{% block content %}
<style>
    .code-container {
        background: var(--bg-secondary);
        border: 1px solid var(--border);
        border-radius: 16px;
        overflow: hidden;
    }
    .code-header {
        padding: 16px 20px;
        border-bottom: 1px solid var(--border-subtle);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .code-meta {
        display: flex;
        align-items: center;
        gap: 16px;
        font-size: 13px;
        color: var(--foreground-secondary);
    }
    .code-content {
        overflow-x: auto;
    }
    .code-table {
        width: 100%;
        border-collapse: collapse;
        font-family: 'SF Mono', 'Consolas', 'Liberation Mono', Menlo, monospace;
        font-size: 13px;
        line-height: 1.6;
    }
    .code-table td {
        padding: 0 20px;
        vertical-align: top;
    }
    .line-number {
        width: 1%;
        min-width: 50px;
        text-align: right;
        color: var(--foreground-tertiary);
        user-select: none;
        padding-right: 20px;
        border-right: 1px solid var(--border-subtle);
    }
    .line-content {
        white-space: pre;
        color: var(--foreground-secondary);
        padding-left: 20px;
    }
    .binary-notice {
        padding: 64px;
        text-align: center;
        color: var(--foreground-tertiary);
    }
</style>

<div class="breadcrumb">
    <a href="/ui/repos">Repositories</a>
    <span class="breadcrumb-sep">/</span>
    <a href="/ui/repos/{{ repo_name }}">{{ repo_name }}</a>
    <span class="breadcrumb-sep">/</span>
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}">{{ ref_name }}</a>
    {% for crumb in breadcrumbs %}
    <span class="breadcrumb-sep">/</span>
    {% if loop.last %}
    <span>{{ crumb.name }}</span>
    {% else %}
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}/{{ crumb.path }}">{{ crumb.name }}</a>
    {% endif %}
    {% endfor %}
</div>

<div class="flex items-center justify-between" style="margin-bottom: 32px;">
    <h1 class="flex items-center gap-3" style="margin-bottom: 0;">
        <svg class="icon" style="width: 28px; height: 28px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
        </svg>
        {{ file_name }}
        {% if is_lfs %}
            {% if lfs_status == "chunked" %}
            <span class="badge badge-success">Xet</span>
            {% elif lfs_status == "processing" %}
            <span class="badge badge-warning">Processing</span>
            {% elif lfs_status == "raw" %}
            <span class="badge badge-info">LFS</span>
            {% else %}
            <span class="badge">LFS</span>
            {% endif %}
        {% endif %}
    </h1>
    {% if is_lfs and lfs_status and lfs_oid %}
    <a href="/{{ repo_name }}.git/info/lfs/objects/{{ lfs_oid }}" class="btn btn-primary">
        <svg style="width: 16px; height: 16px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
        </svg>
        Download
    </a>
    {% endif %}
</div>

<div class="code-container">
    <div class="code-header">
        <div class="code-meta">
            <span>{{ size_display }}</span>
            {% if not is_lfs %}
            <span>{{ line_count }} lines</span>
            {% endif %}
        </div>
    </div>
    {% if is_binary %}
    <div class="binary-notice">
        <p>Binary file not shown</p>
        <p class="text-sm mt-2">{{ size_display }}</p>
    </div>
    {% else %}
    <div class="code-content">
        <table class="code-table">
            {% for line in lines %}
            <tr>
                <td class="line-number">{{ loop.index }}</td>
                <td class="line-content">{{ line }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}
</div>
{% endblock %}"##;

const EDIT_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}Edit {{ file_name }} - OpenXet{% endblock %}
{% block content %}
<style>
    .edit-container {
        background: var(--bg-secondary);
        border: 1px solid var(--border);
        border-radius: 16px;
        overflow: hidden;
    }
    .edit-header {
        padding: 16px 20px;
        border-bottom: 1px solid var(--border-subtle);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .edit-textarea {
        width: 100%;
        min-height: 500px;
        padding: 20px;
        background: var(--bg);
        border: none;
        color: var(--foreground-secondary);
        font-family: 'SF Mono', 'Consolas', 'Liberation Mono', Menlo, monospace;
        font-size: 13px;
        line-height: 1.6;
        resize: vertical;
    }
    .edit-textarea:focus {
        outline: none;
    }
    .commit-section {
        padding: 20px;
        border-top: 1px solid var(--border-subtle);
        background: var(--bg-secondary);
    }
    .commit-input {
        width: 100%;
        padding: 12px 16px;
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: 8px;
        color: var(--foreground);
        font-size: 14px;
        margin-bottom: 16px;
    }
    .commit-input:focus {
        outline: none;
        border-color: var(--foreground-tertiary);
    }
    .commit-input::placeholder {
        color: var(--foreground-tertiary);
    }
    .button-group {
        display: flex;
        gap: 12px;
        justify-content: flex-end;
    }
</style>

<div class="breadcrumb">
    <a href="/ui/repos">Repositories</a>
    <span class="breadcrumb-sep">/</span>
    <a href="/ui/repos/{{ repo_name }}">{{ repo_name }}</a>
    <span class="breadcrumb-sep">/</span>
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}">{{ ref_name }}</a>
    {% for crumb in breadcrumbs %}
    <span class="breadcrumb-sep">/</span>
    {% if loop.last %}
    <span>{{ crumb.name }}</span>
    {% else %}
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}/{{ crumb.path }}">{{ crumb.name }}</a>
    {% endif %}
    {% endfor %}
</div>

<div class="flex items-center justify-between" style="margin-bottom: 32px;">
    <h1 class="flex items-center gap-3" style="margin-bottom: 0;">
        <svg class="icon" style="width: 28px; height: 28px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
        </svg>
        Editing {{ file_name }}
    </h1>
</div>

<form method="POST" action="/ui/repos/{{ repo_name }}/edit/{{ ref_name }}/{{ path }}">
    <div class="edit-container">
        <div class="edit-header">
            <span class="text-secondary text-sm">{{ path }}</span>
        </div>
        <textarea name="content" class="edit-textarea" spellcheck="false">{{ content }}</textarea>
        <div class="commit-section">
            <input type="text" name="message" class="commit-input" placeholder="Commit message (optional)" />
            <div class="button-group">
                <a href="/ui/repos/{{ repo_name }}/blob/{{ ref_name }}/{{ path }}" class="btn btn-secondary">Cancel</a>
                <button type="submit" class="btn btn-primary">Commit changes</button>
            </div>
        </div>
    </div>
</form>
{% endblock %}"##;

const ERROR_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}Error - OpenXet{% endblock %}
{% block content %}
<div class="card">
    <div style="padding: 48px; text-align: center;">
        <h1 style="margin-bottom: 16px;">Something went wrong</h1>
        <p class="text-secondary">{{ message }}</p>
        <a href="/" class="btn btn-secondary mt-6">Return home</a>
    </div>
</div>
{% endblock %}"##;
