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
// Embedded Templates
// =============================================================================

const BASE_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Git-Xet{% endblock %}</title>
    <style>
        :root {
            --bg: #0d1117;
            --bg-secondary: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --link: #58a6ff;
            --accent: #238636;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
        }
        a { color: var(--link); text-decoration: none; }
        a:hover { text-decoration: underline; }

        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 16px 24px;
        }
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            gap: 24px;
        }
        .logo {
            font-size: 20px;
            font-weight: 600;
            color: var(--text);
        }
        .nav { display: flex; gap: 16px; }
        .nav a { color: var(--text-muted); }
        .nav a:hover { color: var(--text); text-decoration: none; }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 24px;
        }

        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            margin-bottom: 16px;
        }
        .card-header {
            padding: 16px;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
        }
        .card-body { padding: 16px; }

        .list { list-style: none; }
        .list-item {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .list-item:last-child { border-bottom: none; }
        .list-item:hover { background: rgba(255,255,255,0.02); }

        .icon {
            width: 20px;
            height: 20px;
            fill: var(--text-muted);
        }

        .badge {
            font-size: 12px;
            padding: 2px 8px;
            border-radius: 12px;
            background: var(--border);
            color: var(--text-muted);
        }

        .stats {
            display: flex;
            gap: 24px;
            margin-bottom: 24px;
        }
        .stat {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px 24px;
        }
        .stat-value {
            font-size: 32px;
            font-weight: 600;
        }
        .stat-label {
            color: var(--text-muted);
            font-size: 14px;
        }

        .empty {
            text-align: center;
            padding: 48px;
            color: var(--text-muted);
        }

        .breadcrumb {
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
            color: var(--text-muted);
        }
        .breadcrumb a { color: var(--link); }

        code {
            background: var(--bg);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 14px;
        }

        .file-icon { color: var(--text-muted); }
        .folder-icon { color: #54aeff; }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <a href="/" class="logo">Git-Xet</a>
            <nav class="nav">
                <a href="/ui/repos">Repositories</a>
                <a href="/ui/stats">Stats</a>
            </nav>
        </div>
    </header>
    <main class="container">
        {% block content %}{% endblock %}
    </main>
</body>
</html>"##;

const INDEX_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}Git-Xet Server{% endblock %}
{% block content %}
<h1 style="margin-bottom: 24px;">Welcome to Git-Xet Server</h1>

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

<div class="card">
    <div class="card-header">Quick Start</div>
    <div class="card-body">
        <p style="margin-bottom: 12px;">Clone a repository:</p>
        <code>git clone http://localhost:8080/REPO_NAME.git</code>

        <p style="margin: 16px 0 12px;">Push to a repository:</p>
        <code>git push http://localhost:8080/REPO_NAME.git main</code>
    </div>
</div>

<div class="card">
    <div class="card-header">Recent Repositories</div>
    {% if repos %}
    <ul class="list">
        {% for repo in repos %}
        <li class="list-item">
            <svg class="icon folder-icon" viewBox="0 0 16 16"><path d="M1.75 1A1.75 1.75 0 000 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0016 13.25v-8.5A1.75 1.75 0 0014.25 3H7.5a.25.25 0 01-.2-.1l-.9-1.2C6.07 1.26 5.55 1 5 1H1.75z"/></svg>
            <a href="/ui/repos/{{ repo }}">{{ repo }}</a>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <div class="empty">No repositories yet</div>
    {% endif %}
</div>
{% endblock %}"##;

const REPOS_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}Repositories - Git-Xet{% endblock %}
{% block content %}
<h1 style="margin-bottom: 24px;">Repositories</h1>

<div class="card">
    <div class="card-header">All Repositories ({{ repos | length }})</div>
    {% if repos %}
    <ul class="list">
        {% for repo in repos %}
        <li class="list-item">
            <svg class="icon folder-icon" viewBox="0 0 16 16"><path d="M1.75 1A1.75 1.75 0 000 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0016 13.25v-8.5A1.75 1.75 0 0014.25 3H7.5a.25.25 0 01-.2-.1l-.9-1.2C6.07 1.26 5.55 1 5 1H1.75z"/></svg>
            <a href="/ui/repos/{{ repo }}">{{ repo }}</a>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <div class="empty">
        <p>No repositories yet.</p>
        <p style="margin-top: 8px;">Create one by pushing:</p>
        <code style="display: inline-block; margin-top: 8px;">git push http://localhost:8080/my-repo.git main</code>
    </div>
    {% endif %}
</div>
{% endblock %}"##;

const REPO_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}{{ repo_name }} - Git-Xet{% endblock %}
{% block content %}
<div class="breadcrumb">
    <a href="/ui/repos">Repositories</a>
    <span>/</span>
    <span>{{ repo_name }}</span>
</div>

<h1 style="margin-bottom: 24px;">{{ repo_name }}</h1>

<div class="card">
    <div class="card-header">Clone</div>
    <div class="card-body">
        <code>git clone http://localhost:8080/{{ repo_name }}.git</code>
    </div>
</div>

<div class="card">
    <div class="card-header">Branches</div>
    {% if refs %}
    <ul class="list">
        {% for ref in refs %}
        <li class="list-item">
            <svg class="icon" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M11.75 2.5a.75.75 0 100 1.5.75.75 0 000-1.5zm-2.25.75a2.25 2.25 0 113 2.122V6A2.5 2.5 0 0110 8.5H6a1 1 0 00-1 1v1.128a2.251 2.251 0 11-1.5 0V5.372a2.25 2.25 0 111.5 0v1.836A2.492 2.492 0 016 7h4a1 1 0 001-1v-.628A2.25 2.25 0 019.5 3.25zM4.25 12a.75.75 0 100 1.5.75.75 0 000-1.5zM3.5 3.25a.75.75 0 111.5 0 .75.75 0 01-1.5 0z"/></svg>
            <a href="/ui/repos/{{ repo_name }}/tree/{{ ref.name }}">{{ ref.name }}</a>
            <span class="badge">{{ ref.short_hash }}</span>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <div class="empty">No branches yet (empty repository)</div>
    {% endif %}
</div>
{% endblock %}"##;

const TREE_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}{{ repo_name }}/{{ path }} - Git-Xet{% endblock %}
{% block content %}
<div class="breadcrumb">
    <a href="/ui/repos">Repositories</a>
    <span>/</span>
    <a href="/ui/repos/{{ repo_name }}">{{ repo_name }}</a>
    <span>/</span>
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}">{{ ref_name }}</a>
    {% for crumb in breadcrumbs %}
    <span>/</span>
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}/{{ crumb.path }}">{{ crumb.name }}</a>
    {% endfor %}
</div>

<h1 style="margin-bottom: 24px; display: flex; align-items: center; gap: 12px;">
    <svg class="icon folder-icon" style="width: 32px; height: 32px;" viewBox="0 0 16 16"><path d="M1.75 1A1.75 1.75 0 000 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0016 13.25v-8.5A1.75 1.75 0 0014.25 3H7.5a.25.25 0 01-.2-.1l-.9-1.2C6.07 1.26 5.55 1 5 1H1.75z"/></svg>
    {{ current_name }}
</h1>

<div class="card">
    <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
        <span>Files</span>
        <span class="badge">{{ entries | length }} items</span>
    </div>
    {% if entries %}
    <ul class="list">
        {% if parent_path %}
        <li class="list-item">
            <svg class="icon folder-icon" viewBox="0 0 16 16"><path d="M1.75 1A1.75 1.75 0 000 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0016 13.25v-8.5A1.75 1.75 0 0014.25 3H7.5a.25.25 0 01-.2-.1l-.9-1.2C6.07 1.26 5.55 1 5 1H1.75z"/></svg>
            <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}{% if parent_path != "" %}/{{ parent_path }}{% endif %}">..</a>
        </li>
        {% endif %}
        {% for entry in entries %}
        <li class="list-item" style="display: flex; align-items: center; justify-content: space-between;">
            <div style="display: flex; align-items: center; gap: 12px;">
                {% if entry.is_dir %}
                <svg class="icon folder-icon" viewBox="0 0 16 16"><path d="M1.75 1A1.75 1.75 0 000 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0016 13.25v-8.5A1.75 1.75 0 0014.25 3H7.5a.25.25 0 01-.2-.1l-.9-1.2C6.07 1.26 5.55 1 5 1H1.75z"/></svg>
                <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}/{{ entry.full_path }}">{{ entry.name }}</a>
                {% else %}
                <svg class="icon file-icon" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M3.75 1.5a.25.25 0 00-.25.25v12.5c0 .138.112.25.25.25h9.5a.25.25 0 00.25-.25V6h-2.75A1.75 1.75 0 019 4.25V1.5H3.75zm6.75.062V4.25c0 .138.112.25.25.25h2.688a.252.252 0 00-.011-.013l-2.914-2.914a.272.272 0 00-.013-.011zM2 1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237v9.586A1.75 1.75 0 0113.25 16h-9.5A1.75 1.75 0 012 14.25V1.75z"/></svg>
                <a href="/ui/repos/{{ repo_name }}/blob/{{ ref_name }}/{{ entry.full_path }}">{{ entry.name }}</a>
                {% if entry.is_lfs %}
                    {% if entry.lfs_status == "chunked" %}
                    <span class="badge" style="background: #238636; color: white;">Xet</span>
                    {% elif entry.lfs_status == "processing" %}
                    <span class="badge" style="background: #9e6a03; color: white;">Processing</span>
                    {% elif entry.lfs_status == "raw" %}
                    <span class="badge" style="background: #1f6feb; color: white;">LFS</span>
                    {% else %}
                    <span class="badge" style="background: #6e7681;">LFS (not uploaded)</span>
                    {% endif %}
                {% endif %}
                {% endif %}
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
                {% if entry.lfs_size %}
                <span style="color: var(--text-muted); font-size: 13px;">{{ entry.lfs_size }}</span>
                {% endif %}
                {% if entry.is_lfs and entry.lfs_status and entry.lfs_oid %}
                <a href="/{{ repo_name }}.git/info/lfs/objects/{{ entry.lfs_oid }}" class="download-btn" style="padding: 4px 8px; background: var(--border); border-radius: 4px; font-size: 12px; color: var(--text);" title="Download">
                    <svg style="width: 14px; height: 14px; vertical-align: middle;" viewBox="0 0 16 16" fill="currentColor"><path d="M2.75 14A1.75 1.75 0 011 12.25v-2.5a.75.75 0 011.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 00.25-.25v-2.5a.75.75 0 011.5 0v2.5A1.75 1.75 0 0113.25 14H2.75z"/><path d="M7.25 7.689V2a.75.75 0 011.5 0v5.689l1.97-1.969a.749.749 0 111.06 1.06l-3.25 3.25a.749.749 0 01-1.06 0L4.22 6.78a.749.749 0 111.06-1.06l1.97 1.969z"/></svg>
                </a>
                {% endif %}
            </div>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <div class="empty">Empty directory</div>
    {% endif %}
</div>
{% endblock %}"##;

const BLOB_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}{{ repo_name }}/{{ path }} - Git-Xet{% endblock %}
{% block content %}
<style>
    .code-container {
        background: #0d1117;
        border-radius: 6px;
        overflow: hidden;
    }
    .code-header {
        padding: 8px 16px;
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .code-content {
        overflow-x: auto;
    }
    .code-table {
        width: 100%;
        border-collapse: collapse;
        font-family: 'SF Mono', 'Consolas', 'Liberation Mono', Menlo, monospace;
        font-size: 13px;
        line-height: 1.5;
    }
    .code-table td {
        padding: 0 16px;
        vertical-align: top;
    }
    .line-number {
        width: 1%;
        min-width: 50px;
        text-align: right;
        color: var(--text-muted);
        user-select: none;
        padding-right: 16px;
        border-right: 1px solid var(--border);
    }
    .line-content {
        white-space: pre;
        color: var(--text);
    }
    .binary-notice {
        padding: 48px;
        text-align: center;
        color: var(--text-muted);
    }
</style>

<div class="breadcrumb">
    <a href="/ui/repos">Repositories</a>
    <span>/</span>
    <a href="/ui/repos/{{ repo_name }}">{{ repo_name }}</a>
    <span>/</span>
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}">{{ ref_name }}</a>
    {% for crumb in breadcrumbs %}
    <span>/</span>
    {% if loop.last %}
    <span>{{ crumb.name }}</span>
    {% else %}
    <a href="/ui/repos/{{ repo_name }}/tree/{{ ref_name }}/{{ crumb.path }}">{{ crumb.name }}</a>
    {% endif %}
    {% endfor %}
</div>

<h1 style="margin-bottom: 24px; display: flex; align-items: center; gap: 12px;">
    <svg class="icon file-icon" style="width: 32px; height: 32px;" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M3.75 1.5a.25.25 0 00-.25.25v12.5c0 .138.112.25.25.25h9.5a.25.25 0 00.25-.25V6h-2.75A1.75 1.75 0 019 4.25V1.5H3.75zm6.75.062V4.25c0 .138.112.25.25.25h2.688a.252.252 0 00-.011-.013l-2.914-2.914a.272.272 0 00-.013-.011zM2 1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237v9.586A1.75 1.75 0 0113.25 16h-9.5A1.75 1.75 0 012 14.25V1.75z"/></svg>
    {{ file_name }}
    {% if is_lfs %}
        {% if lfs_status == "chunked" %}
        <span class="badge" style="background: #238636; color: white;">Xet</span>
        {% elif lfs_status == "processing" %}
        <span class="badge" style="background: #9e6a03; color: white;">Processing</span>
        {% elif lfs_status == "raw" %}
        <span class="badge" style="background: #1f6feb; color: white;">LFS</span>
        {% else %}
        <span class="badge" style="background: #6e7681;">LFS (not uploaded)</span>
        {% endif %}
    {% endif %}
</h1>

<div class="card code-container">
    <div class="code-header">
        <div style="display: flex; align-items: center; gap: 12px;">
            <span>{{ size_display }}</span>
            {% if not is_lfs %}
            <span class="badge">{{ line_count }} lines</span>
            {% endif %}
        </div>
        {% if is_lfs and lfs_status and lfs_oid %}
        <a href="/{{ repo_name }}.git/info/lfs/objects/{{ lfs_oid }}" style="padding: 6px 12px; background: var(--accent); border-radius: 6px; font-size: 13px; color: white; display: inline-flex; align-items: center; gap: 6px;">
            <svg style="width: 16px; height: 16px;" viewBox="0 0 16 16" fill="currentColor"><path d="M2.75 14A1.75 1.75 0 011 12.25v-2.5a.75.75 0 011.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 00.25-.25v-2.5a.75.75 0 011.5 0v2.5A1.75 1.75 0 0113.25 14H2.75z"/><path d="M7.25 7.689V2a.75.75 0 011.5 0v5.689l1.97-1.969a.749.749 0 111.06 1.06l-3.25 3.25a.749.749 0 01-1.06 0L4.22 6.78a.749.749 0 111.06-1.06l1.97 1.969z"/></svg>
            Download
        </a>
        {% endif %}
    </div>
    {% if is_binary %}
    <div class="binary-notice">
        <p>Binary file not shown</p>
        <p style="margin-top: 8px; font-size: 14px;">{{ size_display }}</p>
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

const ERROR_TEMPLATE: &str = r##"{% extends "base.html" %}
{% block title %}Error - Git-Xet{% endblock %}
{% block content %}
<div class="card">
    <div class="card-header">Error</div>
    <div class="card-body">
        <p>{{ message }}</p>
        <p style="margin-top: 16px;"><a href="/">Return to home</a></p>
    </div>
</div>
{% endblock %}"##;
