//! Template engine setup.

use once_cell::sync::Lazy;
use tera::{Context, Tera};

/// Global template engine instance.
pub static TEMPLATES: Lazy<Tera> = Lazy::new(|| {
    // Load templates from the templates directory
    let template_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/web_ui/templates/**/*");
    match Tera::new(template_dir) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Template parsing error: {}", e);
            std::process::exit(1);
        }
    }
});

/// Render a template with context
pub fn render(template: &str, context: &Context) -> Result<String, tera::Error> {
    TEMPLATES.render(template, context)
}

/// Render markdown to sanitized HTML
pub fn render_markdown(markdown: &str) -> String {
    use pulldown_cmark::{Parser, Options, html};

    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(markdown, options);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);

    // Sanitize HTML to prevent XSS
    ammonia::clean(&html_output)
}
