//! Ports of the input sanitizers in backend/src/security.ts.

/// Node `sanitizeText`: strip control chars, truncate to `max_len` chars, then keep
/// only `b i u em strong br span` (no attributes); other tags are unwrapped and
/// `script`/`style` are dropped with their content.
pub fn text(input: &str, max_len: usize) -> String {
    let truncated: String = input
        .chars()
        .filter(|&c| !is_stripped_control(c))
        .take(max_len)
        .collect();
    ammonia::Builder::empty()
        .tags(["b", "i", "u", "em", "strong", "br", "span"].into())
        .clean(&truncated)
        .to_string()
}

/// `[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]` (keeps \t \n \r).
fn is_stripped_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{7f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_keeps_plain_text() {
        assert_eq!(text("Project Ideas", 100), "Project Ideas");
    }

    #[test]
    fn text_strips_control_chars_and_truncates_by_chars() {
        assert_eq!(text("a\u{0}b\u{7}c\u{7f}", 100), "abc");
        assert_eq!(text("ééééé", 3), "ééé");
        assert_eq!(text("tab\tand\nnewline", 100), "tab\tand\nnewline");
    }

    #[test]
    fn text_removes_dangerous_markup() {
        assert_eq!(text("<script>alert(1)</script>Hi", 100), "Hi");
        assert_eq!(text("<img src=x onerror=alert(1)>Hi", 100), "Hi");
        assert_eq!(text("<a href=\"javascript:x\">link</a>", 100), "link");
        assert_eq!(text("<b onclick=\"x\">bold</b>", 100), "<b>bold</b>");
        assert_eq!(text("<style>p{}</style>ok", 100), "ok");
    }

    #[test]
    fn text_escapes_like_dom_serialization() {
        assert_eq!(text("Tom & Jerry", 100), "Tom &amp; Jerry");
        assert_eq!(text("1 < 2", 100), "1 &lt; 2");
    }
}
