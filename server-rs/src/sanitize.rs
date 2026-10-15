//! Ports of the input sanitizers in backend/src/security.ts.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

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

/// Why a drawing payload was rejected (Node `DrawingSanitizationError` or a schema failure).
#[derive(Debug, PartialEq)]
pub enum SanitizeError {
    /// Element/appState/file shape is invalid (Node: zod failure).
    Invalid,
    /// A file entry was rejected; `status` is 400 or 413, message names the file.
    File {
        status: u16,
        file_id: String,
        message: String,
    },
}

/// Node `sanitizeSvg`: SVG tag/attribute allow-list, local-only clip/mask refs,
/// `<image>` limited to safe data URLs or `/api/files/..`, `<use>` to `#id`.
pub fn svg(input: &str) -> String {
    const TAGS: [&str; 18] = [
        "svg", "defs", "pattern", "g", "image", "symbol", "use", "clipPath", "mask", "rect",
        "circle", "ellipse", "line", "polyline", "polygon", "path", "text", "tspan",
    ];
    // `xmlns:xlink` / `xlink:href` arrive as namespaced attributes with local
    // names `xlink` / `href`, so the local names are what the allow-list holds.
    const ATTRS: [&str; 49] = [
        "xmlns",
        "xlink",
        "version",
        "id",
        "viewBox",
        "preserveAspectRatio",
        "x",
        "y",
        "width",
        "height",
        "cx",
        "cy",
        "r",
        "rx",
        "ry",
        "x1",
        "y1",
        "x2",
        "y2",
        "points",
        "d",
        "fill",
        "fill-opacity",
        "fill-rule",
        "stroke",
        "stroke-width",
        "stroke-opacity",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-miterlimit",
        "stroke-dasharray",
        "stroke-dashoffset",
        "opacity",
        "transform",
        "clip-path",
        "mask",
        "clipPathUnits",
        "maskUnits",
        "maskContentUnits",
        "vector-effect",
        "patternUnits",
        "patternContentUnits",
        "font-size",
        "font-family",
        "font-weight",
        "letter-spacing",
        "text-anchor",
        "dominant-baseline",
        "href",
    ];
    let cleaned = ammonia::Builder::empty()
        .tags(TAGS.into())
        .generic_attributes(ATTRS.into())
        .clean_content_tags(
            [
                "script",
                "style",
                "foreignObject",
                "iframe",
                "noscript",
                "template",
                "title",
                "desc",
            ]
            .into(),
        )
        .url_schemes(["data", "http", "https"].into())
        .clean(input)
        .to_string();
    let local_refs = CLIP_OR_MASK_ATTR.replace_all(cleaned.trim(), |caps: &regex::Captures| {
        if LOCAL_URL_REF.is_match(&caps[1]) {
            caps[0].to_string()
        } else {
            String::new()
        }
    });
    sanitize_image_and_use_tags(&local_refs).trim().to_string()
}

static CLIP_OR_MASK_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\s(?:clip-path|mask)="([^"]*)""#).unwrap());
// JS `\w` is ASCII-only, so the ports spell the class out.
static LOCAL_URL_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^url\(#[A-Za-z0-9_-]+\)$").unwrap());
static IMAGE_OR_USE_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<(image|use)\b[^>]*>").unwrap());
static HREF_VALUE: LazyLock<[Regex; 4]> = LazyLock::new(|| {
    [
        r#"(?i)\shref\s*=\s*"([^"]*)""#,
        r#"(?i)\shref\s*=\s*'([^']*)'"#,
        r#"(?i)\sxlink:href\s*=\s*"([^"]*)""#,
        r#"(?i)\sxlink:href\s*=\s*'([^']*)'"#,
    ]
    .map(|re| Regex::new(re).unwrap())
});
static XLINK_HREF_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\sxlink:href\s*=\s*(?:"[^"]*"|'[^']*')"#).unwrap());
static HREF_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\shref\s*=\s*(?:"[^"]*"|'[^']*')"#).unwrap());
static HAS_HREF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\shref\s*=").unwrap());
static OPEN_IMAGE_OR_USE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<(image|use)\b").unwrap());
static SAFE_SVG_IMAGE_DATA_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^data:image/(?:png|jpe?g|gif|webp|avif|bmp|svg\+xml);base64,[a-z0-9+/=\s]+$")
        .unwrap()
});
static API_FILE_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/api/files/[A-Za-z0-9_-]{1,200}/[A-Za-z0-9_-]{1,200}$").unwrap()
});
static LOCAL_FRAGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^#[A-Za-z0-9_-]+$").unwrap());

/// Node `sanitizeSvgImageTags`: drop `<image>`/`<use>` tags whose href is not safe,
/// and normalize the surviving reference to a plain `href`.
fn sanitize_image_and_use_tags(content: &str) -> String {
    IMAGE_OR_USE_TAG
        .replace_all(content, |caps: &regex::Captures| {
            let tag_text = &caps[0];
            let is_use = caps[1].eq_ignore_ascii_case("use");
            let href = HREF_VALUE
                .iter()
                .find_map(|re| re.captures(tag_text))
                .map(|c| c[1].trim().to_string());
            let Some(href) = href.filter(|h| {
                if is_use {
                    LOCAL_FRAGMENT.is_match(h)
                } else {
                    SAFE_SVG_IMAGE_DATA_URL.is_match(h) || API_FILE_REF.is_match(h)
                }
            }) else {
                return String::new();
            };
            let without_xlink = XLINK_HREF_ATTR.replace_all(tag_text, "");
            let replacement = format!(" href=\"{href}\"");
            if HAS_HREF.is_match(&without_xlink) {
                HREF_ATTR
                    .replace(&without_xlink, regex::NoExpand(&replacement))
                    .into_owned()
            } else {
                OPEN_IMAGE_OR_USE
                    .replace(&without_xlink, |c: &regex::Captures| {
                        format!("<{}{replacement}", &c[1])
                    })
                    .into_owned()
            }
        })
        .into_owned()
}

/// Node `sanitizeElementText`: strip control chars, truncate; never HTML-escaped.
pub fn element_text(input: &str, max_len: usize) -> String {
    input
        .chars()
        .filter(|&c| !is_stripped_control(c))
        .take(max_len)
        .collect()
}

/// Node `sanitizeUrl` for element links.
pub fn url(input: &str) -> String {
    let trimmed = input.trim();
    let lower = trimmed.to_ascii_lowercase();
    let safe = ["https://", "http://", "mailto:", "/", "./", "../"]
        .iter()
        .any(|prefix| lower.starts_with(prefix));
    if safe {
        trimmed.to_string()
    } else {
        String::new()
    }
}

/// Field types checked by Node's `elementSchema` (all optional and nullable).
enum Kind {
    Num,
    Str,
    Bool,
    StrArray,
    Array,
    Object,
    NumOrShortStr,
    NonEmptyShortStr,
    Any,
}

fn kind_matches(kind: &Kind, v: &Value) -> bool {
    if v.is_null() {
        return true;
    }
    match kind {
        Kind::Num => v.is_number(),
        Kind::Str => v.is_string(),
        Kind::Bool => v.is_boolean(),
        Kind::StrArray => v.as_array().is_some_and(|a| a.iter().all(Value::is_string)),
        Kind::Array => v.is_array(),
        Kind::Object => v.is_object(),
        Kind::NumOrShortStr => {
            v.is_number() || v.as_str().is_some_and(|s| s.chars().count() <= 200)
        }
        Kind::NonEmptyShortStr => v
            .as_str()
            .is_some_and(|s| (1..=200).contains(&s.chars().count())),
        Kind::Any => true,
    }
}

const ELEMENT_FIELDS: [(&str, Kind); 29] = [
    ("id", Kind::NonEmptyShortStr),
    ("type", Kind::Str),
    ("x", Kind::Num),
    ("y", Kind::Num),
    ("width", Kind::Num),
    ("height", Kind::Num),
    ("angle", Kind::Num),
    ("strokeColor", Kind::Str),
    ("backgroundColor", Kind::Str),
    ("fillStyle", Kind::Str),
    ("strokeWidth", Kind::Num),
    ("strokeStyle", Kind::Str),
    ("roundness", Kind::Any),
    ("boundElements", Kind::Array),
    ("groupIds", Kind::StrArray),
    ("frameId", Kind::Str),
    ("seed", Kind::Num),
    ("version", Kind::Num),
    ("versionNonce", Kind::Num),
    ("isDeleted", Kind::Bool),
    ("opacity", Kind::Num),
    ("link", Kind::Str),
    ("locked", Kind::Bool),
    ("text", Kind::Str),
    ("fontSize", Kind::Num),
    ("fontFamily", Kind::NumOrShortStr),
    ("textAlign", Kind::Str),
    ("verticalAlign", Kind::Str),
    ("customData", Kind::Object),
];

/// Node `elementSchema` (passthrough) + text/link transforms; None if a typed field is wrong.
pub fn element(value: &Value) -> Option<Value> {
    let mut obj = value.as_object()?.clone();
    for (field, kind) in &ELEMENT_FIELDS {
        if let Some(v) = obj.get(*field) {
            if !kind_matches(kind, v) {
                return None;
            }
        }
    }
    if let Some(Value::String(text)) = obj.get_mut("text") {
        *text = element_text(text, 5000);
    }
    if let Some(Value::String(link)) = obj.get_mut("link") {
        *link = url(link);
    }
    Some(Value::Object(obj))
}

fn finite_in(v: &Value, min: f64, max: f64) -> bool {
    v.as_f64()
        .is_some_and(|n| n.is_finite() && n >= min && n <= max)
}

fn one_of(v: &Value, allowed: &[&str]) -> bool {
    v.as_str().is_some_and(|s| allowed.contains(&s))
}

fn bool_record(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|m| m.values().all(Value::is_boolean))
}

/// Node `appStateSchema` bounds; unknown keys pass through. None if a known field is wrong.
pub fn app_state(value: &Value) -> Option<Value> {
    let obj = value.as_object()?;
    for (key, v) in obj {
        if v.is_null() {
            continue;
        }
        let ok = match key.as_str() {
            "gridSize" => finite_in(v, 0.0, 1000.0),
            "gridStep" => finite_in(v, 1.0, 1000.0),
            "currentItemStrokeWidth" => finite_in(v, 0.0, 50.0),
            "currentItemFontSize" => finite_in(v, 1.0, 500.0),
            "scrollX" | "scrollY" => finite_in(v, -10_000_000.0, 10_000_000.0),
            "cursorX" | "cursorY" => finite_in(v, f64::MIN, f64::MAX),
            "viewBackgroundColor" | "currentItemStrokeColor" | "currentItemBackgroundColor" => {
                v.is_string()
            }
            "currentItemFillStyle" => one_of(v, &["solid", "hachure", "cross-hatch", "dots"]),
            "currentItemStrokeStyle" => one_of(v, &["solid", "dashed", "dotted"]),
            "currentItemTextAlign" => one_of(v, &["left", "center", "right"]),
            "currentItemVerticalAlign" => one_of(v, &["top", "middle", "bottom"]),
            "currentItemRoundness" => {
                one_of(v, &["sharp", "round"])
                    || (one_of(&v["type"], &["round", "sharp"]) && finite_in(&v["value"], 0.0, 1.0))
            }
            "currentItemFontFamily" => {
                finite_in(v, 0.0, f64::MAX) || v.as_str().is_some_and(|s| s.chars().count() <= 200)
            }
            "zoom" => finite_in(&v["value"], 0.01, 100.0),
            "selection" => v.as_array().is_some_and(|a| a.iter().all(Value::is_string)),
            "selectedElementIds" | "selectedGroupIds" => bool_record(v),
            "activeEmbeddable" => v["elementId"].is_string() && v["state"].is_string(),
            "activeTool" => {
                v["type"].is_string() && (v["customType"].is_null() || v["customType"].is_string())
            }
            "collaborators" => v.is_object(),
            _ => true,
        };
        if !ok {
            return None;
        }
    }
    Some(value.clone())
}

static SAFE_IMAGE_DATA_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^data:(?:image/png|image/jpeg|image/gif|image/webp|image/avif|image/bmp|image/svg\+xml);base64,[A-Za-z0-9+/=\s]+$",
    )
    .unwrap()
});
static VALID_FILE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,200}$").unwrap());

/// Byte length of a base64 body, like Node `Buffer.byteLength(b64, "base64")`.
fn base64_decoded_len(body: &str) -> usize {
    let clean: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let padding = clean.iter().rev().take_while(|&&b| b == b'=').count();
    (clean.len() * 3 / 4).saturating_sub(padding)
}

fn file_error(status: u16, file_id: &str, message: String) -> SanitizeError {
    SanitizeError::File {
        status,
        file_id: file_id.to_string(),
        message,
    }
}

/// Node `sanitizeDrawingData` files handling.
pub fn files(value: &Value, max_bytes: usize) -> Result<Value, SanitizeError> {
    let Some(map) = value.as_object() else {
        return Ok(value.clone());
    };
    let mut out = serde_json::Map::new();
    for (file_id, file) in map {
        if !VALID_FILE_ID.is_match(file_id) {
            continue;
        }
        let Some(fields) = file.as_object() else {
            out.insert(file_id.clone(), file.clone());
            continue;
        };
        let mut clean = serde_json::Map::new();
        for (key, v) in fields {
            let sanitized = match (key.as_str(), v.as_str()) {
                ("dataURL", Some(data_url)) => sanitize_data_url(file_id, data_url, max_bytes)?,
                (_, Some(s)) => text(s, 1000),
                (_, None) => String::new(),
            };
            clean.insert(key.clone(), Value::String(sanitized));
        }
        out.insert(file_id.clone(), Value::Object(clean));
    }
    Ok(Value::Object(out))
}

fn sanitize_data_url(
    file_id: &str,
    value: &str,
    max_bytes: usize,
) -> Result<String, SanitizeError> {
    if value.is_empty() || API_FILE_REF.is_match(value) {
        return Ok(value.to_string());
    }
    if value.starts_with("data:") {
        if !SAFE_IMAGE_DATA_URL.is_match(value) {
            return Err(file_error(
                400,
                file_id,
                format!("Image file \"{file_id}\" has an invalid or unsupported image data URL and was rejected."),
            ));
        }
        let body = value.split_once(',').map_or("", |(_, b)| b);
        if base64_decoded_len(body) > max_bytes {
            return Err(file_error(
                413,
                file_id,
                format!("Image file \"{file_id}\" exceeds the maximum allowed size of {max_bytes} bytes."),
            ));
        }
        return Ok(value.to_string());
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        if value.len() > 2048 {
            return Err(file_error(
                400,
                file_id,
                format!("Image file \"{file_id}\" has an invalid image URL and was rejected."),
            ));
        }
        return Ok(value.to_string());
    }
    Err(file_error(
        400,
        file_id,
        format!("Image file \"{file_id}\" has an invalid image reference and was rejected."),
    ))
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

    use serde_json::json;

    #[test]
    fn svg_keeps_allowed_geometry_and_camel_case() {
        let input = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" width="10"><defs><clipPath id="c1"><rect x="0" y="0" width="5" height="5"></rect></clipPath></defs><g clip-path="url(#c1)" transform="translate(1 1)"><path d="M0 0L5 5" stroke="#000" stroke-width="2"></path><text x="1" y="2" font-family="Virgil">hi &amp; bye</text></g></svg>"##;
        let out = svg(input);
        assert!(out.contains(r#"viewBox="0 0 10 10""#), "{out}");
        assert!(out.contains("<clipPath id=\"c1\">"), "{out}");
        assert!(out.contains(r##"clip-path="url(#c1)""##), "{out}");
        assert!(out.contains(r#"d="M0 0L5 5""#), "{out}");
        assert!(out.contains("hi &amp; bye"), "{out}");
    }

    #[test]
    fn svg_strips_scripts_handlers_and_forbidden_tags() {
        let input = r##"<svg onload="alert(1)"><script>alert(2)</script><foreignObject><div>x</div></foreignObject><style>*{}</style><filter id="f"></filter><marker id="m"></marker><rect width="1" height="1" onclick="x()" style="fill:red" class="c"></rect><a href="javascript:alert(3)"><text>t</text></a></svg>"##;
        let out = svg(input);
        for forbidden in [
            "onload",
            "alert",
            "script",
            "foreignObject",
            "<div",
            "style",
            "filter",
            "marker",
            "onclick",
            "class=",
            "javascript",
            "<a",
        ] {
            assert!(!out.contains(forbidden), "{forbidden} survived: {out}");
        }
        assert!(out.contains("<rect"), "{out}");
        assert!(out.contains("<text>t</text>"), "{out}");
    }

    #[test]
    fn svg_limits_clip_and_mask_to_local_refs() {
        let out = svg(
            r#"<svg><g clip-path="url(https://evil.example/x.svg#a)" mask="url(#ok)"><rect></rect></g></svg>"#,
        );
        assert!(!out.contains("evil"), "{out}");
        assert!(out.contains(r##"mask="url(#ok)""##), "{out}");
    }

    #[test]
    fn svg_image_and_use_hrefs() {
        let png = "data:image/png;base64,iVBORw0KGgo=";
        let out = svg(&format!(
            r##"<svg><image href="{png}" width="1"></image><image href="/api/files/d1/f1"></image><image href="http://evil.example/x.png"></image><image xlink:href="data:text/html;base64,PHNjcmlwdD4="></image><use href="#shape"></use><use href="http://evil.example/s.svg#x"></use></svg>"##
        ));
        assert!(out.contains(&format!(r#"href="{png}""#)), "{out}");
        assert!(out.contains(r#"href="/api/files/d1/f1""#), "{out}");
        assert!(!out.contains("evil"), "{out}");
        assert!(!out.contains("text/html"), "{out}");
        assert!(out.contains(r##"<use href="#shape""##), "{out}");
    }

    #[test]
    fn svg_converts_xlink_href_to_href() {
        let out = svg(r#"<svg><image xlink:href="/api/files/d1/f1"></image></svg>"#);
        assert!(out.contains(r#"<image href="/api/files/d1/f1""#), "{out}");
        assert!(!out.contains("xlink:href"), "{out}");
    }

    #[test]
    fn element_text_keeps_angle_brackets() {
        assert_eq!(element_text("3 < 4 & <ok>\u{1}", 5000), "3 < 4 & <ok>");
        assert_eq!(element_text("abcdef", 3), "abc");
    }

    #[test]
    fn url_allows_only_safe_schemes() {
        assert_eq!(url(" https://x.example/a "), "https://x.example/a");
        assert_eq!(url("mailto:a@b.c"), "mailto:a@b.c");
        assert_eq!(url("/drawings/1"), "/drawings/1");
        assert_eq!(url("../up"), "../up");
        assert_eq!(url("JavaScript:alert(1)"), "");
        assert_eq!(url("data:text/html,x"), "");
        assert_eq!(url("vbscript:x"), "");
        assert_eq!(url("ftp://x"), "");
        assert_eq!(url("example.com"), "");
    }

    #[test]
    fn element_transforms_text_and_link_and_passes_unknown_fields() {
        let out = element(&json!({
            "id": "e1", "type": "text", "x": 1.5, "text": "a\u{0}<b>", "link": "javascript:x",
            "customField": {"keep": true}, "groupIds": ["g"], "isDeleted": false
        }))
        .unwrap();
        assert_eq!(out["text"], "a<b>");
        assert_eq!(out["link"], "");
        assert_eq!(out["customField"], json!({"keep": true}));
    }

    #[test]
    fn element_rejects_wrong_types() {
        for bad in [
            json!({"x": "1"}),
            json!({"id": ""}),
            json!({"isDeleted": "no"}),
            json!({"groupIds": [1]}),
            json!({"boundElements": {}}),
            json!({"customData": []}),
            json!({"fontFamily": true}),
            json!("not an object"),
        ] {
            assert!(element(&bad).is_none(), "{bad}");
        }
        assert!(element(&json!({"x": null, "fontFamily": "Virgil"})).is_some());
    }

    #[test]
    fn app_state_bounds() {
        let ok = json!({
            "gridSize": 20, "zoom": {"value": 1}, "viewBackgroundColor": "#fff",
            "currentItemRoundness": {"type": "round", "value": 0.5}, "theme": "dark", "name": ""
        });
        assert_eq!(app_state(&ok).unwrap(), ok);
        for bad in [
            json!({"gridSize": 5000}),
            json!({"zoom": {"value": 0}}),
            json!({"currentItemFillStyle": "zigzag"}),
            json!({"currentItemRoundness": "curvy"}),
            json!({"selectedElementIds": {"a": "yes"}}),
            json!({"scrollX": 1e9}),
            json!([]),
        ] {
            assert!(app_state(&bad).is_none(), "{bad}");
        }
    }

    const PNG: &str = "data:image/png;base64,iVBORw0KGgo=";

    #[test]
    fn files_keep_valid_entries_and_drop_bad_ids() {
        let out = files(
            &json!({
                "f1": {"id": "f1", "mimeType": "image/png", "dataURL": PNG, "created": 1700000000},
                "bad id!": {"dataURL": PNG},
                "f2": {"dataURL": "/api/files/d1/f2"},
                "f3": {"dataURL": "https://cdn.example/x.png"},
                "f4": {"dataURL": ""},
                "f5": "not-an-object"
            }),
            1024,
        )
        .unwrap();
        assert_eq!(out["f1"]["dataURL"], PNG);
        assert_eq!(out["f1"]["mimeType"], "image/png");
        assert_eq!(
            out["f1"]["created"], "",
            "Node turns non-string fields into \"\""
        );
        assert!(out.get("bad id!").is_none());
        assert_eq!(out["f2"]["dataURL"], "/api/files/d1/f2");
        assert_eq!(out["f3"]["dataURL"], "https://cdn.example/x.png");
        assert_eq!(out["f4"]["dataURL"], "");
        assert_eq!(out["f5"], "not-an-object");
    }

    #[test]
    fn files_reject_unsafe_and_oversized_images() {
        let err = files(
            &json!({"f1": {"dataURL": "data:text/html;base64,PGI+"}}),
            1024,
        )
        .unwrap_err();
        assert!(
            matches!(err, SanitizeError::File { status: 400, ref file_id, .. } if file_id == "f1")
        );
        let err = files(&json!({"f1": {"dataURL": "javascript:alert(1)"}}), 1024).unwrap_err();
        assert!(matches!(err, SanitizeError::File { status: 400, .. }));
        let long = format!("https://x.example/{}", "a".repeat(2048));
        let err = files(&json!({"f1": {"dataURL": long}}), 1024).unwrap_err();
        assert!(matches!(err, SanitizeError::File { status: 400, .. }));
        let err = files(&json!({"f1": {"dataURL": PNG}}), 4).unwrap_err();
        assert!(matches!(err, SanitizeError::File { status: 413, .. }));
    }
}
