use serde_json::{Map, Value};

/// Node `userPreferencesSchema.partial()` (strict): the validated object, or None.
pub fn validate(input: &Value) -> Option<Map<String, Value>> {
    let mut out = Map::new();
    for (key, value) in input.as_object()? {
        let valid = match key.as_str() {
            "theme" => one_of(value, &["light", "dark"]),
            "dashboardSortField" => one_of(value, &["name", "createdAt", "updatedAt"]),
            "dashboardSortDirection" => one_of(value, &["asc", "desc"]),
            "language" => value
                .as_str()
                .map(str::trim)
                .filter(|s| (1..=35).contains(&s.chars().count()))
                .map(|s| Value::String(s.to_string())),
            "gridStep" => value
                .as_i64()
                .filter(|n| (1..=100).contains(n))
                .map(Value::from),
            "editorAutoHide" | "compactSidebar" => value.as_bool().map(Value::Bool),
            _ => None,
        };
        out.insert(key.clone(), valid?);
    }
    Some(out)
}

fn one_of(value: &Value, allowed: &[&str]) -> Option<Value> {
    value
        .as_str()
        .filter(|s| allowed.contains(s))
        .map(|s| Value::String(s.to_string()))
}

/// Node `parseStoredPreferences`: stored JSON that fails validation becomes `{}`.
pub fn parse_stored(raw: Option<&str>) -> Map<String, Value> {
    raw.and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|value| validate(&value))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_known_fields() {
        let input = json!({
            "theme": "light", "dashboardSortField": "updatedAt",
            "dashboardSortDirection": "desc", "language": " id ", "gridStep": 100,
            "editorAutoHide": false, "compactSidebar": true
        });
        let out = validate(&input).unwrap();
        assert_eq!(
            out["language"], "id",
            "language is trimmed like zod .trim()"
        );
        assert_eq!(out["gridStep"], 100);
        assert_eq!(validate(&json!({})).unwrap().len(), 0);
    }

    #[test]
    fn rejects_bad_values_and_unknown_keys() {
        for bad in [
            json!({"theme": "purple"}),
            json!({"dashboardSortField": "id"}),
            json!({"dashboardSortDirection": "up"}),
            json!({"language": "   "}),
            json!({"language": "x".repeat(36)}),
            json!({"gridStep": 0}),
            json!({"gridStep": 101}),
            json!({"gridStep": 1.5}),
            json!({"editorAutoHide": "yes"}),
            json!({"other": true}),
            json!([1]),
            json!(null),
        ] {
            assert!(validate(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn stored_preferences_fall_back_to_empty() {
        assert_eq!(parse_stored(None).len(), 0);
        assert_eq!(parse_stored(Some("not json")).len(), 0);
        assert_eq!(parse_stored(Some(r#"{"theme":"purple"}"#)).len(), 0);
        assert_eq!(parse_stored(Some(r#"{"theme":"dark"}"#))["theme"], "dark");
    }
}
