use chrono::NaiveDateTime;

/// SQL for "now" as a UTC `TIMESTAMP(3)` value, matching what Prisma writes.
pub const NOW_UTC: &str = "timezone('utc', now())";

/// Formats a Prisma `TIMESTAMP(3)` (stored as UTC) the way `Date#toJSON` does.
pub fn iso(dt: NaiveDateTime) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn iso_matches_js_to_json() {
        let dt = NaiveDate::from_ymd_opt(2026, 10, 15)
            .unwrap()
            .and_hms_milli_opt(7, 5, 9, 42)
            .unwrap();
        assert_eq!(iso(dt), "2026-10-15T07:05:09.042Z");
    }
}
