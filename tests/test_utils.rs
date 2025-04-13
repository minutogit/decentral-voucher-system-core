// cargo test --test test_utils

#[cfg(test)]
mod tests {
    use voucher_lib::services::utils::{get_current_timestamp, get_timestamp};
    use chrono::{DateTime, Datelike, Timelike, Utc};

    use regex::Regex;

    // Helper function to parse the timestamp string and check basic format
    fn parse_and_validate_format(timestamp_str: &str) -> Result<DateTime<Utc>, String> {
        // Regex to validate the ISO 8601 format with microseconds and Z suffix
        // Example: 2023-10-27T10:30:55.123456Z
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$").unwrap();
        if !re.is_match(timestamp_str) {
            return Err(format!("Timestamp '{}' does not match expected format YYYY-MM-DDTHH:MM:SS.ffffffZ", timestamp_str));
        }

        // Try parsing the timestamp
        DateTime::parse_from_rfc3339(timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| format!("Failed to parse timestamp '{}': {}", timestamp_str, e))
    }

    #[test]
    fn test_get_current_timestamp_format() {
        let timestamp = get_current_timestamp();
        println!("Current Timestamp: {}", timestamp);
        assert!(parse_and_validate_format(&timestamp).is_ok());
    }

    #[test]
    fn test_get_timestamp_add_years() {
        let years_to_add = 2;
        let now = Utc::now();
        let expected_year = now.year() + years_to_add;

        let timestamp = get_timestamp(years_to_add, false);
        println!("Timestamp (+{} years): {}", years_to_add, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), expected_year, "Year should be incremented correctly");
        // We can't easily assert the exact day/month/time due to potential leap year adjustments
        // and the exact moment Utc::now() is called, but we check the year.
    }

    #[test]
    fn test_get_timestamp_end_of_current_year() {
        let now = Utc::now();
        let current_year = now.year();

        let timestamp = get_timestamp(0, true);
        println!("Timestamp (End of Current Year {}): {}", current_year, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), current_year, "Year should be the current year");
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        // Check for 999_999 microseconds (which corresponds to 999_999_000 nanoseconds)
        assert_eq!(parsed_dt.nanosecond(), 999_999_000, "Nanoseconds should indicate the last microsecond");
    }

    #[test]
    fn test_get_timestamp_end_of_future_year() {
        let years_to_add = 3;
        let now = Utc::now();
        let expected_year = now.year() + years_to_add;

        let timestamp = get_timestamp(years_to_add, true);
         println!("Timestamp (End of Future Year {}): {}", expected_year, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), expected_year, "Year should be the future year");
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(parsed_dt.nanosecond(), 999_999_000, "Nanoseconds should indicate the last microsecond");
    }

    // --- Tests related to Leap Year Logic ---
    // NOTE: Directly testing the internal leap year adjustment logic of `get_timestamp`
    // is difficult because it always starts from `Utc::now()`. We cannot easily force
    // it to start from Feb 29th without mocking the clock.
    // However, we can test the `end_of_year` flag in a leap year context and trust
    // that the underlying `chrono` library handles date calculations correctly,
    // including the fallback logic implemented in `get_timestamp`.

    #[test]
    fn test_get_timestamp_end_of_leap_year() {
        let now = Utc::now();
        let mut years_to_add = 0;
        // Find the next leap year relative to the current year
        loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                break; // Found a leap year
            }
            years_to_add += 1;
            if years_to_add > 4 { // Safety break
                 panic!("Could not find a leap year within 4 years for testing");
            }
        }

        let leap_year = now.year() + years_to_add;
        println!("Testing end_of_year for leap year: {}", leap_year);

        let timestamp = get_timestamp(years_to_add, true);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), leap_year, "Year should be the target leap year");
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(parsed_dt.nanosecond(), 999_999_000, "Nanoseconds should indicate the last microsecond");
    }

     #[test]
    fn test_get_timestamp_add_years_crossing_leap_day() {
        // This test demonstrates adding years, but doesn't guarantee crossing Feb 29th
        // in a specific way due to starting from Utc::now().
        // It primarily verifies the year increment is correct, even if the target is a leap year.
        let now = Utc::now();
        let mut years_to_add = 0;
        // Find the next leap year relative to the current year
         loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                 if years_to_add > 0 { // Ensure we actually add years
                    break;
                 }
            }
            years_to_add += 1;
            if years_to_add > 4 { // Safety break
                 panic!("Could not find a future leap year within 4 years for testing");
            }
        }

        let target_leap_year = now.year() + years_to_add;
        println!("Testing add_years to reach leap year: {}", target_leap_year);

        let timestamp = get_timestamp(years_to_add, false);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), target_leap_year, "Year should be the target leap year");
        // Further assertions on day/month are unreliable without mocking time.
    }
}
