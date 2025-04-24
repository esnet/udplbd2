// use crate::db::timeseries::TimeseriesData;
// use chrono::SecondsFormat;

// /// Converts timeseries data to CSV format
// pub fn timeseries_to_csv(series: &[TimeseriesData]) -> String {
//     let mut csv = String::new();

//     // Add header row
//     csv.push_str("timestamp,series_name,value\n");

//     // Add data rows
//     for ts in series {
//         for point in &ts.data {
//             // Format timestamp as ISO 8601 with Z suffix
//             let timestamp = point.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);

//             // Escape series name if it contains commas
//             let series_name = if ts.name.contains(',') {
//                 format!("\"{}\"", ts.name)
//             } else {
//                 ts.name.clone()
//             };

//             // Add row
//             csv.push_str(&format!("{},{},{}\n", timestamp, series_name, point.value));
//         }
//     }

//     csv
// }

// /// Converts timeseries data to CSV format with wide format (each series in its own column)
// pub fn timeseries_to_wide_csv(series: &[TimeseriesData]) -> String {
//     if series.is_empty() {
//         return String::from("timestamp\n");
//     }

//     // Collect all unique timestamps across all series
//     let mut all_timestamps = Vec::new();
//     for ts in series {
//         for point in &ts.data {
//             if !all_timestamps.contains(&point.timestamp) {
//                 all_timestamps.push(point.timestamp);
//             }
//         }
//     }

//     // Sort timestamps
//     all_timestamps.sort();

//     // Create header row with series names
//     let mut csv = String::from("timestamp");
//     for ts in series {
//         // Escape series name if it contains commas
//         let series_name = if ts.name.contains(',') {
//             format!("\"{}\"", ts.name)
//         } else {
//             ts.name.clone()
//         };

//         csv.push_str(&format!(",{}", series_name));
//     }
//     csv.push('\n');

//     // Add data rows
//     for timestamp in all_timestamps {
//         // Format timestamp as ISO 8601 with Z suffix
//         let timestamp_str = timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
//         csv.push_str(&timestamp_str);

//         // Add value for each series at this timestamp
//         for ts in series {
//             let value = ts
//                 .data
//                 .iter()
//                 .find(|point| point.timestamp == timestamp)
//                 .map(|point| point.value.to_string())
//                 .unwrap_or_default();

//             csv.push_str(&format!(",{}", value));
//         }

//         csv.push('\n');
//     }

//     csv
// }
