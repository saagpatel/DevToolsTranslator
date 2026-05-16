#![forbid(unsafe_code)]

use dtt_core::{PerfAnomalySeverityV1, UiPerfTrendPointV1};

#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyCandidate {
    pub bucket_start_ms: i64,
    pub metric_name: String,
    pub score: f64,
    pub baseline_value: f64,
    pub observed_value: f64,
    pub severity: PerfAnomalySeverityV1,
}

pub fn detect_anomalies(points: &[UiPerfTrendPointV1]) -> Vec<AnomalyCandidate> {
    let mut sorted = points.to_vec();
    sorted.sort_by_key(|point| point.bucket_start_ms);

    let mut output = Vec::new();
    for index in 0..sorted.len() {
        if index == 0 {
            continue;
        }
        let window_start = index.saturating_sub(20);
        let mut baseline_window = sorted[window_start..index]
            .iter()
            .map(|point| point.metric_value)
            .collect::<Vec<f64>>();
        if baseline_window.is_empty() {
            continue;
        }
        let baseline = median(&mut baseline_window);
        let mad = median_absolute_deviation(&baseline_window, baseline);
        let denom = (1.4826 * mad).max(1e-9);
        let observed = sorted[index].metric_value;
        let score = ((observed - baseline).abs()) / denom;
        let Some(severity) = severity_for_score(score) else {
            continue;
        };
        output.push(AnomalyCandidate {
            bucket_start_ms: sorted[index].bucket_start_ms,
            metric_name: sorted[index].metric_name.clone(),
            score,
            baseline_value: baseline,
            observed_value: observed,
            severity,
        });
    }

    output
}

pub fn severity_for_score(score: f64) -> Option<PerfAnomalySeverityV1> {
    if score >= 6.0 {
        return Some(PerfAnomalySeverityV1::Critical);
    }
    if score >= 4.5 {
        return Some(PerfAnomalySeverityV1::High);
    }
    if score >= 3.5 {
        return Some(PerfAnomalySeverityV1::Medium);
    }
    if score >= 2.5 {
        return Some(PerfAnomalySeverityV1::Low);
    }
    None
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let len = values.len();
    if len == 0 {
        return 0.0;
    }
    if len % 2 == 1 {
        values[len / 2]
    } else {
        (values[(len / 2) - 1] + values[len / 2]) / 2.0
    }
}

fn median_absolute_deviation(values: &[f64], center: f64) -> f64 {
    let mut deviations = values.iter().map(|value| (value - center).abs()).collect::<Vec<f64>>();
    median(&mut deviations)
}

#[cfg(test)]
mod tests {
    use super::{detect_anomalies, severity_for_score};
    use dtt_core::{PerfBudgetResultV1, UiPerfTrendPointV1};

    #[test]
    fn severity_threshold_boundaries() {
        assert!(severity_for_score(2.49).is_none());
        assert_eq!(severity_for_score(2.5), Some(dtt_core::PerfAnomalySeverityV1::Low));
        assert_eq!(severity_for_score(3.5), Some(dtt_core::PerfAnomalySeverityV1::Medium));
        assert_eq!(severity_for_score(4.5), Some(dtt_core::PerfAnomalySeverityV1::High));
        assert_eq!(severity_for_score(6.0), Some(dtt_core::PerfAnomalySeverityV1::Critical));
    }

    #[test]
    fn detects_outlier_from_recent_window() {
        let mut points = Vec::new();
        for offset in 0..22_i64 {
            points.push(UiPerfTrendPointV1 {
                run_kind: "sustained_capture_24h".to_string(),
                bucket_start_ms: 1000 + offset,
                metric_name: "drift_pct".to_string(),
                metric_value: if offset == 21 { 99.0 } else { 10.0 },
                baseline_value: 10.0,
                trend_delta_pct: 0.0,
                budget_result: PerfBudgetResultV1::Pass,
            });
        }
        let anomalies = detect_anomalies(&points);
        assert!(!anomalies.is_empty());
        assert_eq!(anomalies.last().map(|item| item.observed_value), Some(99.0));
    }
}
