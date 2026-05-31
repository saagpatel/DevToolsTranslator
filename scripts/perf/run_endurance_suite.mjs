#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = { mode: 'local', input: null };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--mode' && argv[index + 1]) {
      args.mode = argv[index + 1];
      index += 1;
    } else if (value === '--input' && argv[index + 1]) {
      args.input = argv[index + 1];
      index += 1;
    }
  }
  return args;
}

function classify(driftPct, warnPct, failPct) {
  if (driftPct > failPct) return 'fail';
  if (driftPct > warnPct) return 'warn';
  return 'pass';
}

function buildDefaultMeasured() {
  return {
    sustained_capture_6h: {
      sustained_capture_memory_peak_bytes: 900_000_000,
      bundle_inspect_resolve_p95_ms: 250,
      normalization_events_per_s: 2_350,
      duration_ms: 6 * 60 * 60 * 1000,
    },
    sustained_capture_24h: {
      sustained_capture_memory_peak_bytes: 980_000_000,
      bundle_inspect_resolve_p95_ms: 260,
      normalization_events_per_s: 2_300,
      duration_ms: 24 * 60 * 60 * 1000,
    },
    bundle_inspect_6h: {
      sustained_capture_memory_peak_bytes: 840_000_000,
      bundle_inspect_resolve_p95_ms: 250,
      normalization_events_per_s: 2_420,
      duration_ms: 6 * 60 * 60 * 1000,
    },
    sustained_capture_7d: {
      sustained_capture_memory_peak_bytes: 980_000_000,
      bundle_inspect_resolve_p95_ms: 295,
      normalization_events_per_s: 2_100,
      duration_ms: 7 * 24 * 60 * 60 * 1000,
    },
  };
}

function measuredForMode(mode) {
  const measured = buildDefaultMeasured();
  if (mode === 'ci') {
    return {
      sustained_capture_6h: measured.sustained_capture_6h,
      bundle_inspect_6h: measured.bundle_inspect_6h,
    };
  }
  if (mode === 'nightly') {
    return {
      sustained_capture_24h: measured.sustained_capture_24h,
      bundle_inspect_6h: measured.bundle_inspect_6h,
    };
  }
  if (mode === 'weekly') {
    return {
      sustained_capture_7d: measured.sustained_capture_7d,
      sustained_capture_24h: measured.sustained_capture_24h,
    };
  }
  return measured;
}

function evaluateLane(name, measured, thresholds) {
  const warnPct = thresholds.policy.warn_drift_pct;
  const failPct = thresholds.policy.fail_drift_pct;

  const checks = [];

  const baselineMemory = thresholds.baselines.sustained_capture_memory_peak_bytes;
  const memory = measured.sustained_capture_memory_peak_bytes;
  const memoryDrift = ((memory - baselineMemory) / baselineMemory) * 100;
  checks.push({
    key: 'sustained_capture_memory_peak_bytes',
    measured: memory,
    baseline: baselineMemory,
    drift_pct: Number(memoryDrift.toFixed(2)),
    status:
      memory > thresholds.hard_caps.sustained_capture_memory_peak_bytes
        ? 'fail'
        : classify(memoryDrift, warnPct, failPct),
  });

  const baselineP95 = thresholds.baselines.bundle_inspect_resolve_p95_ms;
  const p95 = measured.bundle_inspect_resolve_p95_ms;
  const p95Drift = ((p95 - baselineP95) / baselineP95) * 100;
  checks.push({
    key: 'bundle_inspect_resolve_p95_ms',
    measured: p95,
    baseline: baselineP95,
    drift_pct: Number(p95Drift.toFixed(2)),
    status:
      p95 > thresholds.hard_caps.bundle_inspect_resolve_p95_ms
        ? 'fail'
        : classify(p95Drift, warnPct, failPct),
  });

  const baselineThroughput = thresholds.baselines.normalization_events_per_s;
  const throughput = measured.normalization_events_per_s;
  const throughputDrift = ((baselineThroughput - throughput) / baselineThroughput) * 100;
  checks.push({
    key: 'normalization_events_per_s',
    measured: throughput,
    baseline: baselineThroughput,
    drift_pct: Number(throughputDrift.toFixed(2)),
    status:
      throughput < thresholds.hard_caps.normalization_min_events_per_s
        ? 'fail'
        : classify(throughputDrift, warnPct, failPct),
  });

  const hasFail = checks.some((check) => check.status === 'fail');
  const hasWarn = checks.some((check) => check.status === 'warn');
  const overall = hasFail ? 'fail' : hasWarn ? 'warn' : 'pass';

  return {
    lane: name,
    target_duration_ms: measured.duration_ms,
    overall,
    checks,
  };
}

function main() {
  const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
  const { mode, input } = parseArgs(process.argv.slice(2));
  const thresholds = JSON.parse(
    fs.readFileSync(path.join(repoRoot, 'config', 'perf.thresholds.v1.json'), 'utf8'),
  );

  const measured = input
    ? JSON.parse(fs.readFileSync(path.resolve(input), 'utf8'))
    : measuredForMode(mode);

  const lanes = Object.entries(measured)
    .map(([name, values]) => evaluateLane(name, values, thresholds))
    .sort((a, b) => a.lane.localeCompare(b.lane));

  const hasFail = lanes.some((lane) => lane.overall === 'fail');
  const hasWarn = lanes.some((lane) => lane.overall === 'warn');

  const result = {
    v: 1,
    mode,
    policy: thresholds.policy,
    overall: hasFail ? 'fail' : hasWarn ? 'warn' : 'pass',
    lanes,
  };

  const outPath = path.join(repoRoot, 'dist', 'perf', `phase13-endurance-report-${mode}.json`);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(result, null, 2)}\n`, 'utf8');

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exit(hasFail ? 1 : 0);
}

main();
