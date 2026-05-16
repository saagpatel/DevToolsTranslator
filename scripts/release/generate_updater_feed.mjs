#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

function parseArgs(argv) {
  const args = {
    dryRun: false,
    version: null,
    channel: 'staged_public_prerelease',
    stage: null,
    evidencePackPath: null,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--dry-run') {
      args.dryRun = true;
    } else if (value === '--version' && argv[index + 1]) {
      args.version = argv[index + 1];
      index += 1;
    } else if (value === '--channel' && argv[index + 1]) {
      args.channel = argv[index + 1];
      index += 1;
    } else if (value === '--stage' && argv[index + 1]) {
      args.stage = argv[index + 1];
      index += 1;
    } else if (value === '--evidence-pack-path' && argv[index + 1]) {
      args.evidencePackPath = argv[index + 1];
      index += 1;
    }
  }
  return args;
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function rolloutPct(channel) {
  if (channel === 'internal_beta') return 100;
  if (channel === 'staged_public_prerelease') return 25;
  return 5;
}

function stageForPct(pct) {
  if (pct >= 100) return 'pct_100';
  if (pct >= 50) return 'pct_50';
  if (pct >= 25) return 'pct_25';
  return 'pct_5';
}

function main() {
  const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
  const { dryRun, version, channel, stage, evidencePackPath } = parseArgs(process.argv.slice(2));
  if (!version) {
    process.stderr.write('Missing required --version\n');
    process.exit(2);
  }

  const base = path.join(repoRoot, 'dist', 'releases', 'internal-beta', version);
  const feedDir = path.join(repoRoot, 'dist', 'releases', 'update-feed', channel);
  fs.mkdirSync(feedDir, { recursive: true });

  const configuredSignature = process.env.UPDATER_SIGNATURE?.trim() || '';
  const signature = configuredSignature || (dryRun ? 'dry_run_signature' : '');
  const signatureVerified = configuredSignature.length > 0;
  if (!dryRun && !signatureVerified) {
    process.stdout.write(
      `${JSON.stringify(
        {
          status: 'error',
          error_code: 'updater_signature_missing',
          message: 'UPDATER_SIGNATURE must be set for non-dry-run feed generation.',
        },
        null,
        2,
      )}\n`,
    );
    process.exit(1);
  }

  const pct = rolloutPct(channel);
  const resolvedStage = stage ?? stageForPct(pct);
  const defaultEvidencePath = path.join(
    repoRoot,
    'dist',
    'releases',
    'evidence',
    'updater',
    version,
    resolvedStage,
  );

  const latest = {
    v: 1,
    channel,
    version,
    rollout_pct: pct,
    rollout_stage: resolvedStage,
    signature_verified: signatureVerified,
    signature,
    compliance_evidence_pack_path: evidencePackPath ?? defaultEvidencePath,
    artifacts: [
      {
        platform: 'macos',
        arch: 'x64',
        url: `https://github.com/example/devtools-translator/releases/download/v${version}/dtt-desktop-macos-v${version}.zip`,
        sha256: dryRun ? 'dry_run' : sha256(Buffer.from(`macos:${version}`)),
      },
      {
        platform: 'windows',
        arch: 'x64',
        url: `https://github.com/example/devtools-translator/releases/download/v${version}/dtt-desktop-windows-v${version}.zip`,
        sha256: dryRun ? 'dry_run' : sha256(Buffer.from(`windows:${version}`)),
      },
      {
        platform: 'linux',
        arch: 'x64',
        url: `https://github.com/example/devtools-translator/releases/download/v${version}/dtt-desktop-linux-v${version}.tar.gz`,
        sha256: dryRun ? 'dry_run' : sha256(Buffer.from(`linux:${version}`)),
      },
    ].sort((left, right) =>
      `${left.platform}:${left.arch}`.localeCompare(`${right.platform}:${right.arch}`),
    ),
    stage_metadata: {
      stage: resolvedStage,
      policy: '5/25/50/100',
      soak_hours_min: 24,
    },
    source_manifest: path.join(base, 'release-manifest.v1.json'),
  };

  const latestPath = path.join(feedDir, 'latest.json');
  fs.writeFileSync(latestPath, `${JSON.stringify(latest, null, 2)}\n`, 'utf8');

  process.stdout.write(
    `${JSON.stringify(
      {
        status: 'ok',
        dry_run: dryRun,
        channel,
        version,
        signature_verified: signatureVerified,
        latest_path: latestPath,
      },
      null,
      2,
    )}\n`,
  );
}

main();
