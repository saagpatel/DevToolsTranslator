#![forbid(unsafe_code)]

use dtt_core::{
    ReleaseArchV1, ReleaseArtifactKindV1, ReleaseArtifactV1, ReleasePlatformV1,
    UiBundleInspectFindingV1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

pub struct BundleInspectReadResult {
    pub summary_json: Value,
    pub findings: Vec<UiBundleInspectFindingV1>,
}

pub fn build_release_artifacts(
    run_id: &str,
    version: &str,
    dry_run: bool,
) -> std::io::Result<Vec<ReleaseArtifactV1>> {
    build_release_artifacts_for_platform(
        run_id,
        version,
        dry_run,
        ReleasePlatformV1::Macos,
        ReleaseArchV1::X64,
        "x86_64-apple-darwin",
        &[
            (
                ReleaseArtifactKindV1::MacZip,
                format!("dtt-desktop-macos-v{version}.zip"),
                "phase11-placeholder-mac-zip",
            ),
            (
                ReleaseArtifactKindV1::MacDmg,
                format!("dtt-desktop-macos-v{version}.dmg"),
                "phase11-placeholder-mac-dmg",
            ),
        ],
    )
}

pub fn build_release_matrix_artifacts(
    run_id: &str,
    version: &str,
    dry_run: bool,
) -> std::io::Result<Vec<ReleaseArtifactV1>> {
    let mut all = Vec::new();
    all.extend(build_release_artifacts_for_platform(
        run_id,
        version,
        dry_run,
        ReleasePlatformV1::Macos,
        ReleaseArchV1::X64,
        "x86_64-apple-darwin",
        &[
            (
                ReleaseArtifactKindV1::MacZip,
                format!("dtt-desktop-macos-v{version}.zip"),
                "phase11-placeholder-mac-zip",
            ),
            (
                ReleaseArtifactKindV1::MacDmg,
                format!("dtt-desktop-macos-v{version}.dmg"),
                "phase11-placeholder-mac-dmg",
            ),
        ],
    )?);
    all.extend(build_release_artifacts_for_platform(
        run_id,
        version,
        dry_run,
        ReleasePlatformV1::Windows,
        ReleaseArchV1::X64,
        "x86_64-pc-windows-msvc",
        &[
            (
                ReleaseArtifactKindV1::WindowsZip,
                format!("dtt-desktop-windows-v{version}.zip"),
                "phase11-placeholder-win-zip",
            ),
            (
                ReleaseArtifactKindV1::WindowsMsi,
                format!("dtt-desktop-windows-v{version}.msi"),
                "phase11-placeholder-win-msi",
            ),
        ],
    )?);
    all.extend(build_release_artifacts_for_platform(
        run_id,
        version,
        dry_run,
        ReleasePlatformV1::Linux,
        ReleaseArchV1::X64,
        "x86_64-unknown-linux-gnu",
        &[
            (
                ReleaseArtifactKindV1::LinuxTarGz,
                format!("dtt-desktop-linux-v{version}.tar.gz"),
                "phase11-placeholder-linux-tar-gz",
            ),
            (
                ReleaseArtifactKindV1::LinuxDeb,
                format!("dtt-desktop-linux-v{version}.deb"),
                "phase11-placeholder-linux-deb",
            ),
            (
                ReleaseArtifactKindV1::LinuxAppImage,
                format!("dtt-desktop-linux-v{version}.AppImage"),
                "phase11-placeholder-linux-appimage",
            ),
        ],
    )?);
    all.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(all)
}

pub fn read_bundle_summary(bundle_path: &Path) -> std::io::Result<BundleInspectReadResult> {
    let mut archive = open_archive(bundle_path)?;
    let manifest_json = read_json_entry(&mut archive, "manifest.json").unwrap_or(Value::Null);
    let findings = read_findings(&mut archive)?;
    let evidence_refs_count = read_ndjson(&mut archive, "analysis/evidence_refs.ndjson")
        .map(|rows| rows.len())
        .unwrap_or(0);

    let summary_json = serde_json::json!({
        "session_id": manifest_json.get("session_id").and_then(Value::as_str),
        "exported_at_ms": manifest_json.get("exported_at_ms").and_then(Value::as_i64),
        "privacy_mode": manifest_json.get("privacy_mode").and_then(Value::as_str),
        "profile": manifest_json.get("export_profile").and_then(Value::as_str),
        "findings_count": findings.len(),
        "evidence_refs_count": evidence_refs_count,
    });

    Ok(BundleInspectReadResult { summary_json, findings })
}

fn build_release_artifacts_for_platform(
    run_id: &str,
    version: &str,
    dry_run: bool,
    platform: ReleasePlatformV1,
    arch: ReleaseArchV1,
    target_triple: &str,
    concrete_artifacts: &[(ReleaseArtifactKindV1, String, &str)],
) -> std::io::Result<Vec<ReleaseArtifactV1>> {
    let root = std::env::temp_dir()
        .join("dtt-releases")
        .join(version)
        .join(run_id)
        .join(platform_slug(platform));
    fs::create_dir_all(&root)?;

    let mut artifacts = Vec::new();
    for (kind, filename, placeholder) in concrete_artifacts {
        let path = root.join(filename);
        if dry_run {
            artifacts.push(dry_run_artifact(*kind, platform, arch, target_triple, path));
        } else {
            fs::write(&path, placeholder.as_bytes())?;
            artifacts.push(artifact_for_file(*kind, platform, arch, target_triple, &path)?);
        }
    }
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));

    let checksums = root.join("checksums.sha256");
    let manifest = root.join("release-manifest.v1.json");
    if dry_run {
        artifacts.push(dry_run_artifact(
            ReleaseArtifactKindV1::Checksums,
            platform,
            arch,
            target_triple,
            checksums.clone(),
        ));
        artifacts.push(dry_run_artifact(
            ReleaseArtifactKindV1::ReleaseManifest,
            platform,
            arch,
            target_triple,
            manifest,
        ));
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        return Ok(artifacts);
    }

    let checksum_lines = artifacts
        .iter()
        .map(|artifact| format!("{}  {}", artifact.sha256, artifact.path))
        .collect::<Vec<String>>()
        .join("\n");
    fs::write(
        &checksums,
        if checksum_lines.is_empty() { String::new() } else { format!("{checksum_lines}\n") },
    )?;

    let manifest_json = serde_json::json!({
        "v": 1,
        "run_id": run_id,
        "version": version,
        "platform": platform,
        "arch": arch,
        "target_triple": target_triple,
        "artifacts": artifacts,
    });
    fs::write(&manifest, serde_json::to_vec_pretty(&manifest_json)?)?;

    artifacts.push(artifact_for_file(
        ReleaseArtifactKindV1::Checksums,
        platform,
        arch,
        target_triple,
        &checksums,
    )?);
    artifacts.push(artifact_for_file(
        ReleaseArtifactKindV1::ReleaseManifest,
        platform,
        arch,
        target_triple,
        &manifest,
    )?);
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(artifacts)
}

fn platform_slug(platform: ReleasePlatformV1) -> &'static str {
    match platform {
        ReleasePlatformV1::Macos => "macos",
        ReleasePlatformV1::Windows => "windows",
        ReleasePlatformV1::Linux => "linux",
    }
}

fn dry_run_artifact(
    kind: ReleaseArtifactKindV1,
    platform: ReleasePlatformV1,
    arch: ReleaseArchV1,
    target_triple: &str,
    path: PathBuf,
) -> ReleaseArtifactV1 {
    ReleaseArtifactV1 {
        kind,
        platform,
        arch,
        target_triple: target_triple.to_string(),
        path: path.to_string_lossy().to_string(),
        sha256: "dry_run".to_string(),
        size_bytes: 0,
    }
}

fn artifact_for_file(
    kind: ReleaseArtifactKindV1,
    platform: ReleasePlatformV1,
    arch: ReleaseArchV1,
    target_triple: &str,
    path: &Path,
) -> std::io::Result<ReleaseArtifactV1> {
    let bytes = fs::read(path)?;
    Ok(ReleaseArtifactV1 {
        kind,
        platform,
        arch,
        target_triple: target_triple.to_string(),
        path: path.to_string_lossy().to_string(),
        sha256: sha256_hex(&bytes),
        size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    })
}

fn open_archive(bundle_path: &Path) -> std::io::Result<ZipArchive<fs::File>> {
    let file = fs::File::open(bundle_path)?;
    ZipArchive::new(file).map_err(std::io::Error::other)
}

fn read_json_entry(archive: &mut ZipArchive<fs::File>, name: &str) -> std::io::Result<Value> {
    let mut file = archive.by_name(name).map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(std::io::Error::other)
}

fn read_findings(
    archive: &mut ZipArchive<fs::File>,
) -> std::io::Result<Vec<UiBundleInspectFindingV1>> {
    let rows = read_ndjson(archive, "analysis/findings.ndjson")?;
    let mut findings = Vec::new();
    for row in rows {
        findings.push(UiBundleInspectFindingV1 {
            finding_id: row
                .get("finding_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            detector_id: row
                .get("detector_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            title: row.get("title").and_then(Value::as_str).unwrap_or("Untitled").to_string(),
            summary: row.get("summary").and_then(Value::as_str).unwrap_or("No summary").to_string(),
            category: row.get("category").and_then(Value::as_str).unwrap_or("general").to_string(),
            severity_score: row
                .get("severity_score")
                .and_then(Value::as_u64)
                .map(|value| u8::try_from(value).unwrap_or(u8::MAX))
                .unwrap_or(0),
            confidence_score: row.get("confidence_score").and_then(Value::as_f64).unwrap_or(0.0),
            created_at_ms: row.get("created_at_ms").and_then(Value::as_i64).unwrap_or(0),
        });
    }
    findings.sort_by(|left, right| {
        right
            .severity_score
            .cmp(&left.severity_score)
            .then(left.detector_id.cmp(&right.detector_id))
            .then(left.finding_id.cmp(&right.finding_id))
    });
    Ok(findings)
}

fn read_ndjson(archive: &mut ZipArchive<fs::File>, name: &str) -> std::io::Result<Vec<Value>> {
    let mut file = archive.by_name(name).map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut output = Vec::new();
    for line in String::from_utf8_lossy(&bytes).lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        output.push(serde_json::from_str::<Value>(trimmed).map_err(std::io::Error::other)?);
    }
    Ok(output)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}
