#!/usr/bin/env python3
import hashlib, json, os, pathlib, plistlib, subprocess, sys

mode, root, app, dmg, receipt_path = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]), pathlib.Path(sys.argv[5])
def run(*args): return subprocess.run(args,text=True,capture_output=True)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def git(*args):
 r=run("git",*args); return r.stdout.strip() if r.returncode==0 else "unknown"
info_path=app/"Contents/Info.plist"; privacy_path=app/"Contents/Resources/PrivacyInfo.xcprivacy"; binary=app/"Contents/MacOS/Glassbox"
info=plistlib.loads(info_path.read_bytes()) if info_path.is_file() else {}
privacy=plistlib.loads(privacy_path.read_bytes()) if privacy_path.is_file() else {}
verify=run("codesign","--verify","--deep","--strict",str(app)); details=run("codesign","-dvvv","--entitlements",":-",str(app)); sign_text=details.stdout+details.stderr
entitlements={}
try:
 start=sign_text.index("<?xml"); end=sign_text.index("</plist>",start)+len("</plist>"); entitlements=plistlib.loads(sign_text[start:end].encode())
except Exception: pass
dmg_sign=run("codesign","--verify","--strict",str(dmg)); dmg_verify=run("hdiutil","verify",str(dmg))
app_staple=run("xcrun","stapler","validate",str(app)); dmg_staple=run("xcrun","stapler","validate",str(dmg)); gatekeeper=run("spctl","-a","-vvv","--type","execute",str(app))
config_path=root/"apps/glassbox-desktop/src-tauri/tauri.conf.json"; config=json.loads(config_path.read_text())
privacy_audit_path=pathlib.Path(os.environ.get("GLASSBOX_PRIVACY_AUDIT_RECEIPT","")); privacy_audit={}
if privacy_audit_path.is_file(): privacy_audit=json.loads(privacy_audit_path.read_text())
executable_files=[]
for path in app.rglob("*"):
 if path.is_file() and path.stat().st_mode & 0o111: executable_files.append(path.relative_to(app).as_posix())
local_checks={
 "app_and_dmg_exist":app.is_dir() and dmg.is_file(),
 "bundle_identifier_is_glassbox":info.get("CFBundleIdentifier")=="com.glassbox.desktop" and info.get("CFBundleExecutable")=="Glassbox",
 "developer_id_signature_valid":verify.returncode==0 and "Authority=Developer ID Application:" in sign_text and "TeamIdentifier=3TGZFKFNA4" in sign_text,
 "hardened_runtime_enabled":"flags=0x10000(runtime)" in sign_text,
 "app_sandbox_only_entitlement":entitlements=={"com.apple.security.app-sandbox":True},
 "network_and_privileged_entitlements_absent":not any(key.startswith("com.apple.security.network") or key.startswith("com.apple.developer") for key in entitlements),
 "single_executable_closure":executable_files==["Contents/MacOS/Glassbox"],
 "privacy_manifest_present_and_no_collection":privacy.get("NSPrivacyTracking") is False and privacy.get("NSPrivacyTrackingDomains")==[] and privacy.get("NSPrivacyCollectedDataTypes")==[],
 "privacy_artifact_inventory_matches_reviewed_policy":privacy_audit.get("ok") is True and privacy_audit.get("binary_sha256")==sha(binary),
 "strict_offline_csp":config.get("app",{}).get("security",{}).get("csp","").find("connect-src 'none'")>=0 and "unsafe-eval" not in config.get("app",{}).get("security",{}).get("csp",""),
 "dmg_signature_valid":dmg_sign.returncode==0,
 "dmg_filesystem_valid":dmg_verify.returncode==0,
 "signed_app_runtime_launch":os.environ.get("GLASSBOX_SIGNED_RUNTIME_OK")=="1",
 "runtime_test_residue_clean":os.environ.get("GLASSBOX_RUNTIME_RESIDUE_CLEAN")=="1",
}
distribution_checks={"app_stapled":app_staple.returncode==0,"dmg_stapled":dmg_staple.returncode==0,"gatekeeper_accepts":gatekeeper.returncode==0}
readiness_ok=all(local_checks.values()) and not any(distribution_checks.values())
artifact_passed=all(local_checks.values()) and all(distribution_checks.values())
receipt={"schema_version":"glassbox-macos-artifact/v1","ok":artifact_passed,"artifact_passed":artifact_passed,"readiness_ok":readiness_ok,"gate6_promotable":artifact_passed,"git_head":git("rev-parse","HEAD"),"git_tree":git("rev-parse","HEAD^{tree}"),"git_dirty":bool(git("status","--porcelain")),"app_sha256":sha(binary) if binary.is_file() else None,"dmg_sha256":sha(dmg) if dmg.is_file() else None,"config_sha256":sha(config_path),"codesign_identity_line":next((line for line in sign_text.splitlines() if line.startswith("Authority=")),None),"team_identifier":"3TGZFKFNA4" if "TeamIdentifier=3TGZFKFNA4" in sign_text else None,"local_checks":local_checks,"privacy_artifact":privacy_audit,"distribution_checks":distribution_checks,"gatekeeper_output":(gatekeeper.stdout+gatekeeper.stderr).strip(),"stapler_output":{"app":(app_staple.stdout+app_staple.stderr).strip(),"dmg":(dmg_staple.stdout+dmg_staple.stderr).strip()},"errors":[name for name,value in {**local_checks,**distribution_checks}.items() if not value],"external_requirements":[] if artifact_passed else ["submit exact app and DMG to Apple notary service","wait for Accepted status and retain notary log","staple and validate tickets on app and DMG","rerun Gatekeeper assessment"]}
receipt_path.parent.mkdir(parents=True,exist_ok=True); receipt_path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n"); print(json.dumps(receipt,indent=2,sort_keys=True))
raise SystemExit(0 if (readiness_ok if mode=="readiness" else artifact_passed) else 1)
