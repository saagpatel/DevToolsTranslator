#!/usr/bin/env python3
import hashlib,json,os,pathlib,re,shutil,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]);source_binary=pathlib.Path(sys.argv[2]);identity=sys.argv[3];corpus=root/'crates/glassbox-fixtures/corpus/network-import'
def git(*args):
 r=subprocess.run(['git',*args],cwd=root,text=True,capture_output=True);return r.stdout.strip() if r.returncode==0 else 'unknown'
def decode_frames(data):
 out=[]
 while data:
  if len(data)<4:raise ValueError('truncated frame length')
  length=int.from_bytes(data[:4],'big');data=data[4:]
  if length>1024*1024 or len(data)<length:raise ValueError('invalid bounded frame')
  out.append(json.loads(data[:length]));data=data[length:]
 return out
def has_forbidden(value):
 if isinstance(value,dict):return any(key in {'process','process_id','pid','payload','raw_payload','packet_bytes'}or has_forbidden(item)for key,item in value.items())
 if isinstance(value,list):return any(has_forbidden(item)for item in value)
 return False
def run(binary,path,fmt):
 env=os.environ.copy();env.update(GLASSBOX_EXPECT_NO_NETWORK='1',GLASSBOX_SOURCE_FORMAT=fmt,GLASSBOX_CAPTURE_SOURCE='capture_gate_001',GLASSBOX_CAPTURE_SESSION='session_gate_001')
 with path.open('rb')as source:result=subprocess.run([str(binary)],stdin=source,capture_output=True,env=env,timeout=10)
 return result,decode_frames(result.stdout)
with tempfile.TemporaryDirectory(prefix='glassbox-network-import.')as temp_name:
 temp=pathlib.Path(temp_name);decoded=temp/'corpus';decoded.mkdir();fixture_hashes={}
 for source in sorted(corpus.glob('*.hex')):
  data=bytes.fromhex(''.join(source.read_text().split()));target=decoded/source.with_suffix('').name;target.write_bytes(data);fixture_hashes[source.name]=hashlib.sha256(data).hexdigest()
 app=temp/'GlassboxImportWorker.app';binary=app/'Contents/MacOS/glassbox-import-worker';binary.parent.mkdir(parents=True);shutil.copy2(source_binary,binary);binary.chmod(0o755)
 (app/'Contents/Info.plist').write_text('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>glassbox-import-worker</string><key>CFBundleIdentifier</key><string>com.glassbox.import-worker</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>')
 ent=temp/'entitlements.plist';ent.write_text('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>')
 subprocess.run(['codesign','--force','--timestamp=none','--options','runtime','--entitlements',str(ent),'--sign',identity,str(app)],check=True,capture_output=True);subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True,capture_output=True)
 signing=subprocess.run(['codesign','-dvvv','--entitlements',':-',str(app)],text=True,capture_output=True);signing_text=signing.stdout+signing.stderr
 valid=[]
 for name in ['valid-little.pcap','valid-big-secret.pcap','valid-nanosecond-secret.pcap','valid-little.pcapng']:
  result,frames=run(binary,decoded/name,'pcapng-v1'if name.endswith('pcapng')else'pcap-v1');valid.append((name,result,frames))
 invalid=[]
 for name in ['truncated-record.pcap','invalid-length.pcap','oversized-record.pcap','trailer-mismatch.pcapng']:
  result,frames=run(binary,decoded/name,'pcapng-v1'if name.endswith('pcapng')else'pcap-v1');invalid.append((name,result,frames))
 seed=b'SEED_PACKET_SECRET';small=(decoded/'valid-little.pcap').read_bytes();stress=temp/'stress.pcap';stress.write_bytes(small[:24]+small[24:]*20000)
 stress_out=temp/'stress.frames';stress_time=temp/'stress.time';env=os.environ.copy();env.update(GLASSBOX_EXPECT_NO_NETWORK='1',GLASSBOX_SOURCE_FORMAT='pcap-v1',GLASSBOX_CAPTURE_SOURCE='capture_stress_001',GLASSBOX_CAPTURE_SESSION='session_stress_001')
 with stress.open('rb')as source,stress_out.open('wb')as output,stress_time.open('wb')as errors:stress_run=subprocess.run(['/usr/bin/time','-l',str(binary)],stdin=source,stdout=output,stderr=errors,env=env,timeout=30)
 time_text=stress_time.read_text(errors='replace');rss_match=re.search(r'\s+(\d+)\s+maximum resident set size',time_text);max_rss=int(rss_match.group(1))if rss_match else None
 stress_frames=decode_frames(stress_out.read_bytes());stress_observations=sum(frame.get('type')=='observation'for frame in stress_frames);valid_observations=[frame for _,_,frames in valid for frame in frames if frame.get('type')=='observation']
 checks={
  'developer_id_signed_sandboxed_worker':'Authority=Developer ID Application:'in signing_text and'com.apple.security.app-sandbox'in signing_text,
  'network_entitlements_absent':'com.apple.security.network.client'not in signing_text and'com.apple.security.network.server'not in signing_text,
  'pcap_little_big_nanosecond_and_pcapng_pass':all(result.returncode==0 and[f.get('type')for f in frames]==['begin','observation','end']for _,result,frames in valid),
  'malformed_truncated_oversized_and_trailer_mismatch_fail_closed':all(result.returncode!=0 and not any(f.get('type')=='end'for f in frames)for _,result,frames in invalid),
  'packet_native_locators_complete':all(obs['observation']['native_id'].startswith('pcap://capture_gate_001/section/')and'/interface/'in obs['observation']['native_id']and'/packet/'in obs['observation']['native_id']and'@'in obs['observation']['native_id']for obs in valid_observations),
  'raw_payload_and_seeded_secret_absent':all(seed not in result.stdout and seed not in json.dumps(frames).encode()for _,result,frames in valid),
  'process_attribution_absent':all(not has_forbidden(item)for _,_,frames in valid for item in frames),
  'opacity_and_timestamp_resolution_visible':all('opacity'in obs['observation']['fields']and'timestamp_resolution_ns'in obs['observation']['fields']for obs in valid_observations),
  'streaming_20000_packets_complete':stress_run.returncode==0 and stress_observations==20000 and stress_frames[-1].get('type')=='end',
  'streaming_rss_under_128_mib':max_rss is not None and max_rss<=128*1024*1024,
 }
 receipt={'schema_version':'glassbox-network-import/v1','ok':all(checks.values()),'git_head':git('rev-parse','HEAD'),'git_tree':git('rev-parse','HEAD^{tree}'),'git_dirty':bool(git('status','--porcelain')),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'codesign_identity':identity,'checks':checks,'fixture_sha256':fixture_hashes,'stress':{'packets':stress_observations,'input_bytes':stress.stat().st_size,'maximum_resident_set_size_bytes':max_rss},'explicit_limitations':['no process attribution','non-Ethernet link types remain opaque','raw packet payload is never retained','live packet capture is not implemented or authorized'],'errors':[name for name,value in checks.items()if not value]}
 print(json.dumps(receipt,indent=2,sort_keys=True));raise SystemExit(0 if receipt['ok']else 1)
