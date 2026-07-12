export type EvidenceState = 'observed' | 'correlated' | 'unknown' | 'gap';

export interface EvidenceRow {
  id: string;
  time: string;
  actor: string;
  source: string;
  locator: string;
  event: string;
  status: EvidenceState;
  uncertainty: string;
}

export const evidence: EvidenceRow[] = [
  { id: 'e1', time: '14:07:05.812', actor: 'User action', source: 'Chrome tab', locator: 'chrome://selected-tab/input/584923', event: 'Click “Upload”', status: 'observed', uncertainty: '±40 ms' },
  { id: 'e2', time: '14:07:09.231', actor: 'User action', source: 'Chrome tab', locator: 'chrome://selected-tab/file/ab21', event: 'File selected', status: 'observed', uncertainty: '±40 ms' },
  { id: 'e3', time: '14:07:10.052', actor: 'Application', source: 'App logs', locator: 'app://uploads/9f3a/start', event: 'Upload started', status: 'observed', uncertainty: '±80 ms' },
  { id: 'e4', time: '14:07:10.120', actor: 'DNS / Trace', source: 'DNS import', locator: 'dnsmasq://query/22451', event: 'A api.example.test → 93.184.216.34', status: 'observed', uncertainty: '±20 ms' },
  { id: 'e5', time: '14:07:20.210', actor: 'Network', source: 'PCAP import', locator: 'pcap://packet/14331', event: 'POST /upload', status: 'observed', uncertainty: '±80 ms' },
  { id: 'e6', time: '14:07:21.004', actor: 'Application', source: 'App logs', locator: 'app://uploads/9f3a/progress', event: 'Progress: 8.4 MB', status: 'observed', uncertainty: '±80 ms' },
  { id: 'e7', time: '14:07:23.430', actor: 'User action', source: 'Manual marker', locator: 'marker://freeze/start', event: 'Upload freeze reported', status: 'observed', uncertainty: '±200 ms' },
  { id: 'e8', time: '14:07:22.810', actor: 'System resources', source: 'Bounded sampler', locator: 'sampler://memory/5521', event: 'Memory pressure: high', status: 'observed', uncertainty: '±50 ms' },
  { id: 'e9', time: '14:07:22.990', actor: 'Network', source: 'PCAP import', locator: 'pcap://gap/14352', event: '119 packets dropped', status: 'gap', uncertainty: 'duration unknown' },
  { id: 'e10', time: '14:07:23.000', actor: 'DNS / Trace', source: 'DNS import', locator: 'dnsmasq://gap/1', event: 'No DNS evidence in interval', status: 'unknown', uncertainty: 'coverage gap' },
  { id: 'e11', time: '14:07:53.950', actor: 'User action', source: 'Manual marker', locator: 'marker://freeze/end', event: 'Freeze period ended', status: 'observed', uncertainty: '±200 ms' },
  { id: 'e12', time: '14:07:54.321', actor: 'Application', source: 'App logs', locator: 'app://uploads/9f3a/resume', event: 'Upload resumed', status: 'observed', uncertainty: '±80 ms' },
];

export const lanes = ['User action', 'Application', 'System resources', 'Network', 'DNS / Trace'] as const;
