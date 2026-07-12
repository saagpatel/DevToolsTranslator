import React, { useMemo, useState } from 'react';
import { fixtureEvidencePage, lanes, validateEvidencePage, type EvidencePage, type EvidenceRow } from './data';
import { Chevron, Search, Warning } from './icons';

type WorkspaceMode = 'timeline' | 'table';

const sources = ['Chrome tab', 'App logs', 'System sampler', 'PCAP import', 'DNS import'];

function StatusText({ status }: { status: EvidenceRow['status'] }): React.JSX.Element {
  const labels = { observed: 'Observed', correlated: 'Correlated', unknown: 'Unknown', gap: 'Gap / drop' };
  return <span className={`status status--${status}`}>{labels[status]}</span>;
}

function Toolbar({ onExport }: { onExport: () => void }): React.JSX.Element {
  return (
    <header className="toolbar">
      <div className="traffic-lights" aria-hidden="true"><i /><i /><i /></div>
      <strong className="wordmark">Glassbox</strong>
      <span className="toolbar-rule" />
      <span className="investigation-title">Investigation: <b>Upload freeze</b></span>
      <div className="toolbar-actions">
        <button type="button" className="control">Import <Chevron /></button>
        <button type="button" className="control" onClick={onExport}>Export review <Chevron /></button>
        <label className="search"><Search /><span className="sr-only">Search evidence</span><input placeholder="Search evidence" /></label>
      </div>
    </header>
  );
}

function ScopeRail(): React.JSX.Element {
  const [enabled, setEnabled] = useState(() => new Set(sources));
  const toggle = (source: string): void => setEnabled((current) => {
    const next = new Set(current);
    if (next.has(source)) next.delete(source); else next.add(source);
    return next;
  });
  return (
    <aside className="scope-rail" aria-label="Scope and limitations">
      <h2>Scope & limits</h2>
      <section>
        <h3>Sources ({enabled.size} of {sources.length})</h3>
        {sources.map((source) => <label className="source-toggle" key={source}><input type="checkbox" checked={enabled.has(source)} onChange={() => toggle(source)} />{source}</label>)}
      </section>
      <section>
        <h3>Permission tier</h3>
        <p>Standard user</p>
        <p className="warning-text"><Warning /> Explicit imports only</p>
      </section>
      <section>
        <h3>Privacy mode</h3>
        <p>Metadata</p>
        <p className="warning-text"><Warning /> 12 fields redacted</p>
      </section>
      <section>
        <h3>Clocks</h3>
        <p>5 clocks in scope</p>
        <p className="warning-text"><Warning /> Offset up to ±120 ms</p>
      </section>
      <section>
        <h3>Coverage limitations</h3>
        <dl className="limits-list">
          <div><dt className="gap-mark" /> <dd><b>2 gaps</b><span>00:46.812 total</span></dd></div>
          <div><dt className="drop-mark" /> <dd><b>119 drops</b><span>PCAP import</span></dd></div>
          <div><dt className="redaction-mark" /> <dd><b>12 redactions</b><span>content-sensitive</span></dd></div>
          <div><dt className="opaque-mark" /> <dd><b>3 opaque regions</b><span>encrypted payloads</span></dd></div>
        </dl>
      </section>
      <section className="selected-symptom">
        <h3>Selected symptom</h3>
        <strong>Upload freeze</strong>
        <span className="mono">14:07:23.430–14:07:53.950</span>
        <p>User reported no progress; app signpost is missing.</p>
      </section>
    </aside>
  );
}

function Timeline({ rows, selected, onSelect }: { rows: EvidenceRow[]; selected: string; onSelect: (id: string) => void }): React.JSX.Element {
  const positions: Record<string, [number, number]> = {
    e1: [7, 12], e2: [20, 13], e7: [48, 31], e11: [82, 12], e3: [17, 17], e6: [42, 15], e12: [84, 13],
    e8: [39, 48], e5: [17, 17], e9: [48, 42], e4: [17, 18], e10: [48, 42],
  };
  return (
    <div className="timeline" aria-label="Actor-lane evidence timeline">
      <div className="time-axis mono"><span>14:07:00</span><span>14:07:15</span><span>14:07:30</span><span>14:07:45</span><span>14:08:00</span></div>
      {lanes.map((lane) => (
        <section className="lane" key={lane} aria-label={`${lane} lane`}>
          <header><strong>{lane}</strong><span>{lane === 'System resources' ? 'CPU / Memory / Disk' : lane === 'Network' ? 'TCP / TLS / HTTP' : 'Evidence source'}</span></header>
          <div className="lane-track">
            {rows.filter((item) => item.actor === lane && positions[item.id]).map((item) => {
              const [left, width] = positions[item.id];
              return <button key={item.id} type="button" className={`event event--${item.status}${selected === item.id ? ' is-selected' : ''}`} style={{ left: `${left}%`, width: `${width}%` }} onClick={() => onSelect(item.id)}><b>{item.event}</b><span className="mono">{item.time}</span></button>;
            })}
          </div>
        </section>
      ))}
    </div>
  );
}

function EvidenceTable({ rows, selected, onSelect }: { rows: EvidenceRow[]; selected: string; onSelect: (id: string) => void }): React.JSX.Element {
  return (
    <div className="table-wrap" tabIndex={0} aria-label="Scrollable evidence table">
      <table className="evidence-table">
        <caption className="sr-only">Complete tabular equivalent of the actor-lane timeline</caption>
        <thead><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Source</th><th>Native locator</th><th>Event</th><th>Claim</th><th>Uncertainty</th></tr></thead>
        <tbody>{rows.map((row, index) => <tr key={row.id} className={selected === row.id ? 'is-selected' : ''} onClick={() => onSelect(row.id)}><td>{index + 1}</td><td className="mono">{row.time}</td><td>{row.actor}</td><td>{row.source}</td><td className="mono locator">{row.locator}</td><td>{row.event}</td><td><StatusText status={row.status} /></td><td className="mono">{row.uncertainty}</td></tr>)}</tbody>
      </table>
    </div>
  );
}

function Inspector({ selected }: { selected: EvidenceRow }): React.JSX.Element {
  return (
    <aside className="inspector" aria-label="Evidence relationship inspector">
      <section className="inspector-section relation-detail">
        <h2>Why are these linked?</h2>
        <h3>Relation</h3><p>The selected symptom and resource sample overlap inside their clock uncertainty. This is a candidate relation, not causation.</p>
        <h3>Basis</h3><p>Temporal candidate · <span className="mono">overlap-window/v1</span></p>
        <h3>Uncertainty</h3><p>±200 ms symptom · ±50 ms sample · cross-source drift up to 120 ms</p>
        <h3>Supporting evidence</h3><ul><li>Selected: {selected.event}</li><li>Memory pressure high at 14:07:22.810</li></ul>
        <h3>Counterevidence</h3><ul><li>UI thread responsive before 14:07:21</li><li>Previous uploads completed under similar pressure</li></ul>
        <h3>Missing evidence</h3><ul><li>App signpost during freeze</li><li>Server spans outside current scope</li></ul>
        <h3>Falsifier</h3><p>A healthy app-thread signpost throughout the freeze would weaken this hypothesis.</p>
        <div className="epistemic"><span>Epistemic status</span><strong>Correlated — limited evidence</strong><em>Multiple alternatives remain plausible.</em></div>
      </section>
      <section className="inspector-section hypotheses">
        <h2>Competing hypotheses</h2>
        <table><thead><tr><th>Hypothesis</th><th>Support</th><th>Counter</th><th>Status</th></tr></thead><tbody>
          <tr><td>Local pressure contributed</td><td>2</td><td>1</td><td>Inferred</td></tr>
          <tr><td>App thread blocked</td><td>1</td><td>2</td><td>Unknown</td></tr>
          <tr><td>Server throttling</td><td>1</td><td>2</td><td>Unknown</td></tr>
        </tbody></table>
      </section>
      <section className="inspector-section comparison"><h2>Healthy-run comparison</h2><div className="comparison-row"><span>Freeze interval</span><b>Current: anomalous</b><span>Healthy: no freeze</span></div><div className="comparison-row"><span>Upload started</span><b>Current: observed</b><span>Healthy: observed</span></div></section>
    </aside>
  );
}

function ExportDrawer({ onClose }: { onClose: () => void }): React.JSX.Element {
  return <div className="modal-backdrop" role="presentation" onMouseDown={onClose}><section className="export-dialog" role="dialog" aria-modal="true" aria-labelledby="export-title" onMouseDown={(event) => event.stopPropagation()}><header><h2 id="export-title">Export / redaction preview</h2><button type="button" onClick={onClose} aria-label="Close export review">Close</button></header><p>Derived export · authenticity: <strong>unsigned_local</strong></p><table><thead><tr><th>Field</th><th>Class</th><th>Action</th></tr></thead><tbody><tr><td>HTTP Authorization</td><td>credential</td><td>Drop</td></tr><tr><td>Request URL</td><td>content-sensitive</td><td>Structural redaction</td></tr><tr><td>Host identity</td><td>content-sensitive</td><td>Scoped pseudonym</td></tr><tr><td>Status code</td><td>metadata-sensitive</td><td>Preserve</td></tr></tbody></table><footer><button type="button" className="primary">Create derived package</button></footer></section></div>;
}

export function GlassboxApp({ page = fixtureEvidencePage }: { page?: EvidencePage }): React.JSX.Element {
  validateEvidencePage(page);
  const rows = page.rows;
  const [mode, setMode] = useState<WorkspaceMode>('timeline');
  const [selectedId, setSelectedId] = useState('e7');
  const [exportOpen, setExportOpen] = useState(false);
  const selected = useMemo(() => rows.find((row) => row.id === selectedId) ?? rows[0]!, [rows, selectedId]);
  return <><a className="skip-link" href="#workspace">Skip to investigation</a><main className="app-shell"><Toolbar onExport={() => setExportOpen(true)} /><div className="workbench"><ScopeRail /><section className="workspace" id="workspace"><div className="workspace-tabs" role="tablist" aria-label="Evidence view"><button role="tab" aria-selected={mode === 'timeline'} onClick={() => setMode('timeline')}>Timeline (actors)</button><button role="tab" aria-selected={mode === 'table'} onClick={() => setMode('table')}>Table (evidence)</button><span>{rows.length} of {page.totalCount.toLocaleString()} events · paused</span></div>{mode === 'timeline' ? <Timeline rows={rows} selected={selectedId} onSelect={setSelectedId} /> : null}<EvidenceTable rows={rows} selected={selectedId} onSelect={setSelectedId} /></section><Inspector selected={selected} /></div><footer className="status-bar"><span>Anchor: Upload freeze</span><span className="warning-text">Clock certainty limited · no causal conclusion</span></footer></main>{exportOpen ? <ExportDrawer onClose={() => setExportOpen(false)} /> : null}</>;
}

export default GlassboxApp;
