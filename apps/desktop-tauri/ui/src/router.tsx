import React, { createContext, useContext, useEffect, useState } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import type {
  UiBundleInspectEvidenceResolveResultV1,
  UiBundleInspectFindingV1,
  UiBundleInspectOverviewV1,
  UiEvaluateExtensionRolloutStageResultV1,
  UiEvaluateUpdateRolloutResultV1,
  UiListComplianceEvidencePacksItemV1,
  RedactionLevel,
  ReleaseHealthScorecardV1,
  RolloutStageV1,
  UpdateChannelV1,
  UiCheckForUpdateResultV1,
  UiExtensionComplianceSnapshotV1,
  UiListExtensionRolloutsItemV1,
  UiListPerfAnomaliesItemV1,
  UiUpdateRolloutSnapshotV1,
  TelemetryAuditRunV1,
  ReliabilityMetricKeyV1,
  ReleaseArtifactV1,
  ReleasePlatformV1,
  UiConsoleRowV1,
  UiDiagnosticsSnapshotV1,
  UiEvidenceResolveResultV1,
  UiExportCapabilityV1,
  UiExportListItemV1,
  UiFindingCardV1,
  UiNetworkRowV1,
  UiPerfRunListItemV1,
  UiPerfTrendPointV1,
  UiSigningSnapshotV1,
  UiTelemetrySettingsV1,
  TelemetryExportRunV1,
  UiReleaseListItemV1,
  UiReliabilitySeriesPointV1,
  UiReliabilitySnapshotV1,
  UiSessionListItemV1,
  UiSessionOverviewV1,
  UiTimelineBundleV1,
} from '@dtt/shared-types';
import type { DesktopClient } from './api/client.js';
import { buildLiveCaptureViewModel } from './live-capture.js';
import { resolveEvidenceRoute, type EvidenceKindVm } from './evidence-routing.js';

type SessionSubview = 'overview' | 'timeline' | 'network' | 'console' | 'findings' | 'export';

interface AppDependencies {
  readonly client: DesktopClient;
}

interface EvidenceSelectionContextValue {
  readonly selectedEvidence: UiEvidenceResolveResultV1 | null;
  readonly setSelectedEvidence: (next: UiEvidenceResolveResultV1 | null) => void;
}

const EvidenceSelectionContext = createContext<EvidenceSelectionContextValue | null>(null);

function findByDataAttribute(name: string, value: string): HTMLElement | null {
  const selector = `[${name}]`;
  const nodes = document.querySelectorAll<HTMLElement>(selector);
  for (const node of nodes) {
    if (node.getAttribute(name) === value) {
      return node;
    }
  }
  return null;
}

function useEvidenceSelection(): EvidenceSelectionContextValue {
  const value = useContext(EvidenceSelectionContext);
  if (!value) {
    throw new Error('EvidenceSelectionContext is not available');
  }
  return value;
}

function useHighlightFromQuery(isReady: boolean): { fallbackNotice: string | null } {
  const location = useLocation();
  const [fallbackNotice, setFallbackNotice] = useState<string | null>(null);

  useEffect(() => {
    if (!isReady) {
      return;
    }
    const query = new URLSearchParams(location.search);
    const kind = query.get('hl_kind');
    const id = query.get('hl_id');
    const column = query.get('hl_col') ?? '';
    const pointer = query.get('hl_ptr') ?? '';
    const exact = query.get('hl_exact');
    const fallback = query.get('hl_fallback');

    if (!kind || !id) {
      setFallbackNotice(null);
      return;
    }

    const key = [kind, id, column, pointer].join(':');
    const exactTarget = findByDataAttribute('data-highlight-key', key);
    const target = exactTarget ?? findByDataAttribute('data-highlight-container', `${kind}:${id}`);

    if (!target) {
      setFallbackNotice('Target row is unavailable in this view.');
      return;
    }

    if (typeof target.scrollIntoView === 'function') {
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    target.classList.add('pulse-highlight');
    const timeout = window.setTimeout(() => {
      target.classList.remove('pulse-highlight');
    }, 4000);

    if (exact === 'false') {
      setFallbackNotice(fallback || 'Exact pointer unavailable');
    } else {
      setFallbackNotice(null);
    }

    return () => {
      window.clearTimeout(timeout);
      target.classList.remove('pulse-highlight');
    };
  }, [isReady, location.search]);

  return { fallbackNotice };
}

function LoadingState({ title }: { readonly title: string }): React.JSX.Element {
  return <section className="state-card">Loading {title}…</section>;
}

function ErrorState({
  message,
  onRetry,
}: {
  readonly message: string;
  readonly onRetry: () => void;
}): React.JSX.Element {
  return (
    <section className="state-card error" role="alert">
      <p>{message}</p>
      <button type="button" onClick={onRetry}>
        Retry
      </button>
    </section>
  );
}

function EmptyState({
  message,
  cta,
}: {
  readonly message: string;
  readonly cta?: React.JSX.Element;
}): React.JSX.Element {
  return (
    <section className="state-card empty">
      <p>{message}</p>
      {cta ?? null}
    </section>
  );
}

function parseHelloFlags(
  diagnostics: ReadonlyArray<UiDiagnosticsSnapshotV1['diagnostics'][number]>,
): { consent_enabled: boolean; ui_capture_enabled: boolean } | null {
  const hello = [...diagnostics]
    .filter((entry) => entry.kind === 'hello')
    .sort((left, right) => right.ts_ms - left.ts_ms)[0];
  if (!hello) {
    return null;
  }

  const consentMatch = hello.message.match(/\bconsent=(true|false)\b/);
  const uiCaptureMatch = hello.message.match(/\bui_capture=(true|false)\b/);
  if (!consentMatch || !uiCaptureMatch) {
    return null;
  }

  return {
    consent_enabled: consentMatch[1] === 'true',
    ui_capture_enabled: uiCaptureMatch[1] === 'true',
  };
}

function SessionsPage({ client }: AppDependencies): React.JSX.Element {
  const [status, setStatus] = useState<'loading' | 'error' | 'success'>('loading');
  const [rows, setRows] = useState<UiSessionListItemV1[]>([]);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const load = async (): Promise<void> => {
    setStatus('loading');
    try {
      setRows(await client.uiGetSessions(200));
      setStatus('success');
    } catch {
      setStatus('error');
    }
  };

  useEffect(() => {
    void load();
  }, []);

  if (status === 'loading') return <LoadingState title="sessions" />;
  if (status === 'error') return <ErrorState message="Unable to query sessions." onRetry={load} />;
  if (rows.length === 0) {
    return (
      <EmptyState
        message="No sessions yet. Start capture from Live Capture."
        cta={<Link to="/live-capture">Open Live Capture</Link>}
      />
    );
  }

  return (
    <section className="panel">
      <h2>Sessions</h2>
      <table className="data-table" aria-label="Sessions table">
        <thead>
          <tr>
            <th>Session</th>
            <th>Privacy</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Findings</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.session_id} data-highlight-container={`session:${row.session_id}`}>
              <td>
                <Link to={`/sessions/${row.session_id}/overview`}>{row.session_id}</Link>
              </td>
              <td>{row.privacy_mode}</td>
              <td>{row.status === 'running' ? 'Capturing now' : 'Ready to review'}</td>
              <td>{row.duration_ms ?? 'In progress'}</td>
              <td>{row.findings_count}</td>
              <td>
                <button
                  type="button"
                  disabled={row.status === 'running'}
                  onClick={() => {
                    void (async () => {
                      const confirmed = window.confirm(
                        `Delete session ${row.session_id}? This also deletes related artifacts.`,
                      );
                      if (!confirmed) {
                        return;
                      }
                      try {
                        const result = await client.uiDeleteSession(row.session_id);
                        setActionMessage(
                          result.result.db_deleted
                            ? `Deleted ${row.session_id}.`
                            : `Delete blocked: ${result.result.errors[0] ?? 'unknown reason'}`,
                        );
                        await load();
                      } catch {
                        setActionMessage(`Delete failed for ${row.session_id}.`);
                      }
                    })();
                  }}
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {actionMessage ? <p className="mono">{actionMessage}</p> : null}
    </section>
  );
}

function LiveCapturePage({ client }: AppDependencies): React.JSX.Element {
  const [privacyMode, setPrivacyMode] = useState<RedactionLevel>('metadata_only');
  const [consentEnabled, setConsentEnabled] = useState(false);
  const [uiCaptureEnabled, setUiCaptureEnabled] = useState(false);
  const [activeSession, setActiveSession] = useState<string | null>(null);
  const [runningSessionId, setRunningSessionId] = useState<string | null>(null);
  const [sessionCounter, setSessionCounter] = useState(1);
  const [diagnostics, setDiagnostics] = useState<UiDiagnosticsSnapshotV1 | null>(null);
  const [tabs, setTabs] = useState<
    Array<{ tab_id: number; window_id: number; url: string; title: string; active: boolean }>
  >([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const [diag, listedTabs, sessions] = await Promise.all([
        client.uiGetDiagnostics(null),
        client.uiListTabs(),
        client.uiGetSessions(200),
      ]);
      setDiagnostics(diag);
      setTabs(listedTabs);
      const running = sessions.find((row) => row.status === 'running') ?? null;
      setRunningSessionId(running?.session_id ?? null);
      setActiveSession((previous) => running?.session_id ?? previous ?? null);
      const helloFlags = parseHelloFlags(diag.diagnostics);
      if (helloFlags) {
        setConsentEnabled(helloFlags.consent_enabled);
        setUiCaptureEnabled(helloFlags.ui_capture_enabled);
      }
    } catch {
      setError('Unable to reach capture bridge.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const vm = buildLiveCaptureViewModel({
    connection_status: diagnostics?.connection_status ?? 'disconnected',
    consent_enabled: consentEnabled,
    ui_capture_enabled: uiCaptureEnabled,
    active_session_id: activeSession ?? runningSessionId,
    tabs,
    diagnostics: diagnostics?.diagnostics ?? [],
  });

  const startCapture = async (tabId: number): Promise<void> => {
    const sessionId = `sess_ui_${tabId}_${sessionCounter}`;
    try {
      const started = await client.uiStartCapture(tabId, privacyMode, sessionId);
      setActiveSession(started.session_id);
      setRunningSessionId(started.session_id);
      setSessionCounter((prev) => prev + 1);
      await load();
    } catch (error) {
      const rawMessage = error instanceof Error ? error.message : String(error);
      if (/consent/i.test(rawMessage)) {
        setError('Capture blocked: enable "Explicit capture consent" in the extension popup.');
      } else if (/already attached/i.test(rawMessage)) {
        setError('Capture blocked: this tab is already attached to another debugger.');
      } else {
        setError(`Failed to start capture: ${rawMessage}`);
      }
    }
  };

  const stopCapture = async (): Promise<void> => {
    const targetSession = activeSession ?? runningSessionId;
    if (!targetSession) {
      setError('No active session found. Click "Refresh Capture State" and try again.');
      return;
    }
    try {
      await client.uiStopCapture(targetSession);
      setActiveSession(null);
      setRunningSessionId(null);
      await load();
    } catch {
      setError('Failed to stop capture cleanly.');
    }
  };

  const toggleUiCapture = async (): Promise<void> => {
    const next = !uiCaptureEnabled;
    setUiCaptureEnabled(next);
    try {
      await client.uiSetUiCapture(next);
    } catch {
      setError('Unable to toggle UI capture.');
    }
  };

  if (loading) return <LoadingState title="live capture" />;

  return (
    <section className="panel">
      <h2>Live Capture Setup</h2>
      <p>
        Follow this flow: connect your extension, choose a browser tab, start capture, then stop
        capture to process findings.
      </p>
      <div className="state-card">
        <strong>Connection status: {vm.connection_status}</strong>
        <p className="mono">
          Active session: {vm.active_session_id ?? 'none'} · Consent:{' '}
          {consentEnabled ? 'enabled' : 'disabled'}
        </p>
      </div>
      <div className="grid-two">
        <label>
          Privacy mode
          <select
            value={privacyMode}
            onChange={(event) => setPrivacyMode(event.target.value as RedactionLevel)}
          >
            <option value="metadata_only">No page content (safest)</option>
            <option value="redacted">Redacted content</option>
            <option value="full">Full content</option>
          </select>
        </label>
        <label className="inline-checkbox">
          <input
            type="checkbox"
            checked={consentEnabled}
            disabled
            aria-describedby="consent-hint"
          />
          Explicit capture consent is enabled in extension
        </label>
      </div>
      <p id="consent-hint" className="mono">
        If consent is disabled, open the extension popup and enable consent first.
      </p>
      <div className="inline-buttons">
        <button type="button" onClick={() => void load()}>
          Refresh Capture State
        </button>
      </div>
      <label className="inline-checkbox">
        <input type="checkbox" checked={uiCaptureEnabled} onChange={() => void toggleUiCapture()} />
        Enable optional UI capture support
      </label>
      <p>
        Need troubleshooting details? <Link to="/diagnostics">Open diagnostics</Link>.
      </p>
      <details>
        <summary>Advanced details</summary>
        <p className="mono">Pairing port: {diagnostics?.pairing_port ?? 'n/a'}</p>
        <p className="mono">Pairing token: {diagnostics?.pairing_token ?? 'n/a'}</p>
      </details>
      {error ? (
        <div className="state-card error" role="alert">
          {error}
        </div>
      ) : null}
      {vm.empty_reason === 'extension_unavailable' ? (
        <EmptyState message="Extension unavailable or not paired." />
      ) : null}
      {vm.empty_reason === 'no_tabs' ? (
        <EmptyState message="No eligible HTTP/HTTPS tabs found." />
      ) : null}
      <table className="data-table" aria-label="Tabs table">
        <thead>
          <tr>
            <th>Tab</th>
            <th>URL</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {vm.tabs.map((tab) => (
            <tr key={tab.tab_id}>
              <td>{tab.title || tab.tab_id}</td>
              <td>{tab.url}</td>
              <td>
                <button
                  type="button"
                  disabled={!vm.can_start_capture}
                  title={
                    vm.can_start_capture
                      ? 'Start capture'
                      : 'Capture blocked by connection/consent/session state'
                  }
                  onClick={() => void startCapture(tab.tab_id)}
                >
                  Start
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <button
        type="button"
        className="danger"
        disabled={!vm.can_stop_capture}
        title={vm.can_stop_capture ? 'Stop capture' : 'No active capture session'}
        onClick={() => void stopCapture()}
      >
        Stop Capture
      </button>
      <details>
        <summary>Diagnostics</summary>
        <ul>
          {vm.diagnostics.map((entry) => (
            <li key={`${entry.ts_ms}:${entry.kind}`}>
              {entry.kind}: {entry.message}
            </li>
          ))}
        </ul>
      </details>
    </section>
  );
}

function FindingsPage({ client }: AppDependencies): React.JSX.Element {
  const navigate = useNavigate();
  const { setSelectedEvidence } = useEvidenceSelection();
  const [rows, setRows] = useState<UiFindingCardV1[]>([]);
  const [status, setStatus] = useState<'loading' | 'error' | 'success'>('loading');

  const load = async (): Promise<void> => {
    setStatus('loading');
    try {
      setRows(await client.uiGetFindings(null, 100));
      setStatus('success');
    } catch {
      setStatus('error');
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const openEvidence = async (evidenceRefId: string): Promise<void> => {
    const resolved = await client.uiResolveEvidence(evidenceRefId);
    if (!resolved) return;
    setSelectedEvidence(resolved);
    const target = resolveEvidenceRoute({
      session_id: resolved.session_id,
      evidence_kind: resolved.kind as EvidenceKindVm,
      reference_id: resolved.target_id,
      column: resolved.column ?? undefined,
      json_pointer: resolved.json_pointer ?? undefined,
    });
    const query = new URLSearchParams({
      hl_kind: resolved.kind,
      hl_id: resolved.target_id,
      hl_col: resolved.column ?? '',
      hl_ptr: resolved.json_pointer ?? '',
      hl_exact: String(resolved.exact_pointer_found),
      hl_fallback: resolved.fallback_reason ?? '',
    });
    navigate(`${target.path}?${query.toString()}`);
  };

  if (status === 'loading') return <LoadingState title="findings" />;
  if (status === 'error') return <ErrorState message="Unable to load findings." onRetry={load} />;
  if (rows.length === 0) {
    return (
      <EmptyState
        message="No findings yet. This is normal until you capture and stop at least one session."
        cta={<Link to="/live-capture">Open Live Capture</Link>}
      />
    );
  }

  return (
    <section className="panel">
      <h2>Findings</h2>
      {rows.map((finding) => (
        <article key={finding.finding_id} className="finding-card">
          <header>
            <h3>{finding.title}</h3>
            <span className="badge severity">Severity {finding.severity_score}</span>
          </header>
          <p>{finding.summary}</p>
          {finding.claims.map((claim) => (
            <div key={claim.claim_id} className="claim-block">
              <h4>{claim.title}</h4>
              <p>{claim.summary}</p>
              <div className="inline-buttons">
                {claim.evidence_refs.map((_evidence, index) => {
                  const evidenceId =
                    index === 0 ? 'evr_mock_1' : `evr_${claim.claim_id}_${index + 1}`;
                  return (
                    <button
                      key={evidenceId}
                      type="button"
                      onClick={() => void openEvidence(evidenceId)}
                    >
                      Open Evidence {index + 1}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
          <Link to={`/sessions/${finding.session_id}/findings`}>Open Session Findings</Link>
        </article>
      ))}
    </section>
  );
}

function ExportsPage({ client }: AppDependencies): React.JSX.Element {
  const navigate = useNavigate();
  const [rows, setRows] = useState<UiSessionListItemV1[]>([]);
  const [status, setStatus] = useState<'loading' | 'error' | 'success'>('loading');
  const [capability, setCapability] = useState<UiExportCapabilityV1 | null>(null);
  const [exportRuns, setExportRuns] = useState<UiExportListItemV1[]>([]);
  const [releaseRuns, setReleaseRuns] = useState<UiReleaseListItemV1[]>([]);
  const [releaseArtifacts, setReleaseArtifacts] = useState<
    Record<ReleasePlatformV1, ReleaseArtifactV1[]>
  >({
    macos: [],
    windows: [],
    linux: [],
  });
  const [releaseVersion, setReleaseVersion] = useState('0.1.0-beta.1');
  const [releaseNotes, setReleaseNotes] = useState('Internal beta release');
  const [promotionRunId, setPromotionRunId] = useState('');
  const [signingSnapshot, setSigningSnapshot] = useState<UiSigningSnapshotV1 | null>(null);
  const [extensionRollouts, setExtensionRollouts] = useState<UiListExtensionRolloutsItemV1[]>([]);
  const [extensionCompliance, setExtensionCompliance] =
    useState<UiExtensionComplianceSnapshotV1 | null>(null);
  const [extensionRolloutStage, setExtensionRolloutStage] = useState<RolloutStageV1>('pct_5');
  const [updateChannel, setUpdateChannel] = useState<UpdateChannelV1>('staged_public_prerelease');
  const [installId, setInstallId] = useState('install_mock_001');
  const [currentVersion, setCurrentVersion] = useState('0.1.0');
  const [updateSnapshot, setUpdateSnapshot] = useState<UiUpdateRolloutSnapshotV1 | null>(null);
  const [updateCheck, setUpdateCheck] = useState<UiCheckForUpdateResultV1 | null>(null);
  const [extensionEvaluation, setExtensionEvaluation] =
    useState<UiEvaluateExtensionRolloutStageResultV1 | null>(null);
  const [updateEvaluation, setUpdateEvaluation] =
    useState<UiEvaluateUpdateRolloutResultV1 | null>(null);
  const [releaseHealthScorecard, setReleaseHealthScorecard] =
    useState<ReleaseHealthScorecardV1 | null>(null);
  const [compliancePacks, setCompliancePacks] = useState<UiListComplianceEvidencePacksItemV1[]>(
    [],
  );
  const [bundlePath, setBundlePath] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [loadWarning, setLoadWarning] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const load = async (): Promise<void> => {
    setStatus('loading');
    try {
      const sessions = await client.uiGetSessions(25);
      setRows(sessions);
      const primarySession = sessions[0]?.session_id ?? null;
      const firstPass = await Promise.allSettled([
        client.uiListExports(null, 200),
        primarySession ? client.uiGetExports(primarySession) : Promise.resolve(null),
      ]);
      const secondPass = await Promise.allSettled([
        client.uiListReleases(100),
        client.uiGetReleaseArtifactsByPlatform('macos', 100),
        client.uiGetReleaseArtifactsByPlatform('windows', 100),
        client.uiGetReleaseArtifactsByPlatform('linux', 100),
      ]);
      const thirdPass = await Promise.allSettled([
        client.uiListExtensionRollouts(50),
        client.uiGetUpdateRolloutSnapshot(updateChannel),
      ]);
      const fourthPass = await Promise.allSettled([
        client.uiGetReleaseHealthScorecard(releaseVersion, updateChannel),
        client.uiListComplianceEvidencePacks(null, 50),
      ]);

      const getSettled = <T,>(result: PromiseSettledResult<T>, fallback: T): T =>
        result.status === 'fulfilled' ? result.value : fallback;

      const runs = getSettled<UiExportListItemV1[]>(firstPass[0], []);
      const nextCapability = getSettled<UiExportCapabilityV1 | null>(firstPass[1], null);
      const releases = getSettled<UiReleaseListItemV1[]>(secondPass[0], []);
      const macArtifacts = getSettled<ReleaseArtifactV1[]>(secondPass[1], []);
      const windowsArtifacts = getSettled<ReleaseArtifactV1[]>(secondPass[2], []);
      const linuxArtifacts = getSettled<ReleaseArtifactV1[]>(secondPass[3], []);
      const nextExtensionRollouts = getSettled<UiListExtensionRolloutsItemV1[]>(thirdPass[0], []);
      const nextUpdateSnapshot = getSettled<UiUpdateRolloutSnapshotV1 | null>(thirdPass[1], null);
      const nextScorecard = getSettled<ReleaseHealthScorecardV1 | null>(fourthPass[0], null);
      const nextCompliancePacks = getSettled<UiListComplianceEvidencePacksItemV1[]>(
        fourthPass[1],
        [],
      );

      const failedCalls = [...firstPass, ...secondPass, ...thirdPass, ...fourthPass].filter(
        (result) => result.status === 'rejected',
      ).length;
      setLoadWarning(
        failedCalls > 0
          ? `Some export and release sections are unavailable (${failedCalls} section${failedCalls === 1 ? '' : 's'} failed to load).`
          : null,
      );

      setExportRuns(runs);
      setCapability(nextCapability);
      setReleaseRuns(releases);
      setExtensionRollouts(nextExtensionRollouts);
      setUpdateSnapshot(nextUpdateSnapshot);
      setReleaseHealthScorecard(nextScorecard);
      setCompliancePacks(nextCompliancePacks);
      setReleaseArtifacts({
        macos: macArtifacts,
        windows: windowsArtifacts,
        linux: linuxArtifacts,
      });
      const latestRunId = releases[0]?.run_id ?? '';
      if (latestRunId) {
        setPromotionRunId((prev) => prev || latestRunId);
        try {
          setSigningSnapshot(await client.uiGetSigningSnapshot(latestRunId));
        } catch {
          setSigningSnapshot(null);
        }
      } else {
        setSigningSnapshot(null);
      }
      const latestExtensionRolloutId = nextExtensionRollouts[0]?.rollout_id ?? null;
      setExtensionCompliance(
        await client.uiGetExtensionComplianceSnapshot(latestExtensionRolloutId),
      );
      setStatus('success');
    } catch {
      setLoadWarning(null);
      setStatus('error');
    }
  };

  const runExport = async (profile: 'share_safe' | 'full'): Promise<void> => {
    if (!rows[0]) return;
    setRunning(true);
    setMessage(null);
    try {
      const result = await client.uiStartExport(rows[0].session_id, profile, null);
      setMessage(
        result.status === 'completed'
          ? `Export ${result.export_id} completed.`
          : `Export ${result.export_id} status: ${result.status}`,
      );
      await load();
    } catch {
      setMessage('Export failed. Check diagnostics and retry.');
    } finally {
      setRunning(false);
    }
  };

  const openFolder = async (exportId: string | null): Promise<void> => {
    try {
      const result = await client.uiOpenExportFolder(exportId);
      setMessage(result.message ?? `Export folder path: ${result.path ?? 'n/a'}`);
    } catch {
      setMessage('Unable to open export folder.');
    }
  };

  const startRelease = async (): Promise<void> => {
    setRunning(true);
    setMessage(null);
    try {
      const result = await client.uiStartReleaseMatrix(
        'internal_beta',
        releaseVersion,
        releaseNotes,
        true,
      );
      setPromotionRunId(result.run_id);
      setMessage(`Release ${result.run_id} status: ${result.status}`);
      await load();
    } catch {
      setMessage('Release run failed. Check diagnostics and runbooks.');
    } finally {
      setRunning(false);
    }
  };

  const startPromotion = async (): Promise<void> => {
    if (!promotionRunId.trim()) {
      setMessage('Select or enter a release run id for promotion.');
      return;
    }
    setRunning(true);
    setMessage(null);
    try {
      const result = await client.uiStartReleasePromotion(
        'staged_public_prerelease',
        promotionRunId.trim(),
        releaseNotes,
        true,
      );
      setMessage(`Promotion ${result.promotion_id} status: ${result.status}`);
      await load();
    } catch {
      setMessage('Promotion blocked. Check signing snapshot and smoke evidence.');
    } finally {
      setRunning(false);
    }
  };

  const startExtensionPublicRollout = async (): Promise<void> => {
    setRunning(true);
    setMessage(null);
    try {
      const result = await client.uiStartExtensionPublicRollout(
        releaseVersion,
        extensionRolloutStage,
        releaseNotes,
        true,
      );
      setMessage(`Extension rollout ${result.rollout_id} status: ${result.status}`);
      await load();
    } catch {
      setMessage('Extension rollout blocked by compliance checks.');
    } finally {
      setRunning(false);
    }
  };

  const checkForUpdates = async (): Promise<void> => {
    try {
      const result = await client.uiCheckForUpdates(updateChannel, installId, currentVersion);
      setUpdateCheck(result);
      setMessage(
        `Update check: ${result.eligibility}${result.reason ? ` (${result.reason})` : ''}`,
      );
    } catch {
      setMessage('Update check failed.');
    }
  };

  const applyUpdate = async (): Promise<void> => {
    try {
      const result = await client.uiApplyUpdate(updateChannel, installId, currentVersion);
      setMessage(result.message ?? `Update apply result: ${String(result.applied)}`);
    } catch {
      setMessage('Update apply failed.');
    }
  };

  const openBundleInspect = async (): Promise<void> => {
    if (!bundlePath.trim()) {
      setMessage('Enter a bundle path before opening inspect mode.');
      return;
    }
    try {
      const opened = await client.uiOpenBundleInspect(bundlePath.trim());
      navigate(`/bundle-inspect/${encodeURIComponent(opened.inspect_id)}`);
    } catch {
      setMessage('Bundle inspect failed. Verify bundle integrity and path.');
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const nextStage = (stage: RolloutStageV1): RolloutStageV1 =>
    stage === 'pct_5'
      ? 'pct_25'
      : stage === 'pct_25'
        ? 'pct_50'
        : stage === 'pct_50'
          ? 'pct_100'
          : 'pct_100';

  const evaluateExtensionRollout = async (): Promise<void> => {
    setRunning(true);
    try {
      const result = await client.uiEvaluateExtensionRolloutStage(
        releaseVersion,
        extensionRolloutStage,
      );
      setExtensionEvaluation(result);
      setMessage(
        `Extension evaluation: ${result.status} / ${result.action} (score ${result.scorecard.score.toFixed(1)})`,
      );
      await load();
    } catch {
      setMessage('Extension rollout evaluation failed.');
    } finally {
      setRunning(false);
    }
  };

  const advanceExtensionRollout = async (): Promise<void> => {
    setRunning(true);
    try {
      const result = await client.uiAdvanceExtensionRolloutStage(
        releaseVersion,
        extensionRolloutStage,
        nextStage(extensionRolloutStage),
        true,
      );
      setMessage(`Extension advance action: ${result.action} / ${result.status}`);
      await load();
    } catch {
      setMessage('Extension rollout advance failed.');
    } finally {
      setRunning(false);
    }
  };

  const evaluateUpdateRollout = async (): Promise<void> => {
    setRunning(true);
    try {
      const stage = updateSnapshot?.stage ?? 'pct_5';
      const version = updateSnapshot?.version ?? releaseVersion;
      const result = await client.uiEvaluateUpdateRollout(updateChannel, version, stage);
      setUpdateEvaluation(result);
      setMessage(
        `Updater evaluation: ${result.status} / ${result.action} (score ${result.scorecard.score.toFixed(1)})`,
      );
      await load();
    } catch {
      setMessage('Updater rollout evaluation failed.');
    } finally {
      setRunning(false);
    }
  };

  const advanceUpdateRollout = async (): Promise<void> => {
    setRunning(true);
    try {
      const fromStage = updateSnapshot?.stage ?? 'pct_5';
      const version = updateSnapshot?.version ?? releaseVersion;
      const result = await client.uiAdvanceUpdateRollout(
        updateChannel,
        version,
        fromStage,
        nextStage(fromStage),
        true,
      );
      setMessage(`Updater advance action: ${result.action} / ${result.status}`);
      await load();
    } catch {
      setMessage('Updater rollout advance failed.');
    } finally {
      setRunning(false);
    }
  };

  const runRolloutControllerTick = async (): Promise<void> => {
    setRunning(true);
    try {
      const scorecard = await client.uiRunRolloutControllerTick(
        releaseVersion,
        extensionRolloutStage,
        updateChannel,
      );
      setReleaseHealthScorecard(scorecard);
      setMessage(
        `Controller tick: ${scorecard.overall_status} (score ${scorecard.score.toFixed(1)})`,
      );
      await load();
    } catch {
      setMessage('Rollout controller tick failed.');
    } finally {
      setRunning(false);
    }
  };

  if (status === 'loading') return <LoadingState title="exports" />;
  if (status === 'error') {
    return (
      <ErrorState
        message="Unable to load exports right now. Retry, or capture/stop a session first."
        onRetry={load}
      />
    );
  }
  if (rows.length === 0) {
    return (
      <EmptyState
        message="No sessions available for export yet. Start and stop one capture first."
        cta={<Link to="/live-capture">Open Live Capture</Link>}
      />
    );
  }

  return (
    <section className="panel">
      <h2>Exports</h2>
      {loadWarning ? <div className="state-card warning">{loadWarning}</div> : null}
      <p>Share-safe export is the default profile. Full export remains privacy-gated.</p>
      <div className="inline-buttons">
        <button
          type="button"
          disabled={running || !capability?.phase8_ready}
          onClick={() => void runExport('share_safe')}
        >
          Generate Share-Safe Export
        </button>
        <button
          type="button"
          disabled={running || !capability?.phase8_ready || !capability?.full_export_allowed}
          title={capability?.full_export_block_reason ?? 'Full export is policy-gated'}
          onClick={() => void runExport('full')}
        >
          Generate Full Export
        </button>
        <button type="button" onClick={() => void openFolder(exportRuns[0]?.export_id ?? null)}>
          Open Export Folder
        </button>
      </div>
      <p className="mono">{message ?? capability?.full_export_block_reason ?? 'Ready.'}</p>
      <article className="state-card" data-testid="release-health-scorecard">
        <h4>Release Health Scorecard</h4>
        <p className="mono">Status: {releaseHealthScorecard?.overall_status ?? 'unknown'}</p>
        <p className="mono">Score: {releaseHealthScorecard?.score ?? 0}</p>
        <p className="mono">
          Gate Reasons: {releaseHealthScorecard?.gate_reasons.join(', ') || 'none'}
        </p>
        <div className="inline-buttons">
          <button type="button" disabled={running} onClick={() => void runRolloutControllerTick()}>
            Run Rollout Controller Tick
          </button>
        </div>
      </article>
      <table className="data-table" aria-label="Export runs table">
        <thead>
          <tr>
            <th>Export</th>
            <th>Session</th>
            <th>Status</th>
            <th>Profile</th>
            <th>Integrity</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {exportRuns.map((row) => (
            <tr key={row.export_id}>
              <td>{row.export_id}</td>
              <td>{row.session_id}</td>
              <td>{row.status}</td>
              <td>{row.profile}</td>
              <td>{String(row.integrity_ok)}</td>
              <td>
                <button type="button" onClick={() => void openFolder(row.export_id)}>
                  Open
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <hr />
      <h3>Release Ops (Internal Beta)</h3>
      <div className="grid-two">
        <label>
          Version
          <input
            type="text"
            value={releaseVersion}
            onChange={(event) => setReleaseVersion(event.target.value)}
          />
        </label>
        <label>
          Notes
          <input
            type="text"
            value={releaseNotes}
            onChange={(event) => setReleaseNotes(event.target.value)}
          />
        </label>
      </div>
      <div className="inline-buttons">
        <button type="button" disabled={running} onClick={() => void startRelease()}>
          Start Internal Beta Release (Dry Run)
        </button>
      </div>
      <h4>Staged Public Prerelease Promotion</h4>
      <div className="grid-two">
        <label>
          Promote Run ID
          <input
            type="text"
            value={promotionRunId}
            onChange={(event) => setPromotionRunId(event.target.value)}
            placeholder="rel_xxx"
          />
        </label>
        <article className="state-card">
          <p className="mono">Signing: {signingSnapshot?.signing_status ?? 'unknown'}</p>
          <p className="mono">Notarization: {signingSnapshot?.notarization_status ?? 'unknown'}</p>
          <p className="mono">
            Manual smoke: {String(signingSnapshot?.manual_smoke_ready ?? false)}
          </p>
        </article>
      </div>
      {signingSnapshot?.blocking_reasons?.length ? (
        <p className="mono">Blocking: {signingSnapshot.blocking_reasons.join(', ')}</p>
      ) : null}
      <div className="inline-buttons">
        <button
          type="button"
          disabled={running || !signingSnapshot?.manual_smoke_ready}
          title={
            signingSnapshot?.manual_smoke_ready
              ? 'Promote to staged public prerelease'
              : 'Manual smoke evidence is required before non-dry-run promotion'
          }
          onClick={() => void startPromotion()}
        >
          Start Staged Public Promotion (Dry Run)
        </button>
      </div>
      <h4>Extension Public Rollout (Chrome Web Store)</h4>
      <div className="grid-two">
        <label>
          Rollout Stage
          <select
            value={extensionRolloutStage}
            onChange={(event) => setExtensionRolloutStage(event.target.value as RolloutStageV1)}
          >
            <option value="pct_5">pct_5</option>
            <option value="pct_25">pct_25</option>
            <option value="pct_50">pct_50</option>
            <option value="pct_100">pct_100</option>
          </select>
        </label>
        <article className="state-card">
          <p className="mono">
            Compliance: {extensionCompliance?.checks_passed ?? 0} pass /{' '}
            {extensionCompliance?.checks_warn ?? 0} warn / {extensionCompliance?.checks_failed ?? 0}{' '}
            fail
          </p>
          <p className="mono">
            Blocking: {extensionCompliance?.blocking_reasons.join(', ') || 'none'}
          </p>
        </article>
      </div>
      <div className="inline-buttons">
        <button type="button" disabled={running} onClick={() => void startExtensionPublicRollout()}>
          Start Extension Public Rollout (Dry Run)
        </button>
        <button type="button" disabled={running} onClick={() => void evaluateExtensionRollout()}>
          Evaluate Extension Stage
        </button>
        <button type="button" disabled={running} onClick={() => void advanceExtensionRollout()}>
          Advance Extension Stage (Dry Run)
        </button>
      </div>
      {extensionEvaluation ? (
        <p className="mono">
          Eval: {extensionEvaluation.status} / {extensionEvaluation.action} / soak remaining{' '}
          {extensionEvaluation.soak_remaining_ms}ms
        </p>
      ) : null}
      {extensionRollouts.length > 0 ? (
        <table className="data-table" aria-label="Extension rollouts table">
          <thead>
            <tr>
              <th>Rollout</th>
              <th>Version</th>
              <th>Stage</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {extensionRollouts.map((row) => (
              <tr key={row.rollout_id}>
                <td>{row.rollout_id}</td>
                <td>{row.version}</td>
                <td>{row.stage}</td>
                <td>{row.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      {compliancePacks.length > 0 ? (
        <table className="data-table" aria-label="Compliance evidence packs table">
          <thead>
            <tr>
              <th>Pack</th>
              <th>Kind</th>
              <th>Version</th>
              <th>Stage</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {compliancePacks.map((row) => (
              <tr key={row.pack_id}>
                <td>{row.pack_id}</td>
                <td>{row.kind}</td>
                <td>{row.version}</td>
                <td>{row.stage ?? 'none'}</td>
                <td>{row.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      <h4>Desktop Auto-Update Rollout</h4>
      <div className="grid-two">
        <label>
          Channel
          <select
            value={updateChannel}
            onChange={(event) => setUpdateChannel(event.target.value as UpdateChannelV1)}
          >
            <option value="internal_beta">internal_beta</option>
            <option value="staged_public_prerelease">staged_public_prerelease</option>
            <option value="public_stable">public_stable</option>
          </select>
        </label>
        <label>
          Install ID
          <input value={installId} onChange={(event) => setInstallId(event.target.value)} />
        </label>
        <label>
          Current Version
          <input
            value={currentVersion}
            onChange={(event) => setCurrentVersion(event.target.value)}
          />
        </label>
        <article className="state-card">
          <p className="mono">Update stage: {updateSnapshot?.stage ?? 'none'}</p>
          <p className="mono">Rollout %: {updateSnapshot?.rollout_pct ?? 0}</p>
          <p className="mono">Signature verified: {String(updateSnapshot?.signature_verified)}</p>
        </article>
      </div>
      <div className="inline-buttons">
        <button type="button" onClick={() => void checkForUpdates()}>
          Check for Updates
        </button>
        <button
          type="button"
          disabled={updateCheck?.eligibility !== 'eligible'}
          onClick={() => void applyUpdate()}
        >
          Apply Update
        </button>
        <button type="button" disabled={running} onClick={() => void evaluateUpdateRollout()}>
          Evaluate Updater Stage
        </button>
        <button type="button" disabled={running} onClick={() => void advanceUpdateRollout()}>
          Advance Updater Stage (Dry Run)
        </button>
      </div>
      {updateCheck ? (
        <p className="mono">
          Eligibility: {updateCheck.eligibility}
          {updateCheck.reason ? ` (${updateCheck.reason})` : ''}
        </p>
      ) : null}
      {updateEvaluation ? (
        <p className="mono">
          Updater Eval: {updateEvaluation.status} / {updateEvaluation.action} / soak remaining{' '}
          {updateEvaluation.soak_remaining_ms}ms
        </p>
      ) : null}
      <table className="data-table" aria-label="Release runs table">
        <thead>
          <tr>
            <th>Run</th>
            <th>Version</th>
            <th>Status</th>
            <th>Started</th>
          </tr>
        </thead>
        <tbody>
          {releaseRuns.map((row) => (
            <tr key={row.run_id}>
              <td>{row.run_id}</td>
              <td>{row.version}</td>
              <td>{row.status}</td>
              <td>{row.started_at_ms}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h4>Platform Artifact Matrix</h4>
      <div className="grid-two">
        {(['macos', 'windows', 'linux'] as ReleasePlatformV1[]).map((platform) => (
          <article key={platform} className="state-card">
            <h5>{platform}</h5>
            {releaseArtifacts[platform].length === 0 ? (
              <p className="mono">No artifacts yet.</p>
            ) : (
              <ul>
                {releaseArtifacts[platform].map((artifact) => (
                  <li key={`${platform}:${artifact.path}`} className="mono">
                    {artifact.kind} · {artifact.arch} · {artifact.target_triple}
                  </li>
                ))}
              </ul>
            )}
          </article>
        ))}
      </div>
      <hr />
      <h3>Offline Bundle Inspect</h3>
      <div className="grid-two">
        <label>
          Bundle Path
          <input
            type="text"
            value={bundlePath}
            onChange={(event) => setBundlePath(event.target.value)}
            placeholder="/absolute/path/to/export.zip"
          />
        </label>
      </div>
      <button type="button" onClick={() => void openBundleInspect()}>
        Open Bundle Inspect
      </button>
    </section>
  );
}

function SettingsPage({ client }: AppDependencies): React.JSX.Element {
  const [status, setStatus] = useState<'loading' | 'error' | 'success'>('loading');
  const [message, setMessage] = useState<string | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [retainDays, setRetainDays] = useState(30);
  const [maxSessions, setMaxSessions] = useState(1000);
  const [deleteExports, setDeleteExports] = useState(true);
  const [deleteBlobs, setDeleteBlobs] = useState(true);

  const load = async (): Promise<void> => {
    setStatus('loading');
    try {
      const settings = await client.uiGetRetentionSettings();
      setEnabled(settings.policy.enabled);
      setRetainDays(settings.policy.retain_days);
      setMaxSessions(settings.policy.max_sessions);
      setDeleteExports(settings.policy.delete_exports);
      setDeleteBlobs(settings.policy.delete_blobs);
      setStatus('success');
    } catch {
      setStatus('error');
    }
  };

  useEffect(() => {
    void load();
  }, []);

  if (status === 'loading') return <LoadingState title="settings" />;
  if (status === 'error') return <ErrorState message="Unable to load settings." onRetry={load} />;

  return (
    <section className="panel">
      <h2>Settings</h2>
      <p>Control how long old sessions are kept and when cleanup runs.</p>
      <div className="inline-checkbox-group">
        <label className="inline-checkbox">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => setEnabled(event.target.checked)}
          />
          Retention enabled
        </label>
        <label className="inline-checkbox">
          <input
            type="checkbox"
            checked={deleteExports}
            onChange={(event) => setDeleteExports(event.target.checked)}
          />
          Delete exports during retention
        </label>
        <label className="inline-checkbox">
          <input
            type="checkbox"
            checked={deleteBlobs}
            onChange={(event) => setDeleteBlobs(event.target.checked)}
          />
          Delete blobs during retention
        </label>
      </div>
      <div className="grid-two">
        <label>
          Retain days
          <input
            type="number"
            min={1}
            value={retainDays}
            onChange={(event) => setRetainDays(Number(event.target.value))}
          />
        </label>
        <label>
          Max sessions
          <input
            type="number"
            min={1}
            value={maxSessions}
            onChange={(event) => setMaxSessions(Number(event.target.value))}
          />
        </label>
      </div>
      <div className="inline-buttons">
        <button
          type="button"
          onClick={() => {
            void (async () => {
              try {
                await client.uiSetRetentionSettings({
                  enabled,
                  retain_days: retainDays,
                  max_sessions: maxSessions,
                  delete_exports: deleteExports,
                  delete_blobs: deleteBlobs,
                });
                setMessage('Retention settings saved.');
              } catch {
                setMessage('Unable to save retention settings.');
              }
            })();
          }}
        >
          Save Retention Settings
        </button>
        <button
          type="button"
          onClick={() => {
            void (async () => {
              try {
                const result = await client.uiRunRetention('dry_run');
                setMessage(
                  `Dry-run candidates: ${result.report.candidate_sessions}, deleted: ${result.report.deleted_sessions}`,
                );
              } catch {
                setMessage('Retention dry-run failed.');
              }
            })();
          }}
        >
          Run Retention (Dry Run)
        </button>
        <button
          type="button"
          className="danger"
          onClick={() => {
            void (async () => {
              const confirmed = window.confirm(
                'Apply retention now? This will delete eligible sessions and artifacts.',
              );
              if (!confirmed) {
                return;
              }
              try {
                const result = await client.uiRunRetention('apply');
                setMessage(
                  `Retention applied. Deleted ${result.report.deleted_sessions}, failed ${result.report.failed_sessions}.`,
                );
              } catch {
                setMessage('Retention apply failed.');
              }
            })();
          }}
        >
          Run Retention (Apply)
        </button>
      </div>
      {message ? <p className="mono">{message}</p> : null}
    </section>
  );
}

function DiagnosticsPage({ client }: AppDependencies): React.JSX.Element {
  const [status, setStatus] = useState<'loading' | 'error' | 'success'>('loading');
  const [snapshot, setSnapshot] = useState<UiDiagnosticsSnapshotV1 | null>(null);
  const [bridgeRows, setBridgeRows] = useState<UiDiagnosticsSnapshotV1['diagnostics']>([]);
  const [reliabilitySnapshot, setReliabilitySnapshot] = useState<UiReliabilitySnapshotV1 | null>(
    null,
  );
  const [reliabilitySeries, setReliabilitySeries] = useState<UiReliabilitySeriesPointV1[]>([]);
  const [perfRuns, setPerfRuns] = useState<UiPerfRunListItemV1[]>([]);
  const [perfTrends, setPerfTrends] = useState<UiPerfTrendPointV1[]>([]);
  const [perfAnomalies, setPerfAnomalies] = useState<UiListPerfAnomaliesItemV1[]>([]);
  const [telemetrySettings, setTelemetrySettings] = useState<UiTelemetrySettingsV1 | null>(null);
  const [telemetryRuns, setTelemetryRuns] = useState<TelemetryExportRunV1[]>([]);
  const [telemetryAudits, setTelemetryAudits] = useState<TelemetryAuditRunV1[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [loadWarning, setLoadWarning] = useState<string | null>(null);

  const load = async (): Promise<void> => {
    setStatus('loading');
    try {
      const now = Date.now();
      const firstPass = await Promise.allSettled([
        client.uiGetDiagnostics(null),
        client.uiGetBridgeDiagnostics(null, 200),
        client.uiGetReliabilitySnapshot(86_400_000),
        client.uiListReliabilitySeries(
          'ws_disconnect_count' as ReliabilityMetricKeyV1,
          now - 86_400_000,
          now,
          3_600_000,
        ),
        client.uiListPerfRuns(20),
      ]);
      const secondPass = await Promise.allSettled([
        client.uiGetTelemetrySettings(),
        client.uiListTelemetryExports(20),
        client.uiListPerfTrends('sustained_capture_6h', 20),
        client.uiListPerfAnomalies(null, 20),
        client.uiListTelemetryAudits(20),
      ]);

      const getSettled = <T,>(result: PromiseSettledResult<T>, fallback: T): T =>
        result.status === 'fulfilled' ? result.value : fallback;

      const diag = getSettled<UiDiagnosticsSnapshotV1>(firstPass[0], {
        pairing_port: null,
        pairing_token: null,
        connection_status: 'disconnected',
        diagnostics: [],
        capture_drop_markers: 0,
        capture_limit_markers: 0,
      });
      const bridge = getSettled<UiDiagnosticsSnapshotV1['diagnostics']>(firstPass[1], []);
      const relSnapshot = getSettled<UiReliabilitySnapshotV1 | null>(firstPass[2], null);
      const relSeries = getSettled<UiReliabilitySeriesPointV1[]>(firstPass[3], []);
      const perf = getSettled<UiPerfRunListItemV1[]>(firstPass[4], []);
      const nextTelemetrySettings = getSettled<UiTelemetrySettingsV1 | null>(secondPass[0], null);
      const nextTelemetryRuns = getSettled<TelemetryExportRunV1[]>(secondPass[1], []);
      const nextPerfTrends = getSettled<UiPerfTrendPointV1[]>(secondPass[2], []);
      const nextPerfAnomalies = getSettled<UiListPerfAnomaliesItemV1[]>(secondPass[3], []);
      const nextTelemetryAudits = getSettled<TelemetryAuditRunV1[]>(secondPass[4], []);

      const failedCalls = [...firstPass, ...secondPass].filter(
        (result) => result.status === 'rejected',
      ).length;
      setLoadWarning(
        failedCalls > 0
          ? `Some diagnostics data is unavailable (${failedCalls} section${failedCalls === 1 ? '' : 's'} failed to load).`
          : null,
      );

      setSnapshot(diag);
      setBridgeRows(bridge);
      setReliabilitySnapshot(relSnapshot);
      setReliabilitySeries(relSeries);
      setPerfRuns(perf);
      setPerfTrends(nextPerfTrends);
      setPerfAnomalies(nextPerfAnomalies);
      setTelemetrySettings(nextTelemetrySettings);
      setTelemetryRuns(nextTelemetryRuns);
      setTelemetryAudits(nextTelemetryAudits);
      setStatus('success');
    } catch {
      setStatus('error');
    }
  };

  useEffect(() => {
    void load();
  }, []);

  if (status === 'loading') return <LoadingState title="diagnostics" />;
  if (status === 'error')
    return <ErrorState message="Unable to load diagnostics." onRetry={load} />;

  return (
    <section className="panel">
      <h2>About / Diagnostics</h2>
      {loadWarning ? <div className="state-card warning">{loadWarning}</div> : null}
      <p className="mono">Desktop connection: {snapshot?.connection_status ?? 'disconnected'}</p>
      <p className="mono">Capture drops: {snapshot?.capture_drop_markers ?? 0}</p>
      <p className="mono">Capture limits: {snapshot?.capture_limit_markers ?? 0}</p>
      <details>
        <summary>Advanced details</summary>
        <p className="mono">Pairing port: {snapshot?.pairing_port ?? 'n/a'}</p>
        <p className="mono">Pairing token: {snapshot?.pairing_token ?? 'n/a'}</p>
      </details>
      <h3>Telemetry Export</h3>
      <div className="inline-checkbox-group">
        <label className="inline-checkbox">
          <input
            type="checkbox"
            checked={telemetrySettings?.mode === 'local_plus_otlp'}
            onChange={(event) => {
              const nextMode = event.target.checked ? 'local_plus_otlp' : 'local_only';
              setTelemetrySettings((prev) =>
                prev
                  ? {
                      ...prev,
                      mode: nextMode,
                      otlp: { ...prev.otlp, enabled: event.target.checked || prev.otlp.enabled },
                    }
                  : prev,
              );
            }}
          />
          Enable OTLP mode
        </label>
        <label className="inline-checkbox">
          <input
            type="checkbox"
            checked={telemetrySettings?.otlp.enabled ?? false}
            onChange={(event) =>
              setTelemetrySettings((prev) =>
                prev ? { ...prev, otlp: { ...prev.otlp, enabled: event.target.checked } } : prev,
              )
            }
          />
          OTLP sink enabled
        </label>
      </div>
      <div className="inline-buttons">
        <button
          type="button"
          onClick={() => {
            void (async () => {
              if (!telemetrySettings) return;
              try {
                const saved = await client.uiSetTelemetrySettings(telemetrySettings);
                setTelemetrySettings(saved);
                setNotice('Telemetry settings saved.');
              } catch {
                setNotice('Unable to save telemetry settings.');
              }
            })();
          }}
        >
          Save Telemetry Settings
        </button>
        <button
          type="button"
          onClick={() => {
            void (async () => {
              try {
                const result = await client.uiRunTelemetryExport(null, null);
                setNotice(`Telemetry export ${result.run.export_run_id} completed.`);
                await load();
              } catch {
                setNotice('Telemetry export failed.');
              }
            })();
          }}
        >
          Run Telemetry Export
        </button>
        <button
          type="button"
          onClick={() => {
            void (async () => {
              try {
                const result = await client.uiRunTelemetryAudit(
                  telemetryRuns[0]?.export_run_id ?? null,
                );
                setNotice(`Telemetry audit ${result.run.audit_id} status: ${result.run.status}`);
                await load();
              } catch {
                setNotice('Telemetry audit failed.');
              }
            })();
          }}
        >
          Run Telemetry Audit
        </button>
      </div>
      {notice ? <p className="mono">{notice}</p> : null}
      {telemetryRuns.length === 0 ? (
        <p className="mono">No telemetry exports yet.</p>
      ) : (
        <table className="data-table" aria-label="Telemetry export history">
          <thead>
            <tr>
              <th>Run</th>
              <th>Status</th>
              <th>Samples</th>
              <th>Redacted</th>
            </tr>
          </thead>
          <tbody>
            {telemetryRuns.map((run) => (
              <tr key={run.export_run_id}>
                <td>{run.export_run_id}</td>
                <td>{run.status}</td>
                <td>{run.sample_count}</td>
                <td>{run.redacted_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h4>Telemetry Audits</h4>
      {telemetryAudits.length === 0 ? (
        <p className="mono">No telemetry audits yet.</p>
      ) : (
        <table className="data-table" aria-label="Telemetry audit history">
          <thead>
            <tr>
              <th>Audit</th>
              <th>Status</th>
              <th>Violations</th>
            </tr>
          </thead>
          <tbody>
            {telemetryAudits.map((audit) => (
              <tr key={audit.audit_id}>
                <td>{audit.audit_id}</td>
                <td>{audit.status}</td>
                <td>{audit.violations_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h3>Reliability KPIs (24h)</h3>
      {reliabilitySnapshot ? (
        <ul>
          {Object.entries(reliabilitySnapshot.window.totals_by_key).map(([key, value]) => (
            <li key={key} className="mono">
              {key}: {value}
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState message="No reliability samples available." />
      )}
      <h4>Disconnect Trend (bucketed)</h4>
      {reliabilitySeries.length === 0 ? (
        <p className="mono">No trend points yet.</p>
      ) : (
        <table className="data-table" aria-label="Reliability trend table">
          <thead>
            <tr>
              <th>Bucket</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {reliabilitySeries.map((point) => (
              <tr key={`${point.metric_key}:${point.bucket_start_ms}`}>
                <td>{point.bucket_start_ms}</td>
                <td>{point.metric_value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h3>Perf Runs</h3>
      <div className="inline-buttons">
        <button
          type="button"
          onClick={() => {
            void (async () => {
              await client.uiStartPerfRun('sustained_capture', 'fx_phase11_sustained_capture_30m');
              await load();
            })();
          }}
        >
          Start Sustained Capture Perf
        </button>
        <button
          type="button"
          onClick={() => {
            void (async () => {
              await client.uiStartPerfRun(
                'bundle_inspect_large',
                'fx_phase11_large_bundle_inspect',
              );
              await load();
            })();
          }}
        >
          Start Large Inspect Perf
        </button>
        <button
          type="button"
          onClick={() => {
            void (async () => {
              await client.uiStartEnduranceRun('sustained_capture_6h');
              await load();
            })();
          }}
        >
          Start Endurance 6h
        </button>
      </div>
      {perfRuns.length === 0 ? (
        <p className="mono">No perf runs recorded.</p>
      ) : (
        <table className="data-table" aria-label="Perf run table">
          <thead>
            <tr>
              <th>Run</th>
              <th>Kind</th>
              <th>Status</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {perfRuns.map((run) => (
              <tr key={run.perf_run_id}>
                <td>{run.perf_run_id}</td>
                <td>{run.run_kind}</td>
                <td>{run.status}</td>
                <td>{run.started_at_ms}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h4>Perf Trends</h4>
      {perfTrends.length === 0 ? (
        <p className="mono">No perf trends available.</p>
      ) : (
        <table className="data-table" aria-label="Perf trend table">
          <thead>
            <tr>
              <th>Bucket</th>
              <th>Metric</th>
              <th>Delta %</th>
              <th>Budget</th>
            </tr>
          </thead>
          <tbody>
            {perfTrends.map((point) => (
              <tr key={`${point.run_kind}:${point.bucket_start_ms}`}>
                <td>{point.bucket_start_ms}</td>
                <td>{point.metric_name}</td>
                <td>{point.trend_delta_pct}</td>
                <td>{point.budget_result}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h4>Perf Anomalies</h4>
      {perfAnomalies.length === 0 ? (
        <p className="mono">No anomalies detected.</p>
      ) : (
        <table className="data-table" aria-label="Perf anomaly table">
          <thead>
            <tr>
              <th>Run Kind</th>
              <th>Metric</th>
              <th>Severity</th>
              <th>Score</th>
            </tr>
          </thead>
          <tbody>
            {perfAnomalies.map((anomaly) => (
              <tr key={anomaly.anomaly_id}>
                <td>{anomaly.run_kind}</td>
                <td>{anomaly.metric_name}</td>
                <td>{anomaly.severity}</td>
                <td>{anomaly.score.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <ul>
        {bridgeRows.map((entry) => (
          <li key={`${entry.ts_ms}-${entry.kind}`}>
            {entry.kind}: {entry.message}
          </li>
        ))}
      </ul>
    </section>
  );
}

function parseSessionPath(pathname: string): { sessionId: string; subview: SessionSubview } | null {
  const match = pathname.match(
    /^\/sessions\/([^/]+)\/(overview|timeline|network|console|findings|export)$/,
  );
  if (!match) return null;
  return { sessionId: decodeURIComponent(match[1]), subview: match[2] as SessionSubview };
}

function parseBundleInspectPath(pathname: string): { inspectId: string } | null {
  const match = pathname.match(/^\/bundle-inspect\/([^/]+)$/);
  if (!match) {
    return null;
  }
  return { inspectId: decodeURIComponent(match[1]) };
}

function SessionPage({
  client,
  sessionId,
  subview,
}: AppDependencies & {
  readonly sessionId: string;
  readonly subview: SessionSubview;
}): React.JSX.Element {
  const [overview, setOverview] = useState<UiSessionOverviewV1 | null>(null);
  const [timeline, setTimeline] = useState<UiTimelineBundleV1 | null>(null);
  const [network, setNetwork] = useState<UiNetworkRowV1[]>([]);
  const [consoleRows, setConsoleRows] = useState<UiConsoleRowV1[]>([]);
  const [findings, setFindings] = useState<UiFindingCardV1[]>([]);
  const [exportCapability, setExportCapability] = useState<UiExportCapabilityV1 | null>(null);
  const [exportRuns, setExportRuns] = useState<UiExportListItemV1[]>([]);
  const [fullExportConfirmed, setFullExportConfirmed] = useState(false);
  const [exportMessage, setExportMessage] = useState<string | null>(null);
  const [status, setStatus] = useState<'loading' | 'error' | 'success'>('loading');
  const { fallbackNotice } = useHighlightFromQuery(status === 'success');
  const { selectedEvidence } = useEvidenceSelection();

  useEffect(() => {
    void (async () => {
      setStatus('loading');
      try {
        const [
          nextOverview,
          nextTimeline,
          nextNetwork,
          nextConsole,
          nextFindings,
          nextExport,
          nextExportRuns,
        ] = await Promise.all([
          client.uiGetSessionOverview(sessionId),
          client.uiGetTimeline(sessionId),
          client.uiGetNetwork(sessionId),
          client.uiGetConsole(sessionId),
          client.uiGetFindings(sessionId, 100),
          client.uiGetExports(sessionId),
          client.uiListExports(sessionId, 100),
        ]);
        setOverview(nextOverview);
        setTimeline(nextTimeline);
        setNetwork(nextNetwork);
        setConsoleRows(nextConsole);
        setFindings(nextFindings);
        setExportCapability(nextExport);
        setExportRuns(nextExportRuns);
        setStatus('success');
      } catch {
        setStatus('error');
      }
    })();
  }, [client, sessionId]);

  const runSessionExport = async (profile: 'share_safe' | 'full'): Promise<void> => {
    setExportMessage(null);
    try {
      const result = await client.uiStartExport(sessionId, profile, null);
      setExportMessage(`Export ${result.export_id} status: ${result.status}`);
      const nextRuns = await client.uiListExports(sessionId, 100);
      setExportRuns(nextRuns);
    } catch {
      setExportMessage('Export failed. Check diagnostics.');
    }
  };

  const validateExport = async (exportId: string): Promise<void> => {
    try {
      const result = await client.uiValidateExport(exportId);
      setExportMessage(
        result.valid
          ? `Export ${exportId} integrity validated.`
          : `Export ${exportId} invalid: ${result.missing_paths.join(', ') || result.mismatched_files.join(', ')}`,
      );
    } catch {
      setExportMessage(`Unable to validate export ${exportId}.`);
    }
  };

  if (status === 'loading') return <LoadingState title="session" />;
  if (status === 'error') {
    return (
      <ErrorState message="Unable to load session view." onRetry={() => window.location.reload()} />
    );
  }
  if (!overview) {
    return (
      <EmptyState message="Session not found." cta={<Link to="/sessions">Back to Sessions</Link>} />
    );
  }

  return (
    <section className="panel">
      <h2>Session: {sessionId}</h2>
      <nav className="session-subnav" aria-label="Session subviews">
        {(
          ['overview', 'timeline', 'network', 'console', 'findings', 'export'] as SessionSubview[]
        ).map((next) => (
          <Link
            key={next}
            to={`/sessions/${sessionId}/${next}`}
            className={next === subview ? 'active' : ''}
          >
            {next}
          </Link>
        ))}
      </nav>
      {fallbackNotice ? <div className="state-card warning">{fallbackNotice}</div> : null}
      <aside className="state-card">
        <strong>Selected Evidence</strong>
        <p>
          {selectedEvidence ? `${selectedEvidence.kind}:${selectedEvidence.target_id}` : 'none'}
        </p>
      </aside>

      {subview === 'overview' ? (
        <div className="stack">
          <p>Findings: {overview.findings_count}</p>
          <p>Interactions: {overview.interactions_count}</p>
          <p>Network requests: {overview.network_requests_count}</p>
        </div>
      ) : null}

      {subview === 'timeline' ? (
        <table className="data-table">
          <tbody>
            {(timeline?.events ?? []).map((row) => (
              <tr
                key={row.stable_id}
                data-highlight-key={`raw_event:${row.source_id}::`}
                data-highlight-container={`raw_event:${row.source_id}`}
              >
                <td>{row.ts_ms}</td>
                <td>{row.kind}</td>
                <td>{row.label}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {subview === 'network' ? (
        <table className="data-table">
          <tbody>
            {network.map((row) => {
              const key = ['net_row', row.net_request_id, 'status_code', '/status_code'].join(':');
              return (
                <tr
                  key={row.net_request_id}
                  data-highlight-key={key}
                  data-highlight-container={`net_row:${row.net_request_id}`}
                >
                  <td>
                    {row.host}
                    {row.path}
                  </td>
                  <td>{row.method}</td>
                  <td>{row.status_code}</td>
                  <td>{row.duration_ms}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : null}

      {subview === 'console' ? (
        <table className="data-table">
          <tbody>
            {consoleRows.map((row) => (
              <tr
                key={row.console_id}
                data-highlight-key={`console:${row.console_id}::`}
                data-highlight-container={`console:${row.console_id}`}
              >
                <td>{row.level}</td>
                <td>{row.source}</td>
                <td>{row.message_redacted}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {subview === 'findings' ? (
        <div className="stack">
          {findings.map((finding) => (
            <article key={finding.finding_id} className="finding-card">
              <h3>{finding.title}</h3>
              <p>{finding.summary}</p>
            </article>
          ))}
        </div>
      ) : null}

      {subview === 'export' ? (
        <div className="stack">
          <p>Default export profile: {exportCapability?.default_mode}</p>
          <button type="button" onClick={() => void runSessionExport('share_safe')}>
            Generate Share-Safe Export
          </button>
          <label className="inline-checkbox">
            <input
              type="checkbox"
              checked={fullExportConfirmed}
              onChange={(event) => setFullExportConfirmed(event.target.checked)}
            />
            I understand full export may include sensitive payloads.
          </label>
          <button
            type="button"
            disabled={!exportCapability?.full_export_allowed || !fullExportConfirmed}
            title={exportCapability?.full_export_block_reason ?? 'Full export unavailable'}
            onClick={() => void runSessionExport('full')}
          >
            Generate Full Export
          </button>
          <button
            type="button"
            onClick={() => void client.uiOpenExportFolder(exportRuns[0]?.export_id ?? null)}
          >
            Open Export Folder
          </button>
          <p>{exportMessage ?? exportCapability?.full_export_block_reason}</p>
          <table className="data-table" aria-label="Session export runs table">
            <thead>
              <tr>
                <th>Export</th>
                <th>Status</th>
                <th>Profile</th>
                <th>Integrity</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {exportRuns.map((row) => (
                <tr key={row.export_id}>
                  <td>{row.export_id}</td>
                  <td>{row.status}</td>
                  <td>{row.profile}</td>
                  <td>{String(row.integrity_ok)}</td>
                  <td>
                    <button type="button" onClick={() => void validateExport(row.export_id)}>
                      Validate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

function BundleInspectPage({
  client,
  inspectId,
}: AppDependencies & { readonly inspectId: string }): React.JSX.Element {
  const navigate = useNavigate();
  const [status, setStatus] = useState<'loading' | 'error' | 'success'>('loading');
  const [overview, setOverview] = useState<UiBundleInspectOverviewV1 | null>(null);
  const [findings, setFindings] = useState<UiBundleInspectFindingV1[]>([]);
  const [evidenceRefId, setEvidenceRefId] = useState('evr_mock_1');
  const [resolved, setResolved] = useState<UiBundleInspectEvidenceResolveResultV1 | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = async (): Promise<void> => {
    setStatus('loading');
    try {
      const [nextOverview, nextFindings] = await Promise.all([
        client.uiGetBundleInspectOverview(inspectId),
        client.uiListBundleInspectFindings(inspectId, 200),
      ]);
      setOverview(nextOverview);
      setFindings(nextFindings);
      setStatus('success');
    } catch {
      setStatus('error');
    }
  };

  useEffect(() => {
    void load();
  }, [client, inspectId]);

  const resolveEvidence = async (): Promise<void> => {
    if (!evidenceRefId.trim()) {
      setNotice('Enter an evidence ref id to resolve.');
      return;
    }
    try {
      const value = await client.uiResolveBundleInspectEvidence(inspectId, evidenceRefId.trim());
      setResolved(value);
      if (value && !value.exact_pointer_found) {
        setNotice(value.fallback_reason ?? 'Exact pointer unavailable');
      } else {
        setNotice(null);
      }
    } catch {
      setNotice('Unable to resolve evidence for this bundle.');
    }
  };

  if (status === 'loading') return <LoadingState title="bundle inspect" />;
  if (status === 'error')
    return <ErrorState message="Unable to open bundle inspect view." onRetry={load} />;
  if (!overview) return <EmptyState message="Bundle inspect record not found." />;

  return (
    <section className="panel">
      <h2>Bundle Inspect</h2>
      <p className="mono">Inspect: {overview.inspect_id}</p>
      <p className="mono">Path: {overview.bundle_path}</p>
      <p className="mono">Integrity: {String(overview.integrity_valid)}</p>
      <p className="mono">Session: {overview.session_id ?? 'unknown'}</p>
      <p className="mono">Profile: {overview.profile ?? 'unknown'}</p>
      <p className="mono">Findings: {overview.findings_count}</p>
      <p className="mono">Evidence Refs: {overview.evidence_refs_count}</p>

      <h3>Findings</h3>
      {findings.length === 0 ? (
        <EmptyState message="No findings found inside this bundle." />
      ) : (
        <table className="data-table" aria-label="Bundle findings table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Detector</th>
              <th>Severity</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.finding_id}>
                <td>{finding.title}</td>
                <td>{finding.detector_id}</td>
                <td>{finding.severity_score}</td>
                <td>{finding.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h3>Resolve Evidence</h3>
      <div className="inline-buttons">
        <input
          type="text"
          value={evidenceRefId}
          onChange={(event) => setEvidenceRefId(event.target.value)}
          placeholder="evidence_ref_id"
        />
        <button type="button" onClick={() => void resolveEvidence()}>
          Resolve
        </button>
      </div>
      {notice ? <div className="state-card warning">{notice}</div> : null}
      {resolved ? (
        <article
          className="state-card"
          data-highlight-container={`${resolved.kind}:${resolved.target_id}`}
        >
          <p className="mono">
            Target: {resolved.kind}:{resolved.target_id}
          </p>
          <p className="mono">Exact pointer: {String(resolved.exact_pointer_found)}</p>
          <pre>{JSON.stringify(resolved.container_json ?? {}, null, 2)}</pre>
        </article>
      ) : null}

      <div className="inline-buttons">
        <button
          type="button"
          onClick={() => {
            void (async () => {
              await client.uiCloseBundleInspect(inspectId);
              navigate('/exports');
            })();
          }}
        >
          Close Inspect
        </button>
      </div>
    </section>
  );
}

function ScreenRouter({ client }: AppDependencies): React.JSX.Element {
  const location = useLocation();
  const path = location.pathname;
  const sessionRoute = parseSessionPath(path);
  const bundleInspectRoute = parseBundleInspectPath(path);

  if (path === '/' || path === '/sessions') return <SessionsPage client={client} />;
  if (path === '/live-capture') return <LiveCapturePage client={client} />;
  if (path === '/findings') return <FindingsPage client={client} />;
  if (path === '/exports') return <ExportsPage client={client} />;
  if (path === '/settings') return <SettingsPage client={client} />;
  if (path === '/diagnostics') return <DiagnosticsPage client={client} />;
  if (bundleInspectRoute) {
    return <BundleInspectPage client={client} inspectId={bundleInspectRoute.inspectId} />;
  }
  if (sessionRoute)
    return (
      <SessionPage
        client={client}
        sessionId={sessionRoute.sessionId}
        subview={sessionRoute.subview}
      />
    );
  if (/^\/sessions\/[^/]+$/.test(path)) {
    const sessionId = decodeURIComponent(path.split('/')[2]);
    return <Navigate to={`/sessions/${sessionId}/overview`} replace />;
  }
  return <Navigate to="/sessions" replace />;
}

export function AppLayout({ client }: AppDependencies): React.JSX.Element {
  const [selectedEvidence, setSelectedEvidence] = useState<UiEvidenceResolveResultV1 | null>(null);

  return (
    <EvidenceSelectionContext.Provider value={{ selectedEvidence, setSelectedEvidence }}>
      <div className="app-shell">
        <header className="app-header">
          <h1>DevTools Translator</h1>
          <p>Local-first diagnostics with deterministic evidence chains.</p>
        </header>
        <nav className="global-nav" aria-label="Global Navigation">
          <Link to="/sessions">Sessions</Link>
          <Link to="/live-capture">Live Capture</Link>
          <Link to="/findings">Findings</Link>
          <Link to="/exports">Exports</Link>
          <Link to="/settings">Settings</Link>
          <Link to="/diagnostics">About/Diagnostics</Link>
        </nav>
        <main className="main-pane">
          <ScreenRouter client={client} />
        </main>
      </div>
    </EvidenceSelectionContext.Provider>
  );
}

export const sessionSubviews: SessionSubview[] = [
  'overview',
  'timeline',
  'network',
  'console',
  'findings',
  'export',
];
