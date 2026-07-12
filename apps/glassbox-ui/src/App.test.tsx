import React from 'react';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it } from 'vitest';
import { GlassboxApp } from './App';
import type { EvidencePage, EvidenceRow } from './data';

afterEach(cleanup);

describe('Glassbox investigation workbench', () => {
  it('keeps a complete tabular alternative available', async () => {
    const user = userEvent.setup();
    render(<GlassboxApp />);
    expect(screen.getByRole('table', { name: /complete tabular equivalent/i })).toBeTruthy();
    await user.click(screen.getByRole('tab', { name: /table/i }));
    expect(screen.queryByLabelText(/actor-lane evidence timeline/i)).toBeNull();
    expect(screen.getByText('Click “Upload”')).toBeTruthy();
  });

  it('updates selected evidence and opens field-level export review', async () => {
    const user = userEvent.setup();
    render(<GlassboxApp />);
    fireEvent.click(screen.getAllByText('Memory pressure: high')[0]!);
    expect(screen.getByText(/Selected: Memory pressure: high/)).toBeTruthy();
    await user.click(screen.getByRole('button', { name: /export review/i }));
    expect(screen.getByRole('dialog', { name: /export \/ redaction preview/i })).toBeTruthy();
    expect(screen.getByText('Structural redaction')).toBeTruthy();
  });

  it('shows uncertainty, counterevidence, and missing evidence without a causal claim', () => {
    render(<GlassboxApp />);
    expect(screen.getByText(/candidate relation, not causation/i)).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Counterevidence' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Missing evidence' })).toBeTruthy();
    expect(screen.getByText(/no causal conclusion/i)).toBeTruthy();
  });

  it('renders a bounded cursor page for a million-event investigation', async () => {
    const rows: EvidenceRow[] = Array.from({ length: 100 }, (_, index) => ({
      id: `perf-${index}`,
      time: `14:07:${String(index % 60).padStart(2, '0')}.000`,
      actor: 'Application',
      source: 'Encrypted store',
      locator: `glassbox://observation/perf-${index}`,
      event: `Performance event ${index}`,
      status: index === 50 ? 'gap' : 'observed',
      uncertainty: index === 50 ? 'explicit fixture gap' : '±1 ms',
    }));
    const page: EvidencePage = {
      rows,
      totalCount: 1_000_000,
      nextCursor: 'obs:next-page',
      visibleGapCount: 1,
      unmarkedDropCount: 0,
    };
    const user = userEvent.setup();
    render(<GlassboxApp page={page} />);
    expect(screen.getByText('100 of 1,000,000 events · paused')).toBeTruthy();
    const table = screen.getByRole('table', { name: /complete tabular equivalent/i });
    expect(within(table).getAllByRole('row')).toHaveLength(101);
    await user.click(within(table).getByText('Performance event 99'));
    expect(screen.getByText(/Selected: Performance event 99/)).toBeTruthy();
  });

  it('fails closed instead of rendering an unmarked drop count', () => {
    const page: EvidencePage = {
      rows: [{ id: 'drop', time: '0', actor: 'Application', source: 'Fixture', locator: 'fixture://drop', event: 'Drop', status: 'gap', uncertainty: 'unknown' }],
      totalCount: 1,
      nextCursor: null,
      visibleGapCount: 1,
      unmarkedDropCount: 1,
    };
    expect(() => render(<GlassboxApp page={page} />)).toThrow(/unmarked drops/i);
  });
});
